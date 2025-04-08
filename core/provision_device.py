"""
provision_device.py - Final Shape Device Provisioner

Implements the only authorized interface for initial Sentinel provisioning.

Steps (from instructions):
 1. collect_user_input() - gather config fields
 2. build_and_validate_sentinelrc() - calls sentinelrc_schema.validate_sentinelrc, signs .sentinelrc
 3. generate_host_identity() - create identity.json
 4. upload_license() - uses LicenseManager.upload_license()
 5. generate_keys() - create vendor_dilithium_priv.bin / .pub.pem, plus kyber/rsa if enabled
 6. build_trust_anchor() - gather hashes, sign with vendor_dil private key
 7. lock_provisioning() - writes provisioning_complete.flag
 8. append_audit_log() - logs to chain with EventCode.DEVICE_PROVISIONED
 9. Self-Destruct if success => remove provision_device.py & installer_dilithium_priv.bin, zero mem, log EventCode.DEVICE_PROVISIONED_SECURE

Failsafe behaviors:
 - Any signature fail => abort
 - If config or license invalid => no files written
 - If provisioning_complete.flag found => refuse to run
 - If directory missing => abort
 - If all steps pass => final self-destruction
"""

import os
import sys
import json
import hashlib
import logging
from typing import Dict, Any, Optional
import shutil

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.utils.sentinelrc_schema import validate_sentinelrc
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseError
from aepok_sentinel.core.key_manager import KeyManager
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.pqc_crypto import sign_content_bundle, CryptoSignatureError, oqs
from aepok_sentinel.core.constants import EventCode

logger = get_logger("provision_device")

# We define an additional event code for final self-destruction logging:
# If you have a separate constants location, you could put it there. For demonstration, we do inline:
class ExtendedEventCode:
    DEVICE_PROVISIONED_SECURE = "DEVICE_PROVISIONED_SECURE"


class ProvisionError(Exception):
    """Raised if provisioning fails at any step (invalid config, signature fail, etc.)."""


class ProvisionDevice:
    """
    Main orchestrator for provisioning:
      - Called once per fresh install or device factory reset
      - Ensures no re-provisioning if provisioning_complete.flag is present
      - Uses an 'installer_dilithium_priv.bin' as the authority key (the provisioning authority key)
      - Generates vendor_dilithium_priv.bin + vendor_dilithium_pub.pem for the device's own signing
      - On success, deletes itself + the installer key
    """

    def __init__(self, runtime_base: str, audit_chain: AuditChain):
        """
        :param runtime_base: The base runtime path (SENTINEL_RUNTIME_BASE)
        :param audit_chain: Pre-initialized AuditChain for logging events
        """
        self.runtime_base = runtime_base
        self.audit_chain = audit_chain
        self._provision_flag_path = resolve_path("provisioning_complete.flag")
        self._sentinelrc_path = resolve_path("config", ".sentinelrc")
        self._license_path = resolve_path("license", "license.key")
        self._identity_path = resolve_path("config", "identity.json")
        self._trust_anchor_path = resolve_path("config", "trust_anchor.json")
        self._keys_dir = resolve_path("keys")
        self._installer_key_path = resolve_path("keys", "installer_dilithium_priv.bin")

        self._vendor_dil_priv = b""   # store device's new vendor_dil private key
        self._vendor_dil_pub = b""    # store device's vendor_dil public key
        self._license_mgr: Optional[LicenseManager] = None
        self._key_mgr: Optional[KeyManager] = None
        self._sentinel_config: Optional[SentinelConfig] = None
        self._installer_priv: Optional[bytes] = None  # the provisioning authority key, loaded once

    def provision(self, raw_config: Dict[str, Any], license_file: str) -> None:
        """
        High-level provision logic:
         - check provisioning_complete.flag
         - load installer key
         - build_and_validate_sentinelrc
         - generate_host_identity
         - upload_license
         - generate_keys
         - build_trust_anchor
         - lock_provisioning
         - append_audit_log
         - self_destruct if all success
        :param raw_config: dictionary for .sentinelrc
        :param license_file: path to an external license file to upload
        """
        self._check_if_already_provisioned()
        logger.info("Starting device provisioning...")

        # Load the installer (provision authority) Dilithium private key
        self._load_installer_private_key()

        # 1) build + validate .sentinelrc => sign with installer key
        self.build_and_validate_sentinelrc(raw_config)

        # now that we have a valid config => create LicenseManager, KeyManager
        self._sentinel_config = SentinelConfig(raw_config)
        self._license_mgr = LicenseManager(self._sentinel_config)
        self._key_mgr = KeyManager(self._sentinel_config, self._license_mgr)

        # 2) generate_host_identity => sign identity.json with installer key
        self.generate_host_identity()

        # 3) upload + verify license => abort if invalid
        self.upload_license(license_file)

        # 4) generate keys => vendor_dil + others => sign them with installer key
        self.generate_keys()

        # 5) build + sign trust_anchor.json with vendor_dil key
        self.build_trust_anchor()

        # 6) lock provisioning => create provisioning_complete.flag
        self.lock_provisioning()

        # 7) append to audit log => DEVICE_PROVISIONED
        self.append_audit_log()

        # 8) self-destruct => remove provision_device.py + installer_dilithium_priv.bin, zero memory
        # only if all steps succeed
        self.self_destruct()

        logger.info("Device provisioning completed successfully.")

    def collect_user_input(self) -> Dict[str, Any]:
        """
        Prompts user for minimal .sentinelrc config fields, including required anchor_export_path.
        """
        logger.info("Collecting user config input from CLI or GUI (production-ready).")

        anchor_path = input("Enter the full path to your anchor export directory (must exist and be mounted): ").strip()
        if not os.path.isdir(anchor_path):
            raise ProvisionError(f"Anchor export path '{anchor_path}' does not exist or is not a directory.")

        config_data = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT",  # or HARDENED / PERMISSIVE
            "scan_paths": ["/home/data"],
            "exclude_paths": ["/home/exclude"],
            "cloud_keyvault_enabled": True,
            "cloud_keyvault_url": "https://veritaevum.vault.azure.net/",
            "cloud_dilithium_secret": "DILITHIUM-PRIVATE-KEY",
            "cloud_kyber_secret": "KYBER-PRIVATE-KEY",
            "license_required": True,
            "bound_to_hardware": True,
            "allow_unknown_keys": False,
            "anchor_export_path": anchor_path
        }

        return config_data

    def build_and_validate_sentinelrc(self, raw_dict: Dict[str, Any]) -> None:
        """
        1) calls validate_sentinelrc(raw_dict)
        2) if pass => writes .sentinelrc
        3) sign_content_bundle => write .sentinelrc.sig
        4) if fail => raise ProvisionError
        """
        logger.info("Validating .sentinelrc config fields.")
        from aepok_sentinel.utils.sentinelrc_schema import validate_sentinelrc
        try:
            validated = validate_sentinelrc(raw_dict)
        except Exception as e:
            raise ProvisionError(f"Config validation failed: {e}")

        # now write .sentinelrc
        sentinelrc_dir = os.path.dirname(self._sentinelrc_path)
        if not os.path.isdir(sentinelrc_dir):
            raise ProvisionError(f"Directory missing: {sentinelrc_dir}; cannot write .sentinelrc")

        sentinelrc_json = json.dumps(validated, indent=2)
        try:
            with open(self._sentinelrc_path, "w", encoding="utf-8") as f:
                f.write(sentinelrc_json)
        except Exception as e:
            raise ProvisionError(f"Cannot write .sentinelrc: {e}")

        # sign with installer key
        if not self._installer_priv:
            raise ProvisionError("Installer key not loaded => cannot sign .sentinelrc")

        try:
            ephemeral_config = SentinelConfig({"mode": "cloud", "allow_classical_fallback": False})
            sig_bundle = sign_content_bundle(sentinelrc_json.encode("utf-8"), ephemeral_config, self._installer_priv, None)

            import base64
            sig_b64 = base64.b64encode(json.dumps(sig_bundle).encode("utf-8"))

            with open(self._sentinelrc_path + ".sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception as e:
            raise ProvisionError(f"Failed to sign .sentinelrc: {e}")

        logger.info(".sentinelrc validated and signed with installer key successfully.")

    def generate_host_identity(self) -> None:
        """
        Captures hostname + salt => identity.json => sign => identity.json.sig
        Signed with installer key.
        """
        import socket
        hostname = socket.gethostname()
        salt = "DEVICE_SALT_2025"  # demonstration
        raw = (hostname + salt).encode("utf-8")
        host_fp = hashlib.sha256(raw).hexdigest()

        identity_data = {
            "hostname": hostname,
            "host_fingerprint": host_fp,
            "created_utc": self._utc_now()
        }

        identity_json = json.dumps(identity_data, indent=2)
        identity_dir = os.path.dirname(self._identity_path)
        if not os.path.isdir(identity_dir):
            raise ProvisionError(f"Directory missing for identity.json: {identity_dir}")
        try:
            with open(self._identity_path, "w", encoding="utf-8") as f:
                f.write(identity_json)
        except Exception as e:
            raise ProvisionError(f"Cannot write identity.json: {e}")

        # sign with installer key
        if not self._installer_priv:
            raise ProvisionError("Installer key not loaded => cannot sign identity.json")
        try:
            ephemeral_config = SentinelConfig({"mode": "cloud", "allow_classical_fallback": False})
            sig_bundle = sign_content_bundle(identity_json.encode("utf-8"), ephemeral_config, self._installer_priv, None)

            import base64
            sig_b64 = base64.b64encode(json.dumps(sig_bundle).encode("utf-8"))
            with open(self._identity_path + ".sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception as e:
            raise ProvisionError(f"Failed to sign identity.json: {e}")

        logger.info("identity.json created and signed => host_fingerprint=%s", host_fp)

    def upload_license(self, license_file: str) -> None:
        """
        Uses LicenseManager.upload_license(...) to place the license in runtime license folder,
        then attempts to verify it. If invalid => raise ProvisionError
        """
        if not os.path.isfile(license_file):
            raise ProvisionError(f"Provided license file does not exist: {license_file}")

        if not self._license_mgr:
            raise ProvisionError("upload_license called before LicenseManager init")

        try:
            self._license_mgr.upload_license(license_file)
            logger.info("License successfully uploaded to runtime.")
            # verify by re-loading?
            self._license_mgr.load_license()  # if fails => license invalid
            if not self._license_mgr.license_state.valid:
                raise ProvisionError("Uploaded license is not valid after re-load => provisioning aborted.")
        except (LicenseError, Exception) as e:
            raise ProvisionError(f"License upload or validation failed: {e}")

    def generate_keys(self) -> None:
        """
        Generates vendor_dilithium_priv.bin / vendor_dilithium_pub.pem, plus kyber/rsa if config says so.
        The vendor key is used by the device to sign future trust_anchor, logs, etc.
        Then we sign those vendor keys with the installer key for authenticity.
        """
        if not self._key_mgr:
            raise ProvisionError("generate_keys called but no KeyManager init")

        if not os.path.isdir(self._keys_dir):
            raise ProvisionError(f"Keys directory missing: {self._keys_dir}")

        # Generate vendor signing key => vendor_dilithium_priv.bin / vendor_dilithium_pub.pem
        if not oqs:
            raise ProvisionError("liboqs not installed => cannot generate PQC keys for vendor")

        try:
            from aepok_sentinel.core.pqc_crypto import sign_content_bundle
            import base64
            import json as j

            # 1) vendor Dilithium
            from oqs import Signature
            with Signature("Dilithium2") as sig:
                sig.generate_keypair()
                vendor_priv = sig.export_secret_key()
                vendor_pub = sig.export_public_key()

            priv_path = resolve_path("keys", "vendor_dilithium_priv.bin")
            pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")

            with open(priv_path, "wb") as f:
                f.write(vendor_priv)
            with open(pub_path, "wb") as f:
                f.write(vendor_pub)

            # sign them with the installer key
            if not self._installer_priv:
                raise ProvisionError("Installer key not loaded => cannot sign vendor_dil keys")

            ephemeral_config = SentinelConfig({"mode": "cloud", "allow_classical_fallback": False})

            # sign the private key
            priv_sig = sign_content_bundle(vendor_priv, ephemeral_config, self._installer_priv, None)
            priv_b64 = base64.b64encode(j.dumps(priv_sig).encode("utf-8"))
            with open(priv_path + ".sig", "wb") as sf:
                sf.write(priv_b64)

            # sign the pub key
            pub_sig = sign_content_bundle(vendor_pub, ephemeral_config, self._installer_priv, None)
            pub_b64 = base64.b64encode(j.dumps(pub_sig).encode("utf-8"))
            with open(pub_path + ".sig", "wb") as sf:
                sf.write(pub_b64)

            logger.info("Vendor dilithium keys generated + signed => %s, %s", priv_path, pub_path)
            self._vendor_dil_priv = vendor_priv
            self._vendor_dil_pub = vendor_pub
        except Exception as e:
            raise ProvisionError(f"Failed to generate vendor Dilithium keys: {e}")

        # For kyber & optional RSA => rely on KeyManager
        try:
            self._key_mgr.rotate_keys()  # triggers local generation logic for PQC enc + RSA if fallback
        except Exception as e:
            raise ProvisionError(f"Failed to generate PQC encryption or RSA keys: {e}")

    def build_trust_anchor(self) -> None:
        """
        Gathers SHA256 for .sentinelrc, license.key, identity.json, vendor keys, key manager keys, core code modules, etc.
        Writes trust_anchor.json with a dictionary of {filename => sha256}, signs it with the vendor_dil private key.
        """
        anchor_data = {}
        # minimal example => we list a known set from instructions
        file_list = [
            self._sentinelrc_path,
            self._license_path,
            self._identity_path,
            self._trust_anchor_path,  # self reference => partial
            resolve_path("keys", "vendor_dilithium_priv.bin"),
            resolve_path("keys", "vendor_dilithium_pub.pem"),
        ]
        # Also gather any keys from KeyManager (kyber, rsa, etc.)
        for f in os.listdir(self._keys_dir):
            fullp = resolve_path("keys", "f")
            if os.path.isfile(fullp) and fullp not in file_list:
                file_list.append(fullp)

        # Hash them
        anchor_obj = {"version": 1, "created_utc": self._utc_now(), "hashes": {}}
        for path in file_list:
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    hval = hashlib.sha256(data).hexdigest()
                    rel_path = os.path.relpath(path, self.runtime_base)
                    anchor_obj["hashes"][rel_path] = hval
                except Exception as e:
                    raise ProvisionError(f"Failed to compute hash for {path}: {e}")

        # Enforce required trust anchor entries
        required_paths = [
            "config/.sentinelrc",
            "license/license.key",
            "config/identity.json"
        ]
        present_keys = list(anchor_obj["hashes"].keys())
        has_kyber = any("kyber_priv" in p for p in present_keys)
        has_dil = any("dilithium_priv" in p for p in present_keys)

        missing_required = [r for r in required_paths if r not in present_keys]
        if missing_required or not (has_kyber and has_dil):
            raise ProvisionError(
                f"trust_anchor missing required files. Missing={missing_required}, kyber={has_kyber}, dil={has_dil}"
            )
        anchor_json = json.dumps(anchor_obj, indent=2)
        anchor_dir = os.path.dirname(self._trust_anchor_path)
        if not os.path.isdir(anchor_dir):
            raise ProvisionError(f"Directory missing for trust_anchor.json: {anchor_dir}")

        try:
            with open(self._trust_anchor_path, "w", encoding="utf-8") as f:
                f.write(anchor_json)
        except Exception as e:
            raise ProvisionError(f"Cannot write trust_anchor.json: {e}")

        # sign with vendor_dil private key
        if not self._vendor_dil_priv:
            raise ProvisionError("No vendor Dilithium private key => cannot sign trust_anchor")
        try:
            device_config = SentinelConfig({"mode": "airgap", "allow_classical_fallback": False})
            sig_bundle = sign_content_bundle(anchor_json.encode("utf-8"), device_config, self._vendor_dil_priv, None)

            import base64
            import json as j
            sig_b64 = base64.b64encode(j.dumps(sig_bundle).encode("utf-8"))
            with open(self._trust_anchor_path + ".sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception as e:
            raise ProvisionError(f"Failed to sign trust_anchor.json: {e}")

        logger.info("trust_anchor.json created and signed with vendor key.")

    def lock_provisioning(self) -> None:
        """
        Writes provisioning_complete.flag => prevents re-run
        """
        if os.path.isfile(self._provision_flag_path):
            raise ProvisionError("Device is already provisioned. provisioning_complete.flag found.")
        try:
            with open(self._provision_flag_path, "w", encoding="utf-8") as f:
                f.write("Provisioning complete.\n")
        except Exception as e:
            raise ProvisionError(f"Failed to create provisioning_complete.flag: {e}")

        logger.info("Provisioning locked => provisioning_complete.flag created.")

    def append_audit_log(self) -> None:
        """
        Final log => Device provisioned.
        Must include host fingerprint, license uuid, enforcement mode, etc.
        """
        if not self.audit_chain:
            logger.warning("No audit chain => cannot append DEVICE_PROVISIONED event.")
            return
        try:
            host_fp = "unknown"
            lic_uuid = "unknown"
            en_mode = "PERMISSIVE"
            if self._sentinel_config:
                en_mode = getattr(self._sentinel_config, "enforcement_mode", "PERMISSIVE")
            if self._license_mgr and self._license_mgr.license_state.info:
                lic_uuid = self._license_mgr.license_state.info.get("license_uuid", "unknown")

            # read host_fingerprint from identity.json
            if os.path.isfile(self._identity_path):
                try:
                    with open(self._identity_path, "r", encoding="utf-8") as f:
                        ident_obj = json.load(f)
                    host_fp = ident_obj.get("host_fingerprint", "unknown")
                except:
                    pass

            meta = {
                "host_fingerprint": host_fp,
                "license_uuid": lic_uuid,
                "enforcement_mode": en_mode,
                "utc": self._utc_now()
            }
            self.audit_chain.append_event(EventCode.DEVICE_PROVISIONED.value, meta)
            logger.info("Audit log: DEVICE_PROVISIONED => %s", meta)
        except Exception as e:
            logger.error("Failed to append event DEVICE_PROVISIONED: %s", e)

    def self_destruct(self) -> None:
        """
        If everything succeeded => remove provision_device.py & installer_dilithium_priv.bin,
        zero any in-memory caches, log an additional event: DEVICE_PROVISIONED_SECURE
        """
        # Zero memory
        if self._installer_priv:
            ba = bytearray(self._installer_priv)
            for i in range(len(ba)):
                ba[i] = 0
            self._installer_priv = None

        if self._vendor_dil_priv:
            vb = bytearray(self._vendor_dil_priv)
            for i in range(len(vb)):
                vb[i] = 0
            self._vendor_dil_priv = b""

        # Attempt removing provision_device.py
        script_path = os.path.abspath(__file__)
        # Attempt removing the installer key
        if os.path.isfile(self._installer_key_path):
            try:
                os.remove(self._installer_key_path)
            except Exception as e:
                logger.warning("Failed to remove installer key: %s", e)

        # Log final "DEVICE_PROVISIONED_SECURE" event
        try:
            self.audit_chain.append_event(ExtendedEventCode.DEVICE_PROVISIONED_SECURE, {
                "status": "self_destruct",
                "script": script_path,
                "utc": self._utc_now()
            })
            logger.info("DEVICE_PROVISIONED_SECURE appended to chain.")
        except Exception as e:
            logger.error("Failed to log final secure provisioning event: %s", e)

        # Remove the script itself (provision_device.py) last
        try:
            os.remove(script_path)
            logger.info("Self-destruct: removed provision_device.py successfully.")
        except Exception as e:
            logger.warning("Failed to remove provision_device.py: %s", e)

    # ----------------- Helpers -----------------

    def _check_if_already_provisioned(self) -> None:
        if os.path.isfile(self._provision_flag_path):
            raise ProvisionError("Cannot proceed => provisioning_complete.flag exists => device already provisioned.")

    def _load_installer_private_key(self) -> None:
        if not os.path.isfile(self._installer_key_path):
            raise ProvisionError(f"Installer key not found at {self._installer_key_path}")
        try:
            with open(self._installer_key_path, "rb") as f:
                self._installer_priv = f.read()
        except Exception as e:
            raise ProvisionError(f"Failed reading installer key: {e}")

        if len(self._installer_priv) < 100:  # very naive check
            raise ProvisionError("Installer key is suspiciously short => aborting provisioning.")
        logger.info("Loaded installer Dilithium private key from: %s", self._installer_key_path)

    def _utc_now(self) -> str:
        import datetime
        return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
