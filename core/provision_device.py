# provision_device.py
"""
Final-Shape Device Provisioner

Implements the only authorized interface for initial Sentinel provisioning.

Steps:
 1. collect_user_input() - gather config fields
 2. build_and_validate_sentinelrc() - calls sentinelrc_schema.validate_sentinelrc, signs .sentinelrc
 3. generate_host_identity() - create identity.json
 4. upload_license() - uses LicenseManager.upload_license()
 5. generate_keys() - create vendor_dilithium_priv.bin / .pub.pem, plus kyber/rsa if enabled
 6. build_trust_anchor() - gather hashes, sign with vendor_dil private key
 7. lock_provisioning() - writes provisioning_complete.flag
 8. append_audit_log() - logs to chain with EventCode.DEVICE_PROVISIONED
 9. Self-Destruct if success => remove provision_device.py & installer_dilithium_priv.bin, zero mem, log ExtendedEventCode.DEVICE_PROVISIONED_SECURE

Failsafe behaviors:
 - Any signature fail => abort
 - If config or license invalid => no files written
 - If provisioning_complete.flag found => refuse to run
 - If directories are missing => abort
 - If all steps pass => final self-destruction
"""

import sys
import json
import hashlib
import logging
from typing import Dict, Any, Optional
import shutil
import base64

from pathlib import Path

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.utils.sentinelrc_schema import validate_sentinelrc
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseError
from aepok_sentinel.core.key_manager import KeyManager
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.directory_contract import resolve_path, SENTINEL_RUNTIME_BASE
from aepok_sentinel.core.pqc_crypto import sign_content_bundle, CryptoSignatureError, oqs
from aepok_sentinel.core.constants import EventCode

logger = get_logger("provision_device")


class ExtendedEventCode:
    DEVICE_PROVISIONED_SECURE = "DEVICE_PROVISIONED_SECURE"


class ProvisionError(Exception):
    """Raised if provisioning fails at any step (invalid config, signature fail, etc.)."""


class ProvisionDevice:
    """
    Main orchestrator for provisioning:
      - Called once per fresh install or device factory reset
      - Ensures no re-provisioning if provisioning_complete.flag is present
      - Uses an 'installer_dilithium_priv.bin' as the provisioning authority key
      - Generates vendor_dilithium_priv.bin + vendor_dilithium_pub.pem for the device's own signing
      - On success, deletes itself + the installer key
    """

    def __init__(self, runtime_base: str, audit_chain: AuditChain):
        """
        :param audit_chain: Pre-initialized AuditChain for logging events
        """
        self.runtime_base = SENTINEL_RUNTIME_BASE
        self.audit_chain = audit_chain

        # All paths resolved under contract
        self._provision_flag_path = resolve_path("provisioning_complete.flag")
        self._sentinelrc_path = resolve_path("config", ".sentinelrc")
        self._license_path = resolve_path("license", "license.key")
        self._identity_path = resolve_path("config", "identity.json")
        self._trust_anchor_path = resolve_path("config", "trust_anchor.json")
        self._keys_dir = resolve_path("keys")
        self._installer_key_path = resolve_path("keys", "installer_dilithium_priv.bin")
        
        self._vendor_dil_priv: bytearray = bytearray()
        self._vendor_dil_pub: bytes = b""
        self._license_mgr: Optional[LicenseManager] = None
        self._key_mgr: Optional[KeyManager] = None
        self._sentinel_config: Optional[SentinelConfig] = None
        self._installer_priv: Optional[bytes] = None  # provisioning authority key

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

        FIX #38: Wrapped the file-writing steps in a try/except that calls
        _rollback_provisioned_files() on failure.  Previously, if
        build_trust_anchor() failed (e.g. because Kyber keys were missing per
        #36), .sentinelrc, identity.json, and the license had already been
        written to disk with no rollback.  The system was left in a
        half-provisioned state — not locked (no flag), but with partial
        artifacts that could confuse subsequent provisioning attempts.
        """
        self._check_if_already_provisioned()
        logger.info("Starting device provisioning...")

        self._load_installer_private_key()

        # Track files written so we can roll back on failure
        written_files = []

        try:
            # 1) build + validate .sentinelrc => sign
            self.build_and_validate_sentinelrc(raw_config)
            written_files.append(self._sentinelrc_path)
            sig_path = Path(f"{self._sentinelrc_path}.sig")
            if sig_path.is_file():
                written_files.append(sig_path)

            # now that we have a valid config => create LicenseManager, KeyManager
            self._sentinel_config = SentinelConfig(raw_config)
            self._license_mgr = LicenseManager(self._sentinel_config)
            self._key_mgr = KeyManager(self._sentinel_config, self._license_mgr)

            # 2) generate_host_identity => sign identity.json
            self.generate_host_identity()
            written_files.append(self._identity_path)
            sig_path = Path(f"{self._identity_path}.sig")
            if sig_path.is_file():
                written_files.append(sig_path)

            # 3) upload + verify license => abort if invalid
            self.upload_license(license_file)
            written_files.append(self._license_path)

            # 4) generate keys => vendor_dil + others => sign them
            self.generate_keys()
            # Track all key files generated in keys_dir
            if self._keys_dir.is_dir():
                for kf in self._keys_dir.iterdir():
                    if kf.is_file() and kf not in written_files:
                        written_files.append(kf)

            # 5) build + sign trust_anchor.json with vendor_dil key
            self.build_trust_anchor()
            written_files.append(self._trust_anchor_path)
            sig_path = Path(f"{self._trust_anchor_path}.sig")
            if sig_path.is_file():
                written_files.append(sig_path)

        except Exception as e:
            logger.error("Provisioning failed at step => %s. Rolling back written files.", e)
            self._rollback_provisioned_files(written_files)
            raise

        # Past the point of no return — all critical files are written and valid
        # 6) lock provisioning => create provisioning_complete.flag
        self.lock_provisioning()

        # 7) append to audit log => DEVICE_PROVISIONED
        self.append_audit_log()

        # 8) self-destruct => remove provision_device.py + installer_dilithium_priv.bin
        self.self_destruct()

        logger.info("Device provisioning completed successfully.")

    def collect_user_input(self) -> Dict[str, Any]:
        """
        Prompts user for minimal .sentinelrc config fields, including anchor_export_path.
        """
        logger.info("Collecting user config input from CLI or GUI.")
        import os

        anchor_path = input("Enter the full path to your anchor export directory: ").strip()
        if not os.path.isdir(anchor_path):
            raise ProvisionError(f"Anchor export path '{anchor_path}' does not exist or is not a directory.")

        config_data = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT",
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
        Validates + writes .sentinelrc, then signs it with the installer key.
        """
        logger.info("Validating .sentinelrc config fields.")
        from aepok_sentinel.utils.sentinelrc_schema import validate_sentinelrc
        try:
            validated = validate_sentinelrc(raw_dict)
        except Exception:
            logger.exception("Config validation failed.")
            raise ProvisionError("Config validation failed.")

        # Ensure the parent directory exists
        dir_path = self._sentinelrc_path.parent
        if not dir_path.is_dir():
            raise ProvisionError(f"Missing directory for .sentinelrc: {dir_path}")

        sentinelrc_json = json.dumps(validated, indent=2)
        try:
            self._sentinelrc_path.write_text(sentinelrc_json, encoding="utf-8")
        except Exception:
            logger.exception("Cannot write .sentinelrc.")
            raise ProvisionError("Cannot write .sentinelrc")

        # sign with installer key
        if not self._installer_priv:
            raise ProvisionError("Installer key not loaded => cannot sign .sentinelrc")

        try:
            # FIX #73: Added schema_version to ephemeral config — SentinelConfig.__init__
            # requires raw_dict["schema_version"] (not .get()), so omitting it causes KeyError.
            ephemeral_config = SentinelConfig({"schema_version": 1, "mode": "cloud", "allow_classical_fallback": False})
            sig_bundle = sign_content_bundle(
                sentinelrc_json.encode("utf-8"),
                ephemeral_config,
                self._installer_priv,
                None
            )

            sig_b64 = base64.b64encode(json.dumps(sig_bundle).encode("utf-8"))
            with open(f"{self._sentinelrc_path}.sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception:
            logger.exception("Failed to sign .sentinelrc")
            raise ProvisionError("Failed to sign .sentinelrc")

        logger.info(".sentinelrc validated and signed successfully.")

    def generate_host_identity(self) -> None:
        """
        Generates identity.json => sign with installer key => identity.json.sig
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

        dir_path = self._identity_path.parent
        if not dir_path.is_dir():
            raise ProvisionError(f"Missing directory for identity.json: {dir_path}")

        try:
            self._identity_path.write_text(identity_json, encoding="utf-8")
        except Exception:
            logger.exception("Cannot write identity.json")
            raise ProvisionError("Cannot write identity.json")

        # sign with installer key
        if not self._installer_priv:
            raise ProvisionError("Installer key not loaded => cannot sign identity.json")

        try:
            # FIX #73: Added schema_version to ephemeral config — SentinelConfig.__init__
            # requires raw_dict["schema_version"] (not .get()), so omitting it causes KeyError.
            ephemeral_config = SentinelConfig({"schema_version": 1, "mode": "cloud", "allow_classical_fallback": False})
            sig_bundle = sign_content_bundle(identity_json.encode("utf-8"), ephemeral_config, self._installer_priv, None)

            sig_b64 = base64.b64encode(json.dumps(sig_bundle).encode("utf-8"))
            with open(f"{self._identity_path}.sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception:
            logger.exception("Failed to sign identity.json")
            raise ProvisionError("Failed to sign identity.json")

        logger.info("identity.json created and signed => host_fingerprint=%s", host_fp)

    def upload_license(self, license_file: str) -> None:
        """
        Uploads license into the runtime, then verifies it. Fails if invalid.
        """
        import os
        if not os.path.isfile(license_file):  # external path => allowed
            raise ProvisionError(f"License file does not exist: {license_file}")

        if not self._license_mgr:
            raise ProvisionError("upload_license called before LicenseManager init")

        try:
            self._license_mgr.upload_license(license_file)
            logger.info("License uploaded to runtime => verifying license validity.")
            self._license_mgr.load_license()
            if not self._license_mgr.license_state.valid:
                raise ProvisionError("Uploaded license is invalid after re-load.")
        except (LicenseError, Exception):
            logger.exception("License upload/validation error")
            raise ProvisionError("License upload or validation failed.")

    def generate_keys(self) -> None:
        """
        Generates vendor_dilithium_priv.bin / vendor_dilithium_pub.pem, plus kyber/rsa if needed.
        Signs them with the installer key.
        """
        if not self._key_mgr:
            raise ProvisionError("generate_keys called but no KeyManager init")

        if not self._keys_dir.is_dir():
            raise ProvisionError(f"Keys directory missing: {self._keys_dir}")

        if not oqs:
            raise ProvisionError("liboqs not installed => cannot generate PQC keys")

        try:
            # FIX #74: Removed `from oqs import Signature` direct package import.
            # `oqs` is already imported at module level via pqc_crypto.py and
            # checked above (`if not oqs`).  The dual import path was redundant
            # and confusing: if pqc_crypto's oqs is None because liboqs isn't
            # installed, `from oqs import Signature` would also fail with a
            # different error.  If pqc_crypto's import failed for another reason,
            # the `not oqs` guard would be wrong.  Using `oqs.Signature`
            # consistently relies on a single import path.
            with oqs.Signature("Dilithium2") as sig:
                sig.generate_keypair()
                vendor_priv = sig.export_secret_key()
                vendor_pub = sig.export_public_key()

            priv_path = resolve_path("keys", "vendor_dilithium_priv.bin")
            pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")

            priv_path.write_bytes(vendor_priv)
            pub_path.write_bytes(vendor_pub)

            if not self._installer_priv:
                raise ProvisionError("Installer key not loaded => cannot sign vendor_dil keys")

            # FIX #73: Added schema_version to ephemeral config — SentinelConfig.__init__
            # requires raw_dict["schema_version"] (not .get()), so omitting it causes KeyError.
            ephemeral_config = SentinelConfig({"schema_version": 1, "mode": "cloud", "allow_classical_fallback": False})

            # sign the private key
            priv_sig = sign_content_bundle(vendor_priv, ephemeral_config, self._installer_priv, None)
            priv_b64 = base64.b64encode(json.dumps(priv_sig).encode("utf-8"))
            with open(f"{priv_path}.sig", "wb") as sf:
                sf.write(priv_b64)

            # sign the pub key
            pub_sig = sign_content_bundle(vendor_pub, ephemeral_config, self._installer_priv, None)
            pub_b64 = base64.b64encode(json.dumps(pub_sig).encode("utf-8"))
            with open(f"{pub_path}.sig", "wb") as sf:
                sf.write(pub_b64)

            logger.info("Vendor Dilithium keys generated + signed => %s, %s", priv_path, pub_path)
            # FIX #37: Store as bytearray so self_destruct() can zero in-place
            self._vendor_dil_priv = bytearray(vendor_priv)
            self._vendor_dil_pub = vendor_pub
        except Exception:
            logger.exception("Failed to generate vendor Dilithium keys")
            raise ProvisionError("Failed to generate vendor Dilithium keys")

        # FIX #36: The previous code called self._key_mgr.rotate_keys() to
        # generate Kyber (and optional RSA) keys.  However, rotate_keys()
        # checks is_watch_only() and is_license_valid() before proceeding.
        # During initial provisioning the license was just uploaded moments
        # before and may not yet be in a valid state (see #27/#28), so
        # rotate_keys() would silently skip, leaving no Kyber keys on disk.
        # build_trust_anchor() then fails because it requires Kyber key hashes.
        #
        # Fix: generate Kyber (and optional RSA) keys directly here, the same
        # way we generate vendor Dilithium keys above — bypassing the
        # license-gated rotate_keys() entirely.  Provisioning is a one-time
        # bootstrap operation that runs before normal key-rotation policy
        # applies, so the license guard is inappropriate at this stage.
        try:
            # FIX #74: Same as Signature above — use oqs.KeyEncapsulation
            # from the already-imported module instead of a separate package import.
            with oqs.KeyEncapsulation("Kyber512") as kem:
                kem.generate_keypair()
                kyber_priv = kem.export_secret_key()
                kyber_pub = kem.export_public_key()

            kyber_priv_path = resolve_path("keys", "kyber_priv.bin")
            kyber_pub_path = resolve_path("keys", "kyber_pub.bin")
            kyber_priv_path.write_bytes(kyber_priv)
            kyber_pub_path.write_bytes(kyber_pub)

            # Sign each Kyber key file with the installer key
            kyber_priv_sig = sign_content_bundle(kyber_priv, ephemeral_config, self._installer_priv, None)
            kyber_priv_sig_b64 = base64.b64encode(json.dumps(kyber_priv_sig).encode("utf-8"))
            with open(f"{kyber_priv_path}.sig", "wb") as sf:
                sf.write(kyber_priv_sig_b64)

            kyber_pub_sig = sign_content_bundle(kyber_pub, ephemeral_config, self._installer_priv, None)
            kyber_pub_sig_b64 = base64.b64encode(json.dumps(kyber_pub_sig).encode("utf-8"))
            with open(f"{kyber_pub_path}.sig", "wb") as sf:
                sf.write(kyber_pub_sig_b64)

            logger.info("Kyber keys generated + signed => %s, %s", kyber_priv_path, kyber_pub_path)

        except Exception:
            logger.exception("Failed to generate Kyber encryption keys.")
            raise ProvisionError("Failed to generate Kyber encryption keys")

        # Optional RSA key generation if classical fallback is enabled
        if getattr(self._sentinel_config, "allow_classical_fallback", False):
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod
                from cryptography.hazmat.primitives import serialization as _ser
                rsa_key = _rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
                rsa_priv_bytes = rsa_key.private_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=_ser.NoEncryption()
                )
                rsa_pub_bytes = rsa_key.public_key().public_bytes(
                    encoding=_ser.Encoding.PEM,
                    format=_ser.PublicFormat.SubjectPublicKeyInfo
                )

                rsa_priv_path = resolve_path("keys", "rsa_priv.pem")
                rsa_pub_path = resolve_path("keys", "rsa_pub.pem")
                rsa_priv_path.write_bytes(rsa_priv_bytes)
                rsa_pub_path.write_bytes(rsa_pub_bytes)

                rsa_priv_sig = sign_content_bundle(rsa_priv_bytes, ephemeral_config, self._installer_priv, None)
                rsa_priv_sig_b64 = base64.b64encode(json.dumps(rsa_priv_sig).encode("utf-8"))
                with open(f"{rsa_priv_path}.sig", "wb") as sf:
                    sf.write(rsa_priv_sig_b64)

                logger.info("RSA fallback keys generated + signed => %s, %s", rsa_priv_path, rsa_pub_path)

            except Exception:
                logger.exception("Failed to generate RSA fallback keys.")
                raise ProvisionError("Failed to generate RSA fallback keys")

    def build_trust_anchor(self) -> None:
        """
        Gathers SHA256 for .sentinelrc, license.key, identity.json, vendor keys, etc.
        Writes trust_anchor.json, signs with vendor_dil key.
        """
        anchor_obj = {"version": 1, "created_utc": self._utc_now(), "hashes": {}}

        # minimal example => known set
        file_list = [
            self._sentinelrc_path,
            self._license_path,
            self._identity_path,
            self._trust_anchor_path,  # self-reference partial
            resolve_path("keys", "vendor_dilithium_priv.bin"),
            resolve_path("keys", "vendor_dilithium_pub.pem"),
        ]
        for item in self._keys_dir.iterdir():
            if item.is_file() and item not in file_list:
                file_list.append(item)

        for path in file_list:
            if path.is_file():
                try:
                    data = path.read_bytes()
                    hval = hashlib.sha256(data).hexdigest()
                    rel_path = str(path.relative_to(self.runtime_base))
                    anchor_obj["hashes"][rel_path] = hval
                except Exception:
                    logger.exception("Failed hashing file for trust_anchor")
                    raise ProvisionError(f"Failed to compute hash for {path}")

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
            raise ProvisionError(f"trust_anchor missing files => missing={missing_required}, kyber={has_kyber}, dil={has_dil}")

        try:
            identity_bytes = self._identity_path.read_bytes()
            identity_hash = hashlib.sha256(identity_bytes).hexdigest()
            anchor_obj["identity_json_sha256"] = identity_hash
        except Exception as e:
            logger.exception("Failed to compute identity.json SHA-256 for trust anchor binding.")
            raise ProvisionError(f"Cannot bind identity.json to trust_anchor: {e}")

        anchor_json = json.dumps(anchor_obj, indent=2)
        dir_path = self._trust_anchor_path.parent
        if not dir_path.is_dir():
            raise ProvisionError(f"Missing directory for trust_anchor.json: {dir_path}")

        try:
            self._trust_anchor_path.write_text(anchor_json, encoding="utf-8")
        except Exception:
            logger.exception("Cannot write trust_anchor.json")
            raise ProvisionError("Cannot write trust_anchor.json")

        if not self._vendor_dil_priv:
            raise ProvisionError("No vendor Dilithium private key => cannot sign trust_anchor")

        try:
            # FIX #73: Added schema_version — same KeyError fix as the cloud ephemeral configs.
            device_config = SentinelConfig({"schema_version": 1, "mode": "airgap", "allow_classical_fallback": False})
            sig_bundle = sign_content_bundle(anchor_json.encode("utf-8"), device_config, self._vendor_dil_priv, None)
            sig_b64 = base64.b64encode(json.dumps(sig_bundle).encode("utf-8"))
            with open(f"{self._trust_anchor_path}.sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception:
            logger.exception("Failed to sign trust_anchor.json")
            raise ProvisionError("Failed to sign trust_anchor.json")

        logger.info("trust_anchor.json created and signed with vendor key.")

    def lock_provisioning(self) -> None:
        """Writes provisioning_complete.flag => prevents re-run."""
        if self._provision_flag_path.is_file():
            raise ProvisionError("Device is already provisioned. provisioning_complete.flag found.")
        try:
            self._provision_flag_path.write_text("Provisioning complete.\n", encoding="utf-8")
        except Exception:
            logger.exception("Failed to create provisioning_complete.flag")
            raise ProvisionError("Failed to create provisioning_complete.flag")

        logger.info("Provisioning locked => provisioning_complete.flag created.")

    def append_audit_log(self) -> None:
        """
        Final log => DEVICE_PROVISIONED. Must include host fingerprint, license UUID, enforcement mode, etc.
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
            if self._identity_path.is_file():
                try:
                    ident_obj = json.loads(self._identity_path.read_text(encoding="utf-8"))
                    host_fp = ident_obj.get("host_fingerprint", "unknown")
                except Exception:
                    logger.exception("Error reading identity.json for host_fingerprint.")

            meta = {
                "host_fingerprint": host_fp,
                "license_uuid": lic_uuid,
                "enforcement_mode": en_mode,
                "utc": self._utc_now()
            }
            self.audit_chain.append_event(EventCode.DEVICE_PROVISIONED.value, meta)
            logger.info("Audit log: DEVICE_PROVISIONED => %s", meta)
        except Exception:
            logger.exception("Failed to append event DEVICE_PROVISIONED")
            # do not re-raise => not fatal

    def self_destruct(self) -> None:
        """
        If everything succeeded => remove provision_device.py & installer_dilithium_priv.bin,
        zero memory caches, log final event: DEVICE_PROVISIONED_SECURE

        FIX #37: The previous code created bytearray copies of the immutable
        bytes objects (self._installer_priv, self._vendor_dil_priv) and zeroed
        those copies.  The original bytes objects are immutable and remained
        untouched in Python's heap until garbage collected — and even then may
        persist in freed memory.  The "secure zeroization" was theater.

        Fix: _load_installer_private_key() and generate_keys() now store keys
        as bytearray (mutable) from the start.  Here we zero the actual
        bytearray in-place using pqc_crypto.secure_zero(), then discard the
        reference.  This is the best-effort approach within CPython's managed
        heap — true guaranteed zeroization requires a C extension or OS-level
        mlock/madvise, which is beyond Python's memory model.
        """
        from aepok_sentinel.core.pqc_crypto import secure_zero

        # Zero memory — keys are now stored as bytearray (mutable)
        if self._installer_priv:
            if isinstance(self._installer_priv, bytearray):
                secure_zero(self._installer_priv)
            self._installer_priv = None

        if self._vendor_dil_priv:
            if isinstance(self._vendor_dil_priv, bytearray):
                secure_zero(self._vendor_dil_priv)
            self._vendor_dil_priv = bytearray()

        # Attempt removing the installer key
        if self._installer_key_path.is_file():
            try:
                self._installer_key_path.unlink()
            except Exception:
                logger.exception("Failed to remove installer key")

        # Log final "DEVICE_PROVISIONED_SECURE" event
        try:
            self.audit_chain.append_event(ExtendedEventCode.DEVICE_PROVISIONED_SECURE, {
                "status": "self_destruct",
                "script": __file__,
                "utc": self._utc_now()
            })
            logger.info("DEVICE_PROVISIONED_SECURE event appended.")
        except Exception:
            logger.exception("Failed to log final secure provisioning event")

        # Remove the script itself (provision_device.py)
        script_path = Path(__file__).resolve()
        try:
            script_path.unlink()
            logger.info("Self-destruct: removed provision_device.py successfully.")
        except Exception:
            logger.exception("Failed to remove provision_device.py")

    # ----------------- Helpers -----------------

    def _rollback_provisioned_files(self, written_files) -> None:
        """
        FIX #38: Remove all files written during a failed provisioning
        attempt so the system is not left in a half-provisioned state.
        """
        for fpath in reversed(written_files):
            try:
                if fpath.is_file():
                    fpath.unlink()
                    logger.info("Rollback: removed %s", fpath)
            except Exception:
                logger.exception("Rollback: failed to remove %s", fpath)

    def _check_if_already_provisioned(self) -> None:
        if self._provision_flag_path.is_file():
            raise ProvisionError("Cannot proceed => provisioning_complete.flag exists => device already provisioned.")

    def _load_installer_private_key(self) -> None:
        if not self._installer_key_path.is_file():
            raise ProvisionError(f"Installer key not found at {self._installer_key_path}")
        try:
            # FIX #37: Store as bytearray (mutable) so self_destruct() can
            # zero the actual key material in-place, not a throwaway copy.
            self._installer_priv = bytearray(self._installer_key_path.read_bytes())
        except Exception:
            logger.exception("Failed reading installer key")
            raise ProvisionError("Failed reading installer key")

        if len(self._installer_priv) < 100:  # naive check
            raise ProvisionError("Installer key is suspiciously short => aborting provisioning.")
        logger.info("Loaded installer Dilithium private key from: %s", self._installer_key_path)

    def _utc_now(self) -> str:
        import datetime
        return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"