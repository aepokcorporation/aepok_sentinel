# aepok_sentinel/core/key_manager.py

"""
Key Manager

Responsibilities:
 - Load local or cloud keys in a zero-trust manner, verifying signatures if local.
 - Optionally fetch from Azure if config.cloud_keyvault_enabled = True and mode=cloud.
 - Provide rotate_keys() with concurrency lock (key_manager_lock.py).
 - Generate new keys in a two-phase commit; sign each new key with the local device's Dilithium private key,
   verify them, then move them in place or revert on failure.
 - Logs KEY_ROTATED or KEY_GENERATION_FAILED to the audit chain, with fallback behavior in PERMISSIVE mode
   or immediate error in STRICT/HARDENED or license_required.
 - No directory auto-creation for `keys` or `locks`; if missing, raise or degrade.

Important:
 - For read or write to `runtime/keys/`, we use resolve_path("keys", <filename>) to respect directory_contract.
 - For the lock, we use resolve_path("locks", "key_rotation.lock").
"""

import os
import shutil
import time
import json
import base64
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only, is_license_valid
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.key_manager_lock import KeyRotationLock
from aepok_sentinel.core.pqc_crypto import oqs, sign_content_bundle, verify_content_signature

logger = get_logger("key_manager")


class KeyManagerError(Exception):
    """Raised on key load or rotation failures in strict/hardened or if license_required is true."""


class KeyManager:
    """
    Final-shape Key Manager:
      - fetch_current_keys() => loads the newest local keys or fetches from cloud.
      - rotate_keys() => concurrency lock, generate new to temp, sign/verify, commit or revert.
      - logs KEY_ROTATED or KEY_GENERATION_FAILED.
      - no creation of 'keys/' or 'locks/' if missing => either fail in strict/hardened or degrade in permissive mode.
    """

    def __init__(
        self,
        config: SentinelConfig,
        license_mgr: LicenseManager,
        audit_chain: Optional[AuditChain] = None
    ):
        self.config = config
        self.license_mgr = license_mgr
        self.audit_chain = audit_chain
        self.keep_generations = 5

        # Check existence of the `keys` directory
        self.keys_dir = resolve_path("keys")
        if not self.keys_dir.is_dir():
            msg = f"Keys directory missing: {self.keys_dir}"
            if self._must_fail():
                raise RuntimeError(msg)
            else:
                logger.warning("%s (in non-strict mode => degrade).", msg)

        # Check existence of `locks` directory for the rotation lock
        self.lockfile_path = resolve_path("locks", "key_rotation.lock")
        if not self.lockfile_path.parent.is_dir():
            msg = f"Lockfile directory missing: {self.lockfile_path.parent}"
            if self._must_fail():
                raise RuntimeError(msg)
            else:
                logger.warning("%s (in non-strict mode => degrade).", msg)

        # We'll store the device vendor keys in `keys` as well
        # vendor_dilithium_priv.bin => for signing newly generated keys
        # vendor_dilithium_pub.pem => for verifying them if needed
        self.vendor_dil_priv_path = resolve_path("keys", "vendor_dilithium_priv.bin")
        self.vendor_dil_pub_path  = resolve_path("keys", "vendor_dilithium_pub.pem")  # or .pub
        # The code references `.bin`, but we'll unify to `.pem` if we prefer. 
        # We'll just assume it is `.pem` for final shape.

    def fetch_current_keys(self) -> Dict[str, bytes]:
        """
        Load or fetch the current keys:
          - If config.cloud_keyvault_enabled and mode=cloud => attempt Azure fetch.
          - Else load local from the newest files (kyber, dil, optional rsa) verifying their signatures.
        Return a dict with keys e.g. {"kyber_priv": b"...", "dilithium_priv": b"...", "rsa_priv": b"..."}
        Possibly empty if missing or invalid in permissive mode.
        """
        # watch-only is still allowed to read keys
        # check if we have cloud
        if self.config.raw_dict.get("cloud_keyvault_enabled", False) and self.config.mode == "cloud":
            return self._fetch_cloud_keys()
        else:
            return self._load_local_keys_latest()

    def rotate_keys(self) -> None:
        """
        Two-phase key rotation:
          1) If watch-only => skip
          2) Acquire rotation lock
          3) Backup existing
          4) Generate new in a temp subdir
          5) Sign & verify new keys
          6) Commit => rename or revert => logs success or fail
        """
        if is_watch_only(self.license_mgr):
            logger.warning("Cannot rotate keys in watch-only mode.")
            return
        if not is_license_valid(self.license_mgr):
            logger.warning("Cannot rotate keys: license invalid.")
            return

        rotation_days = self.config.raw_dict.get("rotation_interval_days", 0)
        if rotation_days <= 0:
            logger.info("Key rotation disabled (rotation_interval_days <= 0).")
            return

        with KeyRotationLock(str(self.lockfile_path), self._must_fail()):
            backup_path = None
            try:
                backup_path = self._backup_current_keys()
                tmp_dir = self._generate_new_keys_tmp()
                self._verify_new_keys_tmp(tmp_dir)
                self._commit_new_keys(tmp_dir)
                self._purge_old_generations()
                self._chain_event(EventCode.KEY_ROTATED, {"msg": "Key rotation succeeded."})
            except Exception as e:
                logger.error("Key rotation failed => %s", e)
                self._chain_event(EventCode.KEY_GENERATION_FAILED, {"error": str(e)})
                if backup_path:
                    self._restore_backup(backup_path)
                if self._must_fail():
                    raise KeyManagerError(str(e))

    # ---------------------- Private methods ----------------------

    def _fetch_cloud_keys(self) -> Dict[str, bytes]:
        """
        If scif => fail. If cloud => attempt Azure key fetch from secrets:
         - "cloud_dilithium_secret"
         - "cloud_kyber_secret"
         - "cloud_rsa_secret" (optional if allow_classical_fallback)
        Return the dictionary. 
        """
        if self.config.mode in ("scif", "airgap"):
            raise KeyManagerError("No network allowed in scif/airgap for cloud fetch.")

        from aepok_sentinel.core.azure_client import AzureClient, AzureClientError
        try:
            az = AzureClient(self.config, self.license_mgr)
            dil_name = self.config.raw_dict.get("cloud_dilithium_secret", "DILITHIUM-PRIVATE-KEY")
            kyb_name = self.config.raw_dict.get("cloud_kyber_secret", "KYBER-PRIVATE-KEY")
            rsa_name = self.config.raw_dict.get("cloud_rsa_secret", "RSA-PRIVATE-KEY")

            dil_b64 = az.get_secret(dil_name)
            kyb_b64 = az.get_secret(kyb_name)
            if self.config.allow_classical_fallback:
                try:
                    rsa_b64 = az.get_secret(rsa_name)
                except AzureClientError:
                    rsa_b64 = ""
            else:
                rsa_b64 = ""

            return {
                "dilithium_priv": base64.b64decode(dil_b64),
                "kyber_priv":     base64.b64decode(kyb_b64),
                "rsa_priv":       base64.b64decode(rsa_b64) if rsa_b64 else b""
            }
        except Exception as e:
            raise KeyManagerError(f"Cloud fetch error => {e}")

    def _load_local_keys_latest(self) -> Dict[str, bytes]:
        """
        Search for the newest <prefix>_*.bin or .pem for "kyber_priv", "dilithium_priv", "rsa_priv".
        For each found file, read and verify with vendor_dilithium_pub.pem. 
        If missing or invalid => in strict => raise, else degrade to empty.
        """
        if not self.keys_dir.is_dir() and self._must_fail():
            raise KeyManagerError(f"Keys directory missing: {self.keys_dir}")

        # Find newest for each
        kyber_path      = self._find_latest_key("kyber_priv", ".bin")
        dilithium_path  = self._find_latest_key("dilithium_priv", ".bin")
        rsa_path        = None
        if self.config.allow_classical_fallback:
            rsa_path = self._find_latest_key("rsa_priv", ".pem", required=False)

        # If missing required => raise in strict, degrade else
        if not kyber_path or not dilithium_path:
            msg = "Missing required kyber or dilithium key files."
            logger.error(msg)
            if self._must_fail():
                raise KeyManagerError(msg)
            return {}

        # read+verify
        keys = {
            "kyber_priv":     self._read_and_verify(kyber_path),
            "dilithium_priv": self._read_and_verify(dilithium_path),
            "rsa_priv":       b""
        }
        if rsa_path:
            keys["rsa_priv"] = self._read_and_verify(rsa_path)
        return keys

    def _find_latest_key(self, prefix: str, ext: str, required: bool = True) -> Optional[Path]:
        """
        Looks for files named like <prefix>_<timestamp>.ext in keys_dir. 
        Returns the newest by mtime or None if none found.
        """
        if not self.keys_dir.is_dir():
            if required and self._must_fail():
                raise KeyManagerError(f"No keys dir found for searching {prefix} in strict mode.")
            return None

        matches = []
        for item in self.keys_dir.iterdir():
            if item.is_file() and item.name.startswith(prefix) and item.name.endswith(ext):
                matches.append(item)
        if not matches:
            if required and self._must_fail():
                raise KeyManagerError(f"No {prefix} file found in strict mode.")
            elif required:
                logger.warning("Missing %s files in permissive => degrade.", prefix)
            return None

        matches.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return matches[0]

    def _read_and_verify(self, key_path: Path) -> bytes:
        """
        Read the file + file.sig, verify with vendor_dilithium_pub.pem.
        Return raw bytes or empty if failure in permissive mode, raise if strict.
        """
        sig_path = key_path.with_suffix(key_path.suffix + ".sig")
        if not sig_path.is_file():
            msg = f"Signature file missing for {key_path}"
            logger.error(msg)
            if self._must_fail():
                raise KeyManagerError(msg)
            return b""

        try:
            raw_key = key_path.read_bytes()
            raw_sig = sig_path.read_bytes()
        except Exception as e:
            msg = f"Failed reading {key_path} or sig => {e}"
            logger.error(msg)
            if self._must_fail():
                raise KeyManagerError(msg)
            return b""

        # decode sig => base64 => JSON
        try:
            sig_json_bytes = base64.b64decode(raw_sig)
            sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
        except Exception as e:
            msg = f"Corrupt signature for {key_path}: {e}"
            logger.error(msg)
            if self._must_fail():
                raise KeyManagerError(msg)
            return b""

        # read vendor_dil pub
        if not self.vendor_dil_pub_path.is_file():
            msg = "Missing vendor_dilithium_pub.pem => cannot verify."
            logger.error(msg)
            if self._must_fail():
                raise KeyManagerError(msg)
            return b""

        vendor_pub = self.vendor_dil_pub_path.read_bytes()
        ok = verify_content_signature(raw_key, sig_dict, self.config, vendor_pub, None)
        if not ok:
            msg = f"Signature invalid for {key_path}"
            logger.error(msg)
            if self._must_fail():
                raise KeyManagerError(msg)
            return b""

        return raw_key

    def _generate_new_keys_tmp(self) -> Path:
        """
        Create a temp subdir under keys_dir, generate kyber/dil/rsa if needed, sign each with vendor_dil priv.
        Return the tmp Path.
        """
        if not oqs:
            raise KeyManagerError("liboqs not installed => cannot generate PQC keys.")

        import uuid
        tmp_name = f"tmp_rotation_{uuid.uuid4().hex}"
        tmp_dir = self.keys_dir / tmp_name
        tmp_dir.mkdir(exist_ok=False)

        # Generate kyber
        from oqs import KeyEncapsulation, Signature
        with KeyEncapsulation("Kyber512") as kem:
            kem.generate_keypair()
            kyb_priv = kem.export_secret_key()

        # Generate dilithium
        with Signature("Dilithium2") as sig:
            sig.generate_keypair()
            dil_priv = sig.export_secret_key()

        # optional RSA
        rsa_priv = b""
        if getattr(self.config, "allow_classical_fallback", False):
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            rkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_priv = rkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            rsa_fp = hashlib.sha256(rsa_priv).hexdigest()[:16]
            if self.audit_chain:
                try:
                    self.audit_chain.append_event("RSA_KEY_GENERATED", {
                        "enabled_by_config": True,
                        "fingerprint_prefix": rsa_fp,
                        "enforcement_mode": self.config.enforcement_mode,
                        "strict_transport": self.config.strict_transport
                    })
                except Exception as e:
                    logger.warning("Failed to emit RSA_KEY_GENERATED audit event: %s", e)

        # write + sign
        self._write_and_sign(tmp_dir / "kyber_priv.bin",     kyb_priv)
        self._write_and_sign(tmp_dir / "dilithium_priv.bin", dil_priv)
        if rsa_priv:
            self._write_and_sign(tmp_dir / "rsa_priv.pem", rsa_priv)

        return tmp_dir

    def _verify_new_keys_tmp(self, tmp_dir: Path) -> None:
        """
        Ensures the new keys in tmp_dir can be read & verified using _read_and_verify. 
        Raises KeyManagerError if anything is invalid in strict/hardened.
        """
        must_have = ["kyber_priv.bin", "dilithium_priv.bin"]
        if getattr(self.config, "allow_classical_fallback", False):
            must_have.append("rsa_priv.pem")

        for fname in must_have:
            fpath = tmp_dir / fname
            if not fpath.is_file():
                raise KeyManagerError(f"Missing newly generated key file: {fpath}")
            self._read_and_verify(fpath)  # raises if invalid

    def _commit_new_keys(self, tmp_dir: Path) -> None:
        """
        Move each file from tmp_dir => keys_dir with a timestamp suffix, remove tmp_dir.
        """
        stamp = time.strftime("%Y%m%d_%H%M%S")
        for item in tmp_dir.iterdir():
            if not item.is_file():
                continue
            new_name = None
            if item.suffix == ".sig":
                # e.g. "kyber_priv.bin.sig"
                basefile = item.stem  # e.g. "kyber_priv.bin"
                # "kyber_priv" + ".bin" => we can parse out better, or simpler approach:
                new_name = f"{basefile}_{stamp}.sig"
            else:
                # e.g. "kyber_priv.bin"
                split_name = item.name.split(".")
                if len(split_name) > 1:
                    ext = split_name[-1]
                    prefix = ".".join(split_name[:-1])
                    new_name = f"{prefix}_{stamp}.{ext}"
                else:
                    # fallback
                    new_name = f"{item.stem}_{stamp}"
            dst = self.keys_dir / new_name
            item.rename(dst)
        tmp_dir.rmdir()

    def _backup_current_keys(self) -> Path:
        """
        Copies existing *priv* files to a new 'backup_<timestamp>_<uuid>' subdir.
        """
        import uuid
        stamp = time.strftime("%Y%m%d_%H%M%S")
        backup_dir = self.keys_dir / f"backup_{stamp}_{uuid.uuid4().hex}"
        backup_dir.mkdir(exist_ok=False)

        for item in self.keys_dir.iterdir():
            if item.is_file() and ("priv" in item.name):
                shutil.copy2(str(item), str(backup_dir / item.name))

        return backup_dir

    def _restore_backup(self, backup_dir: Path) -> None:
        """
        Remove any new *priv* files, then copy from backup_dir. 
        Then log KEY_ROTATION_REVERTED in chain if present.
        """
        # remove any new *priv*
        for item in self.keys_dir.iterdir():
            if item.is_file() and ("priv" in item.name):
                item.unlink()
        # restore backups
        for bf in backup_dir.iterdir():
            if bf.is_file():
                shutil.copy2(str(bf), str(self.keys_dir / bf.name))

        logger.info("Restored old keys from backup => %s", backup_dir)
        self._chain_event(EventCode.KEY_ROTATION_REVERTED, {
            "backup_path": str(backup_dir),
            "timestamp": self._utc_now_str()
        })

    def _purge_old_generations(self) -> None:
        """
        Keep the newest self.keep_generations for each prefix: kyber_priv, dilithium_priv, rsa_priv.
        remove older + their .sig
        """
        for prefix, ext in [
            ("kyber_priv", ".bin"),
            ("dilithium_priv", ".bin"),
            ("rsa_priv", ".pem")
        ]:
            self._purge_old(prefix, ext)

    def _purge_old(self, prefix: str, ext: str) -> None:
        # gather
        if not self.keys_dir.is_dir():
            return
        matches = []
        for item in self.keys_dir.iterdir():
            if item.is_file() and item.name.startswith(prefix) and item.name.endswith(ext):
                matches.append(item)
        if not matches:
            return

        # sort by mtime desc
        matches.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        to_delete = matches[self.keep_generations:]
        for td in to_delete:
            sigp = Path(str(td) + ".sig")
            if sigp.is_file():
                sigp.unlink()
            td.unlink()
            logger.info("Purged old key => %s", td)

    def _write_and_sign(self, path: Path, data: bytes) -> None:
        """
        Write 'data' to path, then sign it with vendor_dil priv => path.sig
        """
        try:
            path.write_bytes(data)
        except Exception as e:
            raise KeyManagerError(f"Failed to write {path}: {e}")

        # sign
        if not self.vendor_dil_priv_path.is_file():
            if self._must_fail():
                raise KeyManagerError("Missing vendor_dilithium_priv.bin in strict/hardened mode.")
            else:
                logger.warning("No vendor_dilithium_priv.bin => skipping sign in permissive.")
                return

        try:
            vendor_priv = self.vendor_dil_priv_path.read_bytes()
        except Exception as e:
            if self._must_fail():
                raise KeyManagerError(f"Failed reading vendor_dilithium_priv => {e}")
            else:
                logger.warning("Failed reading vendor_dil priv => %s", e)
                return

        from copy import deepcopy
        local_cfg = deepcopy(self.config)
        try:
            sig_bundle = sign_content_bundle(data, local_cfg, vendor_priv, None)
        except Exception as e:
            raise KeyManagerError(f"Failed to sign {path}: {e}")

        import json
        raw_json = json.dumps(sig_bundle).encode("utf-8")
        sig_b64 = base64.b64encode(raw_json)
        try:
            with open(str(path) + ".sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception as e:
            raise KeyManagerError(f"Failed writing signature for {path}: {e}")

    def _must_fail(self) -> bool:
        """
        If enforcement_mode is STRICT/HARDENED => fail on missing sig or invalid key.
        If config.license_required => also fail.
        """
        emode = getattr(self.config, "enforcement_mode", "PERMISSIVE").upper()
        if emode in ("STRICT", "HARDENED"):
            return True
        if getattr(self.config, "license_required", False):
            return True
        return False

    def _utc_now_str(self) -> str:
        import datetime
        return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    def _chain_event(self, event_code: EventCode, metadata: dict) -> None:
        """Helper to append an event to the audit chain with license + host context."""
        if not self.audit_chain:
            return
        try:
            # fill standard fields: license_uuid from license_mgr. 
            lic_info = self.license_mgr.license_state.info
            license_uuid = lic_info.get("license_uuid", "")
            metadata["license_uuid"] = license_uuid
            metadata["host_fingerprint"] = "unknown_host"
            metadata["enforcement_mode"] = getattr(self.config, "enforcement_mode", "PERMISSIVE").upper()
            metadata["utc"] = self._utc_now_str()
            self.audit_chain.append_event(event_code.value, metadata)
        except Exception as e:
            logger.error("Failed to append key manager event %s => %s", event_code.value, e)