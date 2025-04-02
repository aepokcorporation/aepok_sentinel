"""
Step 4: License Management

Implements:
1. LicenseManager that loads and validates a license file.
2. JSON-based license format:
   {
     "license_version": 1,
     "issued_to": "string",
     "expires_on": "YYYY-MM-DD",
     "signature": "<base64 of JSON or combined RSA+Dil>",
     "features": ["full_encryption", ...],
     "license_type": "individual" or "site",
     "bound_to": "<sha256-of-hardware>",
     ...
   }
3. If missing/corrupt => degrade to watch-only, or fail if license_required=true
4. If bound_to != local fingerprint => degrade watch-only or fail
5. If expired => degrade watch-only
6. Integration with config (license_required, bound_to_hardware, allow_classical_fallback)
7. Uses pqc_crypto.py verify_content_signature to check Dilithium + RSA if fallback is allowed
"""

import os
import json
import base64
import hashlib
import datetime
from typing import Optional, Dict, Any

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_crypto import (
    verify_content_signature, CryptoSignatureError
)

logger = get_logger("license")

class LicenseError(Exception):
    """
    Raised if the license is invalid and config.license_required=true.
    Otherwise, we degrade to watch-only.
    """
    pass


class LicenseState:
    """
    Represents the license status after validation.
    watch_only = True if the system must run in watch-only mode.
    """
    def __init__(self, valid: bool, watch_only: bool, info: Dict[str, Any]):
        self.valid = valid
        self.watch_only = watch_only
        self.info = info


class LicenseManager:
    """
    A manager class to handle loading and validating the license.
    Use .load_license() once at startup. Then check .license_state for watch_only or validity.
    """

    def __init__(self, config: SentinelConfig):
        self.config = config
        self.license_state = LicenseState(valid=False, watch_only=False, info={})

    def load_license(self) -> None:
        """
        Reads the license file from config.license_path or degrade/fail if missing or invalid.
        1) If the file is missing or fails to parse => watch-only unless config.license_required => raise LicenseError
        2) If signature check fails => watch-only or raise
        3) If expired => watch-only
        4) If bound_to mismatch => watch-only
        """
        lic_path = self.config.license_path
        if not os.path.isfile(lic_path):
            msg = f"License file not found at {lic_path}"
            logger.warning(msg)
            if self.config.license_required:
                raise LicenseError(msg)
            else:
                self.license_state = LicenseState(valid=False, watch_only=True, info={})
                return

        try:
            with open(lic_path, "rb") as f:
                raw_data = f.read()
        except Exception as e:
            msg = f"Cannot read license file {lic_path}: {e}"
            logger.warning(msg)
            if self.config.license_required:
                raise LicenseError(msg)
            else:
                self.license_state = LicenseState(valid=False, watch_only=True, info={})
                return

        # If the license might be base64, try to decode. If that fails, treat as direct JSON
        lic_json = None
        try:
            # Attempt base64 decode
            maybe_json = base64.b64decode(raw_data)
            lic_json = json.loads(maybe_json.decode("utf-8"))
        except Exception:
            # fallback => raw_data is direct JSON
            try:
                lic_json = json.loads(raw_data.decode("utf-8"))
            except Exception as e:
                msg = f"License parse failed: {e}"
                logger.warning(msg)
                if self.config.license_required:
                    raise LicenseError(msg)
                else:
                    self.license_state = LicenseState(valid=False, watch_only=True, info={})
                    return

        # Now lic_json should be a dict
        if not isinstance(lic_json, dict):
            msg = "License content is not a JSON object"
            logger.warning(msg)
            if self.config.license_required:
                raise LicenseError(msg)
            else:
                self.license_state = LicenseState(valid=False, watch_only=True, info={})
                return

        # Check mandatory fields
        required_keys = ["license_version", "issued_to", "expires_on", "signature"]
        for k in required_keys:
            if k not in lic_json:
                msg = f"License missing required field '{k}'"
                logger.warning(msg)
                if self.config.license_required:
                    raise LicenseError(msg)
                else:
                    self.license_state = LicenseState(valid=False, watch_only=True, info={})
                    return

        # Attempt to verify signature
        # The doc suggests "signature": "<base64 RSA+Dil>", which might be the same structure as sign_content_bundle
        # We'll assume it's base64-encoded JSON with "dilithium" + "rsa" fields. We'll verify the rest of the license.
        signature_b64 = lic_json["signature"]
        try:
            sig_json_bytes = base64.b64decode(signature_b64)
            sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
        except Exception as e:
            msg = f"License signature field is not valid base64-encoded JSON: {e}"
            logger.warning(msg)
            if self.config.license_required:
                raise LicenseError(msg)
            else:
                self.license_state = LicenseState(valid=False, watch_only=True, info={})
                return

        # Build the data to be verified = the license object minus the "signature" field
        lic_copy = lic_json.copy()
        del lic_copy["signature"]  # remove signature from the data we verify

        # Convert to canonical bytes, e.g. sorted JSON or something stable
        # For simplicity, we do standard JSON dumps with sorted keys
        data_bytes = json.dumps(lic_copy, sort_keys=True).encode("utf-8")

        # We rely on "verify_content_signature" from pqc_crypto
        # We do not have the public keys used to sign the license. For now, we might store them in config or some known place
        # The doc suggests a built-in "string" of the pub key. We can define them as well-known or perhaps it's user-supplied
        # We'll do a minimal approach: a built-in or no approach. We'll store them in the license? The doc doesn't specify.
        # For now, assume they are embedded or well-known. We'll store them as static placeholders or config fields.
        # We'll do:
        dil_pub = self._get_license_dilithium_pub()
        rsa_pub = self._get_license_rsa_pub() if self.config.allow_classical_fallback else None

        # Now attempt verify
        ok = verify_content_signature(data_bytes, sig_dict, self.config, dil_pub, rsa_pub)
        if not ok:
            msg = "License signature verification failed."
            logger.warning(msg)
            if self.config.license_required:
                raise LicenseError(msg)
            else:
                self.license_state = LicenseState(valid=False, watch_only=True, info={})
                return

        # Check expiry
        expires_on = lic_json["expires_on"]  # "YYYY-MM-DD"
        if not self._is_date_valid(expires_on):
            msg = f"License expiry date invalid: {expires_on}"
            logger.warning(msg)
            if self.config.license_required:
                raise LicenseError(msg)
            else:
                self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
                return

        expiry_date = datetime.datetime.strptime(expires_on, "%Y-%m-%d").date()
        today = datetime.date.today()
        if expiry_date < today:
            msg = f"License expired on {expiry_date}"
            logger.warning(msg)
            # degrade watch-only
            self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
            return

        # If bound_to_hardware => compare local fingerprint
        if self.config.bound_to_hardware:
            bound_val = lic_json.get("bound_to")
            local_fprint = self._compute_local_fingerprint()
            if not bound_val or bound_val != local_fprint:
                msg = f"Hardware bind mismatch. License bound to {bound_val}, local={local_fprint}"
                logger.warning(msg)
                if self.config.license_required:
                    raise LicenseError(msg)
                else:
                    self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
                    return

        # If we get here => valid
        self.license_state = LicenseState(valid=True, watch_only=False, info=lic_json)
        logger.info("License validated: expires_on=%s, license_type=%s", expires_on, lic_json.get("license_type", "n/a"))

    def _is_date_valid(self, date_str: str) -> bool:
        try:
            datetime.datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return False

    def _compute_local_fingerprint(self) -> str:
        """
        Minimal placeholder approach: we just hash the hostname + a stable token.
        Real usage might gather MAC addresses, etc.
        """
        hostname = os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "unknown")
        raw = (hostname + "_SENTINEL_SALT_2025").encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _get_license_dilithium_pub(self) -> bytes:
        """
        Returns the known Dilithium public key used to sign the license file.
        In a real system, might be embedded or loaded from a config file.
        For the test scenario, we can just store a placeholder or read from config.
        """
        # For demonstration, we store a static or user-provided pub.
        # In real usage, we might do config.license_pub_dil, etc.
        # Let's just do a placeholder  (DIL2 pub keys are ~1312 bytes)
        # We'll treat it as if your environment has it. For tests, we might patch or override.
        return b"FAKE_DIL_PUB_KEY"  # The test can patch verify_content_signature if needed

    def _get_license_rsa_pub(self) -> bytes:
        """
        If allow_classical_fallback, we might also require an RSA public key for license verification.
        """
        return b"FAKE_RSA_PUB_KEY"


def is_watch_only(license_manager: LicenseManager) -> bool:
    """
    Convenience function to check if the system should run watch-only.
    """
    return license_manager.license_state.watch_only


def is_license_valid(license_manager: LicenseManager) -> bool:
    """
    Check if the license is fully valid (not watch-only).
    """
    return license_manager.license_state.valid