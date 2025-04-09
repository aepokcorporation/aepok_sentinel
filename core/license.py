# aepok_sentinel/core/license.py
"""
License Management

Responsibilities:
 - Load and verify a license (stored as a base64-encoded JSON blob in 'license.key').
 - Enforce signature checking via vendor_dilithium_pub.pem (and optional RSA fallback if config allows).
 - Validate expiration, max_installs, and optional hardware binding.
 - Maintain and sign an install_state.json to record usage count per license UUID.
 - Emit chain events for LICENSE_ACTIVATED, LICENSE_INVALID, LICENSE_EXPIRED, INSTALL_REJECTED, etc.
 - In strict/hardened modes or if license_required=True, a failure to validate the license results in an immediate error rather than a watch-only mode.

Note: The system expects the final license blob to be base64-encoded JSON with a "signature" field
(e.g. produced by issue_offline_license.py). 
"""

import os
import json
import base64
import hashlib
import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_crypto import (
    verify_content_signature, CryptoSignatureError, sign_content_bundle
)
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.directory_contract import resolve_path

logger = get_logger("license")


class LicenseError(Exception):
    """Raised if license validation fails and we are in a mode requiring a valid license."""


class InstallStateError(Exception):
    """Raised if install_state.json is missing or invalid in strict/hardened mode."""


class LicenseState:
    """
    Represents the final license status after load:
     - valid: whether it's accepted as valid
     - watch_only: whether we degrade operation to watch-only
     - info: the parsed license data (fields from the JSON)
    """
    def __init__(self, valid: bool, watch_only: bool, info: Dict[str, Any]):
        self.valid = valid
        self.watch_only = watch_only
        self.info = info


class LicenseManager:
    """
    Manages license loading and enforcement:
     - Attempts to read <runtime>/license/license.key
     - Verifies signature using vendor_dilithium_pub.pem
     - Checks expiration, max_installs, etc.
     - Tracks usage in install_state.json (signed with vendor_dilithium_priv.bin).
     - Logs relevant events to the audit chain.
     - If enforcement mode is STRICT/HARDENED or config.license_required=True => raises LicenseError on failure,
       otherwise => degrade to watch_only.
    """

    INSTALL_STATE_FILENAME = "install_state.json"

    def __init__(self,
                 config: SentinelConfig,
                 audit_chain: Optional[AuditChain] = None,
                 sentinel_runtime_base: Optional[str] = None):
        self.config = config
        self.audit_chain = audit_chain
        self.license_state = LicenseState(valid=False, watch_only=False, info={})

        # We may receive a runtime_base, or we rely on directory_contract usage.
        # The code does not auto-create any runtime directories. All must exist.
        if sentinel_runtime_base:
            if not os.path.isdir(sentinel_runtime_base):
                raise RuntimeError(f"Sentinel runtime base does not exist: {sentinel_runtime_base}")

        # 1) Determine default license path from directory_contract
        self.default_license_path = resolve_path("license", "license.key")

        # If the config has an override license_path, we validate it remains under the runtime directory.
        # Then we accept it. Otherwise, we keep the default.
        if "license_path" in config.raw_dict:
            candidate_str = config.raw_dict["license_path"]
            candidate = Path(candidate_str)
            resolved = resolve_path(*candidate.parts)
            # If we must ensure it's under the runtime, we can do:
            # (In final shape, you'd have a known base path to compare. We'll do a naive check.)
            # For example, we might compare if not str(resolved).startswith(str(sentinel_runtime_base_path)):
            # or we skip. We'll do a minimal approach:
            # if sentinel_runtime_base is set, we ensure.
            if sentinel_runtime_base:
                rp = Path(sentinel_runtime_base).resolve()
                if not str(resolved).startswith(str(rp)):
                    raise LicenseError(f"Rejected unsafe override path outside runtime: {resolved}")
            self.license_path = resolved
        else:
            self.license_path = self.default_license_path

        # 2) Identity path (host_fingerprint). No auto-creation.
        self.identity_path = resolve_path("config", "identity.json")

        # 3) Install state path
        self.install_state_path = resolve_path("license", self.INSTALL_STATE_FILENAME)

        # 4) Load the install_state
        self.install_state = self._load_install_state()

    def load_license(self) -> None:
        """
        Attempts to load and validate the license from self.license_path.
        If valid => self.license_state.valid = True
        If invalid => degrade or raise error depending on enforcement or license_required
        """
        # Check if file exists
        if not self.license_path.is_file():
            msg = f"License file not found at: {self.license_path}"
            logger.warning(msg)
            self._chain_event(EventCode.LICENSE_INVALID, {"reason": "file_missing"})
            if self._must_fail():
                raise LicenseError(msg)
            self.license_state = LicenseState(valid=False, watch_only=True, info={})
            return

        # Read raw data
        try:
            raw_data = self.license_path.read_bytes()
        except Exception as e:
            msg = f"Cannot read license file {self.license_path}: {e}"
            logger.warning(msg)
            self._chain_event(EventCode.LICENSE_INVALID, {"reason": "file_unreadable", "error": str(e)})
            if self._must_fail():
                raise LicenseError(msg)
            self.license_state = LicenseState(valid=False, watch_only=True, info={})
            return

        # Parse the base64-encoded JSON
        lic_json = self._parse_license_blob(raw_data)
        if not lic_json:
            if self._must_fail():
                raise LicenseError("License parse error")
            self.license_state = LicenseState(valid=False, watch_only=True, info={})
            return

        # Verify signature
        if not self._verify_license_signature(lic_json):
            msg = "License signature verification failed"
            logger.warning(msg)
            self._chain_event(EventCode.LICENSE_INVALID, {"reason": "signature_fail"})
            if self._must_fail():
                raise LicenseError(msg)
            self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
            return

        # Check expiry
        if self._is_expired(lic_json):
            msg = f"License expired on {lic_json.get('expires_on')}"
            logger.warning(msg)
            self._chain_event(EventCode.LICENSE_EXPIRED,
                              {"license_uuid": lic_json.get("license_uuid", ""),
                               "expires_on": lic_json.get("expires_on")})
            self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
            return

        # Check hardware binding if config.bound_to_hardware
        if getattr(self.config, "bound_to_hardware", False):
            if not self._check_hardware_binding(lic_json):
                if self._must_fail():
                    raise LicenseError("Hardware binding mismatch.")
                self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
                return

        # Check install count
        if not self._check_install_count(lic_json):
            # Already logged event => degrade or raise
            if self._must_fail():
                raise LicenseError("License install limit exceeded.")
            self.license_state = LicenseState(valid=False, watch_only=True, info=lic_json)
            return

        # Mark as valid
        self.license_state = LicenseState(valid=True, watch_only=False, info=lic_json)

        # Log event => LICENSE_ACTIVATED
        meta = {
            "license_uuid": lic_json.get("license_uuid", ""),
            "expires_on": lic_json.get("expires_on"),
            "enforcement_mode": str(self._get_enforcement_mode()),
        }
        self._chain_event(EventCode.LICENSE_ACTIVATED, meta)

    def upload_license(self, src_path: str) -> None:
        """
        Copies the file from src_path => self.license_path and calls load_license().
        If the new license is invalid => degrade or raise error as appropriate.
        """
        if not os.path.isfile(src_path):
            raise LicenseError(f"License file not found: {src_path}")

        license_dir = self.license_path.parent
        if not license_dir.is_dir():
            raise RuntimeError(f"License directory missing: {license_dir}")

        import shutil
        try:
            shutil.copy2(src_path, self.license_path)
        except Exception as e:
            raise LicenseError(f"Failed to copy license from {src_path} => {self.license_path}: {e}")

        self.load_license()

    # ----------------------------------------------
    # Private parsing and checks
    # ----------------------------------------------
    def _parse_license_blob(self, raw_data: bytes) -> Optional[dict]:
        """
        The final license is expected to be base64-encoded JSON with a "signature" field.
        Returns the parsed dict or None if parse fails.
        """
        try:
            decoded = base64.b64decode(raw_data)
            return json.loads(decoded.decode("utf-8"))
        except Exception as e:
            logger.warning("License parse error: %s", e)
            return None

    def _verify_license_signature(self, lic_json: dict) -> bool:
        """
        Extract the 'signature' field, decode it, compare the rest of the license fields with vendor_dilithium_pub.pem
        If config.allow_classical_fallback => optionally load vendor_rsa_pub.pem as well.
        """
        if "signature" not in lic_json:
            return False

        # Extract signature dict
        # The license is a copy of lic_json except "signature" removed
        lic_copy = dict(lic_json)
        sig_b64 = lic_copy.pop("signature")

        try:
            sig_json_bytes = base64.b64decode(sig_b64)
            sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
        except Exception as e:
            logger.warning("License signature field not valid base64 or JSON: %s", e)
            return False

        data_bytes = json.dumps(lic_copy, sort_keys=True).encode("utf-8")

        # Load anchored Dilithium pub key
        try:
            pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")
            dil_pub = pub_path.read_bytes()
        except Exception as e:
            logger.warning("Missing or unreadable vendor_dilithium_pub.pem => cannot verify license: %s", e)
            return False

        # Optionally load RSA pub if fallback is allowed
        rsa_pub = None
        if getattr(self.config, "allow_classical_fallback", False):
            try:
                rsa_path = resolve_path("keys", "vendor_rsa_pub.pem")
                if rsa_path.is_file():
                    rsa_pub = rsa_path.read_bytes()
                else:
                    logger.info("No vendor_rsa_pub.pem found; skipping RSA fallback.")
            except Exception as e:
                logger.warning("Failed to load vendor_rsa_pub.pem: %s", e)

        # Check signature
        return verify_content_signature(data_bytes, sig_dict, self.config, dil_pub, rsa_pub)

    def _is_expired(self, lic_json: dict) -> bool:
        """Check if the license's 'expires_on' field is before today's date."""
        expires_on = lic_json.get("expires_on")
        if not expires_on:
            return True
        try:
            expiry_date = datetime.datetime.strptime(expires_on, "%Y-%m-%d").date()
            return (expiry_date < datetime.date.today())
        except Exception:
            return True

    def _check_hardware_binding(self, lic_json: dict) -> bool:
        """Compare lic_json['bound_to'] with the local host identity fingerprint in identity.json."""
        # read identity
        # We assume identity.json is guaranteed to exist. If not, fail. In strict mode => error. 
        try:
            content = self.identity_path.read_text(encoding="utf-8")
            ident_data = json.loads(content)
            local_fprint = ident_data.get("fingerprint", "")
        except Exception as e:
            logger.warning("Failed to read identity.json for hardware bind check: %s", e)
            return False

        bound_val = lic_json.get("bound_to", "")
        return (bound_val == local_fprint) if bound_val else False

    def _check_install_count(self, lic_json: dict) -> bool:
        """
        Looks up or creates a record in install_state for the license. 
        If host is new, increments usage. If usage > max_installs => fail with INSTALL_REJECTED event.
        """
        license_uuid = lic_json.get("license_uuid", "")
        if not license_uuid:
            return True

        max_installs = lic_json.get("max_installs", 9999999)
        # read local host fingerprint
        local_fp = self._get_local_host_fp()

        state_rec = self.install_state.get(license_uuid)
        if not state_rec:
            state_rec = {"known_installs": [], "install_count": 0}

        if local_fp not in state_rec["known_installs"]:
            new_count = state_rec["install_count"] + 1
            if new_count > max_installs:
                logger.warning("License install limit exceeded: license_uuid=%s, new_count=%d, max=%d",
                               license_uuid, new_count, max_installs)
                self._chain_event(EventCode.INSTALL_REJECTED,
                                  {"license_uuid": license_uuid,
                                   "host_fp": local_fp,
                                   "install_count": str(new_count),
                                   "max_installs": str(max_installs)})
                return False
            # record
            state_rec["install_count"] = new_count
            state_rec["known_installs"].append(local_fp)
            self.install_state[license_uuid] = state_rec
            self._save_install_state()  # updates, sign content => emit INSTALL_UPDATED

        return True

    def _get_local_host_fp(self) -> str:
        """Reads identity.json to get 'fingerprint' field, or returns 'unknown' if fails."""
        try:
            ident_str = self.identity_path.read_text(encoding="utf-8")
            obj = json.loads(ident_str)
            return obj.get("fingerprint", "unknown")
        except Exception as e:
            logger.warning("Failed to read local host identity for install_count => %s", e)
            return "unknown"

    # ---------------------------------------------
    # install_state read/write
    # ---------------------------------------------
    def _load_install_state(self) -> Dict[str, Dict[str, Any]]:
        """
        Reads install_state.json and its signature if present. 
        In strict/hardened => missing or invalid signature => raises.
        Otherwise => degrade to empty usage state.
        """
        if not self.install_state_path.is_file():
            logger.warning("install_state.json is missing => starting fresh usage state.")
            if self._must_fail():
                raise InstallStateError("install_state.json missing in strict/hardened mode.")
            return {}

        sig_path = Path(str(self.install_state_path) + ".sig")
        if not sig_path.is_file():
            msg = "install_state.json.sig missing => cannot verify usage state."
            logger.warning(msg)
            if self._must_fail():
                raise InstallStateError(msg)
            return {}

        try:
            content_str = self.install_state_path.read_text(encoding="utf-8")
            sig_bytes = sig_path.read_bytes()
            import base64, json as j

            sig_dict = j.loads(base64.b64decode(sig_bytes).decode("utf-8"))

            # read vendor_dilithium_pub.pem
            pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")
            vendor_dil_pub = pub_path.read_bytes()

            if not verify_content_signature(content_str.encode("utf-8"), sig_dict, self.config, vendor_dil_pub, None):
                msg = "install_state signature invalid => rejecting load."
                logger.warning(msg)
                if self._must_fail():
                    raise InstallStateError(msg)
                return {}

            data = json.loads(content_str)
            if not isinstance(data, dict):
                raise ValueError("install_state.json not a dict.")
            return data
        except Exception as e:
            msg = f"Failed to load/verify install_state.json => {e}"
            logger.warning(msg)
            if self._must_fail():
                raise InstallStateError(msg)
            return {}

    def _save_install_state(self) -> None:
        """
        Writes and signs install_state.json. Also emits INSTALL_UPDATED to chain after success.
        """
        try:
            content_str = json.dumps(self.install_state, indent=2)
            self.install_state_path.write_text(content_str, encoding="utf-8")

            # sign
            priv_path = resolve_path("keys", "vendor_dilithium_priv.bin")
            vendor_dil = priv_path.read_bytes()

            sig_bundle = sign_content_bundle(content_str.encode("utf-8"), self.config, vendor_dil, None)
            import json as j, base64
            sig_encoded = base64.b64encode(j.dumps(sig_bundle).encode("utf-8"))
            with open(str(self.install_state_path) + ".sig", "wb") as sf:
                sf.write(sig_encoded)

            # After writing => Emit INSTALL_UPDATED
            self._chain_event(EventCode.INSTALL_UPDATED, {"file": str(self.install_state_path)})

        except Exception as e:
            logger.warning("Failed to save or sign install_state.json: %s", e)
            if self._must_fail():
                raise InstallStateError(str(e))

    # ---------------------------------------------
    # Enforcement + chain event helpers
    # ---------------------------------------------
    def _must_fail(self) -> bool:
        """
        In strict/hardened or if config.license_required => fail on invalid license
        Otherwise => degrade to watch_only
        """
        mode = self._get_enforcement_mode()
        if mode in ("STRICT", "HARDENED"):
            return True
        if getattr(self.config, "license_required", False):
            return True
        return False

    def _get_enforcement_mode(self) -> str:
        # fallback => "PERMISSIVE"
        return getattr(self.config, "enforcement_mode", "PERMISSIVE").upper()

    def _chain_event(self, event_code: EventCode, metadata: dict) -> None:
        if not self.audit_chain:
            return
        try:
            self.audit_chain.append_event(event_code.value, metadata)
        except Exception as e:
            logger.error("Failed to append license event %s => %s", event_code.value, e)


def is_watch_only(manager: LicenseManager) -> bool:
    return manager.license_state.watch_only


def is_license_valid(manager: LicenseManager) -> bool:
    return manager.license_state.valid