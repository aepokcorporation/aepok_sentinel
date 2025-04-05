"""
Step 2: Configuration Module

This module:
1. Loads and validates the .sentinelrc JSON config file.
2. Applies default values for optional fields.
3. Merges environment variable overrides (e.g. SENTINEL_MODE) and logs a warning if used.
4. Enforces SCIF/airgap constraints (no network, forced console off, etc.).
5. Raises errors on unknown keys unless allow_unknown_keys = true.

References only logging_setup.py from Step 1. No forward references to future modules.
"""

import os
import json
from typing import Optional, Any, Dict, List
from aepok_sentinel.core.logging_setup import get_logger
from utils.sentinelrc_schema import validate_sentinelrc

logger = get_logger("config")


class ConfigError(Exception):
    """Raised when .sentinelrc is invalid or missing required fields."""
    pass


class SentinelConfig:
    """
    A container for all parsed .sentinelrc fields, plus enforcement_mode logic.
    """

    def __init__(self, raw_dict: Dict[str, Any]):
        # We'll store the raw dict for reference, but also parse into typed attrs.
        self.raw_dict = raw_dict

        # Required fields
        self.schema_version: int = raw_dict["schema_version"]
        self.mode: str = raw_dict["mode"]

        # New field for audit fix [4], [79]:
        # If not set, default to "PERMISSIVE"; we can override for scif/airgap below.
        self.enforcement_mode: str = raw_dict.get("enforcement_mode", "PERMISSIVE")

        # Optional fields (with defaults from instruction manual)
        self.allow_delete: bool = raw_dict.get("allow_delete", False)
        self.encrypt_extensions: List[str] = raw_dict.get("encrypt_extensions", [])
        self.log_path: str = raw_dict.get("log_path", "/var/log/sentinel/")
        self.rotation_interval_days: int = raw_dict.get("rotation_interval_days", 30)
        self.cloud_keyvault_url: str = raw_dict.get("cloud_keyvault_url", "")
        self.license_path: str = raw_dict.get("license_path", "/etc/sentinel/license.key")

        self.scan_paths: List[str] = raw_dict.get("scan_paths", [])
        self.exclude_paths: List[str] = raw_dict.get("exclude_paths", [])
        self.scan_recursive: bool = raw_dict.get("scan_recursive", True)
        self.scan_follow_symlinks: bool = raw_dict.get("scan_follow_symlinks", False)
        self.scan_include_hidden: bool = raw_dict.get("scan_include_hidden", True)
        self.daemon_poll_interval: int = raw_dict.get("daemon_poll_interval", 5)
        self.encryption_enabled: bool = raw_dict.get("encryption_enabled", True)
        self.decryption_enabled: bool = raw_dict.get("decryption_enabled", True)
        self.decryption_requires_chain: bool = raw_dict.get("decryption_requires_chain", True)
        self.chain_verification_on_decrypt: bool = raw_dict.get(
            "chain_verification_on_decrypt",
            self.decryption_requires_chain
        )
        self.quarantine_enabled: bool = raw_dict.get("quarantine_enabled", True)
        self.quarantine_retains_original: bool = raw_dict.get("quarantine_retains_original", True)
        self.manual_override_allowed: bool = raw_dict.get("manual_override_allowed", True)
        self.demo_behavior: str = raw_dict.get("demo_behavior", "real")
        self.pre_scan_hook: str = raw_dict.get("pre_scan_hook", "")
        self.strict_transport: bool = raw_dict.get("strict_transport", False)
        self.license_required: bool = raw_dict.get("license_required", False)
        self.bound_to_hardware: bool = raw_dict.get("bound_to_hardware", False)
        self.license_type: str = raw_dict.get("license_type", "individual")

        # Additional advanced fields
        self.use_cbc_hmac: bool = raw_dict.get("use_cbc_hmac", False)
        self.allow_classical_fallback: bool = raw_dict.get("allow_classical_fallback", True)
        self.cloud_keyvault_enabled: bool = raw_dict.get("cloud_keyvault_enabled", False)
        self.cloud_keyvault_provider: str = raw_dict.get("cloud_keyvault_provider", "azure")
        self.manual_key_entry_enabled: bool = raw_dict.get("manual_key_entry_enabled", True)
        self.max_concurrent_workers: int = raw_dict.get("max_concurrent_workers", 4)
        self.use_inotify: bool = raw_dict.get("use_inotify", True)

        # Allow or disallow unknown keys
        self.allow_unknown_keys: bool = raw_dict.get("allow_unknown_keys", False)

        # Basic validations
        self._validate_schema_version()
        self._validate_mode()
        self._check_for_unknown_keys()
        self._apply_scif_airgap_overrides_if_needed()
        self._validate_enforcement_mode()
        self._validate_coherence()

    def _validate_schema_version(self) -> None:
        if not isinstance(self.schema_version, int) or self.schema_version < 1:
            raise ConfigError("schema_version must be an integer >= 1")

    def _validate_mode(self) -> None:
        valid_modes = ["airgap", "scif", "cloud", "demo", "watch-only"]
        if self.mode not in valid_modes:
            raise ConfigError(f"Invalid mode '{self.mode}'. Must be one of {valid_modes}")

    def _validate_enforcement_mode(self) -> None:
        """
        For scif => must be STRICT
        For airgap => default to HARDENED if not specified
        Otherwise, must be one of STRICT/HARDENED/PERMISSIVE
        """
        # If scif => force STRICT
        if self.mode == "scif":
            self.enforcement_mode = "STRICT"

        # If airgap => default to HARDENED if user didn't explicitly set
        elif self.mode == "airgap":
            if "enforcement_mode" not in self.raw_dict:
                self.enforcement_mode = "HARDENED"

        valid_enforce = ("STRICT", "HARDENED", "PERMISSIVE")
        if self.enforcement_mode not in valid_enforce:
            raise ConfigError(
                f"Invalid enforcement_mode '{self.enforcement_mode}'. "
                f"Must be one of {valid_enforce}."
            )

        # If the sentinelrc signature was invalid, validate_sentinelrc() would raise an error
        # but if it was "invalid but we returned anyway", we treat that as a fail unless "PERMISSIVE".
        # We can't do a real signature check here—no forward references—so we rely on validate_sentinelrc.
        # If validate_sentinelrc sets something like raw_dict["_signature_verified"] = False, do:
        if (self.raw_dict.get("_signature_verified") is False
                and self.enforcement_mode != "PERMISSIVE"):
            raise ConfigError(
                "Signature verification failed for .sentinelrc, "
                f"and enforcement_mode={self.enforcement_mode} does not allow fallback."
            )

    def _check_for_unknown_keys(self) -> None:
        """
        If allow_unknown_keys == false, any extra top-level keys in raw_dict
        that are not in the known set must trigger an error.
        """
        known_keys = {
            "schema_version", "mode", "allow_delete", "encrypt_extensions", "log_path",
            "rotation_interval_days", "cloud_keyvault_url", "license_path", "scan_paths",
            "exclude_paths", "scan_recursive", "scan_follow_symlinks", "scan_include_hidden",
            "daemon_poll_interval", "encryption_enabled", "decryption_enabled", "decryption_requires_chain",
            "chain_verification_on_decrypt", "quarantine_enabled", "quarantine_retains_original",
            "manual_override_allowed", "demo_behavior", "pre_scan_hook", "strict_transport",
            "license_required", "bound_to_hardware", "license_type", "use_cbc_hmac", "allow_classical_fallback",
            "cloud_keyvault_enabled", "cloud_keyvault_provider", "manual_key_entry_enabled",
            "max_concurrent_workers", "use_inotify", "allow_unknown_keys", "enforcement_mode",
            "_signature_verified"  # might be inserted by validate_sentinelrc
        }
        for key in self.raw_dict.keys():
            if key not in known_keys and not self.allow_unknown_keys:
                raise ConfigError(f"Unknown config key '{key}' but allow_unknown_keys=false")

    def _apply_scif_airgap_overrides_if_needed(self) -> None:
        # If mode is scif or airgap => forcibly set no network calls, console off, etc.
        if self.mode == "scif":
            self.cloud_keyvault_url = ""
            self.cloud_keyvault_enabled = False
            self.manual_override_allowed = False
            self.decryption_requires_chain = True
            self.chain_verification_on_decrypt = True

        elif self.mode == "airgap":
            self.cloud_keyvault_url = ""
            self.cloud_keyvault_enabled = False
            self.decryption_requires_chain = True
            self.chain_verification_on_decrypt = True

    def _validate_coherence(self) -> None:
        """
        Catch contradictory settings, e.g. strict_transport=True but allow_classical_fallback=True.
        """
        if self.strict_transport and self.allow_classical_fallback:
            # It's contradictory to enforce PQC/TLS strictly but also allow classical RSA fallback
            raise ConfigError("Incoherent config: strict_transport=True but allow_classical_fallback=True.")


def load_config(file_path: str, parse_env: bool = True) -> SentinelConfig:
    """
    Loads .sentinelrc from file_path, parses and returns a SentinelConfig object.
    If parse_env=True, environment variables like SENTINEL_MODE override the config's mode.

    :param file_path: Path to .sentinelrc
    :param parse_env: Whether to apply environment overrides
    :raises ConfigError: if file is missing, invalid JSON, or required fields are missing
    :return: a fully validated SentinelConfig
    """
    if not os.path.isfile(file_path):
        raise ConfigError(f"Config file '{file_path}' not found.")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as e:
        raise ConfigError(f"Unable to load JSON from '{file_path}': {e}")

    # Validate the sentinelrc structure (including optional signature check).
    # If there's a signature mismatch and enforcement_mode != "PERMISSIVE", we raise inside SentinelConfig.
    try:
        validated_data = validate_sentinelrc(raw_data)  # must return dict, may add "_signature_verified"
    except Exception as e:
        raise ConfigError(f"Schema validation failed: {e}")

    config_obj = SentinelConfig(validated_data)

    # If parse_env=True, we apply a small whitelist of environment overrides.
    if parse_env:
        # At present, only SENTINEL_MODE is allowed.
        env_allowed = ["SENTINEL_MODE"]  # expand if needed
        for env_var in env_allowed:
            val = os.environ.get(env_var)
            if val is not None and env_var == "SENTINEL_MODE":
                if val != config_obj.mode:
                    logger.warning(f"Environment overrides mode: {config_obj.mode} -> {val}")
                    config_obj.mode = val
                    config_obj._validate_mode()
                    # Reapply scif/airgap overrides if we forcibly changed mode
                    config_obj._apply_scif_airgap_overrides_if_needed()
                    config_obj._validate_enforcement_mode()
                    config_obj._validate_coherence()

    # [2] Log a line so we can track config loads in the audit chain later
    logger.info(
        "CONFIG_LOADED: file=%s, mode=%s, enforcement_mode=%s, schema_version=%d",
        file_path,
        config_obj.mode,
        config_obj.enforcement_mode,
        config_obj.schema_version
    )

    return config_obj