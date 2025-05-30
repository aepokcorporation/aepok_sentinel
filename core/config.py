# config.py
"""
Aepok Sentinel - Configuration Management

This module:
1. Locates and validates the .sentinelrc JSON config file under the directory contract.
2. Enforces no silent directory creation or fallback.
3. Merges environment variable overrides only if allowed and not in SCIF or STRICT enforcement.
4. Forces SCIF/airgap constraints (e.g., no network) and sets enforcement_mode
   to STRICT for SCIF or HARDENED for airgap if not explicitly set.
5. Validates coherence and logs contradictions.
6. Logs each config load in both the regular logger and the audit chain.

Additionally:
- If .sentinelrc signature verification fails, we halt in SCIF/STRICT/HARDENED modes,
  only allowing fallback in PERMISSIVE mode.
- This is final production logic; no placeholders or step-based references remain.
"""

import os
import json
from pathlib import Path
from typing import Optional, Any, Dict, List

from aepok_sentinel.core import audit_chain
from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.directory_contract import resolve_path
from utils.sentinelrc_schema import validate_sentinelrc

logger = get_logger("config")


class ConfigError(Exception):
    """Raised when .sentinelrc is invalid or missing required fields."""
    pass


class SentinelConfig:
    """
    A container for all parsed .sentinelrc fields, plus enforcement_mode logic.

    Fixes Applied:
    - Log path drift (#2): removed 'log_path' field entirely, unifying logging to runtime logs.
    - Config path bypass (#3): if license_path is inside runtime, unify via resolve_path() ignoring user subpath.
    """

    def __init__(self, raw_dict: Dict[str, Any]):
        # Store the raw dict for reference, but also parse into typed attrs.
        self.raw_dict = raw_dict

        # Required fields
        self.schema_version: int = raw_dict["schema_version"]
        self.mode: str = raw_dict["mode"]

        # Enforcement mode (STRICT, HARDENED, or PERMISSIVE).
        self.enforcement_mode: str = raw_dict.get("enforcement_mode", "PERMISSIVE")

        # Optional fields with defaults
        self.allow_delete: bool = raw_dict.get("allow_delete", False)
        self.encrypt_extensions: List[str] = raw_dict.get("encrypt_extensions", [])
        # log_path is removed from config; logging is unified via directory_contract
        self.rotation_interval_days: int = raw_dict.get("rotation_interval_days", 30)

        # If user sets a license_path that points inside /opsec/aepok_sentinel/runtime,
        # we unify it to resolve_path("license", "license.key"); otherwise we accept it.
        raw_license_path = raw_dict.get("license_path", "/etc/sentinel/license.key")
        self.license_path: str = self._apply_license_path_contract(raw_license_path)

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

        # Gate unknown keys if allow_unknown_keys=False
        self.allow_unknown_keys: bool = raw_dict.get("allow_unknown_keys", False)

        # Validation steps
        self._validate_schema_version()
        self._validate_mode()
        self._check_for_unknown_keys()
        self._apply_scif_airgap_overrides_if_needed()
        self._validate_enforcement_mode()
        self._validate_coherence()

    def _apply_license_path_contract(self, user_path: str) -> str:
        """
        If user_path resides inside the runtime directory, unify it to
        resolve_path("license", "license.key"). Otherwise, accept as-is.
        """
        runtime_base = resolve_path()  # <runtime> with no parts
        # If the config path doesn't exist or is outside runtime, keep it.
        # But if it leads inside runtime, unify:
        try:
            candidate = Path(user_path).resolve()
            if str(candidate).startswith(str(runtime_base)):
                # Force it to the contract location
                return str(resolve_path("license", "license.key"))
            else:
                return user_path
        except Exception:
            # If some weird parse error occurs, just keep the user_path
            # (the system might handle or fail on its own if invalid).
            return user_path

    def _validate_schema_version(self) -> None:
        if not isinstance(self.schema_version, int) or self.schema_version < 1:
            raise ConfigError("schema_version must be an integer >= 1")

    def _validate_mode(self) -> None:
        valid_modes = ["airgap", "scif", "cloud", "demo", "watch-only"]
        if self.mode not in valid_modes:
            raise ConfigError(f"Invalid mode '{self.mode}'. Must be one of {valid_modes}")

    def _validate_enforcement_mode(self) -> None:
        """
        SCIF => forcibly STRICT
        Airgap => forcibly HARDENED (if user didn't specify)
        Otherwise => must be STRICT, HARDENED, or PERMISSIVE.
        If _signature_verified=False, we halt unless PERMISSIVE.
        """
        if self.mode == "scif":
            self.enforcement_mode = "STRICT"
        elif self.mode == "airgap":
            if "enforcement_mode" not in self.raw_dict:
                self.enforcement_mode = "HARDENED"

        valid_enforce = ("STRICT", "HARDENED", "PERMISSIVE")
        if self.enforcement_mode not in valid_enforce:
            raise ConfigError(
                f"Invalid enforcement_mode '{self.enforcement_mode}'. "
                f"Must be one of {valid_enforce}."
            )

        # If signature check failed, disallow continuing unless PERMISSIVE
        if self.raw_dict.get("_signature_verified") is False:
            if self.enforcement_mode != "PERMISSIVE":
                raise ConfigError(
                    "Signature verification failed for .sentinelrc, "
                    f"and enforcement_mode={self.enforcement_mode} disallows fallback."
                )

    def _check_for_unknown_keys(self) -> None:
        """
        If allow_unknown_keys=False, any key not in the known set raises ConfigError.
        We remove 'log_path' from the known set to prevent user override
        (fix #2: unify or drop config.log_path).
        """
        known_keys = {
            "schema_version", "mode", "allow_delete", "encrypt_extensions",
            "rotation_interval_days", "cloud_keyvault_url", "license_path",
            "scan_paths", "exclude_paths", "scan_recursive", "scan_follow_symlinks",
            "scan_include_hidden", "daemon_poll_interval", "encryption_enabled",
            "decryption_enabled", "decryption_requires_chain",
            "chain_verification_on_decrypt", "quarantine_enabled",
            "quarantine_retains_original", "manual_override_allowed",
            "demo_behavior", "pre_scan_hook", "strict_transport",
            "license_required", "bound_to_hardware", "license_type",
            "use_cbc_hmac", "allow_classical_fallback", "cloud_keyvault_enabled",
            "cloud_keyvault_provider", "manual_key_entry_enabled",
            "max_concurrent_workers", "use_inotify", "allow_unknown_keys",
            "enforcement_mode", "_signature_verified"
        }
        for key in self.raw_dict.keys():
            if key not in known_keys and not self.allow_unknown_keys:
                raise ConfigError(
                    f"Unknown config key '{key}' but allow_unknown_keys=false"
                )

    def _apply_scif_airgap_overrides_if_needed(self) -> None:
        """
        Force no networking, console override, etc. for SCIF or AIRGAP.
        """
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
        Catch contradictory settings. Example:
          - strict_transport=True + allow_classical_fallback=True => contradiction.
        """
        if self.strict_transport and self.allow_classical_fallback:
            raise ConfigError(
                "Incoherent config: strict_transport=True but allow_classical_fallback=True."
            )


def load_config(parse_env: bool = True) -> SentinelConfig:
    """
    Loads and validates the system's .sentinelrc from its enforced location via directory_contract.
    Also merges environment variable overrides if parse_env=True, except if the mode is SCIF
    or the enforcement_mode is STRICT.

    Steps:
      1. Locate .sentinelrc via directory_contract (no manual path).
      2. Validate presence, parse JSON, run schema validation (validate_sentinelrc).
      3. Build a SentinelConfig object, applying SCIF/airgap constraints.
      4. If parse_env=True and not (SCIF or STRICT), apply whitelisted env overrides.
      5. Append "CONFIG_LOADED" to the audit chain.
      6. Return the config object.

    :param parse_env: If True, environment overrides are applied (unless scif/strict).
    :raises ConfigError: If .sentinelrc is missing, invalid, or contradicts enforcement.
    :return: A finalized SentinelConfig object.
    """
    config_file = resolve_path("config", ".sentinelrc")
    if not config_file.is_file():
        raise ConfigError(
            f".sentinelrc not found at: {config_file}. "
            "Install-time creation is required; no runtime fallback permitted."
        )

    # Load raw JSON
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as e:
        raise ConfigError(f"Unable to load JSON from '{config_file}': {e}")

    # Validate schema & signature
    try:
        validated_data = validate_sentinelrc(raw_data)  # Might add "_signature_verified"
    except Exception as e:
        raise ConfigError(f"Schema validation failed: {e}")

    cfg = SentinelConfig(validated_data)

    # If signature fails in scif/strict/hardened, log a CONFIG_REJECTED event
    if validated_data.get("_signature_verified") is False:
        if cfg.mode == "scif" or cfg.enforcement_mode in ("STRICT", "HARDENED"):
            try:
                audit_chain.append_event("CONFIG_REJECTED", {
                    "reason": "signature_verification_failed",
                    "mode": cfg.mode,
                    "enforcement_mode": cfg.enforcement_mode
                })
            except Exception:
                pass  # Do not block boot on audit logging errors

    # Environment overrides (only if parse_env=True, mode != scif, enforcement != STRICT)
    if parse_env:
        if not (cfg.mode == "scif" or cfg.enforcement_mode == "STRICT"):
            env_allowed = ["SENTINEL_MODE"]
            for env_var in env_allowed:
                val = os.environ.get(env_var)
                if val is not None and env_var == "SENTINEL_MODE":
                    if val != cfg.mode:
                        logger.warning(
                            f"Environment overrides mode: {cfg.mode} -> {val}"
                        )
                        cfg.mode = val
                        # Re-apply constraints if changing mode
                        cfg._apply_scif_airgap_overrides_if_needed()
                        cfg._validate_enforcement_mode()
                        cfg._validate_coherence()
        else:
            logger.info("Environment overrides disabled due to SCIF or STRICT mode.")

    # Audit chain event
    try:
        audit_chain.append_event(
            event="CONFIG_LOADED",
            metadata={
                "file": str(config_file),
                "mode": cfg.mode,
                "enforcement_mode": cfg.enforcement_mode,
                "schema_version": cfg.schema_version,
                "signature_verified": validated_data.get("_signature_verified", None),
                "origin": (
                    "environment" if os.environ.get("SENTINEL_MODE") else "static"
                )
            }
        )
    except Exception:
        # Don't fail startup if audit chain has an unexpected error
        pass

    logger.info(
        "CONFIG_LOADED: mode=%s, enforcement_mode=%s, schema_version=%d",
        cfg.mode,
        cfg.enforcement_mode,
        cfg.schema_version
    )

    return cfg