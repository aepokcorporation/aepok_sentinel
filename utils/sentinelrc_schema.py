"""
sentinelrc_schema.py

Provides:
  validate_sentinelrc(raw_dict: dict) -> dict

This function:
  - Ensures required fields exist (schema_version, mode).
  - Validates schema_version >= 1.
  - Enforces enumerations (mode in [scif, airgap, cloud, demo, watch-only], tls_mode in [pqc-only, hybrid, classical]).
  - Assigns default values for optional fields.
  - If unknown keys appear and allow_unknown_keys=false => raises ValueError.
  - Returns a new dict with validated + defaulted fields (final shape for config loading).

No directory creation or path references here (no fallback or side effects).
"""

from typing import Any, Dict

# Allowed enumerations
VALID_MODES = ["scif", "airgap", "cloud", "demo", "watch-only"]
VALID_TLS_MODES = ["pqc-only", "hybrid", "classical"]

# Required fields
REQUIRED_FIELDS = ["schema_version", "mode"]

# Defaults for optional fields
DEFAULTS = {
    "allow_delete": False,
    "encrypt_extensions": [],
    "log_path": "/var/log/sentinel/",
    "rotation_interval_days": 30,
    "cloud_keyvault_url": "",
    "license_path": "/etc/sentinel/license.key",
    "scan_paths": [],
    "exclude_paths": [],
    "scan_recursive": True,
    "scan_follow_symlinks": False,
    "scan_include_hidden": True,
    "daemon_poll_interval": 5,
    "encryption_enabled": True,
    "decryption_enabled": True,
    "decryption_requires_chain": True,
    "chain_verification_on_decrypt": True,
    "quarantine_enabled": True,
    "quarantine_retains_original": True,
    "manual_override_allowed": True,
    "demo_behavior": "real",
    "pre_scan_hook": "",
    "strict_transport": False,
    "license_required": False,
    "bound_to_hardware": False,
    "license_type": "individual",
    "use_cbc_hmac": False,
    "allow_classical_fallback": True,
    "cloud_keyvault_enabled": False,
    "cloud_keyvault_provider": "azure",
    "manual_key_entry_enabled": True,
    "max_concurrent_workers": 4,
    "use_inotify": True,
    "tls_mode": "hybrid",     # [pqc-only, hybrid, classical]
    "allow_unknown_keys": False
    "anchor_export_path": "",
}


def validate_sentinelrc(raw_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strictly validates a .sentinelrc dictionary. Returns a new dict with validated + defaulted fields.
    Raises ValueError/TypeError on invalid data. 
    Steps:
      1. Check required fields.
      2. Check schema_version >= 1.
      3. mode => must be in VALID_MODES
      4. Fill in defaults for optional fields.
      5. If unknown_keys_allowed=false => raise for unknown keys
      6. Validate known fields have correct types or enumerations
      7. Return the final validated dict
    """

    # 1. Required fields
    for req in REQUIRED_FIELDS:
        if req not in raw_dict:
            raise ValueError(f"Missing required field '{req}' in .sentinelrc")

    # 2. schema_version
    schema_version = raw_dict["schema_version"]
    if not isinstance(schema_version, int) or schema_version < 1:
        raise ValueError("schema_version must be an integer >= 1")

    # 3. mode enumeration
    mode_val = raw_dict["mode"]
    if mode_val not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode_val}'. Must be one of {VALID_MODES}")

    # 4. If tls_mode provided, check or fallback
    if "tls_mode" in raw_dict:
        if raw_dict["tls_mode"] not in VALID_TLS_MODES:
            raise ValueError(f"Invalid tls_mode '{raw_dict['tls_mode']}'. Must be one of {VALID_TLS_MODES}")

    # 5. unknown_keys_allowed => check unknown keys if false
    unknown_keys_allowed = raw_dict.get("allow_unknown_keys", False)

    # Build the final dict with defaults
    final_dict: Dict[str, Any] = {}
    for k, default_val in DEFAULTS.items():
        if k in raw_dict:
            final_dict[k] = raw_dict[k]
        else:
            final_dict[k] = default_val

    # If unknown_keys_allowed=false => disallow unknown
    if not unknown_keys_allowed:
        known_keys = set(DEFAULTS.keys()).union(REQUIRED_FIELDS)
        for k in raw_dict.keys():
            if k not in known_keys:
                raise ValueError(f"Unknown config key '{k}' but allow_unknown_keys=false")

    # Basic type checks
    if not isinstance(final_dict["mode"], str):
        raise TypeError("mode must be a string")
    if not isinstance(final_dict["encrypt_extensions"], list):
        raise TypeError("encrypt_extensions must be a list")
    if not isinstance(final_dict["scan_paths"], list):
        raise TypeError("scan_paths must be a list")

    # Validate the final tls_mode
    if final_dict["tls_mode"] not in VALID_TLS_MODES:
        raise ValueError(f"Invalid final tls_mode '{final_dict['tls_mode']}'. Must be in {VALID_TLS_MODES}")

    return final_dict