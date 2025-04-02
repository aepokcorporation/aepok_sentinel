"""
Step 5.7: sentinelrc_schema.py

Provides a strict validator function for .sentinelrc data:
  validate_sentinelrc(raw_dict: dict) -> dict

This enforces:
 - Required fields: schema_version >=1, mode, etc.
 - Enumerations (e.g. mode => [scif, airgap, cloud, demo, watch-only], tls_mode => [pqc-only, hybrid, classical])
 - Types for known fields
 - Defaults for optional fields
 - Raises ValueError or TypeError on invalid data

No forward references to future modules. Final shape code for stricter .sentinelrc validation.
"""

from typing import Any, Dict, List

VALID_MODES = ["scif", "airgap", "cloud", "demo", "watch-only"]
VALID_TLS_MODES = ["pqc-only", "hybrid", "classical"]

REQUIRED_FIELDS = ["schema_version", "mode"]
# We enforce schema_version >= 1

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
    "chain_verification_on_decrypt": True,  # synonyms
    "quarantine_enabled": True,
    "quarantine_retains_original": True,
    "manual_override_allowed": True,
    "demo_behavior": "real",  # or "mock"
    "pre_scan_hook": "",
    "strict_transport": False,
    "license_required": False,
    "bound_to_hardware": False,
    "license_type": "individual",  # or "site"
    "use_cbc_hmac": False,
    "allow_classical_fallback": True,
    "cloud_keyvault_enabled": False,
    "cloud_keyvault_provider": "azure",
    "manual_key_entry_enabled": True,
    "max_concurrent_workers": 4,
    "use_inotify": True,
    "tls_mode": "hybrid",  # e.g. "pqc-only", "hybrid", "classical"
    "allow_unknown_keys": False
}


def validate_sentinelrc(raw_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strictly validates the .sentinelrc structure:
      - schema_version (int >= 1)
      - mode in [scif, airgap, cloud, demo, watch-only]
      - optional fields => assign defaults if missing
      - if unknown keys appear and allow_unknown_keys=false => raise ValueError
      - if tls_mode present => must be in [pqc-only, hybrid, classical]

    Returns a new dict with validated + defaulted fields.
    Raises ValueError or TypeError if invalid.
    """

    # ensure required
    for req in REQUIRED_FIELDS:
        if req not in raw_dict:
            raise ValueError(f"Missing required field '{req}' in .sentinelrc")

    # schema_version checks
    schema_ver = raw_dict["schema_version"]
    if not isinstance(schema_ver, int) or schema_ver < 1:
        raise ValueError("schema_version must be an integer >= 1")

    # mode checks
    mode_val = raw_dict["mode"]
    if mode_val not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode_val}'. Must be one of {VALID_MODES}")

    # If 'tls_mode' is present, validate it or default to 'hybrid'
    if "tls_mode" in raw_dict:
        if raw_dict["tls_mode"] not in VALID_TLS_MODES:
            raise ValueError(f"Invalid tls_mode '{raw_dict['tls_mode']}'. Must be one of {VALID_TLS_MODES}")

    # If 'allow_unknown_keys' is present, note it. Otherwise default to false and check unknown keys
    unknown_keys_allowed = raw_dict.get("allow_unknown_keys", False)

    # fill in defaults for optional fields
    final_dict = {}
    for key, default_val in DEFAULTS.items():
        if key in raw_dict:
            final_dict[key] = raw_dict[key]
        else:
            final_dict[key] = default_val

    # now check for unknown fields if not allowed
    if not unknown_keys_allowed:
        known_keys_set = set(DEFAULTS.keys()).union(REQUIRED_FIELDS)
        for k in raw_dict.keys():
            if k not in known_keys_set:
                raise ValueError(f"Unknown config key '{k}' but allow_unknown_keys=false")

    # do type checks for some known fields
    if not isinstance(final_dict["mode"], str):
        raise TypeError("mode must be a string")
    if not isinstance(final_dict["encrypt_extensions"], list):
        raise TypeError("encrypt_extensions must be a list")
    if not isinstance(final_dict["scan_paths"], list):
        raise TypeError("scan_paths must be a list")
    # optional deeper checks can be done here...

    # ensure final_dict["tls_mode"] is valid if present
    if "tls_mode" in final_dict:
        if final_dict["tls_mode"] not in VALID_TLS_MODES:
            raise ValueError(f"Invalid final tls_mode '{final_dict['tls_mode']}'. Must be one of {VALID_TLS_MODES}")

    return final_dict