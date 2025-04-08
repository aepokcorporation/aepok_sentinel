"""
directory_contract.py

Defines and enforces the required directory and file structure for Aepok Sentinel.
No runtime code in Sentinel is allowed to create or guess directories.

If a required directory or file is missing, this module will raise a RuntimeError
during validation. This enforces the principle that all paths are pre-deployed and
must be present at startup (especially in SCIF or hardened environments).

Usage:
    from aepok_sentinel.core.directory_contract import (
        SENTINEL_RUNTIME_BASE,
        validate_runtime_structure,
        resolve_path
    )

    # 1. Validate all required directories/files at startup
    validate_runtime_structure()

    # 2. Build absolute paths to specific subdirectories or files
    config_file_path = resolve_path("config", "trust_anchor.json")

Audit References:
    - Flaw [75]: Eliminate silent directory creation
    - Flaw [76]: Use a single base path for all runtime logic
    - Flaw [77]: Create a centralized directory contract with strict enforcement
    - Flaw [78]: Raise hard failures if any directory/file is missing
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------------
# BASE RUNTIME PATH
# ---------------------------------------------------------------------------------
# All runtime subdirectories (config, keys, license, etc.) must exist under this path.
#
# In a final SCIF/airgap install, this should be a sealed location like:
#    /opsec/aepok_sentinel/runtime
# or an equivalent path specified at install time.
#
# No code in Aepok Sentinel should ever override or create subpaths automatically.

SENTINEL_RUNTIME_BASE = SENTINEL_RUNTIME_BASE = Path("/opsec/aepok_sentinel/runtime")

# ---------------------------------------------------------------------------------
# REQUIRED DIRECTORY & FILE STRUCTURE
# ---------------------------------------------------------------------------------
# Per your provided runtime tree, these are the subfolders and files
# that MUST exist at startup. If a required directory or file is missing,
# validation fails immediately.

REQUIRED_DIRS = [
    "config",
    "keys",
    "license",
]

# We map each subdirectory to the files that must exist there. 
# If any are missing, we raise a RuntimeError.
REQUIRED_FILES = {
    "config": [
        "boot_attestation.json",
        "identity.json",
        "trust_anchor.json"
    ],
    "keys": [
        "vendor_dilithium_priv.bin",
        "vendor_dilithium_pub.pem"
    ],
    "license": [
        "license.key"
    ],
}

# ---------------------------------------------------------------------------------
# VALIDATION FUNCTION
# ---------------------------------------------------------------------------------


def validate_runtime_structure() -> None:
    """
    Validates the presence of all required directories and files under
    SENTINEL_RUNTIME_BASE. Raises RuntimeError if anything is missing.

    This function should be called once at startup (e.g., early in
    controller.py) to ensure no silent directory creation occurs and
    that the system is in a known-good state.

    Returns:
        None

    Raises:
        RuntimeError: If any required directory or file is missing.
    """
    if not SENTINEL_RUNTIME_BASE.is_dir():
        raise RuntimeError(
            f"Critical: Base runtime path does not exist or is not a directory: "
            f"{SENTINEL_RUNTIME_BASE}"
        )

    for subdir in REQUIRED_DIRS:
        subdir_path = SENTINEL_RUNTIME_BASE / subdir
        if not subdir_path.is_dir():
            raise RuntimeError(
                f"Missing required directory: {subdir_path}. "
                f"System cannot proceed."
            )

        # Check required files in each directory
        expected_files = REQUIRED_FILES.get(subdir, [])
        for filename in expected_files:
            file_path = subdir_path / filename
            if not file_path.is_file():
                raise RuntimeError(
                    f"Missing required file: {file_path}. "
                    f"System cannot proceed."
                )


def resolve_path(*path_parts: str) -> Path:
    """
    Constructs an absolute path under SENTINEL_RUNTIME_BASE.

    This is the only allowed way for other modules to build file paths 
    for the runtime directory structure. It prevents ad-hoc string 
    concatenation and ensures consistent enforcement.

    Args:
        path_parts: Subdirectories and/or filename components to be appended.

    Returns:
        A Path object pointing to the requested location under
        SENTINEL_RUNTIME_BASE.

    Example:
        log_file = resolve_path("logs", "sentinel.log")
    """

    resolved = SENTINEL_RUNTIME_BASE.joinpath(*path_parts).resolve()
        if not str(resolved).startswith(str(SENTINEL_RUNTIME_BASE)):
            raise ValueError(f"Unsafe path resolution: {resolved}")
        return resolved