# directory_contract.py
"""
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
"""

import os
import unicodedata
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------------
# BASE RUNTIME PATH
# ---------------------------------------------------------------------------------
# All runtime subdirectories (config, keys, license, etc.) must exist under this path.
# No code in Aepok Sentinel should ever override or create subpaths automatically.

SENTINEL_RUNTIME_BASE = Path("/opsec/aepok_sentinel/runtime")

# ---------------------------------------------------------------------------------
# REQUIRED DIRECTORIES & FILES
# ---------------------------------------------------------------------------------

REQUIRED_DIRS: List[str] = [
    "config",
    "keys",
    "license",
]

REQUIRED_FILES = {
    "config": [
        "boot_attestation.json",
        "identity.json",
        "trust_anchor.json",
    ],
    "keys": [
        "vendor_dilithium_priv.bin",
        "vendor_dilithium_pub.pem",
    ],
    "license": [
        "license.key",
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
    Constructs an absolute path under SENTINEL_RUNTIME_BASE, enforcing
    Unicode normalization and preventing symlink escapes outside the
    runtime directory.

    This is the only allowed way for other modules to build file paths
    for the runtime directory structure. It prevents ad-hoc string
    concatenation and ensures consistent enforcement.

    Args:
        path_parts: Subdirectories and/or filename components to be appended.

    Returns:
        A Path object pointing to the requested location under
        SENTINEL_RUNTIME_BASE.

    Raises:
        ValueError: If the path attempts to escape the runtime directory,
                    or if Unicode normalization reveals suspicious differences.

    Example:
        log_file = resolve_path("logs", "sentinel.log")
    """
    current = SENTINEL_RUNTIME_BASE

    for raw_part in path_parts:
        normalized_part = unicodedata.normalize("NFC", raw_part)
        if normalized_part != raw_part:
            raise ValueError(
                f"Path component '{raw_part}' changes under NFC normalization. "
                f"Potential Unicode spoofing detected."
            )

        candidate = current / normalized_part

        # Check if this segment is a symlink and resolve it immediately.
        # The final resolved target must still be inside SENTINEL_RUNTIME_BASE.
        try:
            # lstat() to detect symlink at this level
            stat_info = os.lstat(candidate)
            if os.path.islink(candidate):
                real_target = candidate.resolve()
                if not str(real_target).startswith(str(SENTINEL_RUNTIME_BASE)):
                    raise ValueError(
                        f"Symlink '{candidate}' points outside the runtime directory."
                    )
                # Accept the resolved target, ensuring we continue building from real_target
                current = real_target
            else:
                # Regular file or directory so far; just move forward
                current = candidate
        except FileNotFoundError:
            # This path might not exist yet; usage in some contexts is still valid
            # as long as we remain logically under the runtime base.
            current = candidate
        except OSError as e:
            raise ValueError(f"Error accessing path component '{candidate}': {e}")

    # Final check: ensure the fully resolved path is still within SENTINEL_RUNTIME_BASE
    final_resolved = current.resolve()
    if not str(final_resolved).startswith(str(SENTINEL_RUNTIME_BASE)):
        raise ValueError(f"Unsafe path resolution: {final_resolved}")

    return final_resolved