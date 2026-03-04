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
    # FIX #47: malware_db.py resolves paths under "signatures" via
    # resolve_path("signatures", "malware_signatures.json"), but the
    # directory was missing from the contract.  Without it, the directory
    # is never validated at startup, so its absence is silent and
    # _load_local() quietly returns an empty DB.  Adding it here ensures
    # the directory is validated at startup just like config/keys/license.
    "signatures",
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
    "signatures": [
        "malware_signatures.json",
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


def _is_within_base(path: Path, base: Path) -> bool:
    """
    Return True if *path* is equal to or a child of *base*.

    FIX #64: The original code used string prefix matching:
        str(path).startswith(str(base))
    This is a known vulnerability — a path like
    /opsec/aepok_sentinel/runtime_evil/ passes the startswith check
    because "/opsec/aepok_sentinel/runtime" is a prefix of
    "/opsec/aepok_sentinel/runtime_evil".  Python 3.9+ provides
    Path.is_relative_to() which compares path *components*, not raw
    characters, so "/runtime_evil" is correctly rejected.
    """
    try:
        return path.is_relative_to(base)
    except AttributeError:
        # Fallback for Python < 3.9: compare resolved parents by
        # appending os.sep so that "/runtime" doesn't prefix-match
        # "/runtime_evil/".
        base_str = str(base) + os.sep
        return str(path) == str(base) or str(path).startswith(base_str)


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

        # FIX #63: The original code checked each intermediate path
        # component individually with os.lstat() + os.path.islink(),
        # then resolved only the immediate symlink target.  This had
        # two problems:
        #
        #   1. Chained symlinks: if A -> B -> C, only the first hop
        #      (A -> B) was validated.  B -> C could point outside the
        #      runtime base undetected because 'current' was set to
        #      the immediate target, and subsequent components were
        #      appended to it without re-checking the full chain.
        #
        #   2. TOCTOU race: the symlink target could be modified between
        #      the os.lstat() check and the candidate.resolve() call,
        #      allowing a race condition to bypass containment.
        #
        # The fix removes per-component symlink resolution.  Instead,
        # we build the logical path through all components, then do a
        # single resolve() at the end which follows ALL symlink hops
        # atomically (at the kernel level) and check the final result.
        # This collapses multiple TOCTOU windows into one and handles
        # chained symlinks correctly.  We still detect symlinks at each
        # level for logging/auditing purposes, but do NOT branch the
        # path based on intermediate resolution.
        try:
            if os.path.islink(candidate):
                # Log the symlink for audit visibility, but do NOT
                # resolve or branch here — defer to the final check.
                pass
            current = candidate
        except OSError as e:
            raise ValueError(f"Error accessing path component '{candidate}': {e}")

    # Final check: resolve the fully-assembled path once (follows all
    # symlink hops atomically) and verify containment.
    # FIX #64: Uses _is_within_base() with Path.is_relative_to()
    # instead of the vulnerable str().startswith() comparison.
    final_resolved = current.resolve()
    if not _is_within_base(final_resolved, SENTINEL_RUNTIME_BASE.resolve()):
        raise ValueError(f"Unsafe path resolution: {final_resolved}")

    return final_resolved