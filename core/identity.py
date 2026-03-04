# identity.py
"""
Host Identity Module

Provides get_host_fingerprint() which reads the pre-deployed identity.json
from the runtime config directory and returns the host_fingerprint string.

This module is referenced by controller.py during boot to bind the Sentinel
instance to a specific hardware/host identity.  The identity.json file and
its signature must be provisioned at install time; this module will NOT
create or modify them.
"""

import json
import logging
from pathlib import Path

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.directory_contract import resolve_path

logger = get_logger("identity")


def get_host_fingerprint(runtime_base: str = "") -> str:
    """
    Reads identity.json from the runtime config directory and returns the
    ``host_fingerprint`` value stored in it.

    :param runtime_base: Accepted for API compatibility with the controller
                         call-site, but the canonical path is always resolved
                         via directory_contract (resolve_path("config",
                         "identity.json")).
    :returns: The hex fingerprint string, e.g. "e29f1097...".
    :raises RuntimeError: If identity.json is missing or does not contain
                          a ``host_fingerprint`` key.
    """
    identity_path = resolve_path("config", "identity.json")

    if not identity_path.is_file():
        raise RuntimeError(
            f"identity.json not found at {identity_path}. "
            "Device must be provisioned before the controller can boot."
        )

    try:
        with open(identity_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to parse identity.json: {e}")

    fingerprint = data.get("host_fingerprint")
    if not fingerprint:
        raise RuntimeError(
            "identity.json does not contain a 'host_fingerprint' field."
        )

    logger.info("Loaded host fingerprint: %s…", fingerprint[:16])
    return fingerprint
