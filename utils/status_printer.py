"""
status_printer.py

Provides two functions:
 - gather_system_status(config, license_mgr) -> str
   Returns a multiline string summarizing the current .sentinelrc config
   and license state (watch-only or valid).

 - print_system_status(config, license_mgr) -> None
   Prints the status to stdout and logs it at INFO.

No directory creation or fallback logic here. 
Fully final-shape compliance: no references to ephemeral placeholders or steps.
"""

import logging
import sys
from typing import Optional

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only, is_license_valid

logger = get_logger("status_printer")


def gather_system_status(config: SentinelConfig, license_mgr: LicenseManager) -> str:
    """
    Gathers a multiline string summarizing:
      - config.mode (SCIF/airgap => note network disallowed)
      - encryption_enabled, strict_transport
      - license validity or watch-only
      - if mode=cloud => show cloud_keyvault_url
      - other relevant config fields
    """
    lines = []
    lines.append("=== Aepok Sentinel System Status ===")
    lines.append(f"Mode: {config.mode}")
    if config.mode in ("scif", "airgap"):
        lines.append(" - Network calls disallowed.")

    lines.append("Encryption: ENABLED" if config.encryption_enabled else "Encryption: DISABLED")
    lines.append(f"strict_transport: {'TRUE' if config.strict_transport else 'FALSE'}")

    # license state
    if is_license_valid(license_mgr):
        lines.append("License State: VALID")
    elif is_watch_only(license_mgr):
        lines.append("License State: WATCH-ONLY")
    else:
        lines.append("License State: UNKNOWN/INVALID")

    if config.mode == "cloud" and config.cloud_keyvault_url:
        lines.append(f"Cloud KeyVault URL: {config.cloud_keyvault_url}")

    # Additional details
    lines.append(f"allow_delete: {config.allow_delete}")
    lines.append(f"daemon_poll_interval: {config.daemon_poll_interval} (seconds)")
    lines.append(f"Log path: {config.log_path}")
    lines.append(f"License required: {config.license_required}")
    lines.append(f"Hardware binding: {config.bound_to_hardware}")

    return "\n".join(lines)


def print_system_status(config: SentinelConfig, license_mgr: LicenseManager) -> None:
    """
    Prints the system status to stdout and logs an INFO with the summary.
    """
    status_str = gather_system_status(config, license_mgr)
    print(status_str)
    logger.info("System Status:\n%s", status_str)