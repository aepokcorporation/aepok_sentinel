# constants.py
"""
Contains:
 - EventCode enum for standardized audit/log events
 - Intrusion/autoban event codes
 - Other global constants shared across modules
"""

from enum import Enum, unique


@unique
class EventCode(Enum):
    """
    Enumerates standard event codes used in logs and the audit chain.
    """
    # Audit chain / system events
    CHAIN_BROKEN = "CHAIN_BROKEN"
    CHAIN_ROLLOVER = "CHAIN_ROLLOVER"

    # Key management events
    KEY_ROTATED = "KEY_ROTATED"
    KEY_GENERATED = "KEY_GENERATED"

    # License events
    LICENSE_ACTIVATED = "LICENSE_ACTIVATED"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    LICENSE_INVALID = "LICENSE_INVALID"

    # Daemon / file scanning events
    FILE_ENCRYPTED = "FILE_ENCRYPTED"
    FILE_QUARANTINED = "FILE_QUARANTINED"
    FILE_DECRYPTED = "FILE_DECRYPTED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    MALWARE_MATCH = "MALWARE_MATCH"

    # PQC TLS events
    TLS_PQC_NEGOTIATED = "TLS_PQC_NEGOTIATED"
    TLS_FALLBACK = "TLS_FALLBACK"
    TLS_STRICT_FAIL = "TLS_STRICT_FAIL"

    # Controller / daemon lifecycle events
    CONTROLLER_BOOT = "CONTROLLER_BOOT"
    DAEMON_STARTED = "DAEMON_STARTED"
    DEVICE_PROVISIONED = "DEVICE_PROVISIONED"

    # Key management failure/recovery events
    KEY_GENERATION_FAILED = "KEY_GENERATION_FAILED"
    KEY_ROTATION_REVERTED = "KEY_ROTATION_REVERTED"

    # Disk / resource events
    DISK_LIMIT_EXCEEDED = "DISK_LIMIT_EXCEEDED"

    # Install lifecycle events
    INSTALL_UPDATED = "INSTALL_UPDATED"
    INSTALL_REJECTED = "INSTALL_REJECTED"

    # Intrusion / Autoban events
    SOURCE_BLOCKED = "SOURCE_BLOCKED"
    SOURCE_REJECTED = "SOURCE_REJECTED"
    AUTOBAN_TRIGGERED = "AUTOBAN_TRIGGERED"


# Other global constants that might be used across modules
DEFAULT_KEY_GENERATIONS_TO_KEEP = 5
MAX_LOG_FILE_SIZE_MB = 5
LOG_BACKUP_COUNT = 5
