"""
Step 5.6: Constants Module

Contains event codes, string identifiers, and other shared constants
for the Aepok Sentinel system. No references to future logic modules.
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
    # Security checks
    MALWARE_MATCH = "MALWARE_MATCH"
    # PQC TLS events
    TLS_PQC_NEGOTIATED = "TLS_PQC_NEGOTIATED"
    TLS_FALLBACK = "TLS_FALLBACK"
    TLS_STRICT_FAIL = "TLS_STRICT_FAIL"


# Other global constants that might be used across modules
DEFAULT_KEY_GENERATIONS_TO_KEEP = 5
MAX_LOG_FILE_SIZE_MB = 5
LOG_BACKUP_COUNT = 5