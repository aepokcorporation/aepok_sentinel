# pqc_tls_verify.py
"""
Utilities for verifying PQC/hybrid TLS sessions:

 - verify_negotiated_pqc(tls_sock, config) -> bool
   Checks if the negotiated TLS group meets the config.tls_mode requirements.

 - get_server_cert_fingerprint(tls_sock) -> str
   Retrieves the server certificate from the TLS socket and returns its SHA-256 fingerprint (hex).

 - verify_cert_fingerprint(tls_sock, expected_fp) -> bool
   Compares the actual certificate fingerprint with an expected one, returning False if mismatched.

 - check_session_resumption(tls_sock) -> bool
   Attempts to detect if the TLS session was resumed.

 - log_tls_verification_event(tls_sock, config, event="TLS_VERIFICATION")
   Writes an event to the audit chain with negotiated group, certificate fingerprint, PQC mode, etc.
"""

import ssl
import hashlib
import logging
from typing import Optional

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_tls import _get_negotiated_group
from aepok_sentinel.core import audit_chain

logger = logging.getLogger(__name__)


class PQCVerifyError(Exception):
    """
    Raised if PQC or certificate verification fails. (Reserved for future usage)
    """


def verify_negotiated_pqc(tls_sock: ssl.SSLSocket, config: SentinelConfig) -> bool:
    """
    Checks if the TLS socket's negotiated group aligns with config.tls_mode:
      - "pqc-only": Must contain 'kyber' in the negotiated group name.
      - "hybrid":
         * If strict_transport=True => must contain 'kyber',
         * otherwise classical fallback is allowed.
      - "classical": Always accepted (even if strict_transport is set).
      - If the group is unknown and strict_transport=True, we reject.

    Returns True if the policy is satisfied, or False otherwise.
    """
    group_name = _get_negotiated_group(tls_sock) or "unknown_group"
    logger.info("verify_negotiated_pqc: group=%s, tls_mode=%s, strict=%s",
                group_name, config.tls_mode, config.strict_transport)

    if group_name == "unknown_group" and config.strict_transport:
        logger.warning("STRICT mode but negotiated group is unknown => reject")
        return False

    mode = config.tls_mode.lower()
    if mode == "classical":
        # Even if strict_transport is set, user config is contradictory, but we accept classical.
        if config.strict_transport:
            logger.warning("Config mismatch: classical + strict_transport => allowing classical.")
        return True

    if mode == "pqc-only":
        if "kyber" not in group_name.lower():
            logger.warning("PQC-only mode => group=%s is not PQC-based", group_name)
            return False
        return True

    if mode == "hybrid":
        if config.strict_transport:
            if "kyber" not in group_name.lower():
                logger.warning("strict_transport + hybrid => expected PQC group, got '%s'", group_name)
                return False
            return True
        # non-strict => classical fallback allowed
        return True

    # If tls_mode is not recognized, log a warning and accept.
    logger.warning("Unrecognized tls_mode=%s => accepting group=%s", mode, group_name)
    return True


def get_server_cert_fingerprint(tls_sock: ssl.SSLSocket) -> str:
    """
    Returns the SHA-256 hex fingerprint of the server's DER certificate.
    If no certificate is present, returns an empty string.
    """
    der_cert = tls_sock.getpeercert(binary_form=True)
    if not der_cert:
        logger.warning("No peer certificate from TLS socket.")
        return ""
    return hashlib.sha256(der_cert).hexdigest().lower()


def verify_cert_fingerprint(tls_sock: ssl.SSLSocket, expected_fp: str) -> bool:
    """
    Compare the actual fingerprint to the expected one, ignoring case.
    If expected_fp is empty or None, this check is skipped (returns True).
    """
    if not expected_fp:
        logger.debug("No expected fingerprint provided => skipping fingerprint check => True")
        return True

    actual = get_server_cert_fingerprint(tls_sock)
    if not actual:
        logger.warning("No certificate to verify; actual fingerprint is empty => mismatch")
        return False

    match = (actual.lower() == expected_fp.lower())
    if not match:
        logger.warning("Cert fingerprint mismatch! expected=%s, actual=%s",
                       expected_fp.lower(), actual.lower())
    return match


def check_session_resumption(tls_sock: ssl.SSLSocket) -> bool:
    """
    Attempt to detect if the session is reused/resumed. Some Python versions
    expose 'session_reused'; otherwise, this may be unavailable or always False.
    """
    session_reused = getattr(tls_sock, "session_reused", False)
    logger.debug("check_session_resumption => session_reused=%s", session_reused)
    return bool(session_reused)


def log_tls_verification_event(
    tls_sock: ssl.SSLSocket,
    config: SentinelConfig,
    event: str = "TLS_VERIFICATION"
) -> None:
    """
    Logs a TLS verification event to the audit chain, capturing:
      - negotiated group
      - certificate fingerprint
      - enforcement and PQC mode
      - session resumption info
    """
    group_name = _get_negotiated_group(tls_sock) or "unknown_group"
    fingerprint = get_server_cert_fingerprint(tls_sock)
    resumed = check_session_resumption(tls_sock)

    metadata = {
        "negotiated_group": group_name,
        "certificate_sha256": fingerprint,
        "tls_mode": config.tls_mode,
        "strict_transport": config.strict_transport,
        "enforcement_mode": getattr(config, "enforcement_mode", "unspecified"),
        "session_resumed": resumed,
    }
    audit_chain.append_event(event, metadata)
    logger.info("Logged TLS verification event: group=%s, fingerprint=%s, resumed=%s",
                group_name, fingerprint, resumed)