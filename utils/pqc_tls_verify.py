"""
pqc_tls_verify.py (Final Shape)

Utilities for verifying PQC/hybrid TLS sessions:
 - verify_negotiated_pqc(tls_sock, config) -> bool
   Checks if the negotiated group is valid given config.tls_mode, strict_transport, etc.
 - get_server_cert_fingerprint(tls_sock) -> str
   Retrieves the server certificate from TLS, returns SHA-256 fingerprint (hex).
 - verify_cert_fingerprint(tls_sock, expected_fp) -> bool
   Compares actual vs. expected cert fingerprint.
 - check_session_resumption(tls_sock) -> bool
   Detects if session was resumed; for logging or disallowing replay.
 - log_tls_verification_event(tls_sock, config, event="TLS_VERIFICATION")
   Writes group name, cert fingerprint, PQC mode to the audit chain.

Addresses:
 - [33] Real group check from PQC TLS
 - [34] Cert fingerprint logging + PQC state => audit chain
 - [35] Session ticket/resumption tracking (no session ticket usage is recommended,
        but we can detect if a resumed session was used)
"""

import ssl
import hashlib
import logging

from typing import Optional
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_tls import _get_negotiated_group  # real OpenSSL group retrieval
from aepok_sentinel.core import audit_chain

logger = logging.getLogger(__name__)


class PQCVerifyError(Exception):
    """Raised if PQC or certificate verification fails."""


def verify_negotiated_pqc(tls_sock: ssl.SSLSocket, config: SentinelConfig) -> bool:
    """
    Checks if the TLS socket's negotiated group meets the config.tls_mode requirements:
     - pqc-only => must contain 'kyber' (naive check)
     - hybrid => if strict_transport => must contain 'kyber', else classical is allowed
     - classical => always pass
    Returns True if it meets the policy, False otherwise.
    """
    group_name = _get_negotiated_group(tls_sock) or "unknown_group"
    logger.info("verify_negotiated_pqc: group=%s, tls_mode=%s, strict=%s",
                group_name, config.tls_mode, config.strict_transport)

    mode = config.tls_mode.lower()
    if mode == "classical":
        # Even if strict_transport is set, user has a contradictory config. We'll return True for classical mode.
        if config.strict_transport:
            logger.warning("Config: classical + strict => contradictory, but accepting classical.")
        return True

    if mode == "pqc-only":
        if "kyber" not in group_name.lower():
            logger.warning("PQC-only mode => group=%s is not PQC", group_name)
            return False
        return True

    if mode == "hybrid":
        if config.strict_transport:
            # require 'kyber'
            if "kyber" not in group_name.lower():
                logger.warning("strict_transport + hybrid => expected PQC group, got '%s'", group_name)
                return False
            return True
        else:
            # non-strict => allow fallback
            return True

    # fallback => unknown or mis-labeled. Let's just pass
    logger.warning("tls_mode=%s is unrecognized. Accepting group=%s", mode, group_name)
    return True


def get_server_cert_fingerprint(tls_sock: ssl.SSLSocket) -> str:
    """
    Returns SHA-256 hex fingerprint of server's DER certificate. 
    Empty string if no cert is present.
    """
    der_cert = tls_sock.getpeercert(binary_form=True)
    if not der_cert:
        logger.warning("No peer certificate from TLS socket.")
        return ""
    fp = hashlib.sha256(der_cert).hexdigest().lower()
    return fp


def verify_cert_fingerprint(tls_sock: ssl.SSLSocket, expected_fp: str) -> bool:
    """
    Compare the actual fingerprint to the expected one, ignoring case.
    If expected_fp is empty or None, we skip the check (and return True).
    """
    if not expected_fp:
        logger.debug("No expected fingerprint provided, skipping check => True")
        return True

    actual = get_server_cert_fingerprint(tls_sock)
    if not actual:
        logger.warning("No certificate to verify, actual fingerprint is empty.")
        return False

    match = (actual.lower() == expected_fp.lower())
    if not match:
        logger.warning("Cert fingerprint mismatch! expected=%s, actual=%s",
                       expected_fp.lower(), actual.lower())
    return match


def check_session_resumption(tls_sock: ssl.SSLSocket) -> bool:
    """
    Attempt to detect if the session is resumed. 
    Python's `ssl.SSLSocket` doesn't always expose that, but we can do a 
    best-effort check by comparing session ids or something. 
    For demonstration, we show a placeholder approach:
    """
    session_reused = getattr(tls_sock, "session_reused", False)  # python doesn't define this by default, depends on version
    logger.debug("check_session_resumption => session_reused=%s", session_reused)
    return bool(session_reused)


def log_tls_verification_event(
    tls_sock: ssl.SSLSocket,
    config: SentinelConfig,
    event: str = "TLS_VERIFICATION"
) -> None:
    """
    Writes an audit chain event with group name, fingerprint, config enforcement, etc.
    A complementary approach to [34].
    If you want to anchor 'session reuse' or other details, we can do that too.
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