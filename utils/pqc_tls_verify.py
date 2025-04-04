"""
Step 5.4: PQC TLS Verification Utilities

Provides:
  - verify_negotiated_pqc(tls_sock, config) -> bool
    Checks the negotiated group from a live TLS socket, ensures it matches the expected PQC or hybrid mode.
    Potentially detects "downgrade" if strict_transport or tls_mode='pqc-only'.
  - get_server_cert_fingerprint(tls_sock) -> str
    Retrieves the server certificate from TLS, computes SHA-256 fingerprint in hex.
  - verify_cert_fingerprint(tls_sock, expected_fp: str) -> bool
    Compares the actual fingerprint with expected_fp, returns True if match.

No references to future steps. This is a final-shape module used in testing or optional runtime checks.
"""

import ssl
import hashlib
import logging
from typing import Optional

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_tls import _get_negotiated_group  # from step 5.1

logger = get_logger("pqc_tls_verify")


class PQCVerifyError(Exception):
    """Raised if PQC or certificate verification fails."""


def verify_negotiated_pqc(tls_sock: ssl.SSLSocket, config: SentinelConfig) -> bool:
    """
    Checks if the TLS socket's negotiated group is truly PQC or at least hybrid,
    depending on config.tls_mode and config.strict_transport.
    If config.tls_mode='pqc-only' => we require a PQC group.
    If config.tls_mode='hybrid' => we accept either PQC or classical fallback, 
        unless strict_transport=true => must have PQC in that scenario.
    If config.tls_mode='classical' => no PQC required, always True here.

    This is an extra verification step, beyond what connect_pqc_socket might do.

    :param tls_sock: The live SSL socket
    :param config: sentinel config
    :return: True if the group meets the requirement, else False
    """
    group_name = _get_negotiated_group(tls_sock)
    logger.info("verify_negotiated_pqc: group=%s, tls_mode=%s, strict=%s", 
                group_name, config.tls_mode, config.strict_transport)

    # If classical => we don't require PQC
    if config.tls_mode == "classical":
        # If strict_transport=true => theoretically we might want to fail,
        # but let's unify logic: if they set 'classical' with strict, 
        # that's contradictory, but let's return True for classical.
        if config.strict_transport:
            logger.warning("Config says classical + strict_transport. This might be contradictory. Accepting anyway.")
        return True

    # If pqc-only => must see a group with 'kyber' or 'pqc'
    if config.tls_mode == "pqc-only":
        # naive approach: if group_name has 'kyber' => it's PQC
        # If not => fail
        if "kyber" in group_name.lower():
            return True
        logger.warning("PQC-only mode => group=%s not PQC", group_name)
        return False

    # If hybrid => if strict_transport => require 'kyber'
    # else allow classical
    if config.tls_mode == "hybrid":
        if config.strict_transport:
            # must see PQC
            if "kyber" not in group_name.lower():
                logger.warning("strict_transport + hybrid => requires PQC group. Not found in '%s'", group_name)
                return False
        # if not strict => any group is fine
        return True

    # fallback => let pass
    return True


def get_server_cert_fingerprint(tls_sock: ssl.SSLSocket) -> str:
    """
    Retrieves the server certificate from the TLS socket, 
    computes SHA-256 fingerprint (hex).
    Returns an empty string if no cert.
    """
    peercert = tls_sock.getpeercert(binary_form=True)
    if not peercert:
        logger.warning("No peer certificate found.")
        return ""
    sha_val = hashlib.sha256(peercert).hexdigest()
    logger.info("Server cert fingerprint: %s", sha_val)
    return sha_val


def verify_cert_fingerprint(tls_sock: ssl.SSLSocket, expected_fp: str) -> bool:
    """
    Compares the TLS socket's server cert fingerprint to an expected hex string.
    """
    if not expected_fp:
        logger.warning("No expected fingerprint provided, skipping check.")
        return True

    actual_fp = get_server_cert_fingerprint(tls_sock)
    if not actual_fp:
        return False
    match = (actual_fp.lower() == expected_fp.lower())
    if not match:
        logger.warning("Cert fingerprint mismatch. actual=%s, expected=%s", actual_fp, expected_fp)
    return match