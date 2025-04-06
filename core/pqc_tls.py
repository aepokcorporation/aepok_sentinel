"""
pqc_tls.py

Final-shape PQC TLS Transport Layer for Aepok Sentinel.

Addresses:
 - [33]: Real group verification via OpenSSL calls, no naive cipher heuristics.
 - [34]: Logs cert fingerprint + negotiated group into audit chain at session init.
 - [35]: Disables TLS session tickets to avoid reusing session keys.

No directory creation. No stubs. Actual cffi code for group retrieval.
"""

import ssl
import socket
import hashlib
import logging
import os
import binascii
from typing import Optional

import cffi

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core import audit_chain

logger = get_logger("pqc_tls")

# -----------------------------------------------------------------------------
# CFFI Setup: load OpenSSL symbols for group retrieval and NID -> short name
# -----------------------------------------------------------------------------

_ffi = cffi.FFI()
_ffi.cdef(
    """
    typedef ... SSL;
    int SSL_get_shared_group(const SSL *ssl, int n); // Returns NID of nth shared group
    const char* OBJ_nid2sn(int nid); // NID -> short name
    // We also need to disable session tickets => SSL_CTX_set_options might be used, or we rely on OP_NO_TICKET
    // We'll define the OP_NO_TICKET constant manually if not in headers:
    // #define SSL_OP_NO_TICKET 0x00004000
    """
)

# Attempt to find libssl and libcrypto from environment
# For final shape, if custom path needed, user sets LD_LIBRARY_PATH or similar
import ctypes.util

_libssl_path = ctypes.util.find_library("ssl")
_libcrypto_path = ctypes.util.find_library("crypto")
if not _libssl_path or not _libcrypto_path:
    # We won't raise here if user doesn't have them. Possibly fallback or doc note.
    logger.warning("Could not find system libssl/libcrypto. PQC group retrieval might fail.")

_libssl = None
_libcrypto = None
if _libssl_path:
    try:
        _libssl = _ffi.dlopen(_libssl_path)
    except OSError:
        logger.warning("Failed to dlopen(%s). Group retrieval not available.", _libssl_path)

if _libcrypto_path:
    try:
        _libcrypto = _ffi.dlopen(_libcrypto_path)
    except OSError:
        logger.warning("Failed to dlopen(%s). OBJ_nid2sn not available.", _libcrypto_path)


# Manually define OP_NO_TICKET if not in Python’s ssl
OP_NO_TICKET = 0x00004000  # SSL_OP_NO_TICKET from openssl headers


class PQCTlsError(Exception):
    """Raised on handshake or group mismatch if strict_transport is enforced."""


def create_pqc_ssl_context(config: SentinelConfig) -> ssl.SSLContext:
    """
    Creates an SSLContext for TLS 1.3 with optional PQC/hybrid groups, disabling session tickets, etc.
    - Enforces no session tickets => each handshake is fresh
    - If strict_transport and environment lacks OQS provider => we may fail
    - If config.tls_mode='pqc-only' => only PQC groups, 'hybrid' => PQC + classical fallback, 'classical' => normal ECDH
    Returns a fully configured SSLContext.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # Disallow older TLS
    ctx.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1
    # Disable session tickets => mitigate [35]
    ctx.options |= OP_NO_TICKET

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED  # typical usage; can be overridden

    # Optionally load system or custom CA if needed
    # e.g., if config.raw_dict.get("ca_path"): ctx.load_verify_locations(...)

    # Now set the groups. This requires a lower-level call since Python doesn't expose it directly.
    # if config.tls_mode is 'pqc-only', we set only "X25519Kyber768" or similar.
    # if 'classical', just x25519, secp256r1
    # if 'hybrid', both. We'll rely on a helper.
    try:
        _set_supported_groups(ctx, config)
    except OSError as e:
        # If strict => fail
        if config.strict_transport:
            raise PQCTlsError(f"Could not set PQC/hybrid groups in strict mode: {e}")
        else:
            logger.warning("Failed to set PQC groups, continuing in non-strict mode: %s", e)

    return ctx


def connect_pqc_socket(config: SentinelConfig, hostname: str, port: int, timeout: float = 10.0) -> ssl.SSLSocket:
    """
    1) Creates the PQC SSLContext
    2) Connects via TCP to (hostname, port), wraps in SSL
    3) On success, logs the negotiated group + server cert fingerprint to the audit chain
    4) If strict_transport is on but the group isn't PQC, raise PQCTlsError
    5) returns the connected SSLSocket
    """
    ctx = create_pqc_ssl_context(config)
    raw_sock = socket.create_connection((hostname, port), timeout=timeout)
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)

    # handshake done
    negotiated_grp = _get_negotiated_group(tls_sock)

    # get peer cert fingerprint for [34]
    cert_bin = tls_sock.getpeercert(binary_form=True)
    if cert_bin:
        sha256_fp = hashlib.sha256(cert_bin).hexdigest().upper()
    else:
        sha256_fp = "NO_CERT"

    # log to chain => [34], including PQC info
    _log_tls_session_event(
        event="TLS_SESSION_ESTABLISHED",
        negotiated_group=negotiated_grp,
        fingerprint=sha256_fp,
        config=config,
        hostname=hostname,
        port=port
    )

    # if strict => ensure we didn't fallback
    if config.strict_transport:
        # If config says "pqc-only" or "hybrid" => we expected some 'kyber'
        if config.tls_mode != "classical":
            # quick check => if 'kyber' not in group => fail
            if "kyber" not in negotiated_grp.lower():
                tls_sock.close()
                raise PQCTlsError(f"strict_transport enforced, but group={negotiated_grp} not PQC")

    return tls_sock


# -----------------------------------------------------------------------------
# Internal Helpers
# -----------------------------------------------------------------------------

def _set_supported_groups(ctx: ssl.SSLContext, config: SentinelConfig) -> None:
    """
    Uses raw SSL_CTX_set1_groups_list to enforce the named groups from config.tls_mode or config.raw_dict.
    """
    # Choose default groups
    mode = config.tls_mode.lower()
    groups = config.raw_dict.get("allowed_tls_groups", [])

    if not groups:
        if mode == "pqc-only":
            # purely PQC
            groups = ["X25519Kyber768"]  # example
        elif mode == "classical":
            groups = ["X25519", "secp256r1"]
        else:
            # 'hybrid'
            groups = ["X25519Kyber768", "X25519"]

    group_str = ",".join(groups).encode("ascii")

    # get raw SSL_CTX pointer
    # In python 3.11, internal handle might differ. We'll attempt a known approach.
    if not hasattr(ctx, "_sslctx"):  # Python 3.7-3.10
        # fallback attempt
        if not hasattr(ctx, "_context"):  # older or newer?
            raise OSError("Cannot access raw SSL_CTX pointer. Python version mismatch.")
        raw_ctx_addr = ctx._context  # might be an integer handle
    else:
        raw_ctx_addr = ctx._sslctx

    if not isinstance(raw_ctx_addr, int):
        # Some Python builds store the pointer as an int, some as a c_void_p
        # We do best-effort. If it's not integer, we raise
        raise OSError("Raw SSL_CTX pointer is not an integer. Could not set groups.")

    # Now we call the C function
    # int SSL_CTX_set1_groups_list(SSL_CTX *ctx, const char *list);
    import ctypes
    import ctypes.util

    libssl_name = ctypes.util.find_library("ssl")
    if not libssl_name:
        raise OSError("libssl not found on system for setting groups.")

    _cdll_ssl = ctypes.CDLL(libssl_name)
    fn_set_grps = _cdll_ssl.SSL_CTX_set1_groups_list
    fn_set_grps.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    fn_set_grps.restype = ctypes.c_int

    ret = fn_set_grps(ctypes.c_void_p(raw_ctx_addr), ctypes.c_char_p(group_str))
    if ret != 1:
        raise OSError(f"SSL_CTX_set1_groups_list('{group_str.decode()}') failed (ret={ret})")

    logger.info("Set TLS groups to: %s", group_str.decode())


def _get_negotiated_group(tls_sock: ssl.SSLSocket) -> str:
    """
    Retrieves the actual group used in handshake via SSL_get_shared_group(ssl, 0).
    If we can’t load or call the function, fallback to "unknown_group".
    """
    sslobj = getattr(tls_sock, "_sslobj", None)
    if not sslobj:
        return "unknown_group"

    # python's _sslobj might store the pointer in _ssl
    real_ssl = getattr(sslobj, "_ssl", None)
    if real_ssl is None:
        return "unknown_group"

    # real_ssl might be an int pointer
    if not isinstance(real_ssl, int):
        return "unknown_group"

    if not _libssl or not _libcrypto:
        # can't retrieve
        return "unknown_group"

    grp_nid = _libssl.SSL_get_shared_group(_ffi.cast("SSL*", real_ssl), 0)
    if grp_nid <= 0:
        return "unknown_group"

    c_sn = _libcrypto.OBJ_nid2sn(grp_nid)
    if c_sn == _ffi.NULL:
        return "unknown_group"
    return _ffi.string(c_sn).decode("ascii")


def _log_tls_session_event(
    event: str,
    negotiated_group: str,
    fingerprint: str,
    config: SentinelConfig,
    hostname: str,
    port: int
) -> None:
    """
    Logs the TLS session info to the audit chain: group name, cert fingerprint,
    config.enforcement_mode, hostname, etc.
    """
    from aepok_sentinel.core.audit_chain import append_event

    # gather some metadata
    meta = {
        "hostname": hostname,
        "port": port,
        "negotiated_group": negotiated_group,
        "certificate_sha256": fingerprint,
        "enforcement_mode": config.enforcement_mode,  # from config
        "tls_mode": config.tls_mode,
        "strict_transport": config.strict_transport,
    }
    append_event(event, meta)
    logger.info("TLS session established: group=%s, fingerprint=%s", negotiated_group, fingerprint)