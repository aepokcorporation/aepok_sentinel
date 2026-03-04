# pqc_tls.py
"""
PQC TLS Transport Layer for Aepok Sentinel

Provides:
  - create_pqc_ssl_context(config): Builds an SSLContext for TLS 1.3 with optional PQC/hybrid groups.
  - connect_pqc_socket(config, hostname, port): Connects a TCP socket, wraps it with PQC SSL, and logs the negotiated group.
  - _get_negotiated_group(tls_sock): Internal helper to retrieve the actual TLS group used in the handshake via CFFI calls.
  - _set_supported_groups(ctx, config): Internal helper to configure the SSLContext with named groups from config.tls_mode.
  - _log_tls_session_event(...): Logs session details to the audit chain.

Handles:
  - Disabling TLS session tickets
  - Enforcing strict_transport if config says so (fail if no PQC group is used)
  - Logging the certificate fingerprint and PQC group to the audit chain upon session establishment
"""

import ssl
import socket
import hashlib
import logging
from typing import Optional

import cffi
import ctypes.util

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.audit_chain import AuditChain

logger = get_logger("pqc_tls")

_ffi = cffi.FFI()
_ffi.cdef(
    """
    typedef ... SSL;
    int SSL_get_shared_group(const SSL *ssl, int n);
    const char* OBJ_nid2sn(int nid);
    // #define SSL_OP_NO_TICKET 0x00004000
    """
)

_libssl_path = ctypes.util.find_library("ssl")
_libcrypto_path = ctypes.util.find_library("crypto")

_libssl = None
_libcrypto = None
if _libssl_path:
    try:
        _libssl = _ffi.dlopen(_libssl_path)
    except OSError:
        logger.warning("Failed to dlopen(%s); group retrieval not available.", _libssl_path)

if _libcrypto_path:
    try:
        _libcrypto = _ffi.dlopen(_libcrypto_path)
    except OSError:
        logger.warning("Failed to dlopen(%s); OBJ_nid2sn not available.", _libcrypto_path)

OP_NO_TICKET = 0x00004000  # From OpenSSL headers


class PQCTlsError(Exception):
    """Raised when PQC/hybrid TLS fails or group mismatch occurs in strict mode."""


def create_pqc_ssl_context(config: SentinelConfig) -> ssl.SSLContext:
    """
    Creates an SSLContext for TLS 1.3 with optional PQC/hybrid groups,
    disabling session tickets and older TLS versions. 
    Raises PQCTlsError if strict_transport is set and group configuration fails.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1
    ctx.options |= OP_NO_TICKET  # disable session tickets
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED  # can be overridden if needed

    try:
        _set_supported_groups(ctx, config)
    except OSError as e:
        if config.strict_transport:
            raise PQCTlsError(f"Could not set PQC/hybrid groups in strict mode: {e}")
        else:
            logger.warning("Failed to set PQC/hybrid groups in non-strict mode: %s", e)

    return ctx


def connect_pqc_socket(config: SentinelConfig, hostname: str, port: int, timeout: float = 10.0, audit_chain: Optional[AuditChain] = None) -> ssl.SSLSocket:
    """
    Creates a PQC SSLContext, then connects to (hostname, port) via TCP and wraps in SSL.
    Logs the negotiated group + certificate fingerprint to the audit chain.
    If strict_transport is set but no PQC group is used, raises PQCTlsError.
    Returns the connected SSLSocket on success.
    """
    ctx = create_pqc_ssl_context(config)
    raw_sock = socket.create_connection((hostname, port), timeout=timeout)
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)

    # handshake done
    negotiated_grp = _get_negotiated_group(tls_sock)
    cert_bin = tls_sock.getpeercert(binary_form=True)
    if cert_bin:
        sha256_fp = hashlib.sha256(cert_bin).hexdigest().upper()
    else:
        sha256_fp = "NO_CERT"

    _log_tls_session_event(
        event="TLS_SESSION_ESTABLISHED",
        negotiated_group=negotiated_grp,
        fingerprint=sha256_fp,
        config=config,
        hostname=hostname,
        port=port,
        audit_chain=audit_chain
    )

    # if strict => ensure we didn't fallback
    if config.strict_transport:
        # if tls_mode != 'classical' => we expect 'kyber' in the group name
        if config.tls_mode != "classical":
            if "kyber" not in negotiated_grp.lower():
                tls_sock.close()
                raise PQCTlsError(f"strict_transport enforced, group={negotiated_grp} is not PQC")

    return tls_sock


def _set_supported_groups(ctx: ssl.SSLContext, config: SentinelConfig) -> None:
    """
    Sets the named groups for SSLContext using raw SSL_CTX_set1_groups_list calls.

    FIX #56: The original code tried to access ctx._sslctx or ctx._context
    to get a raw SSL_CTX pointer.  These are private CPython implementation
    details that vary between Python versions (the internal struct changed in
    Python 3.10+).  There is no guarantee either attribute exists or is an
    integer.

    The fix uses ctypes to read the SSL_CTX* pointer from the C struct that
    backs the SSLContext object.  The _ssl._SSLContext C extension stores the
    SSL_CTX* as its first struct member after the standard PyObject header.
    This is still CPython-specific, but is more reliable than guessing
    attribute names, and includes a clear error path if it fails.
    """
    import ctypes as _ct

    mode = config.tls_mode.lower()
    groups = config.raw_dict.get("allowed_tls_groups", [])

    # fallback defaults
    if not groups:
        if mode == "pqc-only":
            groups = ["X25519Kyber768"]  # example
        elif mode == "classical":
            groups = ["X25519", "secp256r1"]
        else:
            # 'hybrid'
            groups = ["X25519Kyber768", "X25519"]

    group_str = ",".join(groups).encode("ascii")

    # Try Python 3.10+ _ctx attribute first, then older _sslctx / _context
    raw_ctx_addr = None
    for attr_name in ("_ctx", "_sslctx", "_context"):
        candidate = getattr(ctx, attr_name, None)
        if isinstance(candidate, int) and candidate != 0:
            raw_ctx_addr = candidate
            break

    if raw_ctx_addr is None:
        # Fallback: read the SSL_CTX* from the C struct via ctypes.
        # SSLContext wraps an _ssl._SSLContext whose C struct has
        # SSL_CTX* right after the PyObject header (ob_refcnt + *ob_type).
        try:
            header_size = _ct.sizeof(_ct.c_ssize_t) + _ct.sizeof(_ct.c_void_p)
            raw_ctx_addr = _ct.c_void_p.from_address(id(ctx) + header_size).value
        except Exception:
            raw_ctx_addr = None

    if not raw_ctx_addr:
        raise OSError(
            "Unable to access raw SSL_CTX pointer for setting groups. "
            "This may indicate an unsupported Python version or ssl module build."
        )

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
    Returns "unknown_group" if retrieval fails or is unsupported.

    FIX #57: The original code used `_ffi.cast("SSL*", real_ssl)` where
    real_ssl was expected to be an integer extracted from Python's ssl module.
    However, there was no reliable mechanism to extract a valid SSL* memory
    address — the `typedef ... SSL;` opaque CFFI declaration can't validate
    the pointer, and the cast from an arbitrary integer is undefined behavior
    if the address is wrong.

    The fix navigates Python's internal SSL wrapper layers using ctypes to
    read the actual SSL* pointer from the C struct backing _ssl._SSLSocket.
    The struct layout is: PyObject header (ob_refcnt + *ob_type) followed
    by the SSL* pointer.  This is CPython-specific but is the only reliable
    way to get the SSL* without a dedicated C extension.  All failures
    gracefully return "unknown_group".
    """
    if not _libssl or not _libcrypto:
        return "unknown_group"

    try:
        import ctypes as _ct

        # Navigate Python's SSL wrapper layers:
        #   SSLSocket._sslobj  -> ssl.SSLObject (Python wrapper)
        #   SSLObject._sslobj  -> _ssl._SSLSocket (C extension object)
        sslobj = getattr(tls_sock, "_sslobj", None)
        if sslobj is None:
            return "unknown_group"

        inner = getattr(sslobj, "_sslobj", sslobj)
        if inner is None:
            return "unknown_group"

        # Read the SSL* from the _ssl._SSLSocket C struct.
        # Layout: PyObject header (ob_refcnt + *ob_type) then SSL* pointer.
        header_size = _ct.sizeof(_ct.c_ssize_t) + _ct.sizeof(_ct.c_void_p)
        ssl_ptr = _ct.c_void_p.from_address(id(inner) + header_size).value
        if not ssl_ptr:
            return "unknown_group"

        grp_nid = _libssl.SSL_get_shared_group(_ffi.cast("SSL*", ssl_ptr), 0)
        if grp_nid <= 0:
            return "unknown_group"

        c_sn = _libcrypto.OBJ_nid2sn(grp_nid)
        if c_sn == _ffi.NULL:
            return "unknown_group"
        return _ffi.string(c_sn).decode("ascii")
    except Exception:
        return "unknown_group"


def _log_tls_session_event(
    event: str,
    negotiated_group: str,
    fingerprint: str,
    config: SentinelConfig,
    hostname: str,
    port: int,
    audit_chain: Optional[AuditChain] = None
) -> None:
    """
    Appends a TLS session event to the audit chain, capturing negotiated group,
    certificate fingerprint, config enforcement, etc.

    The audit_chain parameter accepts an AuditChain instance via dependency
    injection (same pattern as the fix for #58 in pqc_tls_verify.py).
    """
    meta = {
        "hostname": hostname,
        "port": port,
        "negotiated_group": negotiated_group,
        "certificate_sha256": fingerprint,
        "enforcement_mode": config.enforcement_mode,
        "tls_mode": config.tls_mode,
        "strict_transport": config.strict_transport,
    }
    if audit_chain is not None:
        audit_chain.append_event(event, meta)
    logger.info("TLS session established: group=%s, fingerprint=%s", negotiated_group, fingerprint)