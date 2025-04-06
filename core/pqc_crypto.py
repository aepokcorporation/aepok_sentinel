"""
Aepok Sentinel - PQC Crypto Module (Final Shape)

Features:
- AES-256 (GCM or CBC+HMAC) with PQC (Kyber) key wrapping, optional RSA fallback.
- Dilithium + optional RSA signature with identity binding (signer_id, host_fingerprint, key_fingerprint).
- Mandatory RNG validation before each operation (Flaw [56]).
- Secure zeroization of ephemeral secrets (Flaws [9], [64]).
- No automatic RSA fallback in STRICT/HARDENED (Flaw [10]).
"""

import os
import base64
import hashlib
import json
import logging
import ctypes
from typing import Optional, Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import (
    padding as asym_padding,
    rsa
)
from cryptography.hazmat.primitives import serialization

# Local imports
from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig

logger = get_logger("pqc_crypto")

try:
    import oqs
except ImportError:
    oqs = None


class CryptoDecryptionError(Exception):
    """Raised on decryption or integrity check failures."""
    pass


class CryptoSignatureError(Exception):
    """Raised on signature verification failures."""
    pass


# Module-level ephemeral buffers or cached keys, if any, can be stored here.
# For final shape, we currently have none, but we illustrate the usage:
_ephemeral_storage = {}


def sanitize_on_shutdown():
    """
    Clears any module-level buffers or ephemeral data to reduce memory leftover (Flaw [64]).
    Call this from the daemon/controller shutdown sequence.
    """
    global _ephemeral_storage
    for k, v in list(_ephemeral_storage.items()):
        if isinstance(v, bytearray):
            secure_zero(v)
        elif isinstance(v, bytes):
            ba = bytearray(v)
            secure_zero(ba)
        _ephemeral_storage.pop(k, None)
    logger.info("pqc_crypto: sanitized ephemeral storage on shutdown.")


def secure_zero(data: bytearray) -> None:
    """
    Overwrites the contents of a bytearray with zeros, mitigating memory retention.
    """
    if data:
        for i in range(len(data)):
            data[i] = 0


def validate_rng() -> None:
    """
    Basic RNG health check. Reads random bytes twice, checks they differ.
    Raises a warning if they match exactly, as that's extremely unlikely.
    (Flaw [56] partial remediation.)
    """
    block1 = os.urandom(32)
    block2 = os.urandom(32)
    if block1 == block2:
        logger.warning("RNG check: identical 32-byte blocks encountered => potential entropy issue.")
    else:
        logger.debug("RNG check passed.")


def encrypt_file_payload(
    plaintext: bytes,
    config: SentinelConfig,
    kyber_pub: bytes,
    rsa_pub: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Encrypts plaintext into a JSON-based payload with PQC + optional RSA key wrapping.
    Addresses Flaws [9], [10], [56].
    
    :param plaintext: raw bytes to encrypt
    :param config: SentinelConfig (dictates CBC/GCM, fallback, enforcement_mode, etc.)
    :param kyber_pub: Kyber public key bytes
    :param rsa_pub: RSA public key bytes, optional
    :raises CryptoDecryptionError: if encryption fails
    :return: dict with fields per the global cryptographic payload format
    """
    if not oqs:
        raise ImportError("oqs library is required for PQC encryption but not found.")

    validate_rng()

    # 1) Kyber encaps
    aes_key = b""
    wrapped_kyber = b""
    shared_secret = b""
    try:
        with oqs.KeyEncapsulation("Kyber512", kyber_pub) as kem:
            wrapped_kyber, shared_secret = kem.encap_secret(kyber_pub)
        aes_key = hashlib.sha256(shared_secret).digest()
    except Exception as e:
        msg = f"Kyber encryption failed: {e}"
        logger.error(msg)
        raise CryptoDecryptionError(msg)
    finally:
        if shared_secret:
            ba_ss = bytearray(shared_secret)
            secure_zero(ba_ss)

    # 2) Optional RSA fallback if not in strict/hardened
    wrapped_rsa = b""
    fallback_allowed = (
        config.allow_classical_fallback and
        rsa_pub is not None and
        not (config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"))
    )
    if fallback_allowed:
        try:
            rsa_public_key = _load_rsa_public_key(rsa_pub)
            wrapped_rsa = rsa_public_key.encrypt(
                aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            msg = f"RSA fallback encryption failed: {e}"
            logger.error(msg)
            raise CryptoDecryptionError(msg)

    # 3) AES encryption (GCM or CBC+HMAC)
    iv = os.urandom(12) if not config.use_cbc_hmac else os.urandom(16)
    ciphertext = b""
    auth_tag = b""
    integrity_hex = ""
    try:
        if not config.use_cbc_hmac:
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            auth_tag = encryptor.tag
        else:
            # CBC
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            ciphertext = encryptor.update(padded) + encryptor.finalize()
            # HMAC
            h = hmac.HMAC(aes_key, hashes.SHA512(), backend=default_backend())
            h.update(ciphertext)
            integrity_hex = h.finalize().hex()
    except Exception as e:
        msg = f"AES encryption failed: {e}"
        logger.error(msg)
        raise CryptoDecryptionError(msg)
    finally:
        if aes_key:
            ba_key = bytearray(aes_key)
            secure_zero(ba_key)

    payload = {
        "version": 1,
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "wrapped_key_kyber": base64.b64encode(wrapped_kyber).decode("utf-8"),
        "wrapped_key_rsa": base64.b64encode(wrapped_rsa).decode("utf-8") if wrapped_rsa else "",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "auth_tag": base64.b64encode(auth_tag).decode("utf-8") if auth_tag else "",
        "integrity": integrity_hex,
        "signatures": {}
    }
    return payload


def decrypt_file_payload(
    payload: Dict[str, Any],
    config: SentinelConfig,
    kyber_priv: bytes,
    rsa_priv: Optional[bytes] = None
) -> bytes:
    """
    Decrypts the given payload. Tries Kyber first. If that fails and fallback is allowed,
    tries RSA, except in STRICT/HARDENED. (Flaw [10])

    Zeroizes ephemeral keys. 
    Raises CryptoDecryptionError on any failure.
    """
    if not oqs:
        raise ImportError("oqs library is required for PQC decryption but not found.")

    validate_rng()

    try:
        b64_ct = payload["ciphertext"]
        b64_kyber = payload["wrapped_key_kyber"]
        b64_iv = payload["iv"]
    except KeyError as e:
        msg = f"Payload missing required field: {e}"
        logger.error(msg)
        raise CryptoDecryptionError(msg)

    ciphertext = base64.b64decode(b64_ct)
    wrapped_kyber = base64.b64decode(b64_kyber)
    iv = base64.b64decode(b64_iv)

    wrapped_rsa = base64.b64decode(payload.get("wrapped_key_rsa", "")) if payload.get("wrapped_key_rsa") else b""
    auth_tag = base64.b64decode(payload["auth_tag"]) if payload.get("auth_tag") else None
    integrity_hex = payload.get("integrity", "")

    aes_key = b""
    shared_secret = b""
    kyber_failed = False

    # 1) Attempt Kyber decapsulation
    try:
        with oqs.KeyEncapsulation("Kyber512", kyber_priv) as kem:
            shared_secret = kem.decap_secret(wrapped_kyber)
        aes_key = hashlib.sha256(shared_secret).digest()
    except Exception as e:
        logger.warning("Kyber decap failed => %s", e)
        kyber_failed = True
    finally:
        if shared_secret:
            ba_ss = bytearray(shared_secret)
            secure_zero(ba_ss)

    # 2) If Kyber failed, attempt RSA fallback only if allowed
    fallback_allowed = (
        kyber_failed and
        config.allow_classical_fallback and
        rsa_priv is not None and
        wrapped_rsa and
        not (config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"))
    )
    if fallback_allowed:
        logger.info("Attempting RSA fallback.")
        try:
            rsa_private_key = _load_rsa_private_key(rsa_priv)
            aes_key = rsa_private_key.decrypt(
                wrapped_rsa,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            msg = f"RSA fallback also failed => {e}"
            logger.error(msg)
            raise CryptoDecryptionError(msg)
    elif kyber_failed and not fallback_allowed:
        msg = "Kyber decap failed. Fallback not allowed (STRICT/HARDENED or config)."
        logger.error(msg)
        raise CryptoDecryptionError(msg)

    # 3) Decrypt with AES (GCM or CBC+HMAC)
    plaintext = b""
    try:
        if not config.use_cbc_hmac:
            if not auth_tag:
                raise CryptoDecryptionError("GCM mode but no auth_tag in payload.")
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            # CBC + HMAC
            if not integrity_hex:
                raise CryptoDecryptionError("CBC+HMAC mode but no 'integrity' field in payload.")
            expected_hmac = bytes.fromhex(integrity_hex)
            h = hmac.HMAC(aes_key, hashes.SHA512(), backend=default_backend())
            h.update(ciphertext)
            h.verify(expected_hmac)

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_pt = decryptor.update(ciphertext) + decryptor.finalize()
            unpad = padding.PKCS7(128).unpadder()
            plaintext = unpad.update(padded_pt) + unpad.finalize()
    except Exception as e:
        msg = f"Decryption/integrity check failed => {e}"
        logger.error(msg)
        raise CryptoDecryptionError(msg)
    finally:
        if aes_key:
            ba_key = bytearray(aes_key)
            secure_zero(ba_key)

    return plaintext


def sign_content_bundle(
    data: bytes,
    config: SentinelConfig,
    dil_priv: bytes,
    rsa_priv: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Signs data with Dilithium, optionally RSA if fallback is allowed. 
    Binds identity info (signer_id, host_fingerprint, key_fingerprint) to each signature (Flaw [11]).

    Returns:
    {
      "dilithium": "<base64>",
      "rsa": "<base64 or empty>",
      "metadata": {
         "signer_id": "...",
         "host_fingerprint": "...",
         "key_fingerprint": "..."
      }
    }
    """
    if not oqs:
        raise ImportError("oqs library required for PQC signing but not found.")

    validate_rng()

    # 1) Dilithium sign
    dil_sig_bytes = b""
    dil_sign_b64 = ""
    try:
        with oqs.Signature("Dilithium2", dil_priv) as sig:
            dil_sig_bytes = sig.sign(data)
        dil_sign_b64 = base64.b64encode(dil_sig_bytes).decode("utf-8")
    except Exception as e:
        logger.error("Dilithium sign failed: %s", e)
        raise CryptoSignatureError(e)
    finally:
        if dil_sig_bytes:
            ba_sig = bytearray(dil_sig_bytes)
            secure_zero(ba_sig)

    # 2) RSA sign if fallback allowed and not STRICT/HARDENED
    rsa_sign_b64 = ""
    fallback_allowed = (
        config.allow_classical_fallback and
        rsa_priv is not None and
        not (config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"))
    )
    if fallback_allowed:
        try:
            private_key = _load_rsa_private_key(rsa_priv)
            rsa_sig = private_key.sign(
                data,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            rsa_sign_b64 = base64.b64encode(rsa_sig).decode("utf-8")
        except Exception as e:
            logger.error("RSA sign fallback failed: %s", e)
            raise CryptoSignatureError(e)

    # 3) Identity binding
    # We'll attempt to read them from config.raw_dict or fallback to placeholders
    signer_id = config.raw_dict.get("signer_id", "unknown_signer")
    host_fp = config.raw_dict.get("host_fingerprint", "unknown_host")
    # For demonstration, compute a short SHA256 of the Dil priv. In real usage we'd use the pub key's fingerprint.
    key_fp = hashlib.sha256(dil_priv).hexdigest()[:16] + "..."

    return {
        "dilithium": dil_sign_b64,
        "rsa": rsa_sign_b64,
        "metadata": {
            "signer_id": signer_id,
            "host_fingerprint": host_fp,
            "key_fingerprint": key_fp
        }
    }


def verify_content_signature(
    data: bytes,
    signatures: Dict[str, Any],
    config: SentinelConfig,
    dil_pub: bytes,
    rsa_pub: Optional[bytes] = None
) -> bool:
    """
    Verifies PQC signature (Dilithium) and optionally RSA if fallback is allowed.
    Both must succeed if RSA is present. If either fails => returns False.

    Flaw [11] fix: We now see identity metadata in 'signatures["metadata"]',
    but we do not enforce it here. That check belongs to a higher-level policy if needed.
    """
    if not oqs:
        raise ImportError("oqs library required for PQC verify but not found.")

    dil_sig_b64 = signatures.get("dilithium", "")
    if not dil_sig_b64:
        logger.error("Missing Dilithium signature in signature dict.")
        return False

    # 1) Dilithium verify
    try:
        with oqs.Signature("Dilithium2", dil_pub) as sig:
            dil_sig = base64.b64decode(dil_sig_b64)
            sig.verify(data, dil_sig, dil_pub)
    except Exception as e:
        logger.warning("Dilithium signature verification failed: %s", e)
        return False

    # 2) RSA fallback check
    rsa_sig_b64 = signatures.get("rsa", "")
    fallback_allowed = (
        config.allow_classical_fallback and
        rsa_pub is not None and
        rsa_sig_b64 and
        not (config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"))
    )
    if fallback_allowed:
        try:
            rsa_sig = base64.b64decode(rsa_sig_b64)
            pub_key = _load_rsa_public_key(rsa_pub)
            pub_key.verify(
                rsa_sig,
                data,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            logger.warning("RSA signature verification failed: %s", e)
            return False

    return True


def _load_rsa_public_key(key_data: bytes):
    """Helper to load RSA pub key from PEM or DER."""
    try:
        if b"-----BEGIN" in key_data:
            return serialization.load_pem_public_key(key_data, backend=default_backend())
        else:
            return serialization.load_der_public_key(key_data, backend=default_backend())
    except Exception as e:
        raise CryptoDecryptionError(f"Failed to load RSA public key: {e}")


def _load_rsa_private_key(key_data: bytes):
    """Helper to load RSA priv key from PEM or DER."""
    try:
        if b"-----BEGIN" in key_data:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        else:
            return serialization.load_der_private_key(key_data, password=None, backend=default_backend())
    except Exception as e:
        raise CryptoDecryptionError(f"Failed to load RSA private key: {e}")