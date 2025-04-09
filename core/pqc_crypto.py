# pqc_crypto.py
"""
Aepok Sentinel - PQC Crypto Module

Provides:
- AES-256 encryption (GCM or CBC+HMAC) with PQC (Kyber) key wrapping, and optional RSA fallback.
- Dilithium plus optional RSA signature, including identity metadata.
- Basic RNG validation before each operation.
- Secure zeroization of ephemeral secrets.

No automatic RSA fallback is allowed when in STRICT/HARDENED modes, per config settings.
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


# Module-level ephemeral storage, if needed.
_ephemeral_storage = {}


def sanitize_on_shutdown():
    """
    Clears any module-level buffers or ephemeral data to reduce memory retention.
    Call this at daemon/controller shutdown.
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
    Overwrites the contents of a bytearray with zeros to mitigate memory retention.
    """
    if data:
        for i in range(len(data)):
            data[i] = 0


def validate_rng() -> None:
    """
    Basic RNG health check. Reads random bytes twice and verifies they differ.
    Logs a warning if identical blocks are encountered.
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
    Encrypts plaintext into a JSON-based payload using Kyber for key wrapping
    and optional RSA fallback if permitted. Then uses AES (GCM or CBC+HMAC)
    to encrypt the data.

    :param plaintext: Raw data to encrypt
    :param config: SentinelConfig controlling encryption mode, fallback, etc.
    :param kyber_pub: Kyber public key bytes
    :param rsa_pub: RSA public key bytes, optional
    :raises CryptoDecryptionError: if encryption fails
    :return: dict with encryption fields suitable for JSON serialization
    """
    if not oqs:
        raise ImportError("oqs library is required for PQC encryption but not found.")

    validate_rng()

    # 1) Kyber encaps to obtain shared_secret => AES key
    aes_key = b""
    wrapped_kyber = b""
    shared_secret = b""
    try:
        with oqs.KeyEncapsulation("Kyber512", kyber_pub) as kem:
            wrapped_kyber, shared_secret = kem.encap_secret(kyber_pub)
        aes_key = hashlib.sha256(shared_secret).digest()
    except Exception as e:
        logger.error("Kyber encryption failed: %s", e)
        raise CryptoDecryptionError(f"Kyber encryption failed: {e}")
    finally:
        if shared_secret:
            secure_zero(bytearray(shared_secret))

    # 2) Optional RSA fallback if not in strict/hardened
    wrapped_rsa = b""
    fallback_allowed = False
    if config.allow_classical_fallback and rsa_pub:
        if config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"):
            logger.warning("Fallback explicitly disallowed: strict_transport or enforcement mode enforced.")
        else:
            fallback_allowed = True
            
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
            logger.error("RSA fallback encryption failed: %s", e)
            raise CryptoDecryptionError(f"RSA fallback encryption failed: {e}")

    # 3) AES encryption (GCM or CBC+HMAC)
    iv = os.urandom(12) if not config.use_cbc_hmac else os.urandom(16)
    ciphertext = b""
    auth_tag = b""
    integrity_hex = ""
    try:
        if not config.use_cbc_hmac:
            # GCM
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            auth_tag = encryptor.tag
        else:
            # CBC + HMAC
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
        logger.error("AES encryption failed: %s", e)
        raise CryptoDecryptionError(f"AES encryption failed: {e}")
    finally:
        if aes_key:
            secure_zero(bytearray(aes_key))

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
    Decrypts the given payload. Attempts Kyber decapsulation first. If that fails
    and fallback is permitted, tries RSA. Then uses AES (GCM or CBC+HMAC) to recover plaintext.

    :raises CryptoDecryptionError: on any failure
    :return: Decrypted plaintext bytes
    """
    if not oqs:
        raise ImportError("oqs library is required for PQC decryption but not found.")

    validate_rng()

    try:
        b64_ct = payload["ciphertext"]
        b64_kyber = payload["wrapped_key_kyber"]
        b64_iv = payload["iv"]
    except KeyError as e:
        logger.error("Payload missing required field: %s", e)
        raise CryptoDecryptionError(f"Payload missing required field: {e}")

    ciphertext = base64.b64decode(b64_ct)
    wrapped_kyber = base64.b64decode(b64_kyber)
    iv = base64.b64decode(b64_iv)

    wrapped_rsa = base64.b64decode(payload.get("wrapped_key_rsa", "")) if payload.get("wrapped_key_rsa") else b""
    auth_tag = None
    try:
        if payload.get("auth_tag"):
            auth_tag = base64.b64decode(payload["auth_tag"])
    except Exception as e:
        logger.warning("GCM tag parse error: %s", e)
        raise CryptoDecryptionError(f"GCM tag parse error: {e}")

    integrity_hex = payload.get("integrity", "")

    aes_key = b""
    shared_secret = b""
    kyber_failed = False

    # 1) Kyber decapsulation
    try:
        with oqs.KeyEncapsulation("Kyber512", kyber_priv) as kem:
            shared_secret = kem.decap_secret(wrapped_kyber)
        aes_key = hashlib.sha256(shared_secret).digest()
    except Exception as e:
        logger.warning("Kyber decapsulation failed: %s", e)
        kyber_failed = True
    finally:
        if shared_secret:
            secure_zero(bytearray(shared_secret))

    # 2) RSA fallback if allowed
    fallback_allowed = False
    if kyber_failed and config.allow_classical_fallback and rsa_priv and wrapped_rsa:
        if config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"):
            logger.warning("RSA fallback blocked due to strict enforcement.")
        else:
            fallback_allowed = True
            
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
            # Emit SIGNATURE_RSA_USED as a fallback marker
            try:
                from aepok_sentinel.core.audit_chain import append_event
                append_event("SIGNATURE_RSA_USED", {
                    "reason": "Kyber decapsulation failed, RSA fallback accepted",
                    "enforcement_mode": config.enforcement_mode,
                    "strict_transport": config.strict_transport,
                    "tls_mode": config.tls_mode,
                })
            except Exception:
                logger.warning("Failed to emit SIGNATURE_RSA_USED audit event.")
        except Exception as e:
            logger.error("RSA fallback also failed => %s", e)
            raise CryptoDecryptionError(f"RSA fallback also failed => {e}")
    elif kyber_failed and not fallback_allowed:
        logger.error("Kyber failed. Fallback not allowed by config or mode.")
        raise CryptoDecryptionError("Kyber decap failed with no fallback allowed.")

    # 3) AES decrypt (GCM or CBC+HMAC)
    plaintext = b""
    try:
        if not config.use_cbc_hmac:
            if not auth_tag:
                raise CryptoDecryptionError("GCM mode requires 'auth_tag'.")
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            if not integrity_hex:
                raise CryptoDecryptionError("CBC+HMAC mode requires 'integrity' field.")
            # Validate HMAC
            try:
                expected_hmac = bytes.fromhex(integrity_hex)
            except Exception as e:
                logger.warning("Malformed integrity hex: %s", e)
                raise CryptoDecryptionError(f"Malformed integrity hex: {e}")

            h = hmac.HMAC(aes_key, hashes.SHA512(), backend=default_backend())
            h.update(ciphertext)
            h.verify(expected_hmac)

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_pt = decryptor.update(ciphertext) + decryptor.finalize()
            unpad = padding.PKCS7(128).unpadder()
            plaintext = unpad.update(padded_pt) + unpad.finalize()
    except Exception as e:
        logger.error("Decryption or integrity check failed => %s", e)
        raise CryptoDecryptionError(f"Decryption or integrity check failed => {e}")
    finally:
        if aes_key:
            secure_zero(bytearray(aes_key))

    return plaintext


def sign_content_bundle(
    data: bytes,
    config: SentinelConfig,
    dil_priv: bytes,
    rsa_priv: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Signs data with Dilithium, optionally RSA if fallback is allowed, embedding minimal identity metadata.
    Returns a dict structured as:
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

    # Dilithium sign
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
            secure_zero(bytearray(dil_sig_bytes))

    # RSA sign fallback if allowed
    rsa_sign_b64 = ""
    fallback_allowed = False
    if config.allow_classical_fallback and rsa_pub:
        if config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"):
            logger.warning("Fallback explicitly disallowed: strict_transport or enforcement mode enforced.")
        else:
            fallback_allowed = True
            
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

    # Identity binding
    signer_id = config.raw_dict.get("signer_id", "unknown_signer")
    host_fp = config.raw_dict.get("host_fingerprint", "unknown_host")
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
    Verifies a Dilithium signature and, if present and allowed, RSA fallback. Both must pass if RSA is included.

    :return: True if verification succeeds, otherwise False
    """
    if not oqs:
        raise ImportError("oqs library required for PQC verify but not found.")

    dil_sig_b64 = signatures.get("dilithium", "")
    if not dil_sig_b64:
        logger.error("Missing Dilithium signature field.")
        return False

    # Dilithium verify
    try:
        with oqs.Signature("Dilithium2", dil_pub) as sig:
            dil_sig = base64.b64decode(dil_sig_b64)
            sig.verify(data, dil_sig, dil_pub)
    except Exception as e:
        logger.warning("Dilithium signature verification failed: %s", e)
        return False

    # RSA fallback if included and allowed
    rsa_sig_b64 = signatures.get("rsa", "")
    fallback_allowed = False
    if config.allow_classical_fallback and rsa_pub:
        if config.strict_transport or config.enforcement_mode in ("STRICT", "HARDENED"):
            logger.warning("Fallback explicitly disallowed: strict_transport or enforcement mode enforced.")
        else:
            fallback_allowed = True
            
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
            # Log fallback signature usage
            try:
                from aepok_sentinel.core import audit_chain
                audit_chain.append_event("SIGNATURE_RSA_USED", {
                    "context": "verify_content_signature",
                    "enforcement_mode": config.enforcement_mode,
                    "host_fingerprint": config.raw_dict.get("host_fingerprint", "unknown")
                })
            except Exception:
                logger.warning("Failed to emit SIGNATURE_RSA_USED event in verify_content_signature.")
        except Exception as e:
            logger.warning("RSA signature verification failed: %s", e)
            return False

    return True


def _load_rsa_public_key(key_data: bytes):
    """
    Loads an RSA public key from PEM or DER data.
    Raises CryptoDecryptionError if load fails.
    """
    try:
        if b"-----BEGIN" in key_data:
            return serialization.load_pem_public_key(key_data, backend=default_backend())
        else:
            return serialization.load_der_public_key(key_data, backend=default_backend())
    except Exception as e:
        raise CryptoDecryptionError(f"Failed to load RSA public key: {e}")


def _load_rsa_private_key(key_data: bytes):
    """
    Loads an RSA private key from PEM or DER data.
    Raises CryptoDecryptionError if load fails.
    """
    try:
        if b"-----BEGIN" in key_data:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        else:
            return serialization.load_der_private_key(key_data, password=None, backend=default_backend())
    except Exception as e:
        raise CryptoDecryptionError(f"Failed to load RSA private key: {e}")