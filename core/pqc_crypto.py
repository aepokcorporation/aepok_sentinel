"""
Step 3: PQC Crypto Module

Implements:
1. AES-256-GCM (default) or AES-256-CBC + HMAC-SHA512 (if .sentinelrc["use_cbc_hmac"] = true).
2. Hybrid PQC wrap (Kyber) plus classical RSA fallback if .sentinelrc["allow_classical_fallback"] = true.
3. Dual-signing with Dilithium + RSA if fallback is allowed; otherwise PQC-only signature.

References:
- logging_setup.py (for logging)
- config.py (for reading config fields like use_cbc_hmac, allow_classical_fallback)
No forward references to future steps.

All cryptographic payloads must comply with Section VI of the instruction doc.
"""

import os
import base64
import hashlib
import json
import logging
from typing import Optional, Dict, Any, Tuple

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig

logger = get_logger("pqc_crypto")

# Attempt to import OQS (liboqs) for PQC KEM/sign.
try:
    import oqs
except ImportError:
    oqs = None

# We'll use cryptography for AES and RSA
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


class CryptoDecryptionError(Exception):
    """Raised on decryption or integrity check failures."""
    pass


class CryptoSignatureError(Exception):
    """Raised on signature verification failures."""
    pass


def encrypt_file_payload(
    plaintext: bytes,
    config: SentinelConfig,
    kyber_pub: bytes,
    rsa_pub: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Encrypts the plaintext into a JSON-based payload:
      {
        "version": 1,
        "ciphertext": "<base64>",
        "wrapped_key_kyber": "<base64>",
        "wrapped_key_rsa": "<base64 or empty if fallback disallowed>",
        "iv": "<base64>",
        "auth_tag": "<base64>" (if GCM),
        "integrity": "<hex>" (if CBC+HMAC),
        "signatures": {
          "dilithium": "...",
          "rsa": "..." or ""
        }
      }

    :param plaintext: raw bytes to encrypt
    :param config: the SentinelConfig, used to decide AES mode, classical fallback, etc.
    :param kyber_pub: public key for Kyber (bytes). If None, we raise ImportError if OQS is missing
    :param rsa_pub: public key for RSA fallback, can be None if fallback is off
    :return: a dict with the structure above
    :raises CryptoDecryptionError: if the system lacks OQS when needed
    """
    if not oqs:
        raise ImportError("The 'oqs' library is required for PQC encryption but not found.")

    # 1) Generate the AES key from Kyber
    # We'll treat kyber_pub as raw bytes. The user is responsible for hex -> bytes if needed externally.
    try:
        with oqs.KeyEncapsulation("Kyber512", kyber_pub) as kem:
            wrapped_kyber, shared_secret = kem.encap_secret(kyber_pub)
    except Exception as e:
        msg = f"Kyber encryption failed: {e}"
        logger.error(msg)
        raise CryptoDecryptionError(msg)

    # Derive AES key (256 bits) from shared_secret via SHA256
    aes_key = hashlib.sha256(shared_secret).digest()

    # 2) If allow_classical_fallback => also wrap the AES key with RSA
    wrapped_rsa = b""
    if config.allow_classical_fallback and rsa_pub:
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

    # 3) AES encryption (GCM by default, or CBC+HMAC if config.use_cbc_hmac)
    if not config.use_cbc_hmac:
        # AES-GCM
        iv = os.urandom(12)  # recommended IV size for GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        auth_tag = encryptor.tag
        b64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
        b64_iv = base64.b64encode(iv).decode("utf-8")
        b64_auth_tag = base64.b64encode(auth_tag).decode("utf-8")
        integrity_hex = ""  # unused in GCM

    else:
        # AES-CBC + HMAC-SHA512
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        b64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
        b64_iv = base64.b64encode(iv).decode("utf-8")

        # compute HMAC-SHA512 over ciphertext
        h = hmac.HMAC(aes_key, hashes.SHA512(), backend=default_backend())
        h.update(ciphertext)
        integrity_hex = h.finalize().hex()

        b64_auth_tag = ""  # unused in CBC mode

    b64_kyber = base64.b64encode(wrapped_kyber).decode("utf-8")
    b64_rsa = base64.b64encode(wrapped_rsa).decode("utf-8") if wrapped_rsa else ""

    # 4) Build payload (version=1)
    payload = {
        "version": 1,
        "ciphertext": b64_ciphertext,
        "wrapped_key_kyber": b64_kyber,
        "wrapped_key_rsa": b64_rsa,
        "iv": b64_iv,
        "auth_tag": b64_auth_tag,
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
    Decrypts the payload (a dict) produced by encrypt_file_payload().

    Steps:
      1. Base64 decode the fields
      2. Attempt Kyber decapsulation to get the AES key
      3. If that fails, or config.allow_classical_fallback is True, try RSA fallback
      4. Use either GCM or CBC+HMAC to decrypt
      5. If CBC, verify HMAC; if GCM, verify tag

    :param payload: The JSON structure from encrypt_file_payload
    :param config: sentinel config
    :param kyber_priv: private key for Kyber
    :param rsa_priv: private key for RSA fallback
    :return: the original plaintext
    :raises CryptoDecryptionError: if integrity fails or all decapsulation fails
    """
    if not oqs:
        raise ImportError("The 'oqs' library is required for PQC decryption but not found.")

    try:
        b64_ciphertext = payload["ciphertext"]
        b64_kyber = payload["wrapped_key_kyber"]
        b64_rsa = payload.get("wrapped_key_rsa", "")
        b64_iv = payload["iv"]
        b64_auth_tag = payload.get("auth_tag", "")
        integrity_hex = payload.get("integrity", "")
    except KeyError as e:
        msg = f"Missing required field in payload: {e}"
        logger.error(msg)
        raise CryptoDecryptionError(msg)

    # decode
    ciphertext = base64.b64decode(b64_ciphertext)
    wrapped_kyber = base64.b64decode(b64_kyber)
    wrapped_rsa = base64.b64decode(b64_rsa) if b64_rsa else b""
    iv = base64.b64decode(b64_iv)

    # 1) Attempt Kyber decap
    aes_key = None
    kyber_ok = True
    try:
        with oqs.KeyEncapsulation("Kyber512", kyber_priv) as kem:
            shared_secret = kem.decap_secret(wrapped_kyber)
        aes_key = hashlib.sha256(shared_secret).digest()
    except Exception as e:
        logger.warning("Kyber decapsulation failed: %s", e)
        kyber_ok = False

    if not kyber_ok or aes_key is None:
        # If allow_classical_fallback => try RSA
        if config.allow_classical_fallback and rsa_priv and wrapped_rsa:
            try:
                aes_key = _load_rsa_private_key(rsa_priv).decrypt(
                    wrapped_rsa,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                logger.info("RSA fallback succeeded.")
            except Exception as e:
                msg = f"Both Kyber decap and RSA fallback failed: {e}"
                logger.error(msg)
                raise CryptoDecryptionError(msg)
        else:
            msg = "Kyber decap failed and fallback is not allowed or not provided."
            logger.error(msg)
            raise CryptoDecryptionError(msg)

    # 2) Now that we have aes_key, do final decryption
    if not config.use_cbc_hmac:
        # GCM mode
        if len(iv) not in (12, 16):
            logger.warning("Unusual IV size for GCM: %d", len(iv))
        if not b64_auth_tag:
            raise CryptoDecryptionError("Missing auth_tag in GCM payload")

        auth_tag = base64.b64decode(b64_auth_tag)
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            msg = f"GCM decryption/auth failed: {e}"
            logger.error(msg)
            raise CryptoDecryptionError(msg)
    else:
        # CBC + HMAC
        # first check HMAC
        expected_hmac = bytes.fromhex(integrity_hex) if integrity_hex else None
        if not expected_hmac:
            raise CryptoDecryptionError("Missing HMAC integrity field in CBC payload")

        # Verify HMAC
        try:
            h = hmac.HMAC(aes_key, hashes.SHA512(), backend=default_backend())
            h.update(ciphertext)
            h.verify(expected_hmac)
        except Exception as e:
            msg = f"HMAC integrity check failed: {e}"
            logger.error(msg)
            raise CryptoDecryptionError(msg)

        # now decrypt
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plain) + unpadder.finalize()
        except Exception as e:
            msg = f"CBC decryption failed: {e}"
            logger.error(msg)
            raise CryptoDecryptionError(msg)

    return plaintext


def sign_content_bundle(
    data: bytes,
    config: SentinelConfig,
    dil_priv: bytes,
    rsa_priv: Optional[bytes] = None
) -> Dict[str, str]:
    """
    Signs data with Dilithium. If allow_classical_fallback is true and rsa_priv is provided,
    also produce an RSA signature. Returns a dictionary:
      {
        "dilithium": "<base64>",
        "rsa": "<base64 or empty>"
      }
    """
    if not oqs:
        raise ImportError("The 'oqs' library is required for PQC signing but not found.")

    # PQC sign
    dil_sign_b64 = ""
    rsa_sign_b64 = ""

    try:
        with oqs.Signature("Dilithium2", dil_priv) as sig:
            sig_bytes = sig.sign(data)
        dil_sign_b64 = base64.b64encode(sig_bytes).decode("utf-8")
    except Exception as e:
        msg = f"Dilithium sign failed: {e}"
        logger.error(msg)
        raise CryptoSignatureError(msg)

    if config.allow_classical_fallback and rsa_priv:
        # RSA sign
        try:
            rsa_private_key = _load_rsa_private_key(rsa_priv)
            rsa_sig = rsa_private_key.sign(
                data,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
            rsa_sign_b64 = base64.b64encode(rsa_sig).decode("utf-8")
        except Exception as e:
            msg = f"RSA signature fallback failed: {e}"
            logger.error(msg)
            raise CryptoSignatureError(msg)

    return {
        "dilithium": dil_sign_b64,
        "rsa": rsa_sign_b64
    }


def verify_content_signature(
    data: bytes,
    signatures: Dict[str, str],
    config: SentinelConfig,
    dil_pub: bytes,
    rsa_pub: Optional[bytes] = None
) -> bool:
    """
    Verifies the signature dictionary produced by sign_content_bundle.
    If allow_classical_fallback is true, we check both Dilithium and RSA; both must pass.
    Otherwise, we only check Dilithium. Return True if valid, False otherwise.
    """
    if not oqs:
        raise ImportError("The 'oqs' library is required for PQC verification but not found.")

    dil_sig_b64 = signatures.get("dilithium", "")
    rsa_sig_b64 = signatures.get("rsa", "")
    if not dil_sig_b64:
        logger.error("Missing Dilithium signature in signatures dict.")
        return False

    # Dilithium verify
    try:
        with oqs.Signature("Dilithium2", dil_pub) as sig:
            dil_sig = base64.b64decode(dil_sig_b64)
            sig.verify(data, dil_sig, dil_pub)  # if fails => raises
    except Exception as e:
        logger.warning("Dilithium signature verify failed: %s", e)
        return False

    if config.allow_classical_fallback and rsa_pub and rsa_sig_b64:
        # RSA verify
        try:
            rsa_sig = base64.b64decode(rsa_sig_b64)
            rsa_public_key = _load_rsa_public_key(rsa_pub)
            rsa_public_key.verify(
                rsa_sig,
                data,
                asym_padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            logger.warning("RSA signature verify failed: %s", e)
            return False

    return True


def _load_rsa_public_key(key_data: bytes):
    """
    Helper to load an RSA public key from PEM or DER bytes.
    """
    try:
        # Try PEM
        if b"-----BEGIN" in key_data:
            return serialization.load_pem_public_key(key_data, backend=default_backend())
        else:
            # DER
            return serialization.load_der_public_key(key_data, backend=default_backend())
    except Exception as e:
        raise CryptoDecryptionError(f"Failed to load RSA public key: {e}")


def _load_rsa_private_key(key_data: bytes):
    """
    Helper to load an RSA private key from PEM or DER bytes.
    """
    try:
        if b"-----BEGIN" in key_data:
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        else:
            return serialization.load_der_private_key(key_data, password=None, backend=default_backend())
    except Exception as e:
        raise CryptoDecryptionError(f"Failed to load RSA private key: {e}")