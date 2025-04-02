"""
Unit tests for aepok_sentinel/core/pqc_crypto.py

Validates:
- GCM vs CBC+HMAC encryption/decryption
- PQC (Kyber) + classical fallback (RSA)
- Dilithium + RSA dual signature
- Tampered data => decryption or signature fails

If oqs is not installed, these tests either skip or raise ImportError.
"""

import os
import unittest
import base64
import sys
from unittest import skipIf

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_crypto import (
    encrypt_file_payload,
    decrypt_file_payload,
    sign_content_bundle,
    verify_content_signature,
    CryptoDecryptionError,
    CryptoSignatureError,
    oqs
)

# We'll generate ephemeral keys for testing. In a real usage, they'd come from step 5 or outside.
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

OQS_MISSING = (oqs is None)

@skipIf(OQS_MISSING, "oqs library not installed; skipping PQC tests")
class TestPqcCrypto(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate ephemeral PQC keys: Kyber512, Dilithium2
        with oqs.KeyEncapsulation("Kyber512") as kem:
            cls.kyber_pub = kem.generate_keypair()
            cls.kyber_priv = kem.export_secret_key()

        with oqs.Signature("Dilithium2") as sig:
            cls.dil_pub = sig.generate_keypair()
            cls.dil_priv = sig.export_secret_key()

        # Generate ephemeral RSA key pair for fallback usage
        rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_public = rsa_private.public_key()
        cls.rsa_pub_pem = rsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cls.rsa_priv_pem = rsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def test_encrypt_decrypt_gcm(self):
        """
        Test default GCM encryption/decryption with PQC + RSA fallback allowed.
        """
        config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "use_cbc_hmac": False,
            "allow_classical_fallback": True
        }
        cfg = SentinelConfig(config_dict)

        plaintext = b"Hello PQC with GCM"
        payload = encrypt_file_payload(
            plaintext=plaintext,
            config=cfg,
            kyber_pub=self.kyber_pub,
            rsa_pub=self.rsa_pub_pem
        )
        self.assertEqual(payload["version"], 1)
        self.assertTrue(payload["ciphertext"])
        self.assertTrue(payload["wrapped_key_kyber"])
        self.assertTrue(payload["wrapped_key_rsa"])
        self.assertTrue(payload["iv"])
        self.assertTrue(payload["auth_tag"])
        self.assertEqual(payload["integrity"], "")

        # decrypt
        recovered = decrypt_file_payload(
            payload,
            cfg,
            kyber_priv=self.kyber_priv,
            rsa_priv=self.rsa_priv_pem
        )
        self.assertEqual(recovered, plaintext)

    def test_encrypt_decrypt_cbc_hmac(self):
        """
        Test AES-CBC + HMAC-SHA512 path. PQC + RSA fallback allowed.
        """
        config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "use_cbc_hmac": True,
            "allow_classical_fallback": True
        }
        cfg = SentinelConfig(config_dict)

        plaintext = b"Hello PQC with CBC+HMAC"
        payload = encrypt_file_payload(
            plaintext=plaintext,
            config=cfg,
            kyber_pub=self.kyber_pub,
            rsa_pub=self.rsa_pub_pem
        )
        self.assertTrue(payload["ciphertext"])
        self.assertTrue(payload["wrapped_key_kyber"])
        self.assertTrue(payload["wrapped_key_rsa"])
        self.assertTrue(payload["iv"])
        self.assertTrue(payload["integrity"])
        self.assertEqual(payload["auth_tag"], "")

        # decrypt
        recovered = decrypt_file_payload(
            payload,
            cfg,
            kyber_priv=self.kyber_priv,
            rsa_priv=self.rsa_priv_pem
        )
        self.assertEqual(recovered, plaintext)

    def test_no_rsa_fallback(self):
        """
        If allow_classical_fallback=false, we omit RSA wrapping in the payload.
        Attempting to decrypt with RSA alone should fail.
        """
        config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "use_cbc_hmac": False,
            "allow_classical_fallback": False
        }
        cfg = SentinelConfig(config_dict)

        plaintext = b"Kyber-only"
        payload = encrypt_file_payload(
            plaintext=plaintext,
            config=cfg,
            kyber_pub=self.kyber_pub,
            rsa_pub=self.rsa_pub_pem  # we pass it in, but config disallows fallback
        )
        # Should have empty wrapped_key_rsa
        self.assertEqual(payload["wrapped_key_rsa"], "")

        # Decryption tries Kyber only
        recovered = decrypt_file_payload(
            payload,
            cfg,
            kyber_priv=self.kyber_priv,
            rsa_priv=self.rsa_priv_pem
        )
        self.assertEqual(recovered, plaintext)

        # If kyber decap fails, there's no RSA fallback => CryptoDecryptionError
        # We'll simulate a tampered kyber CT
        tampered = payload.copy()
        tampered["wrapped_key_kyber"] = base64.b64encode(b"junk").decode("utf-8")
        with self.assertRaises(CryptoDecryptionError):
            decrypt_file_payload(
                tampered, cfg, self.kyber_priv, self.rsa_priv_pem
            )

    def test_tampered_ciphertext(self):
        """
        Tamper with ciphertext => must fail decryption in either GCM or HMAC check.
        """
        cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "use_cbc_hmac": False,
            "allow_classical_fallback": True
        }
        cfg = SentinelConfig(cfg_dict)
        pt = b"Sample data"
        payload = encrypt_file_payload(pt, cfg, self.kyber_pub, self.rsa_pub_pem)

        # Tamper
        tampered = payload.copy()
        ct_bytes = base64.b64decode(tampered["ciphertext"])
        tampered_ct = bytearray(ct_bytes)
        tampered_ct[0] ^= 0xFF  # flip some bits
        tampered["ciphertext"] = base64.b64encode(bytes(tampered_ct)).decode("utf-8")

        with self.assertRaises(CryptoDecryptionError):
            decrypt_file_payload(tampered, cfg, self.kyber_priv, self.rsa_priv_pem)

    def test_sign_verify_dual(self):
        """
        If allow_classical_fallback=true => produce Dilithium + RSA signature, verify both.
        """
        cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_classical_fallback": True
        }
        cfg = SentinelConfig(cfg_dict)
        data = b"Hello signature"

        sigs = sign_content_bundle(data, cfg, self.dil_priv, self.rsa_priv_pem)
        self.assertTrue(sigs["dilithium"])
        self.assertTrue(sigs["rsa"])

        ok = verify_content_signature(data, sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertTrue(ok)

        # Tamper with data => fails
        bad_ok = verify_content_signature(b"other data", sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertFalse(bad_ok)

    def test_sign_verify_pqc_only(self):
        """
        If allow_classical_fallback=false => only Dilithium signature
        """
        cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_classical_fallback": False
        }
        cfg = SentinelConfig(cfg_dict)
        data = b"PQC-only signing"

        sigs = sign_content_bundle(data, cfg, self.dil_priv, self.rsa_priv_pem)
        self.assertTrue(sigs["dilithium"])
        self.assertEqual(sigs["rsa"], "")

        # verify
        ok = verify_content_signature(data, sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertTrue(ok)

        # tamper
        ok2 = verify_content_signature(b"??", sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertFalse(ok2)


if __name__ == "__main__":
    unittest.main()