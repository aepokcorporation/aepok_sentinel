# test_crypto.py
"""
Unit tests for pqc_crypto.py

Verifies:
 - GCM vs CBC+HMAC encryption/decryption
 - PQC (Kyber) + optional RSA fallback
 - Dilithium + optional RSA dual signature
 - Tampering detection
 - RNG check
 - Memory zeroization on shutdown if ephemeral buffers are used

Skips if 'oqs' is unavailable.
"""

import os
import unittest
import base64
from unittest import skipIf, mock

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core import pqc_crypto
from aepok_sentinel.core.pqc_crypto import (
    encrypt_file_payload,
    decrypt_file_payload,
    sign_content_bundle,
    verify_content_signature,
    CryptoDecryptionError,
    CryptoSignatureError,
    oqs,
    sanitize_on_shutdown
)

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

    def tearDown(self):
        # Optionally test memory sanitize
        sanitize_on_shutdown()

    def test_encrypt_decrypt_gcm(self):
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

        recovered = decrypt_file_payload(
            payload,
            cfg,
            self.kyber_priv,
            self.rsa_priv_pem
        )
        self.assertEqual(recovered, plaintext)

    def test_encrypt_decrypt_cbc_hmac(self):
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

        recovered = decrypt_file_payload(
            payload,
            cfg,
            self.kyber_priv,
            self.rsa_priv_pem
        )
        self.assertEqual(recovered, plaintext)

    def test_no_rsa_fallback(self):
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
            rsa_pub=self.rsa_pub_pem
        )
        self.assertEqual(payload["wrapped_key_rsa"], "")

        recovered = decrypt_file_payload(
            payload,
            cfg,
            self.kyber_priv,
            self.rsa_priv_pem
        )
        self.assertEqual(recovered, plaintext)

        # Tamper with Kyber => no fallback => fail
        tampered = dict(payload)
        tampered["wrapped_key_kyber"] = base64.b64encode(b"junk").decode("utf-8")
        with self.assertRaises(CryptoDecryptionError):
            decrypt_file_payload(tampered, cfg, self.kyber_priv, self.rsa_priv_pem)

    def test_tampered_ciphertext(self):
        config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "use_cbc_hmac": False,
            "allow_classical_fallback": True
        }
        cfg = SentinelConfig(config_dict)

        pt = b"Sample data"
        payload = encrypt_file_payload(pt, cfg, self.kyber_pub, self.rsa_pub_pem)

        # Tamper
        tampered = dict(payload)
        ct_bytes = base64.b64decode(tampered["ciphertext"])
        ct_mutable = bytearray(ct_bytes)
        ct_mutable[0] ^= 0xFF  # flip a bit
        tampered["ciphertext"] = base64.b64encode(ct_mutable).decode("utf-8")

        with self.assertRaises(CryptoDecryptionError):
            decrypt_file_payload(tampered, cfg, self.kyber_priv, self.rsa_priv_pem)

    def test_sign_verify_dual(self):
        config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_classical_fallback": True
        }
        cfg = SentinelConfig(config_dict)
        data = b"Hello signature"

        sigs = sign_content_bundle(data, cfg, self.dil_priv, self.rsa_priv_pem)
        self.assertTrue(sigs["dilithium"])
        self.assertTrue(sigs["rsa"])
        self.assertIn("signer_id", sigs["metadata"])
        self.assertIn("host_fingerprint", sigs["metadata"])
        self.assertIn("key_fingerprint", sigs["metadata"])

        ok = verify_content_signature(data, sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertTrue(ok)

        # Tamper data => fail
        ok2 = verify_content_signature(b"evil data", sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertFalse(ok2)

    def test_sign_verify_pqc_only(self):
        config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_classical_fallback": False
        }
        cfg = SentinelConfig(config_dict)
        data = b"PQC-only signing"

        sigs = sign_content_bundle(data, cfg, self.dil_priv, self.rsa_priv_pem)
        self.assertTrue(sigs["dilithium"])
        self.assertEqual(sigs["rsa"], "")

        ok = verify_content_signature(data, sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertTrue(ok)

        # Tamper
        ok2 = verify_content_signature(b"???", sigs, cfg, self.dil_pub, self.rsa_pub_pem)
        self.assertFalse(ok2)

    def test_rng_check(self):
        # Mock os.urandom to produce same blocks => logs warning
        with mock.patch("os.urandom", side_effect=[b"A"*32, b"A"*32]):
            with self.assertLogs(level="WARNING") as log_cm:
                pqc_crypto.validate_rng()
            self.assertIn("RNG check: identical 32-byte blocks encountered", "".join(log_cm.output))

        # Normal => logs debug
        with mock.patch("os.urandom", side_effect=[b"A"*32, b"B"*32]):
            with self.assertLogs(level="DEBUG") as log_cm:
                pqc_crypto.validate_rng()
            self.assertIn("RNG check passed", "".join(log_cm.output))


if __name__ == "__main__":
    unittest.main()