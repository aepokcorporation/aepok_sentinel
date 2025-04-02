"""
Unit tests for aepok_sentinel/utils/pqc_tls_verify.py

Validates:
 - verify_negotiated_pqc with various config combos
 - get_server_cert_fingerprint
 - verify_cert_fingerprint
"""

import unittest
from unittest.mock import patch, MagicMock

import ssl
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.utils.pqc_tls_verify import (
    verify_negotiated_pqc,
    get_server_cert_fingerprint,
    verify_cert_fingerprint
)


class TestPqcTlsVerify(unittest.TestCase):

    def setUp(self):
        self.cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "tls_mode": "hybrid",
            "strict_transport": False
        }
        self.cfg = SentinelConfig(self.cfg_dict)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="X25519Kyber768")
    def test_verify_hybrid_strict_pqc_ok(self, mock_group):
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        self.cfg.raw_dict["strict_transport"] = True
        # group has "kyber" => pass
        res = verify_negotiated_pqc(MagicMock(), self.cfg)
        self.assertTrue(res)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519_only")
    def test_verify_hybrid_strict_pqc_fail(self, mock_group):
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        self.cfg.raw_dict["strict_transport"] = True
        # group has no kyber => fail
        res = verify_negotiated_pqc(MagicMock(), self.cfg)
        self.assertFalse(res)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519_only")
    def test_verify_hybrid_non_strict_ok(self, mock_group):
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        self.cfg.raw_dict["strict_transport"] = False
        # allowed
        res = verify_negotiated_pqc(MagicMock(), self.cfg)
        self.assertTrue(res)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519_only")
    def test_verify_pqc_only_fail(self, mock_group):
        self.cfg.raw_dict["tls_mode"] = "pqc-only"
        res = verify_negotiated_pqc(MagicMock(), self.cfg)
        self.assertFalse(res)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="some_kyber_group")
    def test_verify_pqc_only_ok(self, mock_group):
        self.cfg.raw_dict["tls_mode"] = "pqc-only"
        res = verify_negotiated_pqc(MagicMock(), self.cfg)
        self.assertTrue(res)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519")
    def test_classical_mode(self, mock_group):
        self.cfg.raw_dict["tls_mode"] = "classical"
        res = verify_negotiated_pqc(MagicMock(), self.cfg)
        self.assertTrue(res)

    def test_get_server_cert_fingerprint_no_cert(self):
        mock_sock = MagicMock()
        mock_sock.getpeercert.return_value = None
        fp = get_server_cert_fingerprint(mock_sock)
        self.assertEqual(fp, "")

    def test_get_server_cert_fingerprint_ok(self):
        mock_sock = MagicMock()
        # pass a dummy PEM in binary_form
        # Actually binary_form is the DER. We'll just do some bytes.
        mock_sock.getpeercert.return_value = b"FakeDERCert"
        import hashlib
        sha = hashlib.sha256(b"FakeDERCert").hexdigest()

        fp = get_server_cert_fingerprint(mock_sock)
        self.assertEqual(fp, sha)

    @patch("aepok_sentinel.utils.pqc_tls_verify.get_server_cert_fingerprint", return_value="abc123")
    def test_verify_cert_fingerprint_match(self, mock_fp):
        mock_sock = MagicMock()
        ok = verify_cert_fingerprint(mock_sock, "abc123")
        self.assertTrue(ok)

    @patch("aepok_sentinel.utils.pqc_tls_verify.get_server_cert_fingerprint", return_value="abc123")
    def test_verify_cert_fingerprint_mismatch(self, mock_fp):
        mock_sock = MagicMock()
        ok = verify_cert_fingerprint(mock_sock, "zzz999")
        self.assertFalse(ok)

    def test_verify_cert_fingerprint_no_expected(self):
        mock_sock = MagicMock()
        # No expected => True
        ok = verify_cert_fingerprint(mock_sock, "")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()