"""
Unit tests for aepok_sentinel/utils/pqc_tls_verify.py (Final Shape)
Covering:
 - verify_negotiated_pqc with config combos
 - get_server_cert_fingerprint
 - verify_cert_fingerprint
 - check_session_resumption
 - log_tls_verification_event => ensures audit chain is called
"""

import unittest
from unittest.mock import patch, MagicMock

import ssl
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.utils.pqc_tls_verify import (
    verify_negotiated_pqc,
    get_server_cert_fingerprint,
    verify_cert_fingerprint,
    check_session_resumption,
    log_tls_verification_event,
    PQCVerifyError
)


class TestPqcTlsVerify(unittest.TestCase):

    def setUp(self):
        self.cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "tls_mode": "hybrid",
            "strict_transport": False,
            "enforcement_mode": "PERMISSIVE"
        }
        self.cfg = SentinelConfig(self.cfg_dict)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="X25519Kyber768")
    def test_verify_hybrid_pqc_ok(self, mock_grp):
        """
        hybrid => if strict=False => always pass, or strict=True => must have 'kyber'
        """
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        self.cfg.raw_dict["strict_transport"] = True
        mock_sock = MagicMock()
        result = verify_negotiated_pqc(mock_sock, self.cfg)
        self.assertTrue(result)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519_only")
    def test_verify_hybrid_strict_fail(self, mock_grp):
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        self.cfg.raw_dict["strict_transport"] = True
        mock_sock = MagicMock()
        ok = verify_negotiated_pqc(mock_sock, self.cfg)
        self.assertFalse(ok)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519")
    def test_verify_classical_ok(self, mock_grp):
        self.cfg.raw_dict["tls_mode"] = "classical"
        mock_sock = MagicMock()
        ok = verify_negotiated_pqc(mock_sock, self.cfg)
        self.assertTrue(ok)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="somekybergroup")
    def test_verify_pqc_only_ok(self, mock_grp):
        self.cfg.raw_dict["tls_mode"] = "pqc-only"
        mock_sock = MagicMock()
        ok = verify_negotiated_pqc(mock_sock, self.cfg)
        self.assertTrue(ok)

    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="x25519")
    def test_verify_pqc_only_fail(self, mock_grp):
        self.cfg.raw_dict["tls_mode"] = "pqc-only"
        mock_sock = MagicMock()
        ok = verify_negotiated_pqc(mock_sock, self.cfg)
        self.assertFalse(ok)

    def test_get_server_cert_fingerprint_no_cert(self):
        mock_sock = MagicMock()
        mock_sock.getpeercert.return_value = None
        fp = get_server_cert_fingerprint(mock_sock)
        self.assertEqual(fp, "")

    def test_get_server_cert_fingerprint_ok(self):
        mock_sock = MagicMock()
        fake_cert = b"FAKE_DER"
        mock_sock.getpeercert.return_value = fake_cert
        from hashlib import sha256
        expected = sha256(fake_cert).hexdigest().lower()
        fp = get_server_cert_fingerprint(mock_sock)
        self.assertEqual(fp, expected)

    def test_verify_cert_fingerprint_no_expected(self):
        # If no expected => always True
        mock_sock = MagicMock()
        self.assertTrue(verify_cert_fingerprint(mock_sock, ""))

    @patch("aepok_sentinel.utils.pqc_tls_verify.get_server_cert_fingerprint", return_value="abc123")
    def test_verify_cert_fingerprint_match(self, mock_fp):
        mock_sock = MagicMock()
        self.assertTrue(verify_cert_fingerprint(mock_sock, "abc123"))

    @patch("aepok_sentinel.utils.pqc_tls_verify.get_server_cert_fingerprint", return_value="zzz999")
    def test_verify_cert_fingerprint_mismatch(self, mock_fp):
        mock_sock = MagicMock()
        self.assertFalse(verify_cert_fingerprint(mock_sock, "abc123"))

    def test_check_session_resumption_false(self):
        mock_sock = MagicMock()
        mock_sock.session_reused = False
        self.assertFalse(check_session_resumption(mock_sock))

    def test_check_session_resumption_true(self):
        mock_sock = MagicMock()
        mock_sock.session_reused = True
        self.assertTrue(check_session_resumption(mock_sock))

    @patch("aepok_sentinel.utils.pqc_tls_verify.audit_chain.append_event")
    @patch("aepok_sentinel.utils.pqc_tls_verify._get_negotiated_group", return_value="X25519Kyber768")
    @patch("aepok_sentinel.utils.pqc_tls_verify.get_server_cert_fingerprint", return_value="abcd1234")
    @patch("aepok_sentinel.utils.pqc_tls_verify.check_session_resumption", return_value=True)
    def test_log_tls_verification_event(
        self, mock_reuse, mock_fp, mock_grp, mock_append
    ):
        mock_sock = MagicMock()
        log_tls_verification_event(mock_sock, self.cfg)
        mock_append.assert_called_once()
        args = mock_append.call_args[0]
        self.assertEqual(args[0], "TLS_VERIFICATION")
        metadata = args[1]
        self.assertIn("negotiated_group", metadata)
        self.assertIn("certificate_sha256", metadata)
        self.assertIn("session_resumed", metadata)
        self.assertTrue(metadata["session_resumed"])


if __name__ == "__main__":
    unittest.main()