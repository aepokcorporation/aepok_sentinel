"""
Unit tests for aepok_sentinel/core/pqc_tls.py

Validates:
 - create_pqc_ssl_context (sets TLS 1.3, tries to set PQC groups)
 - connect_pqc_socket with mock server or partial checks
 - strict_transport fallback
 - mock environment for OQS provider

We won't do a real PQC handshake unless we have an OQS-enabled OpenSSL environment. 
We do minimal tests to confirm code paths are correct.
"""

import os
import ssl
import unittest
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_tls import (
    create_pqc_ssl_context, connect_pqc_socket, PQCTlsError
)


class TestPqcTls(unittest.TestCase):

    def setUp(self):
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "strict_transport": False,
            "tls_mode": "hybrid",
            "allowed_tls_groups": ["X25519Kyber768Draft00", "X25519"]
        }
        self.cfg = SentinelConfig(self.config_dict)

    @patch("aepok_sentinel.core.pqc_tls._set_hybrid_groups")
    def test_create_context_ok(self, mock_set_groups):
        """
        Basic test: if we can set groups, no error.
        """
        ctx = create_pqc_ssl_context(self.cfg)
        self.assertIsInstance(ctx, ssl.SSLContext)
        mock_set_groups.assert_called_once()

    @patch("aepok_sentinel.core.pqc_tls._set_hybrid_groups", side_effect=OSError("fail set groups"))
    def test_create_context_strict_transport_fail(self, mock_set_groups):
        """
        If strict_transport=true => OSError in set groups => PQCTlsError
        """
        self.cfg.raw_dict["strict_transport"] = True
        with self.assertRaises(PQCTlsError):
            create_pqc_ssl_context(self.cfg)

    @patch("aepok_sentinel.core.pqc_tls._set_hybrid_groups")
    @patch("ssl.SSLSocket")
    @patch("socket.create_connection")
    def test_connect_pqc_socket_strict_fallback(self, mock_conn, mock_ssl_sock, mock_set_groups):
        """
        If strict_transport = True but we see a 'non-PQC' group => PQCTlsError
        """
        self.cfg.raw_dict["strict_transport"] = True
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        # Mock the SSL wrap
        mock_ssl_socket = MagicMock()
        # We'll simulate the cipher() => returns ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        # => _get_negotiated_group returns "x25519_or_pqc"
        # We'll patch _get_negotiated_group to return "x25519" => triggers fail if we expect PQC
        # but let's do a direct patch below
        mock_ssl_sock.return_value.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        # We'll forcibly patch the private function to produce a non-PQC group
        with patch("aepok_sentinel.core.pqc_tls._get_negotiated_group", return_value="x25519_only"):
            with self.assertRaises(PQCTlsError):
                connect_pqc_socket(self.cfg, "testhost", 443)

    @patch("aepok_sentinel.core.pqc_tls._set_hybrid_groups")
    @patch("ssl.SSLSocket")
    @patch("socket.create_connection")
    def test_connect_pqc_socket_non_strict(self, mock_conn, mock_ssl_sock, mock_set_groups):
        """
        If strict_transport = False => no error even if we get classical only
        """
        mock_ssl_socket = MagicMock()
        mock_ssl_sock.return_value = mock_ssl_socket
        mock_ssl_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        with patch("aepok_sentinel.core.pqc_tls._get_negotiated_group", return_value="x25519"):
            s = connect_pqc_socket(self.cfg, "testhost", 443)
            self.assertEqual(s, mock_ssl_socket)

    def test_no_openssl_conf_strict(self):
        """
        If no OPENSSL_CONF but strict => raise
        """
        self.cfg.raw_dict["strict_transport"] = True
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(PQCTlsError):
                create_pqc_ssl_context(self.cfg)


if __name__ == "__main__":
    unittest.main()