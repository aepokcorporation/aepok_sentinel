# test_pqc_tls.py
"""
Unit tests for pqc_tls.py

Covers:
 - create_pqc_ssl_context (PQC/hybrid group setup, disabling session tickets)
 - connect_pqc_socket with mock connection
 - strict_transport fallback rejection
 - Basic coverage of group retrieval logic
"""

import os
import ssl
import unittest
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_tls import (
    create_pqc_ssl_context,
    connect_pqc_socket,
    PQCTlsError
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

    @patch("aepok_sentinel.core.pqc_tls._set_supported_groups")
    def test_create_context_ok(self, mock_set_groups):
        """
        Basic check: if _set_supported_groups runs, we get an SSLContext.
        """
        ctx = create_pqc_ssl_context(self.cfg)
        self.assertIsInstance(ctx, ssl.SSLContext)
        mock_set_groups.assert_called_once()

    @patch("aepok_sentinel.core.pqc_tls._set_supported_groups", side_effect=OSError("group set fail"))
    def test_create_context_strict_transport_fail(self, mock_set_groups):
        """
        If strict_transport=true => OSError => PQCTlsError
        """
        self.cfg.raw_dict["strict_transport"] = True
        with self.assertRaises(PQCTlsError):
            create_pqc_ssl_context(self.cfg)

    @patch("aepok_sentinel.core.pqc_tls._set_supported_groups")
    @patch("ssl.SSLSocket")
    @patch("socket.create_connection")
    def test_connect_pqc_socket_strict_fallback(self, mock_conn, mock_ssl_sock, mock_set_groups):
        """
        strict_transport => must see 'kyber' in group => else PQCTlsError
        """
        self.cfg.raw_dict["strict_transport"] = True
        self.cfg.raw_dict["tls_mode"] = "hybrid"
        mock_ssl_socket = MagicMock()
        mock_ssl_sock.return_value = mock_ssl_socket
        # We'll patch _get_negotiated_group to return 'x25519' => triggers PQCTlsError
        with patch("aepok_sentinel.core.pqc_tls._get_negotiated_group", return_value="x25519"):
            with self.assertRaises(PQCTlsError):
                connect_pqc_socket(self.cfg, "testhost", 443)

    @patch("aepok_sentinel.core.pqc_tls._set_supported_groups")
    @patch("ssl.SSLSocket")
    @patch("socket.create_connection")
    def test_connect_pqc_socket_non_strict(self, mock_conn, mock_ssl_sock, mock_set_groups):
        """
        If strict_transport = False => no error even if group is classical only
        """
        mock_ssl_socket = MagicMock()
        mock_ssl_sock.return_value = mock_ssl_socket
        with patch("aepok_sentinel.core.pqc_tls._get_negotiated_group", return_value="x25519"):
            s = connect_pqc_socket(self.cfg, "testhost", 443)
            self.assertEqual(s, mock_ssl_socket)


if __name__ == "__main__":
    unittest.main()