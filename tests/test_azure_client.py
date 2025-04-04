"""
Unit tests for aepok_sentinel/core/azure_client.py

Validates:
 - SCIF/airgap => error
 - watch-only => read-only, no writes
 - config => cloud, azure, valid cloud_keyvault_url => success
 - requests calls use custom PQC TLS context if needed
 - delete fails if allow_delete=false
"""

import unittest
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.azure_client import AzureClient, AzureClientError
from aepok_sentinel.core.pqc_tls import PQCTlsError


class TestAzureClient(unittest.TestCase):

    def setUp(self):
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_provider": "azure",
            "cloud_keyvault_url": "https://fakevault.azure.net",
            "allow_delete": True,
            "tls_mode": "hybrid",
            "strict_transport": False
        }
        self.cfg = SentinelConfig(self.config_dict)
        self.license_mgr = LicenseManager(self.cfg)
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})

    def test_invalid_mode_scif(self):
        self.cfg.raw_dict["mode"] = "scif"
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    def test_invalid_provider(self):
        self.cfg.raw_dict["cloud_keyvault_provider"] = "aws"
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    def test_missing_keyvault_url(self):
        self.cfg.raw_dict["cloud_keyvault_url"] = ""
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    @patch("aepok_sentinel.core.azure_client.create_pqc_ssl_context")
    def test_build_requests_session_non_classical(self, mock_create_ctx, mock_sess_cls):
        """
        If tls_mode != classical => create PQC context for requests
        """
        AzureClient(self.cfg, self.license_mgr)
        mock_create_ctx.assert_called_once()
        mock_sess_cls.assert_called_once()

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    @patch("aepok_sentinel.core.azure_client.create_pqc_ssl_context", side_effect=PQCTlsError("pqc fail"))
    def test_strict_transport_fail(self, mock_create_ctx, mock_sess_cls):
        """
        If strict_transport=true => PQCTlsError => raise AzureClientError
        """
        self.cfg.raw_dict["strict_transport"] = True
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    @patch("aepok_sentinel.core.azure_client.create_pqc_ssl_context", side_effect=PQCTlsError("pqc fail"))
    def test_strict_transport_false_fallback(self, mock_create_ctx, mock_sess_cls):
        """
        If strict_transport=false => fallback to default session
        """
        # Should not raise
        self.cfg.raw_dict["strict_transport"] = False
        cli = AzureClient(self.cfg, self.license_mgr)
        # We get a client w/ fallback session
        self.assertIsInstance(cli, AzureClient)

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    def test_get_secret(self, mock_sess_cls):
        mock_sess = MagicMock()
        mock_sess_cls.return_value = mock_sess
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"value": "secretvalue"}
        mock_sess.get.return_value = mock_resp

        cli = AzureClient(self.cfg, self.license_mgr)
        val = cli.get_secret("mysecret")
        self.assertEqual(val, "secretvalue")

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    def test_set_secret_watch_only(self, mock_sess_cls):
        mock_sess = MagicMock()
        mock_sess_cls.return_value = mock_sess

        # Force watch-only
        self.license_mgr.license_state.watch_only = True
        cli = AzureClient(self.cfg, self.license_mgr)
        with self.assertRaises(AzureClientError):
            cli.set_secret("abc", "value")

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    def test_set_secret_ok(self, mock_sess_cls):
        mock_sess = MagicMock()
        mock_sess_cls.return_value = mock_sess
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_sess.put.return_value = mock_resp

        cli = AzureClient(self.cfg, self.license_mgr)
        cli.set_secret("abc", "value")
        mock_sess.put.assert_called_once()

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    def test_delete_secret_not_allowed(self, mock_sess_cls):
        mock_sess = MagicMock()
        mock_sess_cls.return_value = mock_sess

        self.cfg.raw_dict["allow_delete"] = False
        cli = AzureClient(self.cfg, self.license_mgr)
        with self.assertRaises(AzureClientError):
            cli.delete_secret("secret1")

    @patch("aepok_sentinel.core.azure_client.requests.Session")
    def test_delete_secret_ok(self, mock_sess_cls):
        mock_sess = MagicMock()
        mock_sess_cls.return_value = mock_sess
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_sess.delete.return_value = mock_resp

        cli = AzureClient(self.cfg, self.license_mgr)
        cli.delete_secret("secret1")
        mock_sess.delete.assert_called_once()


if __name__ == "__main__":
    unittest.main()