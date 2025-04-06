"""
Unit tests for aepok_sentinel/core/azure_clients.py (Final Shape)

Checks:
 - SCIF/airgap => error
 - watch-only => read-only
 - classical mode => default TLS
 - strict => PQC error => fail
 - non-strict => PQC error => fallback
 - set/delete logic with allow_delete
"""

import unittest
from unittest.mock import patch, MagicMock

import requests
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.azure_clients import AzureClient, AzureClientError
from aepok_sentinel.core.pqc_tls import PQCTlsError


class TestAzureClients(unittest.TestCase):

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
        # default is watch_only=False, valid=True
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})

    def test_scif_or_airgap_disallowed(self):
        for mode in ["scif", "airgap"]:
            self.cfg.raw_dict["mode"] = mode
            with self.assertRaises(AzureClientError):
                AzureClient(self.cfg, self.license_mgr)

    def test_wrong_provider(self):
        self.cfg.raw_dict["cloud_keyvault_provider"] = "aws"
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    def test_no_url(self):
        self.cfg.raw_dict["cloud_keyvault_url"] = ""
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
    @patch("aepok_sentinel.core.azure_clients.create_pqc_ssl_context")
    def test_pqc_session_hybrid(self, mock_pqc_ctx, mock_session):
        """
        If tls_mode != classical => we attempt PQC context.
        """
        AzureClient(self.cfg, self.license_mgr)
        mock_pqc_ctx.assert_called_once()
        mock_session.assert_called_once()

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
    @patch("aepok_sentinel.core.azure_clients.create_pqc_ssl_context", side_effect=PQCTlsError("pqc fail"))
    def test_strict_transport_true_fail(self, mock_pqc_ctx, mock_session):
        self.cfg.raw_dict["strict_transport"] = True
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr)

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
    @patch("aepok_sentinel.core.azure_clients.create_pqc_ssl_context", side_effect=PQCTlsError("pqc fail"))
    def test_strict_transport_false_fallback(self, mock_pqc_ctx, mock_session):
        """
        Non-strict => fallback to default
        """
        self.cfg.raw_dict["strict_transport"] = False
        client = AzureClient(self.cfg, self.license_mgr)
        self.assertIsInstance(client, AzureClient)

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
    def test_get_secret_ok(self, mock_sess_cls):
        mock_sess = MagicMock()
        mock_sess_cls.return_value = mock_sess
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"value": "secretval"}
        mock_sess.get.return_value = mock_resp

        cli = AzureClient(self.cfg, self.license_mgr)
        val = cli.get_secret("mysecret")
        self.assertEqual(val, "secretval")

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
    def test_set_secret_watch_only(self, mock_sess_cls):
        self.license_mgr.license_state.watch_only = True
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr).set_secret("name", "val")

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
    def test_delete_secret_disallowed(self, mock_sess_cls):
        self.cfg.raw_dict["allow_delete"] = False
        with self.assertRaises(AzureClientError):
            AzureClient(self.cfg, self.license_mgr).delete_secret("secret1")

    @patch("aepok_sentinel.core.azure_clients.requests.Session")
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