"""
Unit tests for aepok_sentinel/utils/status_printer.py (Final Shape)

Validates:
 - gather_system_status returns the expected fields
 - print_system_status logs and prints
"""

import unittest
from unittest.mock import patch, MagicMock
import io

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.utils.status_printer import (
    gather_system_status,
    print_system_status
)


class TestStatusPrinter(unittest.TestCase):

    def setUp(self):
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "encryption_enabled": True,
            "strict_transport": False,
            "cloud_keyvault_url": "https://fakevault.example",
            "daemon_poll_interval": 10,
            "log_path": "/var/log/sentinel/",
            "allow_delete": False,
            "license_required": True,
            "bound_to_hardware": False
        }
        self.cfg = SentinelConfig(self.config_dict)
        self.license_mgr = LicenseManager(self.cfg)
        # default license => valid, not watch_only
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})

    def test_gather_system_status_valid_license(self):
        status_str = gather_system_status(self.cfg, self.license_mgr)
        self.assertIn("Mode: cloud", status_str)
        self.assertIn("Encryption: ENABLED", status_str)
        self.assertIn("strict_transport: FALSE", status_str)
        self.assertIn("License State: VALID", status_str)
        self.assertIn("Cloud KeyVault URL: https://fakevault.example", status_str)
        self.assertIn("allow_delete: False", status_str)
        self.assertIn("daemon_poll_interval: 10", status_str)
        self.assertIn("Log path: /var/log/sentinel/", status_str)
        self.assertIn("License required: True", status_str)
        self.assertIn("Hardware binding: False", status_str)

    def test_gather_system_status_watch_only(self):
        self.license_mgr.license_state.valid = False
        self.license_mgr.license_state.watch_only = True
        status_str = gather_system_status(self.cfg, self.license_mgr)
        self.assertIn("License State: WATCH-ONLY", status_str)

    def test_gather_system_status_scif(self):
        self.cfg.raw_dict["mode"] = "scif"
        status_str = gather_system_status(self.cfg, self.license_mgr)
        self.assertIn("Mode: scif", status_str)
        self.assertIn("Network calls disallowed.", status_str)

    @patch("aepok_sentinel.utils.status_printer.logger")
    @patch("sys.stdout", new_callable=io.StringIO)
    def test_print_system_status(self, mock_stdout, mock_logger):
        print_system_status(self.cfg, self.license_mgr)
        output = mock_stdout.getvalue()
        self.assertIn("Mode: cloud", output)
        mock_logger.info.assert_called_once()
        self.assertIn("System Status:", mock_logger.info.call_args[0][0])


if __name__ == "__main__":
    unittest.main()