"""
Unit tests for Step 7.5: aepok_sentinel/core/autoban.py

Validates:
 - record_bad_source => actual firewall command or fail
 - is_blocked => memory check
 - watch-only => no real block
 - autoban_enabled => skip block if disabled
 - logs to chain with SOURCE_BLOCKED or AUTOBAN_TRIGGERED
"""

import os
import unittest
import tempfile
import shutil
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.autoban import AutobanManager, AutobanError


class TestAutobanManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "autoban_enabled": True
        }
        self.cfg = SentinelConfig(self.config_dict)
        self.license_mgr = LicenseManager(self.cfg)
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})
        self.audit_chain = AuditChain(chain_dir=self.temp_dir)
        self.blocklist_file = os.path.join(self.temp_dir, "blocked_ips.json")

        self.ab = AutobanManager(
            config=self.cfg,
            license_mgr=self.license_mgr,
            audit_chain=self.audit_chain,
            blocklist_file=self.blocklist_file
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("sys.platform", "linux")
    @patch("aepok_sentinel.core.autoban.subprocess.run")
    @patch("aepok_sentinel.core.autoban.AutobanManager._is_cmd_available", return_value=True)
    def test_record_bad_source_linux_ok(self, mock_which, mock_run):
        """
        On linux => we try 'ufw' or 'iptables' => mock success
        """
        mock_run.return_value.returncode = 0
        self.ab.record_bad_source("1.2.3.4", "malware")
        # ensure block
        self.assertTrue(self.ab.is_blocked("1.2.3.4"))
        # check chain => we see AUTOBAN_TRIGGERED
        with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        import json
        rec = json.loads(lines[0])
        self.assertEqual(rec["event"], "AUTOBAN_TRIGGERED")

    @patch("sys.platform", "win32")
    @patch("aepok_sentinel.core.autoban.subprocess.run")
    def test_record_bad_source_windows(self, mock_run):
        mock_run.return_value.returncode = 0
        self.ab.record_bad_source("5.6.7.8", "tamper")
        self.assertTrue(self.ab.is_blocked("5.6.7.8"))

    @patch("sys.platform", "darwin")
    @patch("aepok_sentinel.core.autoban.AutobanManager._is_cmd_available", side_effect=lambda c: True if c=="ipfw" else False)
    @patch("aepok_sentinel.core.autoban.subprocess.run")
    def test_record_bad_source_mac(self, mock_run, mock_which):
        mock_run.return_value.returncode = 0
        self.ab.record_bad_source("9.8.7.6", "some reason")
        self.assertTrue(self.ab.is_blocked("9.8.7.6"))

    def test_skip_when_disabled(self):
        self.ab.autoban_enabled = False
        self.ab.record_bad_source("1.1.1.1", "test")
        # not blocked
        self.assertFalse(self.ab.is_blocked("1.1.1.1"))
        # chain => no entry
        if os.path.isfile(self.audit_chain.current_file_path):
            with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 0)

    def test_watch_only(self):
        self.license_mgr.license_state.watch_only = True
        with patch("aepok_sentinel.core.autoban.AutobanManager.enforce_block") as mock_block:
            self.ab.record_bad_source("2.2.2.2", "test")
            mock_block.assert_not_called()
        self.assertFalse(self.ab.is_blocked("2.2.2.2"))
        with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        import json
        rec = json.loads(lines[0])
        self.assertEqual(rec["event"], "SOURCE_BLOCKED")

    @patch("sys.platform", "linux")
    @patch("aepok_sentinel.core.autoban.subprocess.run")
    def test_enforce_block_fail(self, mock_run):
        mock_run.return_value.returncode = 1
        with self.assertRaises(AutobanError):
            self.ab.record_bad_source("10.0.0.1", "error test")

    def test_blocklist_persistence(self):
        # block an ip
        with patch("aepok_sentinel.core.autoban.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            self.ab.record_bad_source("3.3.3.3", "test")

        # reload manager
        new_ab = AutobanManager(self.cfg, self.license_mgr, self.audit_chain, self.blocklist_file)
        self.assertTrue(new_ab.is_blocked("3.3.3.3"))


if __name__ == "__main__":
    unittest.main()