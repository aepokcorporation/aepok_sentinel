"""
Unit tests for aepok_sentinel/core/autoban.py (Final Shape)

Covering:
 - record_bad_source => actual firewall block unless watch-only or disabled
 - signature-based blocklist load/save
 - TTL expiration
 - verified firewall command path & hashing
"""

import os
import unittest
import tempfile
import shutil
import time
from unittest.mock import patch, MagicMock, mock_open

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.autoban import AutobanManager, AutobanError


class TestAutobanManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.blocklist_file = os.path.join(self.temp_dir, "blocked_ips.json")
        # create the directory if needed
        os.makedirs(self.temp_dir, exist_ok=True)

        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "autoban_enabled": True,
            "autoban_block_ttl_days": 1
        }
        self.cfg = SentinelConfig(self.config_dict)
        self.license_mgr = LicenseManager(self.cfg)
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})
        self.audit_chain = AuditChain(chain_dir=self.temp_dir)
        self.ab = AutobanManager(
            config=self.cfg,
            license_mgr=self.license_mgr,
            audit_chain=self.audit_chain,
            blocklist_file=self.blocklist_file
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("sys.platform", "linux")
    @patch("aepok_sentinel.core.autoban.which", return_value="/usr/sbin/ufw")
    @patch("aepok_sentinel.core.autoban.AutobanManager._verify_binary_trusted", return_value=True)
    @patch("subprocess.run")
    def test_record_bad_source_linux_ok(self, mock_run, mock_verify, mock_which):
        mock_run.return_value.returncode = 0
        self.ab.record_bad_source("1.2.3.4", "testing")
        self.assertTrue(self.ab.is_blocked("1.2.3.4"))

        # ensure blocklist file was saved + sig
        sig_path = self.blocklist_file + ".sig"
        self.assertTrue(os.path.isfile(self.blocklist_file))
        self.assertTrue(os.path.isfile(sig_path))

        # check chain => AUTOBAN_TRIGGERED
        chain_file = self.audit_chain.current_file_path
        with open(chain_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)

    def test_autoban_disabled(self):
        self.ab.autoban_enabled = False
        self.ab.record_bad_source("9.8.7.6", "disabled")
        self.assertFalse(self.ab.is_blocked("9.8.7.6"))

    def test_watch_only(self):
        self.license_mgr.license_state.watch_only = True
        with patch.object(self.ab, "enforce_block") as mock_block:
            self.ab.record_bad_source("2.3.4.5", "test")
            mock_block.assert_not_called()
        self.assertFalse(self.ab.is_blocked("2.3.4.5"))

    def test_block_ttl_expired(self):
        # manually add a source w/ an old blocked_on
        old_ts = int(time.time()) - (2*86400)  # 2 days ago
        self.ab.blocked_data["10.0.0.1"] = {"blocked_on": str(old_ts)}
        # save
        self.ab._save_blocklist()

        # re-init manager => should purge
        with patch.object(self.ab, "enforce_unblock") as mock_unblock:
            new_ab = AutobanManager(
                config=self.cfg,
                license_mgr=self.license_mgr,
                audit_chain=self.audit_chain,
                blocklist_file=self.blocklist_file
            )
            self.assertFalse(new_ab.is_blocked("10.0.0.1"))
            mock_unblock.assert_called_once()

    @patch("sys.platform", "win32")
    @patch("aepok_sentinel.core.autoban.which", return_value="C:\\Windows\\System32\\netsh.exe")
    @patch("aepok_sentinel.core.autoban.AutobanManager._verify_binary_trusted", return_value=True)
    @patch("subprocess.run")
    def test_record_bad_source_windows(self, mock_run, mock_verify, mock_which):
        mock_run.return_value.returncode = 0
        self.ab.record_bad_source("5.6.7.8", "windows test")
        self.assertTrue(self.ab.is_blocked("5.6.7.8"))

    @patch("aepok_sentinel.core.autoban.AutobanManager._verify_binary_trusted", return_value=False)
    def test_untrusted_binary(self, mock_trusted):
        with self.assertRaises(AutobanError):
            self.ab.record_bad_source("11.22.33.44", "untrusted")

    @patch("aepok_sentinel.core.autoban.which", return_value=None)
    def test_no_firewall_command_found(self, mock_which):
        with self.assertRaises(AutobanError):
            self.ab.record_bad_source("8.8.8.8", "nofw")

    def test_missing_dir_raises(self):
        # if user tries a non-existent path
        bad_file = os.path.join(self.temp_dir, "nonexist_dir", "blocked.json")
        with self.assertRaises(RuntimeError):
            AutobanManager(self.cfg, self.license_mgr, self.audit_chain, blocklist_file=bad_file)


if __name__ == "__main__":
    unittest.main()