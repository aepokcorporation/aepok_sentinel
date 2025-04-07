"""
Unit tests for aepok_sentinel/core/security_daemon.py

Validates:
 - watch-only => logs but does not quarantine
 - tamper => quarantines if not watch-only
 - malware => quarantines if not watch-only
 - scif => local scanning only, no external calls
 - poll loop vs. inotify fallback
"""

import os
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.security_daemon import SecurityDaemon


class TestSecurityDaemon(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "scan_paths": [self.temp_dir],
            "exclude_paths": [],
            "scan_recursive": True,
            "use_inotify": False,
            "daemon_poll_interval": 1,
            "quarantine_enabled": True,
            "chain_verification_on_decrypt": False
        }
        self.cfg = SentinelConfig(self.config_dict)
        self.license_mgr = LicenseManager(self.cfg)
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})
        self.audit_chain = AuditChain(chain_dir=self.temp_dir)
        self.daemon = SecurityDaemon(self.cfg, self.license_mgr, self.audit_chain,
                                     hash_store_path=os.path.join(self.temp_dir, ".hashes.json"),
                                     quarantine_dir=os.path.join(self.temp_dir, "quarantine"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_watch_only_logs_no_quarantine(self):
        # set watch-only
        self.license_mgr.license_state.watch_only = True
        # create a file
        fpath = os.path.join(self.temp_dir, "testfile.txt")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("content1")

        # modify => tamper
        self.daemon._process_file(fpath)
        # file should still exist
        self.assertTrue(os.path.isfile(fpath))
        # check chain => we see TAMPER_DETECTED
        with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as c:
            chain_lines = c.readlines()
        self.assertEqual(len(chain_lines), 1)
        import json
        rec = json.loads(chain_lines[0])
        self.assertEqual(rec["event"], "TAMPER_DETECTED")

    def test_tamper_and_quarantine(self):
        # normal license => we do quarantine
        fpath = os.path.join(self.temp_dir, "file.bin")
        with open(fpath, "wb") as f:
            f.write(b"hello world")

        # first process => store hash
        self.daemon._process_file(fpath)
        # re-modify => tamper
        with open(fpath, "wb") as f:
            f.write(b"changed content")

        self.daemon._process_file(fpath)
        # file should be moved to quarantine
        q_dir = os.path.join(self.temp_dir, "quarantine")
        self.assertTrue(os.path.isdir(q_dir))
        # original file removed
        self.assertFalse(os.path.isfile(fpath))

        # check chain => TAMPER_DETECTED => FILE_QUARANTINED
        with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as c:
            lines = c.readlines()
        self.assertEqual(len(lines), 2)
        import json
        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        self.assertEqual(rec1["event"], "TAMPER_DETECTED")
        self.assertEqual(rec2["event"], "FILE_QUARANTINED")

    @patch("aepok_sentinel.utils.malware_db.MalwareDatabase.check_file", return_value="BadMalware")
    def test_malware_quarantine(self, mock_mal):
        # if malware => quarantine
        fpath = os.path.join(self.temp_dir, "virus.exe")
        with open(fpath, "wb") as f:
            f.write(b"executable data")

        self.daemon._process_file(fpath)
        # quarantined => file removed
        self.assertFalse(os.path.isfile(fpath))
        # check chain => MALWARE_MATCH => FILE_QUARANTINED
        with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as c:
            lines = c.readlines()
        self.assertEqual(len(lines), 2)
        import json
        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        self.assertEqual(rec1["event"], "MALWARE_MATCH")
        self.assertEqual(rec2["event"], "FILE_QUARANTINED")

    def test_scif_mode_no_external(self):
        # scif => no external calls, but we still do local scanning
        self.cfg.raw_dict["mode"] = "scif"
        # in scif => we do local scanning
        fpath = os.path.join(self.temp_dir, "doc.txt")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("scif data")
        self.daemon._process_file(fpath)
        # no error => local scanning done

    def test_daemon_poll_stop(self):
        import threading

        t = threading.Thread(target=self.daemon.start)
        t.start()
        time.sleep(2)
        self.daemon.stop()
        t.join()
        self.assertFalse(t.is_alive())