# test_daemon.py
"""
Unit tests for security_daemon.py

Verifies:
 - Watch-only => logs tamper/malware but doesn't quarantine
 - Non-watch-only => quarantines tampered or malicious files
 - Basic SCIF mode usage
 - Poll loop vs inotify fallback
"""

import os
import shutil
import unittest
import tempfile
import time
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
            "quarantine_enabled": True
        }
        self.cfg = SentinelConfig(self.config_dict)
        self.license_mgr = LicenseManager(self.cfg)
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})
        self.audit_chain = AuditChain(chain_dir=self.temp_dir)

        hash_store_path = os.path.join(self.temp_dir, ".hashes.json")
        quarantine_path = os.path.join(self.temp_dir, "quarantine")
        os.mkdir(quarantine_path)

        self.daemon = SecurityDaemon(
            self.cfg,
            self.license_mgr,
            self.audit_chain,
            hash_store_path=hash_store_path,
            quarantine_dir=quarantine_path
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_watch_only_logs_no_quarantine(self):
        self.license_mgr.license_state.watch_only = True
        testfile = os.path.join(self.temp_dir, "testfile.txt")
        with open(testfile, "w", encoding="utf-8") as f:
            f.write("content1")

        # first pass => store hash
        self.daemon._process_file(testfile)
        # second pass => tamper
        with open(testfile, "w", encoding="utf-8") as f:
            f.write("content2")
        self.daemon._process_file(testfile)

        self.assertTrue(os.path.isfile(testfile), "File should remain un-quarantined in watch-only mode")

        chain_file = self.audit_chain.current_file_path
        with open(chain_file, "r", encoding="utf-8") as c:
            lines = c.readlines()
        self.assertEqual(len(lines), 2)

        import json
        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        # first is storing hash => no event
        # second => TAMPER_DETECTED
        # Actually we get MALWARE_MATCH or TAMPER_DETECTED only if detected. 
        # Here it’s a tamper => TAMPER_DETECTED
        self.assertEqual(rec2["event"], "TAMPER_DETECTED")

    def test_tamper_and_quarantine(self):
        testfile = os.path.join(self.temp_dir, "file.bin")
        with open(testfile, "wb") as f:
            f.write(b"hello world")
        # store
        self.daemon._process_file(testfile)
        # tamper
        with open(testfile, "wb") as f:
            f.write(b"different content")

        self.daemon._process_file(testfile)
        # file => quarantined => removed from original location
        self.assertFalse(os.path.isfile(testfile))
        # chain => TAMPER_DETECTED + FILE_QUARANTINED
        chain_file = self.audit_chain.current_file_path
        with open(chain_file, "r", encoding="utf-8") as c:
            lines = c.readlines()
        self.assertEqual(len(lines), 2)

        import json
        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        self.assertEqual(rec1["event"], "TAMPER_DETECTED")
        self.assertEqual(rec2["event"], "FILE_QUARANTINED")

    @patch("aepok_sentinel.utils.malware_db.MalwareDatabase.check_file", return_value="BadMalware")
    def test_malware_quarantine(self, mock_check):
        fpath = os.path.join(self.temp_dir, "virus.exe")
        with open(fpath, "wb") as f:
            f.write(b"some malicious data")

        self.daemon._process_file(fpath)
        self.assertFalse(os.path.isfile(fpath), "Malware should be quarantined")

        chain_file = self.audit_chain.current_file_path
        with open(chain_file, "r", encoding="utf-8") as c:
            lines = c.readlines()
        self.assertEqual(len(lines), 2)
        import json
        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        self.assertEqual(rec1["event"], "MALWARE_MATCH")
        self.assertEqual(rec2["event"], "FILE_QUARANTINED")

    def test_scif_mode_no_external(self):
        self.cfg.raw_dict["mode"] = "scif"
        testfile = os.path.join(self.temp_dir, "doc.txt")
        with open(testfile, "w", encoding="utf-8") as f:
            f.write("scif data")
        # no error => local scanning
        self.daemon._process_file(testfile)

    def test_daemon_poll_stop(self):
        import threading
        t = threading.Thread(target=self.daemon.start)
        t.start()
        time.sleep(1)
        self.daemon.stop()
        t.join()
        self.assertFalse(t.is_alive(), "Daemon thread should stop cleanly.")


if __name__ == "__main__":
    unittest.main()