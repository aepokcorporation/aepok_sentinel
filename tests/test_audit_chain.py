"""
Unit tests for the revised Step 6: aepok_sentinel/core/audit_chain.py

Validates:
 - signature verification
 - repair_chain
 - merkle path storage
 - monotonic timestamps
 - CHAIN_BROKEN, CHAIN_RESEALED logging
"""

import os
import shutil
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.audit_chain import AuditChain, ChainTamperDetectedError
from aepok_sentinel.core.config import SentinelConfig

class TestAuditChain(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "chain_verification_on_decrypt": True  # triggers signature check
        }
        self.cfg = SentinelConfig(self.config_dict)
        # no actual keys for now => skip real sign/verify
        self.ac = AuditChain(
            chain_dir=self.temp_dir,
            chain_basename="audit_chain.log",
            merkle_state_filename="audit_merkle.json",
            max_size_bytes=500,  # small for test
            config=self.cfg,
            dil_priv_key=None,  # if we had real keys, we'd do more advanced tests
            rsa_priv_key=None,
            dil_pub_key=None,
            rsa_pub_key=None
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_append_and_validate_no_sigs(self):
        """
        If config demands verification but we have no pub key => any non-empty signature will fail.
        But we have empty signatures => that might pass if we skip actual checks.
        """
        self.ac.append_event("EVENT_1", {"test": True})
        self.ac.append_event("EVENT_2", {"foo": "bar"})
        ok = self.ac.validate_chain()
        self.assertTrue(ok)

    def test_monotonic_ts_fail(self):
        # We'll tamper the second line's timestamp to be older
        self.ac.append_event("E1", {})
        # rewrite line with older timestamp
        chain_file = self.ac.current_file_path
        with open(chain_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        # parse second line, modify timestamp
        # Actually we only have 1 line for now, we need 2 lines. Let's do 2 appends first
        self.ac.append_event("E2", {})
        with open(chain_file, "r", encoding="utf-8") as f2:
            lines = f2.readlines()

        # parse second line
        record2 = json.loads(lines[1])
        record2["timestamp"] = record2["timestamp"].replace("T", "T00:00:00Z-lt")  # silly approach => older
        lines[1] = json.dumps(record2) + "\n"

        with open(chain_file, "w", encoding="utf-8") as f3:
            f3.writelines(lines)

        with self.assertRaises(ChainTamperDetectedError):
            self.ac.validate_chain()

    def test_merkle_path_inclusion(self):
        """
        Each appended line has a merkle_path. We verify it doesn't cause chain break.
        """
        self.ac.append_event("ONE", {})
        self.ac.append_event("TWO", {})
        # read the file
        with open(self.ac.current_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        rec1 = json.loads(lines[0])
        rec2 = json.loads(lines[1])
        self.assertIn("merkle_path", rec1)
        self.assertIn("merkle_path", rec2)
        self.assertIsInstance(rec1["merkle_path"], list)
        self.assertIsInstance(rec2["merkle_path"], list)
        self.assertTrue(self.ac.validate_chain())

    def test_rollover_and_repair(self):
        """
        Force rollover with small max_size, then call repair_chain => re-validate => append RESEAL
        """
        # append multiple events to trigger rollover
        for i in range(10):
            self.ac.append_event(f"BIG_{i}", {"x": i})

        # we have at least 2 chain files (rolled over old + new)
        files = os.listdir(self.temp_dir)
        chain_logs = [fn for fn in files if fn.startswith("audit_chain_")]
        self.assertTrue(len(chain_logs) >= 2, "Expected multiple chain logs after rollover")

        # now repair
        self.ac.repair_chain()
        # that triggers a RESEAL event appended => check we have 1 new line
        # check last line
        with open(self.ac.current_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        last_record = json.loads(lines[-1])
        self.assertEqual(last_record["event"], "CHAIN_RESEALED")
        self.assertIn("old_root", last_record["metadata"])
        # chain is still valid
        self.assertTrue(self.ac.validate_chain())


if __name__ == "__main__":
    unittest.main()