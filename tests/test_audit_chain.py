import os
import json
import shutil
import unittest
import tempfile
import time
from unittest.mock import patch, MagicMock
from pathlib import Path

from aepok_sentinel.core.audit_chain import (
    AuditChain,
    AuditChainError,
    ChainTamperDetectedError
)


class TestAuditChain(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_missing_audit_directory(self, mock_resolve_path):
        """
        If the 'audit' directory doesn't exist, we raise AuditChainError immediately.
        """
        mock_resolve_path.return_value = Path(self.temp_dir) / "nonexistent_audit"
        with self.assertRaises(AuditChainError):
            AuditChain(pqc_priv_keys={}, pqc_pub_keys={})

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_basic_append_and_validate(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()  # create the folder
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(
            pqc_priv_keys={},  # no signing
            pqc_pub_keys={},   # no verifying
            max_size_bytes=1000
        )
        chain.append_event("CONFIG_LOADED", {"file": ".sentinelrc"})
        is_valid = chain.validate_chain(raise_on_fail=False)
        self.assertTrue(is_valid, "Expected chain to be valid with a single event")

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_replay_detection(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(
            pqc_priv_keys={},  # no signing
            pqc_pub_keys={},
            max_size_bytes=1000
        )
        # append an event
        chain.append_event("FIRST_EVENT", {})

        # tamper with boot_hash => set last_known_root = something else
        boot_hash_file = audit_path / "boot_hash.json"
        with open(boot_hash_file, "r", encoding="utf-8") as bf:
            data = json.load(bf)
        data["last_known_root"] = "FAKE_ROOT"
        with open(boot_hash_file, "w", encoding="utf-8") as bf:
            json.dump(data, bf)

        # now append a new event => should raise ChainTamperDetectedError
        with self.assertRaises(ChainTamperDetectedError):
            chain.append_event("SECOND_EVENT", {})

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_rollover_and_checkpoint(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        # Provide a mock private key to see if checkpoint is signed
        dummy_dil_priv = b"DIL_PRIV_KEY"
        chain = AuditChain(
            pqc_priv_keys={"dilithium": dummy_dil_priv},
            pqc_pub_keys={},
            max_size_bytes=300  # small => triggers rollover quickly
        )

        # append multiple events
        for i in range(5):
            chain.append_event(f"EVENT_{i}", {"idx": i, "data": "x" * 50})  # each ~ 70+ bytes => triggers rollover

        # check if old chain file was renamed
        files = os.listdir(audit_path)
        old_chain_logs = [f for f in files if f.startswith("old_chain_")]
        self.assertTrue(len(old_chain_logs) >= 1, "Expected at least one old_chain_ file after rollover")

        # check for checkpoint
        cpoints = [f for f in files if f.startswith("chain_checkpoint_")]
        self.assertTrue(len(cpoints) >= 1, "Expected at least one chain_checkpoint_ file after rollover")

        # see if checkpoint has 'signature'
        with open(audit_path / cpoints[0], "r", encoding="utf-8") as cf:
            cdata = json.load(cf)
        self.assertIn("signature", cdata, "checkpoint file should have a signature if we had a private key")

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_background_verification(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(
            pqc_priv_keys={},
            pqc_pub_keys={},
            max_size_bytes=500,
            background_verification_interval=1  # 1 minute
        )

        # We won't actually wait a full minute. We'll patch time.sleep or we can do a quick test 
        # showing the thread is started. Then we'll stop it.
        self.assertIsNotNone(chain._bg_thread, "Expected a background thread to be started")
        self.assertTrue(chain._bg_thread.is_alive(), "Background thread should be alive")

        chain.stop()
        self.assertFalse(chain._bg_thread.is_alive(), "Background thread should be stopped after chain.stop()")

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_atomic_write_via_chain_tmp(self, mock_resolve_path):
        """
        Confirm that appending an event writes to .chain_tmp first, then appends to chain file.
        """
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(pqc_priv_keys={}, pqc_pub_keys={})
        chain.append_event("TEST_EVENT", {})

        # check that .chain_tmp exists but is empty afterwards or removed
        tmp_path = audit_path / "audit_chain_tmp.json"
        self.assertTrue(tmp_path.is_file(), ".chain_tmp should be created during append")
        # but it might or might not be empty after the write. Let's check contents
        with open(tmp_path, "r", encoding="utf-8") as tf:
            tmp_contents = tf.read().strip()
        # There's no strict requirement to remove or empty it after, but let's see if it's stale
        self.assertTrue(len(tmp_contents) > 0, "tmp file might still contain the last record")

        # chain file should have the new record
        chain_file = audit_path / "audit_chain.log"
        with open(chain_file, "r", encoding="utf-8") as cf:
            lines = cf.readlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["event"], "TEST_EVENT")


if __name__ == "__main__":
    unittest.main()