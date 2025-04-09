# test_audit_chain.py
"""
Unit tests for audit_chain.py

Covers:
 - Initialization failure if 'audit' dir missing
 - append_event -> single event => valid chain
 - Replay detection via tampered boot_hash
 - Rollover + checkpoint creation
 - Optional background verification setup
 - .chain_tmp usage
"""

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
        # Create the 'audit' folder
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(
            pqc_priv_keys={},
            pqc_pub_keys={},
            max_size_bytes=1000
        )
        chain.append_event("CONFIG_LOADED", {"file": ".sentinelrc"})
        is_valid = chain.validate_chain(raise_on_fail=False)
        self.assertTrue(is_valid, "Expected valid single-event chain")

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_replay_detection(self, mock_resolve_path):
        # Create 'audit' folder
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(
            pqc_priv_keys={},
            pqc_pub_keys={},
            max_size_bytes=1000
        )
        chain.append_event("FIRST_EVENT", {})

        # Tamper boot_hash => set last_known_root to something else
        boot_hash_file = audit_path / "boot_hash.json"
        with open(boot_hash_file, "r", encoding="utf-8") as bf:
            data = json.load(bf)
        data["last_known_root"] = "FAKE_ROOT"
        with open(boot_hash_file, "w", encoding="utf-8") as bf:
            json.dump(data, bf)

        # new event => ChainTamperDetectedError
        with self.assertRaises(ChainTamperDetectedError):
            chain.append_event("SECOND_EVENT", {})

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_rollover_and_checkpoint(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        dummy_dil_priv = b"DIL_PRIV_KEY"
        chain = AuditChain(
            pqc_priv_keys={"dilithium": dummy_dil_priv},
            pqc_pub_keys={},
            max_size_bytes=300
        )

        # multiple events
        for i in range(5):
            chain.append_event(f"EVENT_{i}", {"idx": i, "data": "x" * 50})

        files = os.listdir(audit_path)
        old_chain_logs = [f for f in files if f.startswith("old_chain_")]
        self.assertTrue(len(old_chain_logs) >= 1, "Expected old_chain_ after rollover")

        cpoints = [f for f in files if f.startswith("chain_checkpoint_")]
        self.assertTrue(len(cpoints) >= 1, "Expected chain_checkpoint_ after rollover")

        with open(audit_path / cpoints[0], "r", encoding="utf-8") as cf:
            cdata = json.load(cf)
        self.assertIn("signature", cdata, "Checkpoint should have a signature with dilithium key")

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_background_verification(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(
            pqc_priv_keys={},
            pqc_pub_keys={},
            max_size_bytes=500,
            background_verification_interval=1
        )

        self.assertIsNotNone(chain._bg_thread, "Expect background verification thread")
        self.assertTrue(chain._bg_thread.is_alive())

        chain.stop()
        self.assertFalse(chain._bg_thread.is_alive())

    @patch("aepok_sentinel.core.audit_chain.resolve_path")
    def test_atomic_write_via_chain_tmp(self, mock_resolve_path):
        audit_path = Path(self.temp_dir) / "audit"
        audit_path.mkdir()
        mock_resolve_path.return_value = audit_path

        chain = AuditChain(pqc_priv_keys={}, pqc_pub_keys={})
        chain.append_event("TEST_EVENT", {})

        tmp_path = audit_path / "audit_chain_tmp.json"
        self.assertTrue(tmp_path.is_file(), ".chain_tmp should exist during append")

        chain_file = audit_path / "audit_chain.log"
        with open(chain_file, "r", encoding="utf-8") as cf:
            lines = cf.readlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["event"], "TEST_EVENT")


if __name__ == "__main__":
    unittest.main()