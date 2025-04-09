# tests/test_key_manager.py

"""
Unit tests for final-shape KeyManager and KeyRotationLock.

Verifies:
 - fetch_current_keys() in local + cloud modes
 - rotate_keys() with concurrency lock => success or fail => chain events
 - revert on generation failure => KEY_GENERATION_FAILED
 - in watch_only => skip rotation
 - strict/hardened => must fail if missing files or invalid sig
"""

import os
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.key_manager import KeyManager, KeyManagerError
from aepok_sentinel.core.key_manager_lock import KeyRotationLock
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode


class TestKeyManagerFinalShape(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.runtime_base = os.path.join(self.temp_dir, "runtime")
        os.makedirs(os.path.join(self.runtime_base, "keys"), exist_ok=True)
        os.makedirs(os.path.join(self.runtime_base, "locks"), exist_ok=True)

        # Minimal config
        self.cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_enabled": False,
            "license_required": False,
            "allow_classical_fallback": True,
            "rotation_interval_days": 30,
            "enforcement_mode": "PERMISSIVE"
        }
        self.cfg = SentinelConfig(self.cfg_dict)

        # Mock license manager => valid, not watch_only
        self.lic_mgr = LicenseManager(self.cfg)
        self.lic_mgr.license_state = LicenseState(valid=True, watch_only=False, info={"license_uuid": "abc-123"})

        # minimal vendor pub/priv
        with open(os.path.join(self.runtime_base, "keys", "vendor_dilithium_priv.bin"), "wb") as f:
            f.write(b"FAKE_DEVICE_DIL_PRIV")
        with open(os.path.join(self.runtime_base, "keys", "vendor_dilithium_pub.pem"), "wb") as f:
            f.write(b"FAKE_DEVICE_DIL_PUB")

        self.chain = AuditChain(chain_dir=self.temp_dir)
        self.km = KeyManager(self.cfg, self.lic_mgr, audit_chain=self.chain)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _read_chain_events(self):
        events_path = self.chain.current_file_path
        if not os.path.isfile(events_path):
            return []
        with open(events_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        import json
        return [json.loads(ln) for ln in lines]

    def test_missing_keys_dir_strict(self):
        # remove keys dir
        shutil.rmtree(os.path.join(self.runtime_base, "keys"))
        self.cfg.raw_dict["enforcement_mode"] = "STRICT"
        with self.assertRaises(RuntimeError):
            KeyManager(self.cfg, self.lic_mgr, self.chain)

    def test_fetch_local_keys_empty(self):
        # no actual key files => in PERMISSIVE => empty dict
        got = self.km.fetch_current_keys()
        self.assertEqual(got, {})

        # in STRICT => fail
        self.cfg.raw_dict["enforcement_mode"] = "STRICT"
        km2 = KeyManager(self.cfg, self.lic_mgr, self.chain)
        with self.assertRaises(KeyManagerError):
            km2.fetch_current_keys()

    @patch("aepok_sentinel.core.pqc_crypto.sign_content_bundle", return_value={"fake": "sig"})
    @patch("aepok_sentinel.core.pqc_crypto.verify_content_signature", return_value=True)
    @patch("os.urandom", return_value=b"A" * 32)
    def test_rotate_keys_ok(self, mock_rand, mock_verify, mock_sign):
        # Attempt rotation => success => KEY_ROTATED
        self.km.rotate_keys()
        evts = self._read_chain_events()
        # 1 event => KEY_ROTATED
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["event"], "KEY_ROTATED")

        # confirm new files in <keys> with timestamp
        all_files = os.listdir(os.path.join(self.runtime_base, "keys"))
        self.assertTrue(any("kyber_priv_" in x for x in all_files))
        self.assertTrue(any("dilithium_priv_" in x for x in all_files))

    @patch("aepok_sentinel.core.pqc_crypto.sign_content_bundle", side_effect=Exception("Signature failure"))
    def test_rotate_fail_sign(self, mock_sign):
        # old key
        with open(os.path.join(self.runtime_base, "keys", "kyber_priv_20220101.bin"), "wb") as f:
            f.write(b"old_kyber")

        self.km.rotate_keys()
        evts = self._read_chain_events()
        self.assertEqual(evts[-1]["event"], "KEY_GENERATION_FAILED")

        # old key remains
        files = os.listdir(os.path.join(self.runtime_base, "keys"))
        self.assertIn("kyber_priv_20220101.bin", files)

    def test_watch_only_skip_rotate(self):
        self.lic_mgr.license_state.watch_only = True
        self.km.rotate_keys()
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 0)

    @patch("aepok_sentinel.core.azure_client.AzureClient.get_secret")
    def test_fetch_cloud_keys_ok(self, mock_get):
        self.cfg.raw_dict["cloud_keyvault_enabled"] = True
        self.cfg.raw_dict["mode"] = "cloud"
        mock_get.side_effect = ["ZGlsX2RhdGE=", "a3liZXJfZGF0YQ==", "cnNhX2RhdGE="]  # base64 of "dil_data", "kyber_data", "rsa_data"
        keys = self.km.fetch_current_keys()
        self.assertEqual(keys["dilithium_priv"], b"dil_data")
        self.assertEqual(keys["kyber_priv"], b"kyber_data")
        self.assertEqual(keys["rsa_priv"], b"rsa_data")

    def test_strict_invalid_sig_on_file(self):
        # place a fake kyber file but no .sig => in strict => fail
        self.cfg.raw_dict["enforcement_mode"] = "STRICT"
        with open(os.path.join(self.runtime_base, "keys", "kyber_priv_20230314.bin"), "wb") as f:
            f.write(b"fake kyber data")
        with self.assertRaises(KeyManagerError):
            self.km.fetch_current_keys()


class TestKeyRotationLock(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.lockfile = os.path.join(self.temp_dir, "key_rotation.lock")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_lockfile_acquire(self):
        from aepok_sentinel.core.key_manager_lock import KeyRotationLock
        with KeyRotationLock(self.lockfile, must_fail_on_error=True) as lk:
            # we hold the lock
            pass  # no error => success

    def test_lockfile_fail_degrade(self):
        from aepok_sentinel.core.key_manager_lock import KeyRotationLock
        # if we forcibly remove the lockfile's parent dir => can't open
        os.rmdir(self.temp_dir)
        # degrade => no raise
        with KeyRotationLock(self.lockfile, must_fail_on_error=False):
            pass  # proceed anyway

        # must_fail=True => raise
        os.mkdir(self.temp_dir)
        os.rmdir(self.temp_dir)  # remove again
        with self.assertRaises(RuntimeError):
            with KeyRotationLock(self.lockfile, must_fail_on_error=True):
                pass


if __name__ == "__main__":
    unittest.main()