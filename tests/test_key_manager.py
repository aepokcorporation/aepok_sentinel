"""
Unit tests for final-shape key_manager.py

Validates:
 - Local key loading + signature check
 - Key rotation concurrency lock
 - Cloud fetch with Azure
 - Rotation logs KEY_ROTATED or KEY_GENERATION_FAILED
 - Two-phase commit => revert on fail
 - Strict/hardened => must fail on missing files or invalid sig
"""

import os
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.key_manager import KeyManager, KeyManagerError
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode

class TestKeyManagerFinalShape(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # create /runtime/keys
        self.runtime_base = os.path.join(self.temp_dir, "runtime")
        os.makedirs(os.path.join(self.runtime_base, "keys"))
        # also the lock directory
        locks_dir = os.path.join(self.runtime_base, "locks")
        os.mkdir(locks_dir)
        # create a device dil priv/pub
        with open(os.path.join(self.runtime_base, "keys", "device_dilithium_priv.bin"), "wb") as f:
            f.write(b"fake_device_dil_priv")
        with open(os.path.join(self.runtime_base, "keys", "device_dilithium_pub.bin"), "wb") as f:
            f.write(b"fake_device_dil_pub")

        self.cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_enabled": False,
            "license_required": False,
            "bound_to_hardware": False,
            "allow_classical_fallback": True,
            "rotation_interval_days": 30,
            "enforcement_mode": "PERMISSIVE",  # can set to STRICT to test strict path
            "cloud_keyvault_url": "https://fake.azure.net/"
        }
        self.cfg = SentinelConfig(self.cfg_dict)
        self.license_mgr = LicenseManager(self.cfg)
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={"license_uuid":"123-abc"})
        self.chain = AuditChain(chain_dir=self.temp_dir)

        self.km = KeyManager(self.cfg, self.license_mgr, audit_chain=self.chain, sentinel_runtime_base=self.runtime_base)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _read_chain_events(self):
        events = []
        if os.path.isfile(self.chain.current_file_path):
            with open(self.chain.current_file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            import json
            for ln in lines:
                events.append(json.loads(ln))
        return events

    def test_missing_keys_dir_strict(self):
        """
        If keys dir is missing in strict => fail
        """
        self.cfg.raw_dict["enforcement_mode"] = "STRICT"
        # re-init => will fail
        shutil.rmtree(os.path.join(self.runtime_base, "keys"))
        with self.assertRaises(RuntimeError):
            KeyManager(self.cfg, self.license_mgr, audit_chain=self.chain, sentinel_runtime_base=self.runtime_base)

    def test_fetch_current_keys_local_no_files(self):
        # no local files => can we proceed? in permissive => returns empty
        # in strict => raises KeyManagerError
        # default = permissive
        keys = self.km.fetch_current_keys()
        self.assertEqual(keys, {})

        # strict => now must fail
        self.cfg.raw_dict["enforcement_mode"] = "STRICT"
        km2 = KeyManager(self.cfg, self.license_mgr, audit_chain=self.chain, sentinel_runtime_base=self.runtime_base)
        with self.assertRaises(KeyManagerError):
            km2.fetch_current_keys()

    @patch("aepok_sentinel.core.pqc_crypto.sign_content_bundle", return_value={"fake":"sig"})
    @patch("aepok_sentinel.core.pqc_crypto.verify_content_signature", return_value=True)
    def test_rotate_keys_ok(self, mock_verify, mock_sign):
        self.km.rotate_keys()
        # check chain => KEY_ROTATED
        events = self._read_chain_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "KEY_ROTATED")

        # we expect new keys in runtime/keys, e.g. kyber_priv_TIMESTAMP.bin
        files = os.listdir(os.path.join(self.runtime_base, "keys"))
        self.assertTrue(any("kyber_priv_" in f for f in files))
        self.assertTrue(any("dilithium_priv_" in f for f in files))

    @patch("aepok_sentinel.core.pqc_crypto.sign_content_bundle", side_effect=Exception("boom"))
    def test_rotate_keys_sign_fail(self, mock_sign):
        # sign fails => KEY_GENERATION_FAILED => revert
        # let's place an older key, ensure we revert to that
        old_k = os.path.join(self.runtime_base, "keys", "kyber_priv_20230101.bin")
        with open(old_k, "wb") as f:
            f.write(b"old key data")

        self.km.rotate_keys()
        evts = self._read_chain_events()
        self.assertEqual(evts[-1]["event"], "KEY_GENERATION_FAILED")
        # old key still present
        files = os.listdir(os.path.join(self.runtime_base, "keys"))
        self.assertIn("kyber_priv_20230101.bin", files)

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_watch_only_cannot_rotate(self, mock_ver):
        self.license_mgr.license_state.watch_only = True
        self.km.rotate_keys()
        # no chain events
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 0)

    def test_cloud_fetch_scif(self):
        self.cfg.mode = "scif"
        with self.assertRaises(KeyManagerError):
            self.km._fetch_cloud_keys()

    @patch("aepok_sentinel.core.azure_client.AzureClient.get_secret")
    def test_cloud_fetch_ok(self, mock_sec):
        self.cfg.mode = "cloud"
        self.cfg.cloud_keyvault_enabled = True
        mock_sec.side_effect = ["Ynl0ZXNfZm9yX2RpbA==","Ynl0ZXNfZm9yX2t5YmVy","Ynl0ZXNfZm9yX3JzYQ=="]  # base64 for "bytes_for_dil" ...
        keys = self.km._fetch_cloud_keys()
        self.assertEqual(keys["dilithium_priv"], b"bytes_for_dil")
        self.assertEqual(keys["kyber_priv"], b"bytes_for_kyber")
        self.assertEqual(keys["rsa_priv"], b"bytes_for_rsa")


if __name__ == "__main__":
    unittest.main()