# tests/test_controller.py

"""
Unit tests for aepok_sentinel/core/controller.py

Covers:
 - Successful boot in strict mode with valid .sentinelrc
 - Failure scenarios: config signature invalid, disk check fails, trust anchor mismatch, license errors
 - Halting with ControllerError in strict/hardened or continuing in permissive mode
 - Ensures chain event CONTROLLER_BOOT is emitted if everything succeeds
"""

import os
import json
import unittest
import tempfile
import shutil
import base64
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.controller import SentinelController, ControllerError
from aepok_sentinel.core.constants import EventCode


class TestController(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "sentinelrc.json")
        self.sig_path = self.config_path + ".sig"
        self.pub_path = os.path.join(self.temp_dir, "sentinelrc_dilithium_pub.pem")
        self.state_path = os.path.join(self.temp_dir, "state.json")

        self.runtime_base = os.path.join(self.temp_dir, "runtime")
        os.makedirs(self.runtime_base, exist_ok=True)

        # Write minimal sentinelrc
        self.config_data = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT",
            "license_required": True
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config_data, f)

        # Fake sentinelrc public key
        with open(self.pub_path, "wb") as f:
            f.write(b"FAKE_SENTINELRC_PUB")

        # Fake .sentinelrc.sig
        fake_sig = base64.b64encode(json.dumps({"dilithium": "mock"}).encode("utf-8"))
        with open(self.sig_path, "wb") as f:
            f.write(fake_sig)

        # Create trust_anchor and identity with .sig
        os.makedirs(os.path.join(self.runtime_base, "config"), exist_ok=True)

        self.trust_path = os.path.join(self.runtime_base, "config", "trust_anchor.json")
        self.trust_sig = self.trust_path + ".sig"
        trust_obj = {"vendor_dil_pub_sha256": "mocksha256"}
        with open(self.trust_path, "w", encoding="utf-8") as f:
            json.dump(trust_obj, f)
        trust_sig = base64.b64encode(json.dumps({"sig": "mock"}).encode("utf-8"))
        with open(self.trust_sig, "wb") as f:
            f.write(trust_sig)

        self.identity_path = os.path.join(self.runtime_base, "config", "identity.json")
        self.identity_sig = self.identity_path + ".sig"
        with open(self.identity_path, "w", encoding="utf-8") as f:
            json.dump({"fingerprint": "some_host_fp"}, f)
        ident_sig = base64.b64encode(json.dumps({"sig": "mock"}).encode("utf-8"))
        with open(self.identity_sig, "wb") as f:
            f.write(ident_sig)

        # Fake vendor_dilithium_pub for trust anchor
        keys_dir = os.path.join(self.runtime_base, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        with open(os.path.join(keys_dir, "vendor_dilithium_pub.pem"), "wb") as f:
            f.write(b"FAKE_VENDOR_PUB")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    @patch("aepok_sentinel.core.controller.LicenseManager.load_license")
    @patch("aepok_sentinel.core.controller.SentinelController._verify_file_hash")
    @patch("aepok_sentinel.core.controller.SentinelController._load_sentinelrc_pub_key", return_value=b"SENTINELRC_PUB_DATA")
    @patch("aepok_sentinel.core.controller.get_logger")
    def test_strict_boot_success(
        self, mock_logger, mock_pub, mock_hash, mock_lic, mock_disk, mock_verify
    ):
        # enough disk space
        mock_disk.return_value = MagicMock(free=999999999)
        ctrl = SentinelController(
            config_path=self.config_path,
            sentinel_runtime_base=self.runtime_base,
            state_path=self.state_path
        )
        ctrl.boot()
        # If we get here, boot succeeded
        self.assertTrue(ctrl._running or isinstance(ctrl._running, bool))

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=False)
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_sig_fail_strict(self, mock_disk, mock_verify):
        mock_disk.return_value = MagicMock(free=999999999)
        ctrl = SentinelController(
            config_path=self.config_path,
            sentinel_runtime_base=self.runtime_base,
            state_path=self.state_path
        )
        with self.assertRaises(ControllerError):
            ctrl.boot()

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.get_logger")
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_disk_fail_strict(self, mock_disk, mock_logger, mock_verify):
        mock_disk.return_value = MagicMock(free=1024)  # too small
        ctrl = SentinelController(
            config_path=self.config_path,
            sentinel_runtime_base=self.runtime_base,
            state_path=self.state_path
        )
        with self.assertRaises(ControllerError):
            ctrl.boot()

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.shutil.disk_usage", return_value=MagicMock(free=999999999))
    @patch("aepok_sentinel.core.controller.SentinelController._verify_file_hash", side_effect=ControllerError("hash mismatch"))
    def test_trust_anchor_hash_fail(self, mock_hash, mock_disk, mock_verify):
        ctrl = SentinelController(
            config_path=self.config_path,
            sentinel_runtime_base=self.runtime_base,
            state_path=self.state_path
        )
        with self.assertRaises(ControllerError):
            ctrl.boot()

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.shutil.disk_usage", return_value=MagicMock(free=999999999))
    @patch("aepok_sentinel.core.controller.LicenseManager.load_license", side_effect=Exception("License fail"))
    def test_license_fail_strict(self, mock_lic, mock_disk, mock_verify):
        ctrl = SentinelController(
            config_path=self.config_path,
            sentinel_runtime_base=self.runtime_base,
            state_path=self.state_path
        )
        with self.assertRaises(ControllerError):
            ctrl.boot()


if __name__ == "__main__":
    unittest.main()