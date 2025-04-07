import os
import json
import unittest
import tempfile
import shutil
import base64
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.controller import SentinelController, ControllerError
from aepok_sentinel.core.constants import EventCode

class TestControllerFinalShape(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "sentinelrc.json")
        self.sig_path = self.config_path + ".sig"
        self.pub_path = os.path.join(self.temp_dir, "sentinelrc_dilithium_pub.pem")
        self.state_path = os.path.join(self.temp_dir, "state.json")
        self.runtime_base = os.path.join(self.temp_dir, "runtime")
        os.makedirs(self.runtime_base)

        # Write config
        self.config_data = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT",
            "license_required": True
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config_data, f)

        # Fake pubkey
        with open(self.pub_path, "wb") as f:
            f.write(b"MOCK_PUBKEY")

        # Fake signature
        fake_sig = base64.b64encode(json.dumps({"dilithium": "mock"}).encode("utf-8"))
        with open(self.sig_path, "wb") as f:
            f.write(fake_sig)

        # trust_anchor.json
        self.trust_path = os.path.join(self.runtime_base, "trust_anchor.json")
        self.trust_sig = self.trust_path + ".sig"
        trust_data = {
            "vendor_dil_pub_sha256": "mockedsha256hash"
        }
        with open(self.trust_path, "w", encoding="utf-8") as f:
            json.dump(trust_data, f)
        trust_sig = base64.b64encode(json.dumps({"sig": "mock"}).encode("utf-8"))
        with open(self.trust_sig, "wb") as f:
            f.write(trust_sig)

        # identity.json
        self.identity_path = os.path.join(self.runtime_base, "identity.json")
        self.identity_sig = self.identity_path + ".sig"
        with open(self.identity_path, "w", encoding="utf-8") as f:
            json.dump({"fingerprint": "host123"}, f)
        ident_sig = base64.b64encode(json.dumps({"sig": "mock"}).encode("utf-8"))
        with open(self.identity_sig, "wb") as f:
            f.write(ident_sig)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.get_host_fingerprint", return_value="host123")
    @patch("aepok_sentinel.core.controller.SentinelController._verify_file_hash")
    @patch("aepok_sentinel.core.controller.LicenseManager.load_license")
    @patch("aepok_sentinel.core.controller.AuditChain.append_event")
    @patch("aepok_sentinel.core.controller.validate_runtime_structure")
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_full_boot_passes_strict(
        self, mock_disk, mock_validate, mock_append, mock_lic, mock_hash, mock_fp, mock_sig
    ):
        mock_disk.return_value = MagicMock(free=999999999)
        ctrl = SentinelController(self.config_path, self.runtime_base, self.state_path)
        ctrl.boot()
        self.assertEqual(ctrl._host_fingerprint, "host123")
        self.assertTrue(ctrl._license_uuid != "")
        last_event = mock_append.call_args_list[-1][0][0]
        self.assertEqual(last_event, EventCode.CONTROLLER_BOOT.value)

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=False)
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_config_sig_fail_halts_boot(self, mock_disk, mock_verify):
        mock_disk.return_value = MagicMock(free=999999999)
        with self.assertRaises(ControllerError):
            SentinelController(self.config_path, self.runtime_base, self.state_path).boot()

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.get_host_fingerprint", return_value="host123")
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_disk_check_failure(self, mock_disk, mock_fp, mock_verify):
        mock_disk.return_value = MagicMock(free=1024)  # Low disk
        with self.assertRaises(ControllerError):
            SentinelController(self.config_path, self.runtime_base, self.state_path).boot()

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.get_host_fingerprint", return_value="host123")
    @patch("aepok_sentinel.core.controller.SentinelController._verify_file_hash", side_effect=ControllerError("hash fail"))
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_vendor_pub_hash_fail(self, mock_disk, mock_hash, mock_fp, mock_verify):
        mock_disk.return_value = MagicMock(free=999999999)
        with self.assertRaises(ControllerError):
            SentinelController(self.config_path, self.runtime_base, self.state_path).boot()

    @patch("aepok_sentinel.core.controller.verify_content_signature", return_value=True)
    @patch("aepok_sentinel.core.controller.get_host_fingerprint", return_value="host123")
    @patch("aepok_sentinel.core.controller.LicenseManager.load_license", side_effect=ControllerError("license fail"))
    @patch("aepok_sentinel.core.controller.shutil.disk_usage")
    def test_license_load_fails_in_strict(self, mock_disk, mock_lic, mock_fp, mock_verify):
        mock_disk.return_value = MagicMock(free=999999999)
        with self.assertRaises(ControllerError):
            SentinelController(self.config_path, self.runtime_base, self.state_path).boot()

if __name__ == "__main__":
    unittest.main()
