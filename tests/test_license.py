# tests/test_license.py
"""
Final-shape tests for aepok_sentinel/core/license.py

Verifies:
 - The new sealed identity usage
 - The install_state usage
 - The chain events (LICENSE_ACTIVATED, LICENSE_INVALID, LICENSE_EXPIRED, INSTALL_REJECTED)
"""

import os
import json
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import (
    LicenseManager, LicenseError,
    is_watch_only, is_license_valid
)
from aepok_sentinel.core.audit_chain import AuditChain


class TestLicenseFinalShape(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # minimal config
        self.cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "license_required": False,
            "bound_to_hardware": False,
            "allow_classical_fallback": True,
            "license_path": os.path.join(self.temp_dir, "license.key"),
            "enforcement_mode": "PERMISSIVE"  # can set to HARDENED in some tests
        }
        self.cfg = SentinelConfig(self.cfg_dict)
        # create runtime base
        self.runtime_base = os.path.join(self.temp_dir, "runtime")
        os.mkdir(self.runtime_base)
        # create license dir
        license_dir = os.path.join(self.runtime_base, "license")
        os.mkdir(license_dir)
        # identity.json => if bound_to_hardware => we read host_fingerprint
        config_dir = os.path.join(self.runtime_base, "config")
        os.mkdir(config_dir)
        with open(os.path.join(config_dir, "identity.json"), "w", encoding="utf-8") as f:
            # minimal identity
            f.write(json.dumps({"fingerprint": "local_host_fp"}))

        # place a default install_state.json
        with open(os.path.join(license_dir, "install_state.json"), "w", encoding="utf-8") as f:
            json.dump({}, f)

        self.audit_chain = AuditChain(chain_dir=self.temp_dir)
        self.manager = LicenseManager(self.cfg, audit_chain=self.audit_chain, sentinel_runtime_base=self.runtime_base)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _read_chain_events(self):
        if not os.path.isfile(self.audit_chain.current_file_path):
            return []
        with open(self.audit_chain.current_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [json.loads(ln) for ln in lines]

    def test_file_not_found(self):
        """
        No license file => watch_only. Also logs LICENSE_INVALID with reason=file_missing
        """
        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        self.assertFalse(is_license_valid(self.manager))
        events = self._read_chain_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "LICENSE_INVALID")
        self.assertIn("file_missing", events[0]["metadata"]["reason"])

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_valid_license_activated(self, mock_verify):
        """
        If license is valid => chain logs LICENSE_ACTIVATED
        """
        # write a simple license
        lic_data = {
            "license_version": 1,
            "license_uuid": "abcd-1234",
            "issued_to": "TestUser",
            "expires_on": "9999-12-31",
            "signature": "base64_of_signature"
        }
        with open(self.manager.license_path, "w", encoding="utf-8") as f:
            json.dump(lic_data, f)

        self.manager.load_license()
        self.assertTrue(is_license_valid(self.manager))
        self.assertFalse(is_watch_only(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["event"], "LICENSE_ACTIVATED")
        self.assertEqual(evts[0]["metadata"]["license_uuid"], "abcd-1234")

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=False)
    def test_signature_fail(self, mock_verify):
        lic_data = {
            "license_version": 1,
            "license_uuid": "xyz-999",
            "issued_to": "UserB",
            "expires_on": "9999-12-31",
            "signature": "some_base64"
        }
        with open(self.manager.license_path, "w", encoding="utf-8") as f:
            json.dump(lic_data, f)

        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        self.assertFalse(is_license_valid(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(evts[0]["event"], "LICENSE_INVALID")
        self.assertIn("signature_fail", evts[0]["metadata"]["reason"])

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_expired_license(self, mock_verify):
        lic_data = {
            "license_version": 1,
            "license_uuid": "expired-lic",
            "issued_to": "UserExpired",
            "expires_on": "2000-01-01",
            "signature": "somebase64"
        }
        with open(self.manager.license_path, "w", encoding="utf-8") as f:
            json.dump(lic_data, f)

        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        self.assertFalse(is_license_valid(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["event"], "LICENSE_EXPIRED")

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_hardware_bound_mismatch(self, mock_verify):
        # turn on bound_to_hardware
        self.cfg.raw_dict["bound_to_hardware"] = True
        # re-init manager
        self.manager = LicenseManager(self.cfg, audit_chain=self.audit_chain, sentinel_runtime_base=self.runtime_base)
        lic_data = {
            "license_version": 1,
            "license_uuid": "hw-001",
            "expires_on": "9999-12-31",
            "signature": "somebase64",
            "bound_to": "some_other_fp"
        }
        with open(self.manager.license_path, "w", encoding="utf-8") as f:
            json.dump(lic_data, f)

        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(evts[0]["event"], "LICENSE_INVALID")
        self.assertIn("hardware_mismatch", evts[0]["metadata"]["reason"])

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_install_count_exceeded(self, mock_verify):
        # turn on install counting
        lic_data = {
            "license_version": 1,
            "license_uuid": "install-limit-xyz",
            "expires_on": "9999-12-31",
            "signature": "somebase64",
            "max_installs": 1
        }
        with open(self.manager.license_path, "w", encoding="utf-8") as f:
            json.dump(lic_data, f)

        # first load => success => we used 1 install
        self.manager.load_license()
        self.assertTrue(is_license_valid(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(evts[-1]["event"], "LICENSE_ACTIVATED")

        # second load => same license => but we are a new 'host_fingerprint'?
        with patch("aepok_sentinel.core.license_identity.read_host_identity",
                   return_value={"fingerprint": "another_fp"}):
            newmgr = LicenseManager(self.cfg, audit_chain=self.audit_chain, sentinel_runtime_base=self.runtime_base)
            newmgr.load_license()
            self.assertTrue(is_watch_only(newmgr))
            # check event => INSTALL_REJECTED
            evts2 = self._read_chain_events()
            self.assertEqual(evts2[-1]["event"], "INSTALL_REJECTED")

    def test_upload_license_ok(self):
        # create a valid license
        with open(self.manager.license_path, "w", encoding="utf-8") as f:
            json.dump({"license_version":1, "signature":"base64", "expires_on":"9999-12-31"}, f)
        # mock signature => True
        with patch.object(self.manager, "_verify_license_signature", return_value=True):
            self.manager.load_license()
            self.assertTrue(is_license_valid(self.manager))

            # now upload a new file that fails sig => degrade
            bad_lic_path = os.path.join(self.temp_dir, "bad_lic.json")
            with open(bad_lic_path, "w", encoding="utf-8") as bf:
                json.dump({"license_version":1, "signature":"ZZZ", "expires_on":"9999-12-31"}, bf)

            with patch.object(self.manager, "_verify_license_signature", return_value=False):
                self.manager.upload_license(bad_lic_path)
                self.assertTrue(is_watch_only(self.manager))

        evts = self._read_chain_events()
        # should have multiple events: LICENSE_ACTIVATED, then LICENSE_INVALID
        evt_names = [e["event"] for e in evts]
        self.assertIn("LICENSE_ACTIVATED", evt_names)
        self.assertIn("LICENSE_INVALID", evt_names)


if __name__ == "__main__":
    unittest.main()