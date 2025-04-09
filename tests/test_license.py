# tests/test_license.py
"""
Unit tests for aepok_sentinel/core/license.py (Final)

Validates:
 - Proper usage of resolve_path for runtime directories
 - License parse from .key (base64-encoded JSON)
 - Signature checks
 - Expiration logic
 - Install-state usage (including INSTALL_UPDATED event)
 - watch_only fallback vs. strict/hardened raise
"""

import os
import json
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import (
    LicenseManager, LicenseError, is_watch_only, is_license_valid
)
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.directory_contract import resolve_path


class TestLicenseFinalShape(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Minimal config
        self.cfg_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "license_required": False,
            "bound_to_hardware": False,
            "allow_classical_fallback": True,
            "enforcement_mode": "PERMISSIVE"  # can override in some tests
        }
        self.cfg = SentinelConfig(self.cfg_dict)

        # Create a mock runtime structure
        self.runtime_base = os.path.join(self.temp_dir, "runtime")
        os.mkdir(self.runtime_base)
        os.mkdir(os.path.join(self.runtime_base, "license"))
        os.mkdir(os.path.join(self.runtime_base, "config"))
        os.mkdir(os.path.join(self.runtime_base, "keys"))

        # Identity file
        identity_path = resolve_path("config", "identity.json")
        with open(identity_path, "w", encoding="utf-8") as f:
            json.dump({"fingerprint": "local_host_fp"}, f)

        # Fake vendor_dilithium_pub.pem
        vendor_pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")
        with open(vendor_pub_path, "wb") as f:
            f.write(b"FAKE_DIL_PUB")  # placeholder

        # Minimal install_state.json
        install_state_path = resolve_path("license", "install_state.json")
        with open(install_state_path, "w", encoding="utf-8") as f:
            json.dump({}, f)

        # We'll define the license_path in config:
        self.license_path = os.path.join(self.temp_dir, "runtime", "license", "license.key")
        self.cfg.raw_dict["license_path"] = self.license_path

        self.audit_chain = AuditChain(chain_dir=self.temp_dir)
        self.manager = LicenseManager(self.cfg, audit_chain=self.audit_chain, sentinel_runtime_base=self.runtime_base)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _read_chain_events(self):
        chain_file = self.audit_chain.current_file_path
        if not os.path.isfile(chain_file):
            return []
        with open(chain_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [json.loads(ln) for ln in lines]

    def test_file_not_found(self):
        # no license.key created => watch_only
        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["event"], "LICENSE_INVALID")
        self.assertIn("file_missing", evts[0]["metadata"]["reason"])

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_valid_license_activated(self, mock_verify):
        # create a base64-encoded JSON with minimal fields
        lic_obj = {
            "license_uuid": "abcd-1234",
            "expires_on": "9999-12-31",
            "signature": "fake_signature_b64"
        }
        import base64
        lic_json_str = json.dumps(lic_obj)
        b64_data = base64.b64encode(lic_json_str.encode("utf-8")).decode("utf-8")

        with open(self.license_path, "w", encoding="utf-8") as f:
            f.write(b64_data)

        self.manager.load_license()
        self.assertTrue(is_license_valid(self.manager))
        self.assertFalse(is_watch_only(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["event"], "LICENSE_ACTIVATED")

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=False)
    def test_signature_fail(self, mock_verify):
        lic_obj = {
            "license_uuid": "xyz-999",
            "expires_on": "9999-12-31",
            "signature": "some_base64"
        }
        lic_json_str = json.dumps(lic_obj)
        b64_data = json.dumps(lic_obj)  # intentionally not base64 to see if parse fails
        # Actually let's just store as base64 anyway
        import base64
        encoded = base64.b64encode(lic_json_str.encode("utf-8")).decode("utf-8")
        with open(self.license_path, "w", encoding="utf-8") as f:
            f.write(encoded)

        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(evts[0]["event"], "LICENSE_INVALID")
        self.assertIn("signature_fail", evts[0]["metadata"]["reason"])

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_expired_license(self, mock_verify):
        lic_obj = {
            "license_uuid": "expired-lic",
            "expires_on": "2000-01-01",
            "signature": "somebase64"
        }
        from base64 import b64encode
        data_str = json.dumps(lic_obj)
        enc = b64encode(data_str.encode("utf-8")).decode("utf-8")
        with open(self.license_path, "w", encoding="utf-8") as f:
            f.write(enc)

        self.manager.load_license()
        self.assertTrue(is_watch_only(self.manager))
        evts = self._read_chain_events()
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["event"], "LICENSE_EXPIRED")

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_install_count_exceeded(self, mock_verify):
        # set max_installs=1 => second unique host => exceed
        lic_obj = {
            "license_uuid": "install-limit-xyz",
            "expires_on": "9999-12-31",
            "signature": "somebase64",
            "max_installs": 1
        }
        import base64
        data_str = json.dumps(lic_obj)
        enc = base64.b64encode(data_str.encode("utf-8")).decode("utf-8")
        with open(self.license_path, "w", encoding="utf-8") as f:
            f.write(enc)

        # first load => success
        self.manager.load_license()
        self.assertTrue(is_license_valid(self.manager))
        # second load => simulate new host identity => limit exceeded
        with patch("aepok_sentinel.core.license.LicenseManager._get_local_host_fp", return_value="another_fp"):
            self.manager.load_license()
            self.assertTrue(is_watch_only(self.manager))
        evts = self._read_chain_events()
        # Expect LICENSE_ACTIVATED then INSTALL_REJECTED
        self.assertEqual(evts[0]["event"], "LICENSE_ACTIVATED")
        self.assertEqual(evts[1]["event"], "INSTALL_REJECTED")

    def test_upload_license_ok(self):
        """
        Upload a new license => old is replaced => load again
        """
        # write a valid one
        from base64 import b64encode
        lic_obj = {
            "license_uuid": "orig-abc",
            "expires_on": "9999-12-31",
            "signature": "somebase64"
        }
        enc = b64encode(json.dumps(lic_obj).encode("utf-8")).decode("utf-8")
        with open(self.license_path, "w", encoding="utf-8") as f:
            f.write(enc)

        with patch.object(self.manager, "_verify_license_signature", return_value=True):
            self.manager.load_license()
            self.assertTrue(is_license_valid(self.manager))

            # new license => signature fail => degrade
            bad_lic_path = os.path.join(self.temp_dir, "bad.license")
            lic_obj2 = {
                "license_uuid": "bad-xyz",
                "expires_on": "9999-12-31",
                "signature": "fakeB64"
            }
            enc2 = b64encode(json.dumps(lic_obj2).encode("utf-8")).decode("utf-8")
            with open(bad_lic_path, "w", encoding="utf-8") as bf:
                bf.write(enc2)

            with patch.object(self.manager, "_verify_license_signature", return_value=False):
                self.manager.upload_license(bad_lic_path)
                self.assertTrue(is_watch_only(self.manager))

        evts = self._read_chain_events()
        # LICENSE_ACTIVATED, then LICENSE_INVALID
        e_names = [e["event"] for e in evts]
        self.assertIn("LICENSE_ACTIVATED", e_names)
        self.assertIn("LICENSE_INVALID", e_names)

    @patch("aepok_sentinel.core.license.LicenseManager._verify_license_signature", return_value=True)
    def test_install_updated_event(self, mock_verify):
        """
        Whenever we add a new host, we save install_state.json => must emit INSTALL_UPDATED.
        """
        lic_obj = {
            "license_uuid": "some-lic",
            "expires_on": "9999-12-31",
            "signature": "somebase64",
            "max_installs": 10
        }
        from base64 import b64encode
        data_str = json.dumps(lic_obj)
        enc = b64encode(data_str.encode("utf-8")).decode("utf-8")
        with open(self.license_path, "w", encoding="utf-8") as f:
            f.write(enc)

        self.manager.load_license()
        events = self._read_chain_events()
        # Expect LICENSE_ACTIVATED + INSTALL_UPDATED
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event"], "LICENSE_ACTIVATED")
        self.assertEqual(events[1]["event"], "INSTALL_UPDATED")
        self.assertIn("install_state.json", events[1]["metadata"]["file"])


if __name__ == "__main__":
    unittest.main()