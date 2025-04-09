# test_provision_device.py
"""
Unit tests for provision_device.py

Covers:
 - Normal provisioning flow with valid config + license
 - Already provisioned scenario
 - Missing directories => fails
 - Basic checks for final artifacts
"""

import os
import shutil
import json
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.provision_device import ProvisionDevice, ProvisionError
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode


class TestProvisionDevice(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Simulate the runtime structure
        os.makedirs(os.path.join(self.temp_dir, "config"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "license"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "keys"), exist_ok=True)

        self.audit_chain = AuditChain(chain_dir=self.temp_dir)
        self.provisioner = ProvisionDevice(runtime_base=self.temp_dir, audit_chain=self.audit_chain)

        # Write a dummy installer key
        installer_key_path = os.path.join(self.temp_dir, "keys", "installer_dilithium_priv.bin")
        with open(installer_key_path, "wb") as f:
            f.write(b"dummy_installer_key_xxx" * 6)  # >100 bytes to pass naive check

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_provision_happy_path(self):
        """
        Normal scenario: no provisioning_complete.flag, valid config, existing license file => success
        """
        lic_path = os.path.join(self.temp_dir, "fake_license.key")
        with open(lic_path, "w", encoding="utf-8") as f:
            f.write("license content")

        raw_config = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT",
            "scan_paths": ["/some/data"],
            "exclude_paths": [],
            "license_required": True
        }

        # Patch calls to avoid real crypto or license ops
        with patch("aepok_sentinel.core.provision_device.LicenseManager.upload_license"), \
             patch("aepok_sentinel.core.provision_device.LicenseManager.load_license"), \
             patch("aepok_sentinel.core.provision_device.KeyManager.rotate_keys"):
            self.provisioner.provision(raw_config, lic_path)

        prov_flag = os.path.join(self.temp_dir, "provisioning_complete.flag")
        self.assertTrue(os.path.isfile(prov_flag))

        # .sentinelrc + .sig
        sentinelrc = os.path.join(self.temp_dir, "config", ".sentinelrc")
        self.assertTrue(os.path.isfile(sentinelrc))
        self.assertTrue(os.path.isfile(sentinelrc + ".sig"))

        # trust_anchor.json + .sig
        ta = os.path.join(self.temp_dir, "config", "trust_anchor.json")
        self.assertTrue(os.path.isfile(ta))
        self.assertTrue(os.path.isfile(ta + ".sig"))

        chain_log = os.path.join(self.temp_dir, "audit_chain.log")
        self.assertTrue(os.path.isfile(chain_log))
        with open(chain_log, "r", encoding="utf-8") as cf:
            lines = cf.readlines()
        self.assertTrue(any('"event":"DEVICE_PROVISIONED"' in line for line in lines))

    def test_provision_already_done(self):
        # create provisioning_complete.flag
        flag_path = os.path.join(self.temp_dir, "provisioning_complete.flag")
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write("done")

        with self.assertRaises(ProvisionError):
            self.provisioner.provision({}, "/no/license")

    def test_missing_dirs(self):
        """
        If keys dir is removed => generate_keys fails
        """
        shutil.rmtree(os.path.join(self.temp_dir, "keys"))
        raw_conf = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT"
        }
        lic_file = os.path.join(self.temp_dir, "dummy.lic")
        with open(lic_file, "w", encoding="utf-8") as f:
            f.write("license x")

        with patch("aepok_sentinel.core.provision_device.LicenseManager.upload_license"), \
             patch("aepok_sentinel.core.provision_device.LicenseManager.load_license"):
            with self.assertRaises(ProvisionError):
                self.provisioner.provision(raw_conf, lic_file)


if __name__ == "__main__":
    unittest.main()