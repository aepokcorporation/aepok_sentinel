"""
Unit tests for aepok_sentinel/core/provision_device.py

We do a minimal coverage approach:
 - test normal flow with mocked user input + license file
 - test repeated provisioning => fails
 - test missing directories => fails
 - test sign/sig creation
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
        # We'll create subdirs that 'directory_contract' might expect
        os.makedirs(os.path.join(self.temp_dir, "config"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "license"), exist_ok=True)
        os.makedirs(os.path.join(self.temp_dir, "identity"), exist_ok=True)  # if needed
        os.makedirs(os.path.join(self.temp_dir, "keys"), exist_ok=True)

        # Create a mock AuditChain
        self.audit_chain = AuditChain(chain_dir=self.temp_dir)

        self.provisioner = ProvisionDevice(runtime_base=self.temp_dir, audit_chain=self.audit_chain)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_provision_happy_path(self):
        """
        Normal scenario: no provisioning_complete.flag, valid config, existing license file => success
        """
        # Make a dummy license file
        lic_path = os.path.join(self.temp_dir, "fake_license.key")
        with open(lic_path, "w", encoding="utf-8") as f:
            f.write("license content")

        # We'll define a raw_config that passes sentinelrc_schema
        raw_config = {
            "schema_version": 1,
            "mode": "cloud",
            "enforcement_mode": "STRICT",
            "scan_paths": ["/some/data"],
            "exclude_paths": [],
            "license_required": True
        }

        # Patch the calls to upload_license + rotate_keys so we don't do real crypto
        with patch("aepok_sentinel.core.provision_device.LicenseManager.upload_license") as mock_uplic, \
             patch("aepok_sentinel.core.provision_device.LicenseManager.load_license") as mock_ldlic, \
             patch("aepok_sentinel.core.provision_device.KeyManager.rotate_keys") as mock_rot:

            # No exceptions => success
            self.provisioner.provision(raw_config, lic_path)

        # Check that provisioning_complete.flag is created
        prov_flag = os.path.join(self.temp_dir, "provisioning_complete.flag")
        self.assertTrue(os.path.isfile(prov_flag))

        # Check that we have .sentinelrc and .sentinelrc.sig
        src = os.path.join(self.temp_dir, "config/.sentinelrc")
        self.assertTrue(os.path.isfile(src))
        self.assertTrue(os.path.isfile(src + ".sig"))

        # Check that trust_anchor.json is created
        ta = os.path.join(self.temp_dir, "trust_anchor.json")
        self.assertTrue(os.path.isfile(ta))
        self.assertTrue(os.path.isfile(ta + ".sig"))

        # Check an appended event => DEVICE_PROVISIONED
        chain_file = os.path.join(self.temp_dir, "audit_chain.log")
        self.assertTrue(os.path.isfile(chain_file))
        with open(chain_file, "r", encoding="utf-8") as cf:
            lines = cf.readlines()
        self.assertTrue(any('"event":"DEVICE_PROVISIONED"' in line for line in lines))

    def test_provision_already_done(self):
        """
        If provisioning_complete.flag exists => fail immediately
        """
        flag_path = os.path.join(self.temp_dir, "provisioning_complete.flag")
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write("done")

        with self.assertRaises(ProvisionError):
            self.provisioner.provision({}, "/no/license")

    def test_missing_dirs(self):
        """
        If config or license directories are missing => fail
        We'll remove the 'keys' dir
        """
        shutil.rmtree(os.path.join(self.temp_dir, "keys"))
        raw_conf = {"schema_version": 1, "mode": "cloud", "enforcement_mode": "STRICT"}
        lic = os.path.join(self.temp_dir, "dummy.lic")
        with open(lic, "w", encoding="utf-8") as f:
            f.write("license x")
        # Expect ProvisionError when generate_keys tries to find 'keys' dir
        with self.assertRaises(ProvisionError):
            self.provisioner.provision(raw_conf, lic)
