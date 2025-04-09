#!/usr/bin/env python3
# test_issue_offline_license.py
"""
Unit tests for issue_offline_license.py

Checks:
 - Offline usage with a fake key
 - Ensures .key file is produced in base64 form
 - Decodes the .key => verifies JSON with 'signature' field
 - Validates 10-year expiration limit
"""

import os
import sys
import json
import base64
import subprocess
import unittest
import tempfile
import shutil


class TestIssueOfflineLicense(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.script_path = os.path.expanduser("~/sentinel_signing/issue_offline_license.py")

        # Create a fake offline key
        self.fake_key_path = os.path.join(self.temp_dir, "fake_dil_priv.bin")
        with open(self.fake_key_path, "wb") as fk:
            fk.write(os.urandom(128))  # 128 random bytes, pretend it's a private key

        # Create out_dir
        self.out_dir = os.path.join(self.temp_dir, "client_licenses")
        os.mkdir(self.out_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_offline_key_ok(self):
        """
        Test offline usage => produce a .key file with base64 content.
        Then decode that content => ensure JSON with 'signature' dict is present.
        """
        cmd = [
            "python3",
            self.script_path,
            "--issued-to", "TestClient",
            "--expires-on", "2030-01-01",
            "--license-type", "individual",
            "--max-installs", "5",
            "--features", "enc,airgap",
            "--offline-key", self.fake_key_path,
            "--out-dir", self.out_dir
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, msg=f"STDERR={proc.stderr}")

        # Output should mention "License created successfully => <path>"
        lines = proc.stdout.strip().split("\n")
        last_line = lines[-1]
        self.assertIn("License created successfully => ", last_line)
        out_file = last_line.split("=>")[-1].strip()
        self.assertTrue(os.path.isfile(out_file), "Expected a .key file to be created")

        # Read the base64 data
        with open(out_file, "r", encoding="utf-8") as f:
            b64_data = f.read().strip()
        decoded = base64.b64decode(b64_data)
        lic_obj = json.loads(decoded.decode("utf-8"))
        self.assertIn("license_uuid", lic_obj)
        self.assertIn("signature", lic_obj)
        self.assertIsInstance(lic_obj["signature"], dict, "Signature must be a dict object in JSON")
        self.assertEqual(lic_obj["issued_to"], "TestClient")

    def test_ten_year_limit(self):
        """
        If user attempts to set expires-on beyond 10 years from now => script fails.
        """
        cmd = [
            "python3",
            self.script_path,
            "--issued-to", "ExcessClient",
            "--expires-on", "2055-01-01",  # definitely more than 10 years
            "--offline-key", self.fake_key_path,
            "--out-dir", self.out_dir
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0, "Should fail due to >10 year limit.")
        self.assertIn("exceeds the 10-year maximum limit", proc.stderr)

    def test_missing_out_dir(self):
        # remove out_dir => must fail
        shutil.rmtree(self.out_dir)
        cmd = [
            "python3",
            self.script_path,
            "--issued-to", "TestClient",
            "--expires-on", "2030-01-01",
            "--offline-key", self.fake_key_path,
            "--out-dir", self.out_dir
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0, "Should fail if the output directory is missing.")
        self.assertIn("does not exist", proc.stderr)

    def test_expired_today(self):
        """
        If expires-on <= today => fail
        """
        from datetime import date
        today_str = date.today().strftime("%Y-%m-%d")
        cmd = [
            "python3",
            self.script_path,
            "--issued-to", "ExpiredUser",
            "--expires-on", today_str,  # same day => fail
            "--offline-key", self.fake_key_path,
            "--out-dir", self.out_dir
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("is not in the future", proc.stderr)


if __name__ == "__main__":
    unittest.main()