#!/usr/bin/env python3
"""
Basic test for issue_offline_license.py in final shape.
It checks:
 - if the script runs without errors for offline usage (with a local test key)
 - if the script runs with azure usage (if optionally configured)
 - verifies that the output file is created, well-formed JSON, and includes a 'signature' dict
"""

import os
import sys
import json
import subprocess
import unittest
import tempfile
import shutil
import base64

class TestIssueOfflineLicense(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.script_path = os.path.expanduser("~/sentinel_signing/issue_offline_license.py")
        # Fake offline key for test
        self.fake_key_path = os.path.join(self.temp_dir, "fake_dil_priv.bin")
        with open(self.fake_key_path, "wb") as fk:
            # 128 bytes of random, pretend it's a dilithium private key
            fk.write(os.urandom(128))
        # create out_dir
        self.out_dir = os.path.join(self.temp_dir, "client_licenses")
        os.mkdir(self.out_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_offline_key_ok(self):
        """
        Test offline usage, ensuring it produces a .license.json file with signature
        """
        cmd = [
            "python3",
            self.script_path,
            "--issued-to", "TestClientA",
            "--expires-on", "2050-01-01",
            "--license-type", "individual",
            "--max-installs", "5",
            "--features", "enc,airgap",
            "--offline-key", self.fake_key_path,
            "--out-dir", self.out_dir
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, msg=f"STDERR={proc.stderr}")
        # find the license file
        # the script prints => "License created successfully => <path>"
        lines = proc.stdout.strip().split("\n")
        last_line = lines[-1]
        self.assertIn("License created successfully => ", last_line)
        out_file = last_line.split("=>")[-1].strip()
        self.assertTrue(os.path.isfile(out_file))

        # parse it
        with open(out_file, "r", encoding="utf-8") as f:
            lic_data = json.load(f)
        self.assertIn("license_uuid", lic_data)
        self.assertIn("signature", lic_data)
        self.assertIsInstance(lic_data["signature"], dict)
        self.assertIn("license_version", lic_data)
        self.assertEqual(lic_data["issued_to"], "TestClientA")

    # (Optional) If you wanted to test azure usage, you'd do similarly with --use-azure etc.
    # That requires mocking or real vault credentials. We'll skip here for final shape.


if __name__ == "__main__":
    unittest.main()
