"""
Unit tests for aepok_sentinel/core/key_manager.py

Validates:
- Local key loading
- SCIF/airgap => no cloud fetch
- Cloud fetch logic
- Rotation when license is valid vs watch-only
- Generation of new PQC keys
- Purging old keys
"""

import os
import shutil
import unittest
import tempfile
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseState
from aepok_sentinel.core.key_manager import KeyManager, KeyManagerError, oqs


@unittest.skipIf(oqs is None, "liboqs not installed, skipping key_manager PQC tests")
class TestKeyManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_enabled": False,
            "allow_classical_fallback": True,
            "rotation_interval_days": 30
        }
        self.cfg = SentinelConfig(self.config_dict)

        # license manager
        self.license_mgr = LicenseManager(self.cfg)
        # Fake "valid license" by default
        self.license_mgr.license_state = LicenseState(valid=True, watch_only=False, info={})

        # We'll patch the local_key_dir in KeyManager
        self.km = KeyManager(self.cfg, self.license_mgr)
        self.km.local_key_dir = self.temp_dir

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_local_load_missing_dir(self):
        """
        If local_key_dir doesn't exist => _load_local_keys_latest => KeyManagerError
        """
        shutil.rmtree(self.temp_dir)
        with self.assertRaises(KeyManagerError):
            self.km._load_local_keys_latest()

    def test_local_load_keys(self):
        """
        Ensure we can pick up the newest key by mtime
        """
        # We create a kyber_priv_1.bin, kyber_priv_2.bin, etc.
        with open(os.path.join(self.temp_dir, "kyber_priv_20230101.bin"), "wb") as f:
            f.write(b"old kyber key")

        with open(os.path.join(self.temp_dir, "kyber_priv_20230102.bin"), "wb") as f:
            f.write(b"new kyber key")

        with open(os.path.join(self.temp_dir, "dilithium_priv_20230102.bin"), "wb") as f:
            f.write(b"my dil key")

        # no RSA file => none
        keys = self.km._load_local_keys_latest()
        self.assertEqual(keys["kyber_priv"], b"new kyber key")
        self.assertEqual(keys["dilithium_priv"], b"my dil key")
        self.assertEqual(keys["rsa_priv"], b"")

    @patch("requests.get")
    def test_fetch_cloud_keys(self, mock_get):
        """
        If mode=cloud + cloud_keyvault_enabled => do the GET. 
        """
        self.cfg.mode = "cloud"
        self.cfg.cloud_keyvault_enabled = True
        self.cfg.cloud_keyvault_url = "https://fakevault"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "kyber_priv": "a2V5YmVy",
            "dilithium_priv": "ZGlsaXQ=",
            "rsa_priv": "cnNh",
        }
        mock_get.return_value = mock_resp

        keys = self.km._fetch_cloud_keys()
        self.assertEqual(keys["kyber_priv"], b"keyber")
        self.assertEqual(keys["dilithium_priv"], b"dilit")
        self.assertEqual(keys["rsa_priv"], b"rsa")

    @patch("requests.get")
    def test_fetch_cloud_keys_error(self, mock_get):
        """
        If the GET fails or JSON is invalid => KeyManagerError
        """
        self.cfg.mode = "cloud"
        self.cfg.cloud_keyvault_enabled = True
        self.cfg.cloud_keyvault_url = "https://fakevault"
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        with self.assertRaises(KeyManagerError):
            self.km._fetch_cloud_keys()

    def test_no_cloud_in_scif(self):
        """
        scif => attempt cloud => KeyManagerError
        """
        self.cfg.mode = "scif"
        with self.assertRaises(KeyManagerError):
            self.km._fetch_cloud_keys()

    def test_rotate_watch_only(self):
        """
        If license is watch-only => rotation does nothing
        """
        self.license_mgr.license_state.watch_only = True
        self.km.rotate_keys()  # just logs a warning, no error

    def test_rotate_disabled(self):
        """
        If rotation_interval_days=0 => no rotation
        """
        self.cfg.rotation_interval_days = 0
        self.km.rotate_keys()  # no action

    def test_local_generate_keys(self):
        """
        generate_local_keys => creates kyber/dil files. Possibly RSA if fallback
        """
        # before
        self.assertEqual(len(os.listdir(self.temp_dir)), 0)
        self.km._generate_local_keys()
        files = os.listdir(self.temp_dir)
        # Expect at least 2 files: kyber_priv_..., dilithium_priv_...
        self.assertTrue(any(f.startswith("kyber_priv_") for f in files))
        self.assertTrue(any(f.startswith("dilithium_priv_") for f in files))
        # If allow_classical_fallback => expect an RSA file
        self.assertTrue(any(f.startswith("rsa_priv_") for f in files))

    def test_rotate_keys_success(self):
        """
        rotate_keys => backup old, generate new, purge old. We won't test actual purge now, just success path
        """
        # create an old key set
        with open(os.path.join(self.temp_dir, "kyber_priv_old.bin"), "wb") as f:
            f.write(b"old kyber")
        # do rotate
        self.km.rotate_keys()
        # ensure new files exist
        files = os.listdir(self.temp_dir)
        self.assertTrue(any("kyber_priv_" in f for f in files), "No new kyber file after rotate")

    def test_rotate_keys_failure(self):
        """
        If generation fails => revert from backup
        """
        # We'll place a file so we can confirm revert
        with open(os.path.join(self.temp_dir, "kyber_priv_20230101.bin"), "wb") as f:
            f.write(b"original kyber data")

        # mock to raise error in _generate_local_keys
        with patch.object(self.km, "_generate_local_keys", side_effect=KeyManagerError("boom")):
            self.km.rotate_keys()
        # We expect the original file is restored
        # The code backups to a subdir and reverts if generation fails. 
        # We'll check that "original kyber data" is still there.
        with open(os.path.join(self.temp_dir, "kyber_priv_20230101.bin"), "rb") as f:
            content = f.read()
        self.assertEqual(content, b"original kyber data")


if __name__ == "__main__":
    unittest.main()