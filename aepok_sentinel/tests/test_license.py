"""
Unit tests for aepok_sentinel/core/license.py

Validates:
- Missing/corrupt license => watch-only or error if license_required=true
- Signature check (we mock out the pqc_crypto verify function)
- Expired => watch-only
- Hardware mismatch => watch-only
- Bound hardware with license_required => raise LicenseError or degrade
- Valid => fully valid
"""

import os
import unittest
import json
import base64
from unittest.mock import patch, MagicMock

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import (
    LicenseManager, LicenseError, is_watch_only, is_license_valid
)


class TestLicense(unittest.TestCase):

    def setUp(self):
        self.config_dict = {
            "schema_version": 1,
            "mode": "cloud",
            "license_required": False,
            "bound_to_hardware": False,
            "allow_classical_fallback": True,
            "license_path": "test_license.json"
        }

        # We'll create a small JSON license in memory
        # "signature" is base64 of a JSON dict with "dilithium"/"rsa"
        self.license_data = {
            "license_version": 1,
            "issued_to": "TestUser",
            "expires_on": "9999-12-31",
            "signature": "",
            "features": ["full_encryption"],
            "license_type": "individual"
        }

        # We mock the filesystem read in each test so we don't need actual files.

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    def test_valid_license(self, mock_open, mock_isfile):
        """
        If license is valid, not expired, signature passes => valid = True, watch_only = False
        """
        # We'll produce a dummy signature with base64 of {"dilithium":"abc", "rsa":"xyz"}
        sig_dict = {"dilithium": "abc", "rsa": "xyz"}
        sig_b64 = base64.b64encode(json.dumps(sig_dict).encode("utf-8")).decode("utf-8")
        self.license_data["signature"] = sig_b64

        file_content = json.dumps(self.license_data).encode("utf-8")
        mock_open.return_value.__enter__.return_value.read.return_value = file_content

        # mock the verify_content_signature call to return True
        with patch("aepok_sentinel.core.license.verify_content_signature", return_value=True):
            cfg = SentinelConfig(self.config_dict)
            lm = LicenseManager(cfg)
            lm.load_license()

            self.assertTrue(is_license_valid(lm))
            self.assertFalse(is_watch_only(lm))

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    def test_missing_signature(self, mock_open, mock_isfile):
        """
        If signature is missing => degrade watch-only or raise if license_required
        """
        data_no_sig = {
            "license_version": 1,
            "issued_to": "TestUser",
            "expires_on": "9999-12-31"
        }
        file_content = json.dumps(data_no_sig).encode("utf-8")
        mock_open.return_value.__enter__.return_value.read.return_value = file_content

        # license_required = false => degrade
        cfg_dict = self.config_dict.copy()
        cfg_dict["license_required"] = False
        cfg = SentinelConfig(cfg_dict)
        lm = LicenseManager(cfg)
        lm.load_license()
        self.assertFalse(is_license_valid(lm))
        self.assertTrue(is_watch_only(lm))

        # license_required = true => raise
        cfg_dict2 = self.config_dict.copy()
        cfg_dict2["license_required"] = True
        cfg2 = SentinelConfig(cfg_dict2)
        lm2 = LicenseManager(cfg2)
        with self.assertRaises(LicenseError):
            lm2.load_license()

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    def test_expired_license(self, mock_open, mock_isfile):
        """
        If expires_on < today => degrade watch-only
        """
        data_expired = {
            "license_version": 1,
            "issued_to": "OldUser",
            "expires_on": "2000-01-01",
            "signature": "dummy",
        }
        file_content = json.dumps(data_expired).encode("utf-8")
        mock_open.return_value.__enter__.return_value.read.return_value = file_content

        # Also mock verify => True
        with patch("aepok_sentinel.core.license.verify_content_signature", return_value=True):
            cfg = SentinelConfig(self.config_dict)
            lm = LicenseManager(cfg)
            lm.load_license()
            self.assertFalse(is_license_valid(lm))
            self.assertTrue(is_watch_only(lm))

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    def test_tampered_signature(self, mock_open, mock_isfile):
        """
        If signature check fails => degrade watch-only or raise if required
        """
        self.license_data["signature"] = "some_base64"
        file_content = json.dumps(self.license_data).encode("utf-8")
        mock_open.return_value.__enter__.return_value.read.return_value = file_content

        # mock the verify call => False
        with patch("aepok_sentinel.core.license.verify_content_signature", return_value=False):
            cfg = SentinelConfig(self.config_dict)
            lm = LicenseManager(cfg)
            lm.load_license()
            self.assertFalse(is_license_valid(lm))
            self.assertTrue(is_watch_only(lm))

    @patch("os.path.isfile", return_value=False)
    def test_file_not_found(self, mock_isfile):
        """
        If file not found => watch-only or raise if license_required
        """
        cfg1 = self.config_dict.copy()
        cfg1["license_required"] = False
        sc1 = SentinelConfig(cfg1)
        lm1 = LicenseManager(sc1)
        lm1.load_license()
        self.assertTrue(is_watch_only(lm1))

        cfg2 = self.config_dict.copy()
        cfg2["license_required"] = True
        sc2 = SentinelConfig(cfg2)
        lm2 = LicenseManager(sc2)
        with self.assertRaises(LicenseError):
            lm2.load_license()

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    def test_bound_hardware_mismatch(self, mock_open, mock_isfile):
        """
        If bound_to != local fingerprint => degrade or fail if required
        """
        data_bound = {
            "license_version": 1,
            "issued_to": "BoundUser",
            "expires_on": "9999-12-31",
            "signature": "validsig",  # We'll mock verify => True
            "bound_to": "not_the_local_hash"
        }
        file_content = json.dumps(data_bound).encode("utf-8")
        mock_open.return_value.__enter__.return_value.read.return_value = file_content

        with patch("aepok_sentinel.core.license.verify_content_signature", return_value=True):
            cfg_dict = self.config_dict.copy()
            cfg_dict["license_required"] = False
            cfg_dict["bound_to_hardware"] = True
            cfg = SentinelConfig(cfg_dict)
            lm = LicenseManager(cfg)
            # We'll also patch compute_local_fingerprint to return something else
            with patch("aepok_sentinel.core.license.LicenseManager._compute_local_fingerprint",
                       return_value="some_other_hash"):
                lm.load_license()
                self.assertTrue(is_watch_only(lm))
                self.assertFalse(is_license_valid(lm))

            # If license_required => raise
            cfg2_dict = cfg_dict.copy()
            cfg2_dict["license_required"] = True
            cfg2 = SentinelConfig(cfg2_dict)
            lm2 = LicenseManager(cfg2)
            with patch("aepok_sentinel.core.license.LicenseManager._compute_local_fingerprint",
                       return_value="some_other_hash"):
                with self.assertRaises(LicenseError):
                    lm2.load_license()

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", create=True)
    def test_valid_bound_hardware(self, mock_open, mock_isfile):
        """
        If bound_to matches local, not expired, sig verify => valid
        """
        data_bound = {
            "license_version": 1,
            "issued_to": "BoundUser",
            "expires_on": "9999-12-31",
            "signature": "some_base64_sig",
            "bound_to": "mock_fingerprint"
        }
        file_content = json.dumps(data_bound).encode("utf-8")
        mock_open.return_value.__enter__.return_value.read.return_value = file_content

        with patch("aepok_sentinel.core.license.verify_content_signature", return_value=True):
            cfg_dict = self.config_dict.copy()
            cfg_dict["license_required"] = True
            cfg_dict["bound_to_hardware"] = True
            cfg = SentinelConfig(cfg_dict)
            lm = LicenseManager(cfg)
            with patch("aepok_sentinel.core.license.LicenseManager._compute_local_fingerprint",
                       return_value="mock_fingerprint"):
                lm.load_license()
                self.assertTrue(is_license_valid(lm))
                self.assertFalse(is_watch_only(lm))


if __name__ == "__main__":
    unittest.main()