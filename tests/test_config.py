"""
Unit tests for aepok_sentinel/core/config.py

Covers:
- Valid .sentinelrc parsing
- Missing required fields
- Environment variable override
- SCIF/airgap forced constraints
- Unknown keys handling
- Enforcement mode logic
- Coherence checks (strict_transport vs. allow_classical_fallback)
- Signature verification fallback
"""

import os
import json
import unittest
import tempfile
import shutil
from unittest.mock import patch

from aepok_sentinel.core.config import load_config, ConfigError, SentinelConfig


class TestConfig(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_sentinelrc(self, data: dict) -> str:
        fpath = os.path.join(self.temp_dir, "config.json")
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return fpath

    def test_valid_config(self):
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_url": "https://vault.example.com",
            "rotation_interval_days": 15
        }
        fpath = self._write_sentinelrc(data)
        config_obj = load_config(fpath, parse_env=False)

        self.assertEqual(config_obj.schema_version, 1)
        self.assertEqual(config_obj.mode, "cloud")
        self.assertEqual(config_obj.cloud_keyvault_url, "https://vault.example.com")
        self.assertEqual(config_obj.rotation_interval_days, 15)
        # Check defaults
        self.assertFalse(config_obj.allow_delete)
        self.assertEqual(config_obj.log_path, "/var/log/sentinel/")
        self.assertTrue(config_obj.encryption_enabled)
        # Enforcement mode defaults to PERMISSIVE if not set
        self.assertEqual(config_obj.enforcement_mode, "PERMISSIVE")

    def test_missing_required_fields(self):
        # Missing mode
        data1 = {"schema_version": 1}
        f1 = self._write_sentinelrc(data1)
        with self.assertRaises(ConfigError) as ctx1:
            load_config(f1)
        self.assertIn("mode", str(ctx1.exception).lower())

        # Missing schema_version
        data2 = {"mode": "cloud"}
        f2 = self._write_sentinelrc(data2)
        with self.assertRaises(ConfigError) as ctx2:
            load_config(f2)
        self.assertIn("schema_version", str(ctx2.exception).lower())

    def test_invalid_mode(self):
        data = {
            "schema_version": 1,
            "mode": "invalid_mode"
        }
        fpath = self._write_sentinelrc(data)
        with self.assertRaises(ConfigError) as ctx:
            load_config(fpath)
        self.assertIn("invalid_mode", str(ctx.exception))

    def test_env_override(self):
        data = {
            "schema_version": 1,
            "mode": "cloud"
        }
        fpath = self._write_sentinelrc(data)

        with patch.dict(os.environ, {"SENTINEL_MODE": "scif"}):
            cfg = load_config(fpath, parse_env=True)
            self.assertEqual(cfg.mode, "scif")
            # SCIF override => keyvault_url must be "", etc.
            self.assertFalse(cfg.cloud_keyvault_enabled)
            self.assertEqual(cfg.cloud_keyvault_url, "")
            self.assertFalse(cfg.manual_override_allowed)
            # Also enforcement_mode forced to STRICT
            self.assertEqual(cfg.enforcement_mode, "STRICT")

        # If parse_env=False, env var is ignored
        with patch.dict(os.environ, {"SENTINEL_MODE": "airgap"}):
            cfg2 = load_config(fpath, parse_env=False)
            self.assertEqual(cfg2.mode, "cloud")
            self.assertEqual(cfg2.enforcement_mode, "PERMISSIVE")  # unchanged

    def test_scif_constraints(self):
        data = {
            "schema_version": 1,
            "mode": "scif",
            "cloud_keyvault_url": "https://somevault",
            "manual_override_allowed": True  # SCIF should forcibly disable it
        }
        fpath = self._write_sentinelrc(data)
        cfg = load_config(fpath)
        self.assertEqual(cfg.mode, "scif")
        self.assertEqual(cfg.cloud_keyvault_url, "")
        self.assertFalse(cfg.cloud_keyvault_enabled)
        self.assertFalse(cfg.manual_override_allowed)
        self.assertTrue(cfg.decryption_requires_chain)
        self.assertTrue(cfg.chain_verification_on_decrypt)
        self.assertEqual(cfg.enforcement_mode, "STRICT")

    def test_airgap_constraints(self):
        data = {
            "schema_version": 1,
            "mode": "airgap",
            "cloud_keyvault_url": "https://vault.example.com"
        }
        fpath = self._write_sentinelrc(data)
        cfg = load_config(fpath)
        self.assertEqual(cfg.mode, "airgap")
        self.assertEqual(cfg.cloud_keyvault_url, "")
        self.assertFalse(cfg.cloud_keyvault_enabled)
        self.assertTrue(cfg.manual_override_allowed)  # not forcibly false
        self.assertTrue(cfg.decryption_requires_chain)
        # airgap defaults to HARDENED if user didn't specify
        self.assertEqual(cfg.enforcement_mode, "HARDENED")

    def test_file_not_found(self):
        with self.assertRaises(ConfigError):
            load_config("/does/not/exist.json")

    def test_invalid_json(self):
        bad_f = os.path.join(self.temp_dir, "bad.json")
        with open(bad_f, "w", encoding="utf-8") as f:
            f.write("{invalid_json")
        with self.assertRaises(ConfigError):
            load_config(bad_f)

    def test_unknown_keys(self):
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "extra_field": "something"
        }
        fpath = self._write_sentinelrc(data)
        with self.assertRaises(ConfigError) as ctx:
            load_config(fpath)
        self.assertIn("unknown config key 'extra_field'", str(ctx.exception).lower())

        # If allow_unknown_keys=true, we accept the extra field
        data2 = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_unknown_keys": True,
            "extra_field": "something"
        }
        fpath2 = self._write_sentinelrc(data2)
        cfg2 = load_config(fpath2)
        self.assertEqual(cfg2.mode, "cloud")
        self.assertTrue(cfg2.allow_unknown_keys)

    def test_incoherent_settings(self):
        """
        strict_transport + allow_classical_fallback => must raise error
        """
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "strict_transport": True,
            "allow_classical_fallback": True
        }
        fpath = self._write_sentinelrc(data)
        with self.assertRaises(ConfigError) as ctx:
            load_config(fpath)
        self.assertIn("incoherent config", str(ctx.exception).lower())

    def test_signature_verification_fallback(self):
        """
        If _signature_verified=False is set by the schema, we fail in HARDENED or STRICT
        but succeed in PERMISSIVE.
        """
        # 1) SCIF => forced STRICT => fails if signature_verified=False
        data_scif = {
            "schema_version": 1,
            "mode": "scif",
            "_signature_verified": False
        }
        f_scif = self._write_sentinelrc(data_scif)
        with self.assertRaises(ConfigError) as ctx:
            load_config(f_scif)
        self.assertIn("signature verification failed", str(ctx.exception).lower())

        # 2) Hard-coded airgap => default HARDENED => also fails
        data_airgap = {
            "schema_version": 1,
            "mode": "airgap",
            "_signature_verified": False
        }
        f_airgap = self._write_sentinelrc(data_airgap)
        with self.assertRaises(ConfigError) as ctx2:
            load_config(f_airgap)
        self.assertIn("signature verification failed", str(ctx2.exception).lower())

        # 3) Cloud => default PERMISSIVE => no error
        data_cloud = {
            "schema_version": 1,
            "mode": "cloud",
            "_signature_verified": False
        }
        f_cloud = self._write_sentinelrc(data_cloud)
        cfg_cloud = load_config(f_cloud)
        self.assertEqual(cfg_cloud.mode, "cloud")
        self.assertEqual(cfg_cloud.enforcement_mode, "PERMISSIVE")  # no exception raised


if __name__ == "__main__":
    unittest.main()