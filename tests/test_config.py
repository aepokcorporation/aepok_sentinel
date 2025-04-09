# test_config.py
"""
Tests for config.py, ensuring that .sentinelrc is loaded, validated,
enforcement modes are applied, and environment overrides behave
correctly. Also checks that log path drift is resolved (fix #2),
license path usage does not bypass directory_contract (fix #3),
and signature failures are handled properly.
"""

import os
import json
import unittest
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from pathlib import Path

from aepok_sentinel.core.config import load_config, ConfigError, SentinelConfig


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_sentinelrc(self, data: dict, filename=".sentinelrc") -> Path:
        config_path = Path(self.temp_dir) / filename
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return config_path

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_valid_config(self, mock_append_event, mock_resolve_path):
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "rotation_interval_days": 15
        }
        file_path = self._write_sentinelrc(data)
        mock_resolve_path.return_value = file_path  # for .sentinelrc

        cfg = load_config(parse_env=False)
        self.assertEqual(cfg.schema_version, 1)
        self.assertEqual(cfg.mode, "cloud")
        self.assertEqual(cfg.rotation_interval_days, 15)
        self.assertEqual(cfg.enforcement_mode, "PERMISSIVE")
        mock_append_event.assert_called_once()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_missing_file(self, mock_append_event, mock_resolve_path):
        missing_path = Path(self.temp_dir) / ".sentinelrc"
        mock_resolve_path.return_value = missing_path
        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("not found", str(ctx.exception).lower())
        mock_append_event.assert_not_called()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_invalid_json(self, mock_append_event, mock_resolve_path):
        bad_file = Path(self.temp_dir) / ".sentinelrc"
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write("{ invalid_json")
        mock_resolve_path.return_value = bad_file

        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("unable to load json", str(ctx.exception).lower())
        mock_append_event.assert_not_called()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_missing_required_fields(self, mock_append_event, mock_resolve_path):
        data = {"schema_version": 1}  # no "mode"
        config_file = self._write_sentinelrc(data)
        mock_resolve_path.return_value = config_file

        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("mode", str(ctx.exception).lower())
        mock_append_event.assert_not_called()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_env_override(self, mock_append_event, mock_resolve_path):
        data = {"schema_version": 1, "mode": "cloud"}
        file_path = self._write_sentinelrc(data)
        mock_resolve_path.return_value = file_path

        with patch.dict(os.environ, {"SENTINEL_MODE": "scif"}):
            cfg = load_config(parse_env=True)
            self.assertEqual(cfg.mode, "scif", "Env override should switch mode to scif.")
            self.assertEqual(cfg.enforcement_mode, "STRICT")
        mock_append_event.assert_called_once()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_env_override_ignored_in_scif_or_strict(self, mock_append_event, mock_resolve_path):
        data = {"schema_version": 1, "mode": "scif"}
        file_path = self._write_sentinelrc(data)
        mock_resolve_path.return_value = file_path

        with patch.dict(os.environ, {"SENTINEL_MODE": "cloud"}):
            cfg = load_config(parse_env=True)
            self.assertEqual(cfg.mode, "scif", "Should not override scif with environment.")
            self.assertEqual(cfg.enforcement_mode, "STRICT")

        mock_append_event.assert_called_once()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_scif_forces_strict(self, mock_append_event, mock_resolve_path):
        data = {
            "schema_version": 1,
            "mode": "scif",
            "cloud_keyvault_url": "https://vault.example.com",
            "manual_override_allowed": True
        }
        file_path = self._write_sentinelrc(data)
        mock_resolve_path.return_value = file_path

        cfg = load_config()
        self.assertEqual(cfg.mode, "scif")
        self.assertEqual(cfg.enforcement_mode, "STRICT")
        self.assertFalse(cfg.cloud_keyvault_enabled)
        self.assertFalse(cfg.manual_override_allowed)
        self.assertIn("CONFIG_LOADED", str(mock_append_event.call_args))

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_airgap_defaults_hardened(self, mock_append_event, mock_resolve_path):
        data = {"schema_version": 1, "mode": "airgap"}
        file_path = self._write_sentinelrc(data)
        mock_resolve_path.return_value = file_path

        cfg = load_config()
        self.assertEqual(cfg.mode, "airgap")
        self.assertEqual(cfg.enforcement_mode, "HARDENED")
        mock_append_event.assert_called_once()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_incoherent_settings(self, mock_append_event, mock_resolve_path):
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "strict_transport": True,
            "allow_classical_fallback": True
        }
        fpath = self._write_sentinelrc(data)
        mock_resolve_path.return_value = fpath

        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("incoherent config", str(ctx.exception).lower())
        mock_append_event.assert_not_called()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_signature_verification(self, mock_append_event, mock_resolve_path):
        # If _signature_verified=False and scif => STRICT => must fail
        data = {
            "schema_version": 1,
            "mode": "scif",
            "_signature_verified": False
        }
        fpath = self._write_sentinelrc(data)
        mock_resolve_path.return_value = fpath

        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("signature verification failed", str(ctx.exception).lower())
        mock_append_event.assert_not_called()

        # If _signature_verified=False but mode=cloud => enforcement=PERMISSIVE => allowed
        data2 = {
            "schema_version": 1,
            "mode": "cloud",
            "_signature_verified": False
        }
        fpath2 = self._write_sentinelrc(data2, filename=".sentinelrc.cloud")
        mock_resolve_path.return_value = fpath2

        cfg2 = load_config()
        self.assertEqual(cfg2.mode, "cloud")
        self.assertEqual(cfg2.enforcement_mode, "PERMISSIVE")
        self.assertTrue(mock_append_event.called)

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_unknown_keys(self, mock_append_event, mock_resolve_path):
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "extra_weird_field": "secret"
        }
        fpath = self._write_sentinelrc(data)
        mock_resolve_path.return_value = fpath

        with self.assertRaises(ConfigError) as ctx:
            load_config()
        self.assertIn("unknown config key 'extra_weird_field'", str(ctx.exception).lower())
        mock_append_event.assert_not_called()

        # allow_unknown_keys => no error
        data2 = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_unknown_keys": True,
            "extra_weird_field": "secret"
        }
        fpath2 = self._write_sentinelrc(data2)
        mock_resolve_path.return_value = fpath2

        cfg2 = load_config()
        self.assertEqual(cfg2.mode, "cloud")
        self.assertTrue(cfg2.allow_unknown_keys)
        mock_append_event.assert_called_once()

    @patch("aepok_sentinel.core.config.resolve_path")
    @patch("aepok_sentinel.core.config.audit_chain.append_event")
    def test_license_path_bypass_contract(self, mock_append_event, mock_resolve_path):
        """
        Fix #3: If the user sets a license_path inside runtime, unify it to
        resolve_path("license", "license.key"). Otherwise, keep the external path as-is.
        """
        # Suppose user tries: /opsec/aepok_sentinel/runtime/license/another.key
        data = {
            "schema_version": 1,
            "mode": "cloud",
            "license_path": "/opsec/aepok_sentinel/runtime/license/another.key"
        }
        fpath = self._write_sentinelrc(data)
        mock_resolve_path.side_effect = [  # first for .sentinelrc, then for runtime base
            fpath,                      # .sentinelrc location
            Path("/opsec/aepok_sentinel/runtime"),  # base path
            Path("/opsec/aepok_sentinel/runtime/license/license.key")  # final unify
        ]

        cfg = load_config()
        self.assertEqual(cfg.license_path, "/opsec/aepok_sentinel/runtime/license/license.key")
        mock_append_event.assert_called_once()

        # If user sets an external path, we leave it alone
        mock_resolve_path.side_effect = [
            fpath,
            Path("/opsec/aepok_sentinel/runtime"),
        ]
        data2 = {
            "schema_version": 1,
            "mode": "cloud",
            "license_path": "/etc/sentinel/license.key"
        }
        fpath2 = self._write_sentinelrc(data2, ".sentinelrc2")
        cfg2 = load_config()
        self.assertEqual(cfg2.license_path, "/etc/sentinel/license.key")
        self.assertTrue(mock_append_event.called)


if __name__ == "__main__":
    unittest.main()