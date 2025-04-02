"""
Unit tests for aepok_sentinel/utils/sentinelrc_schema.py

Validates:
 - required fields
 - mode enumeration
 - defaults for optional
 - unknown keys check
 - tls_mode check
"""

import unittest

from aepok_sentinel.utils.sentinelrc_schema import (
    validate_sentinelrc, DEFAULTS, REQUIRED_FIELDS
)


class TestSentinelrcSchema(unittest.TestCase):

    def test_missing_required(self):
        raw = {}
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Missing required field", str(ctx.exception))

    def test_schema_version_invalid(self):
        raw = {
            "schema_version": 0,
            "mode": "cloud"
        }
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("schema_version must be an integer", str(ctx.exception))

    def test_mode_invalid(self):
        raw = {
            "schema_version": 1,
            "mode": "invalid_mode"
        }
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Invalid mode 'invalid_mode'", str(ctx.exception))

    def test_basic_valid(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud"
        }
        final = validate_sentinelrc(raw)
        self.assertEqual(final["mode"], "cloud")
        self.assertFalse(final["allow_delete"])  # default
        self.assertIn("log_path", final)
        self.assertIn("tls_mode", final)
        self.assertEqual(final["tls_mode"], "hybrid")  # default

    def test_unknown_keys_disallowed(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "extra_field": "??"
        }
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Unknown config key 'extra_field'", str(ctx.exception))

    def test_unknown_keys_allowed(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "allow_unknown_keys": True,
            "extra_field": 123
        }
        final = validate_sentinelrc(raw)
        self.assertTrue(final["allow_unknown_keys"])
        # no error

    def test_tls_mode_invalid(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "tls_mode": "pqc_fantasy"
        }
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Invalid tls_mode 'pqc_fantasy'", str(ctx.exception))

    def test_tls_mode_valid(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "tls_mode": "pqc-only"
        }
        final = validate_sentinelrc(raw)
        self.assertEqual(final["tls_mode"], "pqc-only")


if __name__ == "__main__":
    unittest.main()