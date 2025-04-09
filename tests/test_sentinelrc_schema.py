# test_sentinelrc_schema.py
"""
Unit tests for sentinelrc_schema.py

Checks:
 - Missing required fields => ValueError
 - schema_version >= 1
 - mode => valid enumeration
 - tls_mode => valid enumeration
 - unknown keys => error if allow_unknown_keys=false
 - defaults assigned if not present
"""

import unittest

from aepok_sentinel.utils.sentinelrc_schema import (
    validate_sentinelrc,
    DEFAULTS,
    REQUIRED_FIELDS
)


class TestSentinelrcSchema(unittest.TestCase):
    def test_missing_required_fields(self):
        raw = {}
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Missing required field", str(ctx.exception))

    def test_schema_version_invalid(self):
        raw = {"schema_version": 0, "mode": "cloud"}
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("must be an integer >= 1", str(ctx.exception))

    def test_invalid_mode(self):
        raw = {"schema_version": 1, "mode": "invalid_mode"}
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Invalid mode 'invalid_mode'", str(ctx.exception))

    def test_defaults_assigned(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud"
        }
        final = validate_sentinelrc(raw)
        # Some known defaults
        self.assertFalse(final["allow_delete"])
        self.assertEqual(final["tls_mode"], "hybrid")
        self.assertFalse(final["allow_unknown_keys"])

    def test_unknown_keys_disallowed(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "extra_field": 123
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
        # No error => pass

    def test_tls_mode_invalid(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "tls_mode": "fantasy"
        }
        with self.assertRaises(ValueError) as ctx:
            validate_sentinelrc(raw)
        self.assertIn("Invalid tls_mode 'fantasy'", str(ctx.exception))

    def test_valid_tls_mode(self):
        raw = {
            "schema_version": 1,
            "mode": "cloud",
            "tls_mode": "pqc-only"
        }
        final = validate_sentinelrc(raw)
        self.assertEqual(final["tls_mode"], "pqc-only")


if __name__ == "__main__":
    unittest.main()