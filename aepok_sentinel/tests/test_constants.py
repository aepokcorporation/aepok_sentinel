"""
Unit tests for aepok_sentinel/core/constants.py

Verifies the EventCode enum and constants are present and correct.
"""

import unittest
from aepok_sentinel.core.constants import EventCode, DEFAULT_KEY_GENERATIONS_TO_KEEP, MAX_LOG_FILE_SIZE_MB, LOG_BACKUP_COUNT


class TestConstants(unittest.TestCase):

    def test_event_code_enum(self):
        # Just verify some known values are present
        self.assertEqual(EventCode.CHAIN_BROKEN.value, "CHAIN_BROKEN")
        self.assertEqual(EventCode.KEY_ROTATED.value, "KEY_ROTATED")
        self.assertEqual(EventCode.FILE_ENCRYPTED.value, "FILE_ENCRYPTED")

    def test_global_constants(self):
        self.assertEqual(DEFAULT_KEY_GENERATIONS_TO_KEEP, 5)
        self.assertEqual(MAX_LOG_FILE_SIZE_MB, 5)
        self.assertEqual(LOG_BACKUP_COUNT, 5)


if __name__ == "__main__":
    unittest.main()