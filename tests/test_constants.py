"""
Unit tests for aepok_sentinel/core/constants.py

Checks:
 - EventCode enum presence (including new intrusion codes)
 - Basic global constants
"""

import unittest
from aepok_sentinel.core.constants import (
    EventCode,
    DEFAULT_KEY_GENERATIONS_TO_KEEP,
    MAX_LOG_FILE_SIZE_MB,
    LOG_BACKUP_COUNT
)

class TestConstants(unittest.TestCase):

    def test_event_code_enum(self):
        # Basic presence checks
        self.assertEqual(EventCode.CHAIN_BROKEN.value, "CHAIN_BROKEN")
        self.assertEqual(EventCode.FILE_ENCRYPTED.value, "FILE_ENCRYPTED")

        # Check the newly added intrusion codes
        self.assertEqual(EventCode.SOURCE_BLOCKED.value, "SOURCE_BLOCKED")
        self.assertEqual(EventCode.SOURCE_REJECTED.value, "SOURCE_REJECTED")
        self.assertEqual(EventCode.AUTOBAN_TRIGGERED.value, "AUTOBAN_TRIGGERED")

    def test_global_constants(self):
        self.assertEqual(DEFAULT_KEY_GENERATIONS_TO_KEEP, 5)
        self.assertEqual(MAX_LOG_FILE_SIZE_MB, 5)
        self.assertEqual(LOG_BACKUP_COUNT, 5)


if __name__ == "__main__":
    unittest.main()
