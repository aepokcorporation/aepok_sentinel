"""
Unit tests for aepok_sentinel/core/logging_setup.py

Covers:
- Basic JSON logging
- Log rotation (including verification of "LOG_ROTATED" entry)
- SCIF console suppression
- Invalid log path handling
"""

import os
import shutil
import logging
import json
import tempfile
import unittest
from unittest.mock import patch
from aepok_sentinel.core.logging_setup import (
    init_logging,
    get_logger,
    LoggingSetupError,
    _LOGGING_INITIALIZED,
    _FILE_HANDLER,
    _CONSOLE_HANDLER
)


class TestLoggingSetup(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Reset the global flags so each test can re-init logging
        # (In real usage, we'd only init once, but for test coverage we reset.)
        global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
        _LOGGING_INITIALIZED = False
        _FILE_HANDLER = None
        _CONSOLE_HANDLER = None

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_basic_logging(self):
        """
        Ensure we can initialize logging and write a basic JSON log line.
        """
        init_logging(
            log_path=self.temp_dir,
            scif_mode=False,
            manual_override_allowed=False,
            debug_console=False
        )
        logger = get_logger("test_subsystem")
        logger.info("Hello from test_logging")

        logfile = os.path.join(self.temp_dir, "sentinel.log")
        with open(logfile, "r", encoding="utf-8") as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 1)
        data = json.loads(lines[0])
        self.assertIn("timestamp", data)
        self.assertIn("subsystem", data)
        self.assertIn("event_code", data)
        self.assertIn("message", data)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["subsystem"], "test_subsystem")
        self.assertEqual(data["event_code"], "INFO")
        self.assertEqual(data["message"], "Hello from test_logging")

    def test_rotation(self):
        """
        Write logs until rotation triggers, ensure multiple files exist.
        Also verify that a 'LOG_ROTATED' event is recorded in the new log file.
        """
        init_logging(
            log_path=self.temp_dir,
            scif_mode=False,
            manual_override_allowed=False,
            debug_console=False,
            max_bytes=200,  # small size to force rotation quickly
            backup_count=2
        )
        logger = get_logger("rotate_test")

        # Write enough lines to exceed 200 bytes at least once
        for i in range(20):
            logger.info(f"Line {i}")

        # Check the directory for multiple log files (sentinel.log, sentinel.log.1, etc.)
        log_files = os.listdir(self.temp_dir)
        possible_logs = [f for f in log_files if f.startswith("sentinel.log")]
        self.assertTrue(
            len(possible_logs) >= 2,
            "Expected log rotation to produce multiple files"
        )

        # Verify 'LOG_ROTATED' event in the current sentinel.log
        current_logfile = os.path.join(self.temp_dir, "sentinel.log")
        with open(current_logfile, "r", encoding="utf-8") as f:
            lines = f.readlines()

        found_log_rotated = any(
            (json.loads(line).get("event_code") == "LOG_ROTATED")
            for line in lines
        )
        self.assertTrue(
            found_log_rotated,
            "Expected a LOG_ROTATED event in the new log file after rotation"
        )

    def test_scif_mode_suppression(self):
        """
        In SCIF mode, console logs are suppressed unless debug_console + manual_override_allowed.
        We'll mock sys.stdout to see if anything is printed.
        """
        # case 1: scif_mode=True, debug_console=False => no console output
        with patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")):
            init_logging(
                log_path=self.temp_dir,
                scif_mode=True,
                manual_override_allowed=False,
                debug_console=False
            )
            logger = get_logger("scif_subsystem")
            logger.info("SCIF console test")
            # Check no console handler
            self.assertIsNone(_CONSOLE_HANDLER)

        # case 2: scif_mode=True, debug_console=True but manual_override_allowed=False => still suppressed
        with patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")):
            global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
            _LOGGING_INITIALIZED = False
            _FILE_HANDLER = None
            _CONSOLE_HANDLER = None

            init_logging(
                log_path=self.temp_dir,
                scif_mode=True,
                manual_override_allowed=False,
                debug_console=True
            )
            logger = get_logger("scif_subsystem")
            logger.info("SCIF console test2")
            self.assertIsNone(_CONSOLE_HANDLER)

        # case 3: scif_mode=True, debug_console=True, manual_override_allowed=True => console enabled
        with patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")):
            global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
            _LOGGING_INITIALIZED = False
            _FILE_HANDLER = None
            _CONSOLE_HANDLER = None

            init_logging(
                log_path=self.temp_dir,
                scif_mode=True,
                manual_override_allowed=True,
                debug_console=True
            )
            logger = get_logger("scif_subsystem")
            logger.info("SCIF console test3")
            self.assertIsNotNone(_CONSOLE_HANDLER)

    def test_invalid_log_path(self):
        """
        If the log path is invalid or not creatable, must raise LoggingSetupError.
        """
        fake_path = os.path.join(self.temp_dir, "nonexistent", "denied")
        with self.assertRaises(LoggingSetupError):
            init_logging(
                log_path=fake_path,
                scif_mode=False,
                manual_override_allowed=False,
                debug_console=False
            )


if __name__ == "__main__":
    unittest.main()