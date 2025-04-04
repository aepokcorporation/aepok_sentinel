"""
Unit tests for aepok_sentinel/core/logging_setup.py

Covers:
- Basic JSON logging
- Log rotation
- SCIF console suppression
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

        # read the log
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
        """
        init_logging(
            log_path=self.temp_dir,
            scif_mode=False,
            manual_override_allowed=False,
            debug_console=False,
            max_bytes=200,  # small for test
            backup_count=2
        )
        logger = get_logger("rotate_test")
        for i in range(20):
            logger.info(f"Line {i}")

        # This should create sentinel.log and sentinel.log.1 (maybe sentinel.log.2 if needed)
        log_files = os.listdir(self.temp_dir)
        # Check if we have at least sentinel.log + sentinel.log.1
        # The RotatingFileHandler only rotates upon next write once size is exceeded,
        # so we expect at least 2 files, possibly 3 if we exceed again.
        possible_logs = [f for f in log_files if f.startswith("sentinel.log")]
        self.assertTrue(len(possible_logs) >= 2, "Expected log rotation to produce multiple files")

    def test_scif_mode_suppression(self):
        """
        In SCIF mode, console logs are suppressed unless debug_console + manual_override_allowed.
        We'll mock sys.stdout to see if anything is printed.
        """
        # case 1: scif_mode=True, debug_console=False => no console output
        with patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")) as mock_stdout:
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
        with patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")) as mock_stdout:
            # Re-init again
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
        with patch("sys.stdout", new_callable=lambda: open(os.devnull, "w")) as mock_stdout:
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