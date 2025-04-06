import os
import json
import shutil
import logging
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

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
        global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
        _LOGGING_INITIALIZED = False
        _FILE_HANDLER = None
        _CONSOLE_HANDLER = None

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("aepok_sentinel.core.logging_setup.resolve_path")
    @patch("aepok_sentinel.core.logging_setup.audit_chain.append_event")
    def test_basic_logging(self, mock_append_event, mock_resolve_path):
        """
        Validate basic JSON logging with directory_contract and no rollover triggered.
        """
        # Mock directory_contract to return our temp logs dir for "logs"
        logs_path = Path(self.temp_dir)
        mock_resolve_path.return_value = logs_path

        # Ensure logs dir exists
        os.mkdir(logs_path)

        init_logging(
            scif_mode=False,
            manual_override_allowed=False,
            debug_console=False
        )
        logger = get_logger("test_subsystem")
        logger.info("Hello from test_logging")

        logfile = logs_path / "sentinel.log"
        with open(logfile, "r", encoding="utf-8") as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 1, "Expected exactly one log line.")
        data = json.loads(lines[0])
        self.assertIn("timestamp", data)
        self.assertIn("subsystem", data)
        self.assertIn("event_code", data)
        self.assertIn("message", data)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["subsystem"], "test_subsystem")
        self.assertEqual(data["event_code"], "INFO")
        self.assertEqual(data["message"], "Hello from test_logging")

        # No rollover => no call to append_event
        mock_append_event.assert_not_called()

    @patch("aepok_sentinel.core.logging_setup.resolve_path")
    @patch("aepok_sentinel.core.logging_setup.audit_chain.append_event")
    def test_rotation_with_chain_event(self, mock_append_event, mock_resolve_path):
        """
        Force rollover and confirm that 'LOG_ROTATED' is appended to the new log file
        AND appended to the audit chain.
        """
        logs_path = Path(self.temp_dir)
        mock_resolve_path.return_value = logs_path
        os.mkdir(logs_path)

        init_logging(
            scif_mode=False,
            manual_override_allowed=False,
            debug_console=False,
            max_bytes=200,  # small size to force rotation quickly
            backup_count=2
        )
        logger = get_logger("rotate_test")

        for i in range(20):
            logger.info(f"Line {i}")

        # Check for multiple log files
        log_files = os.listdir(logs_path)
        possible_logs = [f for f in log_files if f.startswith("sentinel.log")]
        self.assertGreaterEqual(
            len(possible_logs), 2,
            "Expected log rotation to produce multiple files."
        )

        # Verify 'LOG_ROTATED' in the current sentinel.log
        current_logfile = logs_path / "sentinel.log"
        with open(current_logfile, "r", encoding="utf-8") as f:
            lines = f.readlines()

        found_log_rotated = any(
            (json.loads(line).get("event_code") == "LOG_ROTATED") for line in lines
        )
        self.assertTrue(found_log_rotated, "Expected a LOG_ROTATED event in the new log file.")

        # Also verify that the audit chain was updated
        mock_append_event.assert_any_call(
            event="LOG_ROTATED",
            metadata={"logfile": str(current_logfile)}
        )

    @patch("aepok_sentinel.core.logging_setup.resolve_path")
    def test_missing_logs_directory(self, mock_resolve_path):
        """
        If 'logs' directory doesn't exist, raise LoggingSetupError.
        """
        mock_resolve_path.return_value = Path(self.temp_dir) / "missing_logs"

        with self.assertRaises(LoggingSetupError) as cm:
            init_logging(
                scif_mode=False,
                manual_override_allowed=False,
                debug_console=False
            )
        self.assertIn("Logs directory not found", str(cm.exception))

    @patch("aepok_sentinel.core.logging_setup.resolve_path")
    def test_scif_mode_suppression(self, mock_resolve_path):
        """
        In SCIF mode, console logs are off unless debug_console and manual_override_allowed.
        """
        logs_path = Path(self.temp_dir)
        mock_resolve_path.return_value = logs_path
        os.mkdir(logs_path)

        # scif_mode=True, debug_console=False => no console
        init_logging(
            scif_mode=True,
            manual_override_allowed=False,
            debug_console=False
        )
        logger = get_logger("scif_test")
        logger.info("Testing scif_mode console off")
        self.assertIsNone(_CONSOLE_HANDLER)

        # Reset logging
        global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
        _LOGGING_INITIALIZED = False
        _FILE_HANDLER = None
        _CONSOLE_HANDLER = None

        # scif_mode=True, debug_console=True but manual_override_allowed=False => still off
        init_logging(
            scif_mode=True,
            manual_override_allowed=False,
            debug_console=True
        )
        logger = get_logger("scif_test")
        logger.info("Testing scif_mode console override no-permission")
        self.assertIsNone(_CONSOLE_HANDLER)

        # Reset logging again
        _LOGGING_INITIALIZED = False
        _FILE_HANDLER = None
        _CONSOLE_HANDLER = None

        # scif_mode=True, debug_console=True, manual_override_allowed=True => console on
        init_logging(
            scif_mode=True,
            manual_override_allowed=True,
            debug_console=True
        )
        logger = get_logger("scif_test")
        logger.info("Testing scif_mode console override allowed")
        self.assertIsNotNone(_CONSOLE_HANDLER)


if __name__ == "__main__":
    unittest.main()