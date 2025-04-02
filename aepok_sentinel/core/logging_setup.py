"""
Step 1: Logging Setup Module

This module provides:
1. A JSON-based logging formatter that emits each record as a single JSON line.
2. A RotatingFileHandler to enforce 5MB max file size, keeping 5 old log files.
3. Console output control, especially for SCIF mode (forced off unless debug override).
4. A single function init_logging(...) to configure the root logger.
5. A get_logger(subsystem: str) helper to retrieve a subsystem-specific logger.

No references to future modules (config, license, etc.) are allowed.
"""

import os
import sys
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional


class LoggingSetupError(Exception):
    """
    Raised when logging setup fails due to invalid paths or other errors.
    """
    pass


class JSONLogFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects following the schema:
      {
        "timestamp": "UTC iso8601",
        "subsystem": "<string>",
        "event_code": "<string>",
        "message": "<string>",
        "schema_version": 1
      }
    """

    def format(self, record: logging.LogRecord) -> str:
        # Convert record time to UTC isoformat (no microseconds, 'Z' suffix).
        # By default, 'record.created' is epoch float. We'll use datetime.utcfromtimestamp.
        utc_dt = datetime.utcfromtimestamp(record.created).replace(microsecond=0)
        timestamp_str = utc_dt.isoformat() + "Z"

        # We can store the logger's name in "subsystem". That might be the best usage.
        # event_code: typically record.levelname or some short code. We'll store level name here.
        # message: record.getMessage().

        log_dict = {
            "timestamp": timestamp_str,
            "subsystem": record.name,
            "event_code": record.levelname,
            "message": record.getMessage(),
            "schema_version": 1
        }
        # Turn into one-line JSON
        return json.dumps(log_dict)


# Globals to track if we've already initialized logging
_LOGGING_INITIALIZED = False
_FILE_HANDLER: Optional[logging.Handler] = None
_CONSOLE_HANDLER: Optional[logging.Handler] = None


def init_logging(log_path: str,
                 scif_mode: bool,
                 manual_override_allowed: bool,
                 debug_console: bool,
                 max_bytes: int = 5 * 1024 * 1024,
                 backup_count: int = 5) -> None:
    """
    Initializes the root logger with:
      - A rotating file handler pointed at `log_path`/sentinel.log
      - Optionally a console handler, suppressed if scif_mode = True
        unless debug_console = True and manual_override_allowed = True
      - JSON formatting for all log records

    :param log_path: Directory path for log files.
    :param scif_mode: If True, console logs are forcibly suppressed unless override conditions are met.
    :param manual_override_allowed: If True, SCIF console can be enabled via debug_console.
    :param debug_console: If True, tries to enable console logs. In SCIF, only works if manual_override_allowed is True.
    :param max_bytes: Max file size in bytes before rotating. Default 5 MB.
    :param backup_count: Number of old log files to keep. Default 5.

    :raises LoggingSetupError: If the log_path is invalid or we cannot create the log file.
    """
    global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER

    if _LOGGING_INITIALIZED:
        # Already initialized, do nothing
        return

    # Validate log_path
    if not os.path.isdir(log_path):
        # Attempt to create directories if possible
        try:
            os.makedirs(log_path, exist_ok=True)
        except Exception as e:
            raise LoggingSetupError(f"Failed to create or access log path '{log_path}': {e}")

    logfile = os.path.join(log_path, "sentinel.log")
    try:
        # Test we can open for append
        with open(logfile, mode="a", encoding="utf-8"):
            pass
    except Exception as e:
        raise LoggingSetupError(f"Cannot write to log file '{logfile}': {e}")

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    # Ensure no duplicate handlers
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    # 1) File handler with rotation
    file_handler = RotatingFileHandler(
        filename=logfile,
        mode="a",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8"
    )
    formatter = JSONLogFormatter()
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    _FILE_HANDLER = file_handler

    # 2) Console handler
    console_enabled = True
    if scif_mode:
        # SCIF mode => console forcibly off unless debug_console + manual_override_allowed
        console_enabled = (debug_console and manual_override_allowed)

    if console_enabled:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        _CONSOLE_HANDLER = console_handler

    _LOGGING_INITIALIZED = True
    root_logger.info("Logging initialized. scif_mode=%s, console_enabled=%s", scif_mode, console_enabled)


def get_logger(subsystem: str) -> logging.Logger:
    """
    Returns a logger for a given subsystem name. Subsystem is typically
    a short string like 'daemon', 'controller', 'pqc_crypto', etc.
    """
    return logging.getLogger(subsystem)