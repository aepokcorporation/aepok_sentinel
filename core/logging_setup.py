"""
Step 1: Logging Setup Module

This module provides:
1. A JSON-based logging formatter that emits each record as a single JSON line.
2. A RotatingFileHandler (now with file-locking) to enforce 5MB max file size, keeping 5 old log files.
3. Console output control, especially for SCIF mode (forced off unless debug override).
4. A single function init_logging(...) to configure the root logger.
5. A get_logger(subsystem: str) helper to retrieve a subsystem-specific logger.

No references to future modules (config, license, etc.) are allowed.
"""

import os
import sys
import json
import logging
import platform
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional

# Platform-specific locking imports
if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl

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
        utc_dt = datetime.utcfromtimestamp(record.created).replace(microsecond=0)
        timestamp_str = utc_dt.isoformat() + "Z"

        # Subsystem = record.name
        # event_code = record.levelname
        # message = record.getMessage()

        log_dict = {
            "timestamp": timestamp_str,
            "subsystem": record.name,
            "event_code": record.levelname,
            "message": record.getMessage(),
            "schema_version": 1
        }
        return json.dumps(log_dict)


class LockingRotatingFileHandler(RotatingFileHandler):
    """
    A RotatingFileHandler subclass that uses an exclusive file lock
    to prevent concurrent write corruption. Also emits a LOG_ROTATED
    record after each successful rollover.
    """

    def emit(self, record: logging.LogRecord) -> None:
        """
        Acquire a file lock before writing the log record,
        then release it afterward.
        """
        if self.stream is None:
            self.stream = self._open()

        self._lock_file(self.stream)
        try:
            super().emit(record)
        finally:
            self._unlock_file(self.stream)

    def doRollover(self):
        """
        Lock the file, do the normal rollover, then append a single
        'LOG_ROTATED' record to the new file so it's visible in logs.
        """
        if self.stream:
            self._lock_file(self.stream)
        try:
            super().doRollover()
            # Write a one-line JSON "LOG_ROTATED" record to the new log file
            with open(self.baseFilename, mode="a", encoding="utf-8") as f:
                self._lock_file(f)
                try:
                    event = {
                        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                        "subsystem": "logging_setup",
                        "event_code": "LOG_ROTATED",
                        "message": "Log rollover complete",
                        "schema_version": 1
                    }
                    f.write(json.dumps(event) + "\n")
                finally:
                    self._unlock_file(f)
        finally:
            if self.stream:
                self._unlock_file(self.stream)

    @staticmethod
    def _lock_file(file_obj):
        """
        Cross-platform exclusive lock for the file.
        """
        if platform.system() == "Windows":
            # We lock a chunk of size 1 to indicate exclusive lock on entire file
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)

    @staticmethod
    def _unlock_file(file_obj):
        """
        Release the lock on the file.
        """
        if platform.system() == "Windows":
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


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
      - A rotating file handler (with locking) pointed at `log_path`/sentinel.log
      - Optionally a console handler, suppressed if scif_mode = True
        unless debug_console = True and manual_override_allowed = True
      - JSON formatting for all log records

    :param log_path: Directory path for log files.
    :param scif_mode: If True, console logs are forcibly suppressed unless override conditions are met.
    :param manual_override_allowed: If True, SCIF console can be enabled via debug_console.
    :param debug_console: If True, tries to enable console logs. In SCIF, only works if manual_override_allowed is True.
    :param max_bytes: Max file size in bytes before rotating. Default 5 MB.
    :param backup_count: Number of old log files to keep. Default 5.

    :raises LoggingSetupError: If the log_path is missing or the log file cannot be written.
    """
    global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER

    if _LOGGING_INITIALIZED:
        # Already initialized, do nothing
        return

    # Per flaws [75, 78]: do NOT create directories at runtime. Must exist.
    if not os.path.isdir(log_path):
        raise LoggingSetupError(
            f"Required log path does not exist: '{log_path}'. "
            "Create it at install time before starting Sentinel."
        )

    logfile = os.path.join(log_path, "sentinel.log")
    # Test we can open the file for append
    try:
        with open(logfile, mode="a", encoding="utf-8"):
            pass
    except Exception as e:
        raise LoggingSetupError(f"Cannot write to log file '{logfile}': {e}")

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove any existing handlers
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    # 1) File handler with rotation + locking
    file_handler = LockingRotatingFileHandler(
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

    # 2) Console handler (if allowed)
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
    root_logger.info(
        "Logging initialized. scif_mode=%s, console_enabled=%s",
        scif_mode,
        console_enabled
    )


def get_logger(subsystem: str) -> logging.Logger:
    """
    Returns a logger for a given subsystem name. Subsystem is typically
    a short string like 'daemon', 'controller', 'pqc_crypto', etc.
    """
    return logging.getLogger(subsystem)