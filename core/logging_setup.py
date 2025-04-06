"""
Aepok Sentinel - Final Logging Setup

Provides a rotating, locked JSON logger that:
1. Uses directory_contract to locate the logs directory (no arbitrary paths).
2. Fails hard if the logs directory is missing (Flaws [75, 78]).
3. Emits "LOG_ROTATED" to both the log file and the audit chain on rollover (Flaws [8, 83]).
4. Optionally suppresses console output in SCIF mode unless a manual debug override is allowed.

References:
- directory_contract.py: for `resolve_path("logs")`
- audit_chain.py: for `append_event(...)`
- Flaws addressed: [7], [8], [75–78], [83]
"""

import os
import sys
import json
import logging
import platform
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional

from aepok_sentinel.core import audit_chain
from aepok_sentinel.core.directory_contract import resolve_path

# Platform-specific locking imports
if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl


class LoggingSetupError(Exception):
    """Raised if the logs directory is missing or log file can’t be opened."""
    pass


class JSONLogFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects following:
    {
      "timestamp": "UTC iso8601",
      "subsystem": "<string>",
      "event_code": "<string>",
      "message": "<string>",
      "schema_version": 1
    }
    """
    def format(self, record: logging.LogRecord) -> str:
        utc_dt = datetime.utcfromtimestamp(record.created).replace(microsecond=0)
        timestamp_str = utc_dt.isoformat() + "Z"
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
    A rotating handler that uses an exclusive file lock (Flaw [7] fix)
    and emits a "LOG_ROTATED" event to both the log file and audit_chain
    (Flaw [8], [83]) upon rollover.
    """

    def emit(self, record: logging.LogRecord) -> None:
        if self.stream is None:
            self.stream = self._open()

        self._lock_file(self.stream)
        try:
            super().emit(record)
        finally:
            self._unlock_file(self.stream)

    def doRollover(self):
        if self.stream:
            self._lock_file(self.stream)
        try:
            super().doRollover()

            # After rotation, append one JSON line for "LOG_ROTATED" in the new log file
            new_log_path = self.baseFilename
            with open(new_log_path, mode="a", encoding="utf-8") as f:
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

            # Also record an audit_chain event (Flaw [8], [83])
            audit_chain.append_event(
                event="LOG_ROTATED",
                metadata={"logfile": new_log_path}
            )

        finally:
            if self.stream:
                self._unlock_file(self.stream)

    @staticmethod
    def _lock_file(file_obj):
        if platform.system() == "Windows":
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)

    @staticmethod
    def _unlock_file(file_obj):
        if platform.system() == "Windows":
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


_LOGGING_INITIALIZED = False
_FILE_HANDLER: Optional[logging.Handler] = None
_CONSOLE_HANDLER: Optional[logging.Handler] = None


def init_logging(
    scif_mode: bool,
    manual_override_allowed: bool,
    debug_console: bool,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5
) -> None:
    """
    Final-shape logging initializer.
      - Resolves log directory via directory_contract (no external param).
      - Fails if logs directory is missing (Flaws [75,78]).
      - Uses LockingRotatingFileHandler with JSONLogFormatter.
      - Optionally suppresses console for SCIF unless debug override is permitted.
      - Logs and audit-chains "LOG_ROTATED" on rollover.

    :param scif_mode: If True, console logs are forcibly off unless
                      debug_console and manual_override_allowed both True.
    :param manual_override_allowed: If True, SCIF console is enabled if debug_console=True.
    :param debug_console: If True, attempts console logs. SCIF can override if not permitted.
    :param max_bytes: Rotation threshold in bytes (default = 5MB).
    :param backup_count: Number of old logs to keep (default = 5).

    :raises LoggingSetupError: If logs directory is missing or log file can’t be opened.
    """

    global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
    if _LOGGING_INITIALIZED:
        return

    # Resolve the logs directory from directory_contract
    logs_dir = resolve_path("logs")
    if not logs_dir.is_dir():
        raise LoggingSetupError(
            f"Logs directory not found at: {logs_dir}."
            " This must be created at install time."
        )

    logfile = logs_dir / "sentinel.log"

    # Test we can open the log file
    try:
        with open(logfile, "a", encoding="utf-8"):
            pass
    except Exception as e:
        raise LoggingSetupError(f"Cannot write to log file '{logfile}': {e}")

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove any existing handlers
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    # 1) File handler (locked + rotating)
    file_handler = LockingRotatingFileHandler(
        filename=str(logfile),
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
        console_enabled = (debug_console and manual_override_allowed)

    if console_enabled:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        _CONSOLE_HANDLER = console_handler

    _LOGGING_INITIALIZED = True
    root_logger.info(
        "Logging initialized. scif_mode=%s, console_enabled=%s, log_path=%s",
        scif_mode,
        console_enabled,
        logfile
    )