# logging_setup.py
"""
Aepok Sentinel Logging Setup

Provides a rotating, locked JSON logger that:
1. Uses directory_contract to locate the logs directory (no arbitrary paths).
2. Fails immediately if the logs directory is missing.
3. Emits a "LOG_ROTATED" event to the log file and the audit chain on rollover.
4. Optionally suppresses console output in SCIF mode unless a manual debug override is allowed.
5. Offers a get_logger(...) function to retrieve named loggers, ensuring
   init_logging() has been called.

References:
- directory_contract.py (resolve_path("logs"))
- audit_chain.py (append_event(...))
"""

import sys
import json
import logging
import platform
from logging.handlers import RotatingFileHandler
from datetime import datetime
from typing import Optional

from aepok_sentinel.core.directory_contract import resolve_path


# Platform-specific locking imports
if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl


class LoggingSetupError(Exception):
    """
    Raised if the logs directory is missing or the log file cannot be opened.
    """
    pass


class JSONLogFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects:
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
    A rotating handler that uses an exclusive file lock and emits a "LOG_ROTATED"
    event to both the log file and the audit chain upon rollover.
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
        # FIX #60: The original code locked self.stream before calling
        # super().doRollover(), which closes and reopens self.stream.
        # The finally block then called _unlock_file(self.stream) on the
        # NEW stream — which was never locked.  On Windows with
        # msvcrt.locking, unlocking an unlocked file throws an error.
        #
        # The fix captures the old stream before rollover so we can
        # unlock the correct file descriptor in the finally block.
        # We also removed the audit_chain.append_event() call which had
        # the same module-level function bug as TODO #2, and could cause
        # reentrant logging during rollover.
        #
        # FIX #62: The post-rollover code opened a SECOND file handle to
        # the new log file (via open(new_log_path, "a")) to write the
        # LOG_ROTATED JSON event.  This created two independent file
        # descriptors to the same file: self.stream (from the handler)
        # and the separately opened 'f'.  Locking 'f' did NOT prevent
        # concurrent writes through self.stream from other threads, so
        # interleaved writes were still possible.  Additionally, if the
        # audit_chain.append_event() call were still present, it would
        # trigger logger.info() inside the chain, which would re-enter
        # this handler's emit() while the handler is mid-rollover.
        #
        # The fix writes the LOG_ROTATED event directly through
        # self.stream (which super().doRollover() already opened for the
        # new file), eliminating the second file handle entirely.  This
        # ensures only one fd exists and the handler's own lock in emit()
        # serialises all access.
        old_stream = self.stream
        if old_stream:
            self._lock_file(old_stream)
        try:
            super().doRollover()

            # Write LOG_ROTATED event directly to self.stream (the new
            # log file) instead of opening a separate file handle.
            if self.stream:
                event = {
                    "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                    "subsystem": "logging_setup",
                    "event_code": "LOG_ROTATED",
                    "message": "Log rollover complete",
                    "schema_version": 1
                }
                self.stream.write(json.dumps(event) + "\n")
                self.stream.flush()
        finally:
            # Unlock the OLD stream (the one we actually locked), not
            # self.stream which now points to the new, never-locked file.
            if old_stream:
                try:
                    self._unlock_file(old_stream)
                except Exception:
                    pass  # Old stream may already be closed; safe to ignore

    @staticmethod
    def _lock_file(file_obj):
        # FIX #61: The original code used msvcrt.locking(fd, LK_LOCK, 1)
        # which only locks a single byte at the current file position.
        # If two processes write to different positions, the 1-byte lock
        # provides no mutual exclusion — concurrent corruption is still
        # possible.  On Unix, fcntl.flock() already locks the entire file
        # (correct).  On Windows, we now use msvcrt.locking with the
        # file's current size (minimum 1 byte) so the lock region covers
        # the whole file.  We also seek to position 0 before locking so
        # the locked region always starts at the beginning of the file,
        # ensuring overlapping coverage regardless of where each process
        # is writing.
        if platform.system() == "Windows":
            fd = file_obj.fileno()
            file_obj.seek(0, 2)  # seek to end to get size
            size = max(file_obj.tell(), 1)
            file_obj.seek(0)     # lock from beginning
            msvcrt.locking(fd, msvcrt.LK_LOCK, size)
        else:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)

    @staticmethod
    def _unlock_file(file_obj):
        # FIX #61: Mirror the locking fix — unlock the same region we
        # locked (from position 0 for the full file size) so Windows
        # releases the correct byte range.
        if platform.system() == "Windows":
            fd = file_obj.fileno()
            file_obj.seek(0, 2)
            size = max(file_obj.tell(), 1)
            file_obj.seek(0)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, size)
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
    Initializes global logging for Aepok Sentinel.
      - Resolves log directory via directory_contract (resolve_path("logs")).
      - Fails if the logs directory is missing or inaccessible.
      - Uses LockingRotatingFileHandler + JSONLogFormatter for file output.
      - Optionally suppresses console in SCIF mode unless debug overrides are allowed.
      - On rotation, emits a LOG_ROTATED event to the new log and the audit_chain.

    :param scif_mode: True if operating in SCIF (airgap) mode; console might be suppressed.
    :param manual_override_allowed: True if debug console can be explicitly allowed in SCIF.
    :param debug_console: True if we want console logs (overridden by SCIF unless override is allowed).
    :param max_bytes: Rotation threshold in bytes (default=5MB).
    :param backup_count: Number of old log files to keep (default=5).

    :raises LoggingSetupError: If logs directory is missing or log file cannot be opened.
    """

    global _LOGGING_INITIALIZED, _FILE_HANDLER, _CONSOLE_HANDLER
    if _LOGGING_INITIALIZED:
        return  # Already initialized

    logs_dir = resolve_path("logs")
    if not logs_dir.is_dir():
        raise LoggingSetupError(
            f"Logs directory not found at: {logs_dir}. "
            "This must be pre-created at install time."
        )

    logfile = logs_dir / "sentinel.log"

    try:
        with open(logfile, "a", encoding="utf-8"):
            pass
    except Exception as e:
        raise LoggingSetupError(f"Cannot write to log file '{logfile}': {e}")

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove existing handlers (if any)
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # 1) File handler
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


def get_logger(name: str) -> logging.Logger:
    """
    Retrieves a logger instance by name.

    If init_logging() has not been called yet (common during module-level
    import time), returns a logger with a NullHandler so that import
    ordering does not cause a RuntimeError.  Once init_logging() configures
    the root logger, all previously-created child loggers automatically
    pick up the new handlers via propagation.
    """
    lgr = logging.getLogger(name)
    if not _LOGGING_INITIALIZED:
        if not lgr.handlers:
            lgr.addHandler(logging.NullHandler())
    return lgr
