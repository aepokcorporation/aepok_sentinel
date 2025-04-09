# aepok_sentinel/core/key_manager_lock.py

"""
KeyRotationLock

Provides a cross-platform file lock used by KeyManager.rotate_keys() to ensure concurrency safety.
 - If must_fail_on_error = True => raise on lock error
 - Otherwise => log warning / degrade.

This uses a simple approach:
 - Windows => msvcrt.locking
 - Unix => fcntl.flock
No path auto-creation for the lock directory. If missing => fail or degrade per strict mode.
"""

import sys
import logging

logger = logging.getLogger(__name__)


class KeyRotationLock:
    """
    A context manager for exclusive file locking in key rotation. 
    """

    def __init__(self, lockfile_path: str, must_fail_on_error: bool):
        self.lockfile_path = lockfile_path
        self.must_fail = must_fail_on_error
        self.fh = None

    def __enter__(self):
        try:
            self.fh = open(self.lockfile_path, "a+")
            if sys.platform.startswith("win"):
                import msvcrt
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh, fcntl.LOCK_EX)
        except Exception as e:
            msg = f"Failed to acquire rotation lock on {self.lockfile_path}: {e}"
            logger.error(msg)
            if self.must_fail:
                raise RuntimeError(msg)
            else:
                # degrade => no lock
                logger.warning("Proceeding without lock in permissive mode => concurrency risk.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fh:
            try:
                if sys.platform.startswith("win"):
                    import msvcrt
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fh, fcntl.LOCK_UN)
                self.fh.close()
            except Exception:
                pass