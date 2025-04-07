# aepok_sentinel/core/key_manager_lock.py

import os
import sys

class KeyRotationLock:
    """
    Cross-platform lockfile for final-shape key rotation concurrency.
    On Windows, we open the file in exclusive mode.
    On Unix, we use fcntl.flock(...).
    If enforcement_mode is strict => fail if lock can't be acquired.
    Otherwise we block until acquired.
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
            if self.must_fail:
                raise RuntimeError(f"Failed to acquire rotation lock: {e}")
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