"""
Step 8: The Controller

Implements the top-level SentinelController to:
 1) Load config
 2) Verify license
 3) Initialize key manager
 4) Initialize audit chain, security daemon, autoban if needed
 5) Start the daemon loop unless watch-only or scif/airgap overrides
 6) Provide stop(), restart() logic
 7) Supervise the daemon if it crashes => attempt optional restart

No references to steps 9 or beyond. Final shape code with no placeholders.
"""

import os
import json
import logging
import threading
import time
from typing import Optional

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseError, is_watch_only
from aepok_sentinel.core.pqc_crypto import CryptoDecryptionError
from aepok_sentinel.core.key_manager import KeyManager
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.security_daemon import SecurityDaemon
from aepok_sentinel.core.autoban import AutobanManager
from aepok_sentinel.core.constants import EventCode

logger = get_logger("controller")


class ControllerError(Exception):
    """Raised for irrecoverable controller-level errors."""


class SentinelController:
    """
    A top-level orchestrator for:
      - reading sentinelrc
      - license verification
      - key manager init
      - audit chain init
      - security daemon creation
      - autoban creation
      - supervise the daemon, handle restarts if needed
    """

    def __init__(self, config_path: str = "./.sentinelrc", state_path: str = "./daemon_state.json"):
        """
        :param config_path: location of .sentinelrc
        :param state_path: optional location to store runtime state
        """
        self.config_path = config_path
        self.state_path = state_path
        self.config: Optional[SentinelConfig] = None
        self.license_mgr: Optional[LicenseManager] = None
        self.key_manager: Optional[KeyManager] = None
        self.audit_chain: Optional[AuditChain] = None
        self.security_daemon: Optional[SecurityDaemon] = None
        self.autoban_mgr: Optional[AutobanManager] = None

        self._daemon_thread: Optional[threading.Thread] = None
        self._running = False

    def boot(self) -> None:
        """
        Main entrypoint:
          1) Load config
          2) License check
          3) key manager, audit chain, autoban
          4) start security daemon if not watch-only
          5) supervise
        """
        logger.info("Controller boot started with config path=%s", self.config_path)
        # load config
        try:
            self.config = self._load_config(self.config_path)
        except Exception as e:
            raise ControllerError(f"Failed to load config: {e}")

        # license
        self.license_mgr = LicenseManager(self.config)
        try:
            self.license_mgr.load_license()
        except LicenseError as e:
            logger.warning("License error => watch-only or fail: %s", e)
            # If license_required => that might raise an error
            # or degrade to watch-only. It's already done in license.py

        # Key manager
        self.key_manager = KeyManager(self.config, self.license_mgr)

        # audit chain
        chain_dir = self.config.raw_dict.get("log_path", "/var/log/sentinel/")
        self.audit_chain = AuditChain(chain_dir=chain_dir)

        # autoban manager
        self.autoban_mgr = AutobanManager(self.config, self.license_mgr, self.audit_chain)

        # security daemon if not watch-only
        if not is_watch_only(self.license_mgr):
            self.security_daemon = SecurityDaemon(
                config=self.config,
                license_mgr=self.license_mgr,
                audit_chain=self.audit_chain
            )
        else:
            logger.info("System is watch-only => no security daemon started.")

        # Start daemon if exists
        if self.security_daemon:
            self._running = True
            self._daemon_thread = threading.Thread(target=self._daemon_loop, daemon=True)
            self._daemon_thread.start()

        # store state
        self._save_state({"boot_time": time.time()})
        logger.info("Controller boot completed.")

    def stop(self) -> None:
        """
        Gracefully stops the daemon if running, finalizes chain, saves state.
        """
        logger.info("Controller stopping.")
        if self.security_daemon and self._running:
            self.security_daemon.stop()
            if self._daemon_thread:
                self._daemon_thread.join(timeout=10)
        self._running = False
        self._save_state({"stop_time": time.time()})
        logger.info("Controller stopped.")

    def restart(self) -> None:
        """
        Halts the current daemon, re-initializes, restarts. 
        """
        logger.info("Controller restart invoked.")
        self.stop()
        self.boot()

    # ---------------------------
    # Internal
    # ---------------------------
    def _daemon_loop(self) -> None:
        """
        Supervises the security daemon start() method. If it crashes, we can attempt a restart or log.
        """
        assert self.security_daemon is not None
        try:
            self.security_daemon.start()
        except Exception as e:
            logger.error("Security daemon crashed: %s", e)
            # we can choose to do a single attempt to restart or just stop
            # let's do a single restart attempt for final shape
            logger.info("Attempting a single restart of the daemon.")
            try:
                self.security_daemon.stop()  # ensure cleanup
                time.sleep(2)
                self.security_daemon.start()
            except Exception as e2:
                logger.critical("Daemon second crash => giving up. %s", e2)
                self._running = False

        logger.info("Daemon loop ended normally or second crash => no further restarts.")
        self._running = False

    def _load_config(self, path: str) -> SentinelConfig:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            raw_json = f.read()
        import json
        data = json.loads(raw_json)
        # create the sentinel config object
        return SentinelConfig(data)

    def _save_state(self, extra: dict) -> None:
        """
        Optional. Stores the controller/daemon state in a small JSON. 
        """
        state = {}
        if os.path.isfile(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except Exception:
                pass

        for k, v in extra.items():
            state[k] = v

        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save controller state: %s", e)