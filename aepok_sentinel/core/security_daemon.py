"""
Step 7: Security Daemon

A real-time or periodic scanner that:
 - Monitors files in scan_paths (via inotify if use_inotify=true, else polling).
 - Checks tamper vs. .hashes.json store => if mismatch => quarantine & log.
 - Checks malware DB => if malicious => quarantine & log MALWARE_MATCH.
 - Integrates watch-only => no quarantine, no modifications.
 - Integrates SCIF or airgap => local only scanning, no external calls.
 - Writes events to the audit chain with correct EventCodes.
 - Runs continuously, recovers from errors (watchdog behavior).

No forward references to Step 8 or beyond. Final shape compliance.
"""

import os
import time
import json
import shutil
import logging
import hashlib
import threading
from typing import Dict, Optional, Any

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only, is_license_valid
from aepok_sentinel.core.audit_chain import AuditChain, ChainTamperDetectedError
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.utils.malware_db import MalwareDatabase, MalwareDBError

logger = get_logger("security_daemon")


class SecurityDaemonError(Exception):
    """Raised for fatal errors in the security daemon."""


class FileTamperDetectedError(Exception):
    """Raised if a file's hash mismatches the known store, prompting quarantine or watch-only log."""


class SecurityDaemon:
    """
    The enforcement engine:
      - On start, loads config (scan_paths, exclude_paths, use_inotify, quarantine_enabled, etc.)
      - Loads or creates .hashes.json
      - Loads malware DB
      - If watch-only => scanning is read-only, no quarantine
      - Real-time or poll-based monitoring => handle tamper or malware => quarantine or log
      - Writes events to AuditChain => TAMPER_DETECTED, FILE_QUARANTINED, MALWARE_MATCH, etc.
      - Recovers from errors, doesn't crash silently
    """

    def __init__(self,
                 config: SentinelConfig,
                 license_mgr: LicenseManager,
                 audit_chain: AuditChain,
                 hash_store_path: str = "/var/lib/sentinel/.hashes.json",
                 quarantine_dir: str = "/var/lib/sentinel/quarantine"):
        self.config = config
        self.license_mgr = license_mgr
        self.audit_chain = audit_chain
        self.hash_store_path = hash_store_path
        self.quarantine_dir = quarantine_dir
        os.makedirs(quarantine_dir, exist_ok=True)

        # load or create .hashes.json
        self._hash_store = self._load_hash_store()

        # load malware DB
        self.malware_db = MalwareDatabase(config)
        try:
            self.malware_db.load_signatures()
        except MalwareDBError as e:
            logger.warning("Failed to load malware signatures: %s", e)

        # watch-only => no quarantines. scif/airgap => local scanning only
        self._stop_flag = threading.Event()

        # inotify usage if config.use_inotify => attempt import
        self._use_inotify = self.config.raw_dict.get("use_inotify", False)
        self._poll_interval = self.config.daemon_poll_interval

        # We might do concurrency with a single thread. If in watch-only => we skip quarantines.
        # We'll keep it minimal for final shape.

    def start(self) -> None:
        """
        Starts the real-time or poll-based scanning. This blocks until stop() is called or a fatal error occurs.
        For final shape, we do a single loop or thread.
        """
        logger.info("SecurityDaemon started. use_inotify=%s, watch_only=%s",
                    self._use_inotify, is_watch_only(self.license_mgr))

        if self._use_inotify:
            try:
                from inotify_simple import INotify, flags
                self._run_inotify_loop()
            except ImportError:
                logger.warning("inotify_simple not installed; fallback to poll loop.")
                self._run_poll_loop()
        else:
            self._run_poll_loop()

    def stop(self) -> None:
        """
        Signals the daemon to stop scanning gracefully.
        """
        self._stop_flag.set()

    # --------------------------
    # Internal loops
    # --------------------------
    def _run_poll_loop(self) -> None:
        """
        Poll-based approach: we scan the directories every self._poll_interval seconds,
        check for tamper or malware, handle logic, then sleep.
        """
        scan_paths = self.config.scan_paths
        exclude_paths = self.config.exclude_paths
        recursive = self.config.scan_recursive

        while not self._stop_flag.is_set():
            self._scan_directories(scan_paths, exclude_paths, recursive)
            time.sleep(self._poll_interval)

        logger.info("SecurityDaemon poll loop stopped gracefully.")

    def _run_inotify_loop(self) -> None:
        """
        Inotify-based approach if inotify_simple is available. We watch the config.scan_paths,
        handle CREATE, MODIFY, etc. events => check tamper or malware. 
        """
        try:
            from inotify_simple import INotify, flags
        except ImportError:
            logger.error("inotify_simple not installed, cannot proceed with inotify loop.")
            raise

        inotify = INotify()
        watch_flags = flags.CREATE | flags.MODIFY | flags.MOVED_TO
        # We might also watch DELETE or RENAME events if relevant
        for p in self.config.scan_paths:
            if os.path.isdir(p):
                inotify.add_watch(p, watch_flags)
                if self.config.scan_recursive:
                    # recursively add subdirs
                    for root, dirs, files in os.walk(p):
                        for d in dirs:
                            subdir = os.path.join(root, d)
                            inotify.add_watch(subdir, watch_flags)

        logger.info("Inotify loop started, scanning paths: %s", self.config.scan_paths)
        while not self._stop_flag.is_set():
            events = inotify.read(timeout=1000)  # 1 second
            if not events:
                continue
            for e in events:
                # resolve path
                watch_path = inotify.watches[e.wd].path
                full_path = os.path.join(watch_path, e.name)
                if not os.path.isfile(full_path):
                    continue
                # check exclude
                if self._excluded_path(full_path, self.config.exclude_paths):
                    continue
                try:
                    self._process_file(full_path)
                except Exception as ex:
                    logger.warning("Error processing file %s: %s", full_path, ex)

        logger.info("Inotify loop stopped gracefully.")

    # --------------------------
    # Scanning
    # --------------------------
    def _scan_directories(self, paths, excludes, recursive) -> None:
        for p in paths:
            if not os.path.isdir(p):
                continue
            for root, dirs, files in os.walk(p):
                if self._stop_flag.is_set():
                    return
                if self._excluded_path(root, excludes):
                    continue
                for f in files:
                    full_path = os.path.join(root, f)
                    if self._excluded_path(full_path, excludes):
                        continue
                    if os.path.isfile(full_path):
                        try:
                            self._process_file(full_path)
                        except Exception as ex:
                            logger.warning("Error processing file %s: %s", full_path, ex)
                if not recursive:
                    break

    def _process_file(self, filepath: str) -> None:
        """
        Processes a single file: check tamper vs. hash store, check malware DB, handle quarantine or watch-only logic.
        """
        if is_watch_only(self.license_mgr):
            # watch-only => we do scanning but only log, no quarantine
            tamper, threat_name = self._check_file_security(filepath)
            if tamper:
                # log an event
                self._log_chain_event(EventCode.TAMPER_DETECTED, {"file": filepath})
            elif threat_name:
                self._log_chain_event(EventCode.MALWARE_MATCH, {"file": filepath, "threat": threat_name})
            else:
                # update hash store if new
                self._update_file_hash(filepath)
            return

        # normal => we can quarantine
        tamper, threat_name = self._check_file_security(filepath)
        if tamper or threat_name:
            if self.config.quarantine_enabled:
                self._quarantine_file(filepath, tamper, threat_name)
            else:
                # log but not quarantined
                if tamper:
                    self._log_chain_event(EventCode.TAMPER_DETECTED, {"file": filepath})
                if threat_name:
                    self._log_chain_event(EventCode.MALWARE_MATCH, {"file": filepath, "threat": threat_name})
        else:
            # update known hash
            self._update_file_hash(filepath)

    def _check_file_security(self, filepath: str) -> (bool, Optional[str]):
        """
        Returns (tampered, threat_name).
        tampered = True if file's current hash != stored hash
        threat_name = str if file is in malware DB
        """
        tampered = False
        # compute hash
        file_hash = self._compute_sha256(filepath)
        stored_hash = self._hash_store.get(filepath)

        if stored_hash and stored_hash != file_hash:
            tampered = True

        # check malware
        threat_name = self.malware_db.check_file(filepath)

        return (tampered, threat_name)

    def _quarantine_file(self, filepath: str, is_tamper: bool, threat_name: Optional[str]) -> None:
        """
        Moves the file to the quarantine directory, logs an event.
        """
        basename = os.path.basename(filepath)
        q_path = os.path.join(self.quarantine_dir, basename)
        # ensure unique if collision
        i = 0
        while os.path.exists(q_path):
            i += 1
            q_path = os.path.join(self.quarantine_dir, f"{basename}.{i}")
        try:
            shutil.move(filepath, q_path)
        except Exception as e:
            logger.error("Failed to quarantine file %s => %s", filepath, e)
            return

        metadata = {"original_path": filepath, "quarantine_path": q_path}
        if is_tamper:
            metadata["reason"] = "tamper"
        if threat_name:
            metadata["threat"] = threat_name

        self._log_chain_event(EventCode.FILE_QUARANTINED, metadata)

    def _update_file_hash(self, filepath: str) -> None:
        """
        Updates the file's hash in .hashes.json
        """
        file_hash = self._compute_sha256(filepath)
        self._hash_store[filepath] = file_hash
        self._save_hash_store()

    # --------------------------
    # Hash Store
    # --------------------------
    def _load_hash_store(self) -> Dict[str, str]:
        if not os.path.isfile(self.hash_store_path):
            return {}
        try:
            with open(self.hash_store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
        except Exception:
            return {}

    def _save_hash_store(self) -> None:
        try:
            with open(self.hash_store_path, "w", encoding="utf-8") as f:
                json.dump(self._hash_store, f)
        except Exception as e:
            logger.warning("Failed to save hash store: %s", e)

    # --------------------------
    # Utils
    # --------------------------
    def _excluded_path(self, path: str, excludes: list) -> bool:
        for e in excludes:
            if path.startswith(e):
                return True
        return False

    def _compute_sha256(self, filepath: str) -> str:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def _log_chain_event(self, event_code: EventCode, metadata: Dict[str, Any]) -> None:
        """
        Appends an event to the audit chain with the given code + metadata.
        """
        try:
            self.audit_chain.append_event(event_code.value, metadata)
        except ChainTamperDetectedError as e:
            logger.error("Chain tampering detected while logging event %s: %s", event_code, e)
        except Exception as ex:
            logger.error("Failed to append event %s: %s", event_code, ex)