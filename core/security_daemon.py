# security_daemon.py
"""
Security Daemon

Implements:
 - A hash store (.hashes.json + signature) to track file integrity within Sentinel's "security" directory.
 - Periodic or inotify-based scanning of configured paths, detecting tampered or malicious files.
 - Quarantines (if enabled) or logs events if in watch-only mode.
 - Integrates optional autoban logic if an intrusion source is detected in file metadata.
 - Enforces no silent directory creation for quarantine; raises if missing.

Usage:
  from aepok_sentinel.core.security_daemon import SecurityDaemon

  daemon = SecurityDaemon(config, license_mgr, audit_chain, ...)
  daemon.start()   # blocks until stop() or fatal error
"""

import os
import time
import json
import shutil
import logging
import hashlib
import threading
import datetime
from typing import Dict, Optional, Any
from pathlib import Path

from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only
from aepok_sentinel.core.audit_chain import AuditChain, ChainTamperDetectedError
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.pqc_crypto import sign_content_bundle, verify_content_signature
from aepok_sentinel.core.autoban import AutobanManager
from aepok_sentinel.utils.malware_db import MalwareDatabase, MalwareDBError

logger = get_logger("security_daemon")


class SecurityDaemonError(Exception):
    """Raised for fatal errors in the security daemon."""


class FileTamperDetectedError(Exception):
    """Raised when a file’s hash mismatches the stored hash, prompting quarantine or logs."""


class SecurityDaemon:
    """
    Monitors configured directories for file changes:
      - Loads and signs a .hashes.json to track each file’s hash.
      - In watch-only mode, we log tamper or malware but do not quarantine.
      - If quarantining is enabled, tampered or malicious files are moved to quarantine.
      - Attempts to identify intrusion sources in file names for potential autoban triggers.
      - Supports inotify or poll-based scanning, and stops after exceeding max inotify errors.
    """

    MAX_INOTIFY_ERRORS = 5

    def __init__(
        self,
        config: SentinelConfig,
        license_mgr: LicenseManager,
        audit_chain: AuditChain,
        hash_store_path: Path = resolve_path("security", ".hashes.json"),
        quarantine_dir: Path = resolve_path("quarantine"),
        sign_priv_key_path: Path = resolve_path("security", "daemon_dilithium_priv.bin"),
        autoban_mgr: Optional[AutobanManager] = None
    ):
        self.config = config
        self.license_mgr = license_mgr
        self.audit_chain = audit_chain
        self.hash_store_path = hash_store_path
        self.quarantine_dir = quarantine_dir
        self.sign_priv_key_path = sign_priv_key_path
        self.autoban_mgr = autoban_mgr

        if not self.quarantine_dir.is_dir():
            raise RuntimeError(f"Quarantine directory missing: {self.quarantine_dir}")

        self._hash_store: Dict[str, str] = {}
        self._previous_hashes: Dict[str, list] = {}
        self._hash_seen_table: Dict[str, Dict[str, Any]] = {}

        # Load the signed hash store
        self._load_hash_store()
        self._initialize_hash_seen_table()

        # Load malware DB
        self.malware_db = MalwareDatabase(config)
        try:
            self.malware_db.load_signatures()
        except MalwareDBError as e:
            logger.warning("Failed to load malware signatures: %s", e)

        self._stop_flag = threading.Event()

        self._use_inotify = bool(self.config.raw_dict.get("use_inotify", False))
        self._poll_interval = int(self.config.daemon_poll_interval)

    def start(self) -> None:
        """
        Runs the main loop: inotify-based if configured, else poll-based.
        Blocks until stop() is called or a fatal error occurs.
        """
        logger.info(
            "SecurityDaemon start. watch_only=%s, inotify=%s",
            is_watch_only(self.license_mgr),
            self._use_inotify
        )
        self._log_chain_event(
            EventCode.DAEMON_STARTED,
            {
                "mode": "inotify" if self._use_inotify else "poll",
                "watch_only": str(is_watch_only(self.license_mgr)),
                "enforcement_mode": getattr(self.config, "enforcement_mode", "unknown"),
                "scan_paths": self.config.scan_paths
            }
        )

        if self._use_inotify:
            self._run_inotify_loop()
        else:
            self._run_poll_loop()

    def stop(self) -> None:
        """Requests shutdown of the main loop."""
        self._stop_flag.set()

    # ------------------------------
    # Poll-based scanning
    # ------------------------------
    def _run_poll_loop(self) -> None:
        scan_paths = self.config.scan_paths
        exclude_paths = self.config.exclude_paths
        recursive = self.config.scan_recursive

        logger.info("Poll loop started.")
        while not self._stop_flag.is_set():
            self._scan_directories(scan_paths, exclude_paths, recursive)
            time.sleep(self._poll_interval)
        logger.info("Poll loop stopped gracefully.")

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

    # ------------------------------
    # Inotify-based scanning
    # ------------------------------
    def _run_inotify_loop(self) -> None:
        logger.info("Inotify loop started.")
        error_count = 0
        try:
            from inotify_simple import INotify, flags
        except ImportError:
            logger.error("inotify_simple not installed => fallback to poll.")
            self._run_poll_loop()
            return

        inotify = INotify()
        watch_flags = flags.CREATE | flags.MODIFY | flags.MOVED_TO

        for p in self.config.scan_paths:
            if os.path.isdir(p):
                wd = inotify.add_watch(p, watch_flags)
                if self.config.scan_recursive:
                    for root, dirs, _ in os.walk(p):
                        for d in dirs:
                            subdir = os.path.join(root, d)
                            inotify.add_watch(subdir, watch_flags)

        while not self._stop_flag.is_set():
            events = inotify.read(timeout=1000)
            if not events:
                continue
            for e in events:
                watch_path = inotify.watches[e.wd].path
                full_path = os.path.join(watch_path, e.name)
                if not os.path.isfile(full_path):
                    continue
                if self._excluded_path(full_path, self.config.exclude_paths):
                    continue
                try:
                    self._process_file(full_path)
                    error_count = 0
                except Exception as ex:
                    logger.warning("Error processing file %s: %s", full_path, ex)
                    error_count += 1
                    if error_count >= self.MAX_INOTIFY_ERRORS:
                        logger.error("Exceeded max inotify errors => halting daemon.")
                        self._log_chain_event(
                            EventCode.TAMPER_DETECTED,
                            {
                                "reason": "inotify_loop_excessive_errors",
                                "error_count": str(error_count)
                            }
                        )
                        self.stop()
                        break
        logger.info("Inotify loop stopped gracefully.")

    # ------------------------------
    # File event processing
    # ------------------------------
    def _process_file(self, filepath: str) -> None:
        """
        Compares file hash to stored hash. Checks for tamper or malware. 
        If intrusion_source is found, calls autoban. Quarantines if not watch-only and tamper/malware is detected.
        """
        tampered, threat, meta = self._analyze_file(filepath)
        intrusion_source = meta.get("intrusion_source")
        if intrusion_source and self.autoban_mgr:
            reason_str = f"{intrusion_source['type']}:{threat or 'tamper'}" if (tampered or threat) else intrusion_source['type']
            self.autoban_mgr.record_bad_source(intrusion_source["value"], reason_str)

        # watch-only => skip quarantine, but log
        if is_watch_only(self.license_mgr):
            if tampered:
                self._log_chain_event(EventCode.TAMPER_DETECTED, meta)
            if threat:
                mmeta = {"file": filepath, "threat": threat}
                if intrusion_source:
                    mmeta["source_type"] = intrusion_source["type"]
                    mmeta["source_value"] = intrusion_source["value"]
                self._log_chain_event(EventCode.MALWARE_MATCH, mmeta)
            return

        # normal => quarantine or log
        if tampered or threat:
            if self.config.quarantine_enabled:
                self._quarantine_file(filepath, tampered, threat, meta)
            else:
                if tampered:
                    self._log_chain_event(EventCode.TAMPER_DETECTED, meta)
                if threat:
                    mmeta = {"file": filepath, "threat": threat}
                    if intrusion_source:
                        mmeta["source_type"] = intrusion_source["type"]
                        mmeta["source_value"] = intrusion_source["value"]
                    self._log_chain_event(EventCode.MALWARE_MATCH, mmeta)
        else:
            self._update_file_hash(filepath)

    def _analyze_file(self, filepath: str) -> (bool, Optional[str], Dict[str, Any]):
        new_hash = self._compute_sha256(filepath)
        old_hash = self._hash_store.get(filepath)
        metadata = {"file": filepath, "new_hash": new_hash}
        new_size = os.path.getsize(filepath)
        metadata["new_size"] = str(new_size)

        intrusion = self._get_intrusion_source_for_file(filepath)
        if intrusion:
            metadata["intrusion_source"] = intrusion

        tampered = False
        if old_hash and old_hash != new_hash:
            tampered = True
            metadata["old_hash"] = old_hash
            old_size = self._file_size_cache(filepath)
            if old_size is not None:
                metadata["old_size"] = str(old_size)
                diff = new_size - old_size
                metadata["size_diff"] = str(diff)
            if filepath in self._previous_hashes and new_hash in self._previous_hashes[filepath]:
                metadata["replay_detected"] = "true"

        threat = self.malware_db.check_file(filepath)
        return tampered, threat, metadata

    def _quarantine_file(self, filepath: str, tampered: bool, threat_name: Optional[str], meta: Dict[str, Any]) -> None:
        basename = Path(filepath).name
        q_path = self.quarantine_dir / basename
        i = 0
        while q_path.exists():
            i += 1
            q_path = self.quarantine_dir / f"{basename}.{i}"

        try:
            shutil.move(filepath, q_path)
        except Exception as e:
            logger.error("Failed to quarantine file %s => %s", filepath, e)
            return

        meta["quarantine_path"] = str(q_path)
        if threat_name:
            meta["threat"] = threat_name
        if tampered:
            meta["tampered"] = "true"

        self._log_chain_event(EventCode.FILE_QUARANTINED, meta)

    def _update_file_hash(self, filepath: str) -> None:
        new_hash = self._compute_sha256(filepath)
        old_hash = self._hash_store.get(filepath)
        if old_hash and old_hash != new_hash:
            if filepath not in self._previous_hashes:
                self._previous_hashes[filepath] = []
            if old_hash not in self._previous_hashes[filepath]:
                self._previous_hashes[filepath].append(old_hash)

        self._hash_store[filepath] = new_hash
        now = datetime.datetime.utcnow().isoformat() + "Z"
        seen_entry = self._hash_seen_table.get(new_hash)
        if seen_entry:
            seen_entry["count"] += 1
            new_path_added = (filepath not in seen_entry["paths"])
            seen_entry["paths"].add(filepath)
            if new_path_added:
                # Possibly the same hash is reused in a new path => replay reuse detection
                self._log_chain_event("REPLAY_REUSE_DETECTED", {
                    "sha256": new_hash,
                    "new_path": filepath,
                    "known_paths": list(seen_entry["paths"]),
                    "first_seen": seen_entry["first_seen"],
                    "seen_count": seen_entry["count"]
                })
        else:
            self._hash_seen_table[new_hash] = {
                "count": 1,
                "first_seen": now,
                "paths": set([filepath])
            }

        self._save_hash_store()

    def _get_intrusion_source_for_file(self, filepath: str) -> Optional[Dict[str, str]]:
        base = os.path.basename(filepath).lower()
        if base.startswith("usb_"):
            return {"type": "usb", "value": f"usb:{base}"}
        elif base.startswith("mac_"):
            return {"type": "mac", "value": f"mac:{base}"}
        elif base.startswith("dev_"):
            return {"type": "device", "value": f"device:{base}"}
        elif base.startswith("host_"):
            return {"type": "hostname", "value": f"hostname:{base}"}
        elif base.startswith("proc_"):
            return {"type": "process", "value": f"proc:{base}"}
        else:
            # fallback => treat as IP
            return {"type": "ip", "value": f"{base}"}

    def _excluded_path(self, path: str, excludes: list) -> bool:
        for e in excludes:
            if path.startswith(e):
                return True
        return False

    def _load_hash_store(self) -> None:
        if not self.hash_store_path.is_file():
            return
        sig_path = self.hash_store_path.with_suffix(".json.sig")
        if not sig_path.is_file():
            logger.warning("Hash store signature missing => ignoring existing store.")
            return
        try:
            content_str = None
            with open(self.hash_store_path, "r", encoding="utf-8") as f:
                content_str = f.read()
            with open(sig_path, "rb") as sf:
                sig_bytes = sf.read()

            with open(self.sign_priv_key_path, "rb") as kf:
                dil_priv = kf.read()

            import base64, json as j
            sig_dict = j.loads(base64.b64decode(sig_bytes).decode("utf-8"))
            if not verify_content_signature(content_str.encode("utf-8"), sig_dict, self.config, dil_priv, None):
                logger.warning("Hash store signature invalid => ignoring.")
                return

            data = json.loads(content_str)
            if not isinstance(data, dict):
                logger.warning(".hashes.json invalid => ignoring.")
                return
            store = data.get("hashes", {})
            if not isinstance(store, dict):
                logger.warning("No 'hashes' dict found => ignoring.")
                return
            hist = data.get("previous_hashes", {})
            if not isinstance(hist, dict):
                hist = {}

            self._hash_store = store
            self._previous_hashes = hist
            logger.info("Loaded signed .hashes.json with %d entries + history.", len(self._hash_store))
        except Exception as e:
            logger.warning("Failed to load .hashes.json or signature: %s", e)

    def _save_hash_store(self) -> None:
        try:
            dpath = self.hash_store_path.parent
            if not dpath.is_dir():
                raise RuntimeError(f"Hash store directory missing: {dpath}")

            combined_data = {
                "hashes": self._hash_store,
                "previous_hashes": self._previous_hashes
            }
            content_str = json.dumps(combined_data, indent=2)
            
            tmp_hash_path = self.hash_store_path.with_suffix(".json.tmp")
            tmp_sig_path = self.hash_store_path.with_suffix(".json.sig.tmp")
            final_sig_path = self.hash_store_path.with_suffix(".json.sig")
            
            with open(self.hash_store_path, "w", encoding="utf-8") as f:
                f.write(content_str)

            with open(self.sign_priv_key_path, "rb") as kf:
                dil_priv = kf.read()
            sig_bundle = sign_content_bundle(content_str.encode("utf-8"), self.config, dil_priv, None)

            import json as j
            import base64
            sig_b64 = base64.b64encode(j.dumps(sig_bundle).encode("utf-8"))
            with open(f"{self.hash_store_path}.sig", "wb") as sf:
                sf.write(sig_b64)

            os.replace(tmp_hash_path, self.hash_store_path)
            os.replace(tmp_sig_path, final_sig_path)

        except Exception as e:
            logger.warning("Failed to save or sign .hashes.json: %s", e)
            if self.audit_chain:
                try:
                    self.audit_chain.append_event("HASH_STORE_WRITE_FAIL", {
                        "path": str(self.hash_store_path),
                        "error": str(e)
                    })
                except Exception as chain_ex:
                    logger.error("Failed to emit HASH_STORE_WRITE_FAIL to audit chain: %s", chain_ex)

            if not is_watch_only(self.license_mgr) and self.config.quarantine_enabled:
                logger.warning("Enforcing fallback: all scan targets will be quarantined on next pass.")
                # Clear the hash store to trigger tamper detection on all future files
                self._hash_store.clear()
                
    def _initialize_hash_seen_table(self) -> None:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        for path, hval in self._hash_store.items():
            if hval not in self._hash_seen_table:
                self._hash_seen_table[hval] = {
                    "count": 1,
                    "first_seen": now,
                    "paths": set([path])
                }
            else:
                self._hash_seen_table[hval]["count"] += 1
                self._hash_seen_table[hval]["paths"].add(path)

    def _compute_sha256(self, filepath: str) -> str:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def _file_size_cache(self, path: str) -> Optional[int]:
        """
        We do not store file sizes in .hashes.json in this final shape.
        If needed, we could track them. For now returns None.
        """
        return None

    def _log_chain_event(self, event_code: EventCode, metadata: dict) -> None:
        try:
            self.audit_chain.append_event(event_code.value, metadata)
        except ChainTamperDetectedError as e:
            logger.error("Chain tampering detected while logging event %s: %s", event_code, e)
        except Exception as ex:
            logger.error("Failed to append event %s: %s", event_code, ex)