# aepok_sentinel/core/controller.py

"""
Sentinel Controller

This module coordinates the primary boot sequence, runtime checks, and main daemon flow for the Aepok Sentinel system.
It handles:
  1) Loading and signature-checking .sentinelrc to determine enforcement mode.
  2) Validating runtime directories and trust anchors.
  3) Initializing the license manager, key manager, autoban manager, and security daemon (if not watch-only).
  4) Emitting major audit events, including controller startup and any failure conditions in strict/hardened modes.
  5) Providing convenience methods for manual anchor operations and system restarts.

Typical usage:
  controller = SentinelController(
      config_path="~/config/.sentinelrc", 
      sentinel_runtime_base="/opsec/aepok_sentinel/runtime",
      state_path="~/controller_state.json"
  )
  controller.boot()
  ...
  controller.stop()
"""

import os
import json
import logging
import threading
import time
import datetime
import shutil
from typing import Optional, Dict, Any

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.directory_contract import validate_runtime_structure
from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, LicenseError, is_watch_only
from aepok_sentinel.core.key_manager import KeyManager, KeyManagerError
from aepok_sentinel.core.audit_chain import AuditChain, ChainTamperDetectedError
from aepok_sentinel.core.security_daemon import SecurityDaemon
from aepok_sentinel.core.autoban import AutobanManager
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.pqc_crypto import verify_content_signature
from aepok_sentinel.core.pqc_crypto import CryptoSignatureError
from aepok_sentinel.core.pqc_crypto import sign_content_bundle, CryptoDecryptionError

logger = get_logger("controller")


class ControllerError(Exception):
    """
    Raised for irrecoverable controller-level errors encountered during
    boot, trust validation, or strict enforcement checks.
    """


class SentinelController:
    """
    The main orchestrator of the Sentinel system. It performs the entire boot sequence:
      1) Load and verify .sentinelrc with its signature.
      2) Perform disk usage checks, directory validations, trust anchor verification.
      3) Initialize the license manager (license checks), key manager (for cryptographic material),
         autoban manager (blocking suspicious sources), and the audit chain manager.
      4) Emit a CONTROLLER_BOOT event on success, then start the SecurityDaemon if not watch-only.
      5) Provide anchor operations (anchor_now, get_anchor_status) for on-demand chain anchoring.
      6) Provide stop/restart logic to gracefully end or re-initiate the system.

    Typical usage pattern:
        controller = SentinelController(
            config_path="...",
            sentinel_runtime_base="...",
            state_path="..."
        )
        controller.boot()
        ...
        controller.stop()

    If enforcement_mode is STRICT or HARDENED, any missing or invalid signatures will cause a hard fail (ControllerError).
    In PERMISSIVE mode, the system logs warnings and continues in a degraded state.
    """

    def __init__(
        self,
        config_path: str,
        sentinel_runtime_base: str,
        state_path: str,
        chain_dir: Optional[str] = None
    ):
        """
        Initialize the SentinelController with the necessary paths.

        :param config_path: A path (possibly external) to the .sentinelrc configuration file.
        :param sentinel_runtime_base: The top-level runtime directory, usually /opsec/aepok_sentinel/runtime
        :param state_path: Where to store persistent controller/daemon state (not necessarily in runtime).
        :param chain_dir: Optional override for the audit chain directory; if None, we
                          derive from config or default to /var/log/sentinel in permissive mode.
        """
        self.config_path = config_path
        self.sentinel_runtime_base = sentinel_runtime_base
        self.state_path = state_path
        self.chain_dir = chain_dir

        self.config: Optional[SentinelConfig] = None
        self.license_mgr: Optional[LicenseManager] = None
        self.key_manager: Optional[KeyManager] = None
        self.audit_chain: Optional[AuditChain] = None
        self.security_daemon: Optional[SecurityDaemon] = None
        self.autoban_mgr: Optional[AutobanManager] = None

        self._daemon_thread: Optional[threading.Thread] = None
        self._running = False

        self._host_fingerprint: str = "unknown_host"
        self._license_uuid: str = ""

    def boot(self) -> None:
        """
        Perform the main boot sequence:

          1) Load and signature-check .sentinelrc => sets enforcement mode.
          2) Disk usage check (if free < threshold, strict => raise).
          3) validate_runtime_structure(...) => ensures subdirectories are correct.
          4) verify trust_anchor.json and identity.json => signature and hash checks of vendor pub key.
          5) Create and load the LicenseManager => if invalid with must_fail => raises ControllerError.
          6) Create KeyManager, AuditChain, and AutobanManager.
          7) Log CONTROLLER_BOOT event to the chain.
          8) If not watch-only => start the SecurityDaemon in a separate thread.

        Writes some minimal state info to 'state_path'.
        Raises ControllerError if any required step fails in strict/hardened or license_required modes.
        """
        logger.info("Controller: starting boot sequence.")

        # (1) load + signature-check .sentinelrc
        self._load_config_with_signature()

        # (2) disk usage check
        self._disk_sanity_check()

        # (3) validate runtime structure
        try:
            validate_runtime_structure(self.sentinel_runtime_base, strict_fail=self._must_fail())
        except Exception as e:
            logger.error("Runtime structure validation failed: %s", e)
            if self._must_fail():
                raise ControllerError(f"Runtime structure invalid, strict fail: {e}")
            logger.warning("Continuing in permissive mode despite structure error.")

        # (4) verify trust_anchor.json + identity.json
        self._verify_trust_anchor_and_identity()

        # retrieve stable host fingerprint
        # if fails => possibly raise in strict
        try:
            from aepok_sentinel.core.identity import get_host_fingerprint  # hypothetical
            self._host_fingerprint = get_host_fingerprint(self.sentinel_runtime_base)
        except Exception as e:
            logger.warning("Failed to get host fingerprint: %s", e)
            if self._must_fail():
                raise ControllerError(f"Host fingerprint not available: {e}")

        # (5) license
        from aepok_sentinel.core.license import LicenseManager
        self.license_mgr = LicenseManager(self.config)
        try:
            self.license_mgr.load_license()
            lic_info = self.license_mgr.license_state.info
            self._license_uuid = lic_info.get("license_uuid", "")
        except LicenseError as e:
            logger.warning("License error => watch-only or fail: %s", e)
            if self._must_fail():
                raise ControllerError(f"License required but invalid: {e}")

        # (6) KeyManager, AuditChain, Autoban
        self._init_key_manager()
        self._init_audit_chain()
        self._init_autoban()

        # (7) Log CONTROLLER_BOOT
        self._chain_event(EventCode.CONTROLLER_BOOT, {
            "status": "complete",
            "blocked_ip_count": str(self._autoban_blocked_count())
        })

        # (8) if not watch-only => start daemon
        from aepok_sentinel.core.license import is_watch_only
        if not is_watch_only(self.license_mgr):
            self.security_daemon = SecurityDaemon(
                config=self.config,
                license_mgr=self.license_mgr,
                audit_chain=self.audit_chain
            )
            self._running = True
            self._daemon_thread = threading.Thread(target=self._daemon_loop, daemon=True)
            self._daemon_thread.start()
        else:
            logger.info("System in watch-only mode => Security Daemon not started.")

        # Save minimal state
        self._save_state({"boot_utc": self._utc_now()})
        logger.info("Controller boot complete => watch_only=%s", is_watch_only(self.license_mgr))

    def stop(self) -> None:
        """
        Halts the system's SecurityDaemon if running, and saves final state info.
        """
        logger.info("Controller stopping.")
        if self.security_daemon and self._running:
            self.security_daemon.stop()
            if self._daemon_thread:
                self._daemon_thread.join(timeout=10)
        self._running = False
        self._save_state({"stop_utc": self._utc_now()})
        logger.info("Controller stopped.")

    def restart(self) -> None:
        """
        Stop then re-boot the controller (re-initializing config, license, etc.).
        """
        logger.info("Controller restart requested.")
        self.stop()
        self.boot()

    def anchor_now(self) -> None:
        """
        Manually trigger an anchor export if the audit chain is available.
        """
        if self.audit_chain:
            self.audit_chain.trigger_anchor_now()

    def get_anchor_status(self) -> Dict[str, Any]:
        """
        Returns current anchor or checkpoint status from the audit chain.
        """
        if self.audit_chain:
            return self.audit_chain.get_current_root_info()
        return {}

    # ----------------------------------------------------------------
    # Internal Steps and Utility Methods
    # ----------------------------------------------------------------

    def _load_config_with_signature(self) -> None:
        """
        Loads .sentinelrc from self.config_path, plus .sentinelrc.sig if present,
        verifying the signature with sentinelrc_dilithium_pub.pem. In strict/hardened or if
        license_required, missing or invalid sig => raise. Else degrade with warnings.
        On success => builds self.config = a SentinelConfig object.
        """
        if not os.path.isfile(self.config_path):
            raise ControllerError(f".sentinelrc not found: {self.config_path}")

        sig_path = self.config_path + ".sig"
        if not os.path.isfile(sig_path):
            msg = f".sentinelrc.sig missing => cannot verify config in strict/hardened."
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                file_str = f.read()
            with open(sig_path, "rb") as sf:
                sig_b64 = sf.read()
        except Exception as e:
            raise ControllerError(f"Failed to read .sentinelrc or .sentinelrc.sig: {e}")

        import base64
        try:
            sig_json_bytes = base64.b64decode(sig_b64)
            import json as j
            sig_dict = j.loads(sig_json_bytes.decode("utf-8"))
        except Exception as e:
            msg = f".sentinelrc.sig is not valid base64 or JSON: {e}"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            sig_dict = None

        sentinelrc_pub = self._load_sentinelrc_pub_key()
        if sentinelrc_pub and sig_dict:
            data_bytes = file_str.encode("utf-8")
            ok = verify_content_signature(data_bytes, sig_dict, None, sentinelrc_pub, None)
            if not ok:
                msg = "Signature verification failed for .sentinelrc"
                logger.warning(msg)
                if self._must_fail():
                    raise ControllerError(msg)
        elif not sentinelrc_pub:
            msg = "Missing sentinelrc_dilithium_pub.pem => cannot fully verify .sentinelrc in strict/hard."
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)

        # parse config JSON
        try:
            raw_data = json.loads(file_str)
        except Exception as e:
            raise ControllerError(f"Failed to parse .sentinelrc JSON: {e}")

        # build SentinelConfig
        from aepok_sentinel.core.config import SentinelConfig
        try:
            self.config = SentinelConfig(raw_data)
            logger.info("Config loaded with enforcement_mode=%s", self.config.enforcement_mode)
        except Exception as e:
            raise ControllerError(f".sentinelrc validation error: {e}")

    def _disk_sanity_check(self) -> None:
        """
        Checks free disk space under self.sentinel_runtime_base. If too low => in strict => raise, else warn.
        """
        threshold_bytes = 50 * 1024 * 1024  # 50MB
        try:
            stat = shutil.disk_usage(self.sentinel_runtime_base)
            if stat.free < threshold_bytes:
                logger.error("Disk free %d < required %d => strict may fail", stat.free, threshold_bytes)
                self._chain_event(EventCode.DISK_LIMIT_EXCEEDED, {
                    "free_bytes": str(stat.free),
                    "threshold": str(threshold_bytes)
                })
                if self._must_fail():
                    raise ControllerError("Insufficient disk space in strict/hardened mode.")
                logger.warning("Low disk => continuing in permissive mode.")
        except Exception as e:
            logger.warning("disk_sanity_check error: %s", e)
            if self._must_fail():
                raise ControllerError(f"disk_sanity_check error in strict mode: {e}")

        def _verify_trust_anchor_and_identity(self) -> None:
        """
        Verifies trust_anchor.json + identity.json (and their .sig) for:
          - vendor_dilithium_pub.pem hash
          - sentinelrc_dilithium_pub.pem hash (if present)
          - identity signature
        Raises ControllerError if missing or invalid in strict/hardened mode.
        """
        # trust_anchor
        anchor_path = resolve_path("config", "trust_anchor.json")
        anchor_sig = resolve_path("config", "trust_anchor.json.sig")
        self._verify_file_signature(anchor_path, anchor_sig, desc="trust_anchor.json")

        # parse trust_anchor to check file hashes + embedded binding
        try:
            with open(anchor_path, "r", encoding="utf-8") as f:
                anchor_obj = json.load(f)
        except Exception as e:
            if self._must_fail():
                raise ControllerError(f"Cannot parse trust_anchor.json in strict/hardened: {e}")
            logger.warning("trust_anchor.json parse error => permissive degrade: %s", e)
            anchor_obj = {}

        file_hashes = anchor_obj.get("hashes", {})
        for rel_path in file_hashes.keys():
            if rel_path == "config/identity.json":  # already verified later
                continue
            try:
                abs_path = resolve_path(*rel_path.split("/"))
                sig_path = abs_path.with_suffix(abs_path.suffix + ".sig")
                if not abs_path.is_file() or not sig_path.is_file():
                    msg = f"{rel_path} or its .sig is missing => trust anchor integrity broken"
                    logger.warning(msg)
                    if self._must_fail():
                        raise ControllerError(msg)
                    continue
                self._verify_file_signature(abs_path, sig_path, desc=rel_path)
            except Exception as e:
                logger.warning("Signature check failed for %s => %s", rel_path, e)
                if self._must_fail():
                    raise ControllerError(f"Signature check failed for {rel_path}: {e}")

        vend_pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")
        vend_pub_hash = anchor_obj.get("vendor_dil_pub_sha256")
        if vend_pub_hash:
            self._verify_file_hash(vend_pub_path, vend_pub_hash, "vendor_dilithium_pub.pem")
        else:
            msg = "trust_anchor.json missing 'vendor_dil_pub_sha256'"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)

        # sentinelrc pub optional
        sentinelrc_pub_path = resolve_path("keys", "sentinelrc_dilithium_pub.pem")
        sr_pub_hash = anchor_obj.get("sentinelrc_pub_sha256")
        if sr_pub_hash:
            self._verify_file_hash(sentinelrc_pub_path, sr_pub_hash, "sentinelrc_dilithium_pub.pem")
        else:
            logger.warning("No sentinelrc_pub_sha256 in trust_anchor => .sentinelrc pub not bound")

        # identity
        identity_path = resolve_path("config", "identity.json")
        identity_sig = resolve_path("config", "identity.json.sig")
        self._verify_file_signature(identity_path, identity_sig, desc="identity.json")

        # === MOVED: identity_json_sha256 binding check — must follow anchor_obj load ===
        expected_id_hash = anchor_obj.get("identity_json_sha256")
        if expected_id_hash:
            import hashlib
            try:
                data = identity_path.read_bytes()
                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash != expected_id_hash.lower():
                    msg = (
                        f"identity.json hash mismatch => expected={expected_id_hash}, got={actual_hash}"
                    )
                    logger.error(msg)
                    if self._must_fail():
                        raise ControllerError(msg)
                    else:
                        logger.warning("identity.json hash mismatch => continuing in permissive mode.")
            except Exception as e:
                msg = f"Failed to compute identity.json hash => {e}"
                logger.error(msg)
                if self._must_fail():
                    raise ControllerError(msg)
        else:
            logger.warning("No identity_json_sha256 in trust_anchor => skipping hash bind.")

    def _verify_file_signature(self, file_path: Path, sig_path: Path, desc: str) -> None:
        """
        If file or sig is missing => strict => raise, else degrade.
        If signature invalid => strict => raise, else degrade.
        """
        if not file_path.is_file():
            msg = f"{desc} missing => strict/hard => fail"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return
        if not sig_path.is_file():
            msg = f"{desc} signature missing => strict/hard => fail"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return

        # read them
        try:
            data_str = file_path.read_text(encoding="utf-8")
            sig_b64 = sig_path.read_bytes()
        except Exception as e:
            msg = f"Failed to read {desc} or .sig => {e}"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return

        import base64
        import json
        try:
            sig_json = base64.b64decode(sig_b64)
            sig_dict = json.loads(sig_json.decode("utf-8"))
        except Exception as e:
            msg = f"{desc} signature is invalid base64 or JSON => {e}"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return

        # read vendor_dil, used for verifying trust anchor & identity
        vend_path = resolve_path("keys", "vendor_dilithium_pub.pem")
        if not vend_path.is_file():
            msg = "Missing vendor_dilithium_pub.pem => cannot verify trust anchor or identity in strict/hard"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return
        vendor_pub = vend_path.read_bytes()

        ok = verify_content_signature(data_str.encode("utf-8"), sig_dict, None, vendor_pub, None)
        if not ok:
            msg = f"{desc} signature verification failed => strict/hard => fail"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)

    def _verify_file_hash(self, path: Path, expected_sha256: str, desc: str) -> None:
        """
        Compare the file's sha256 to expected_sha256. If mismatch => strict => raise, else degrade.
        """
        if not path.is_file():
            msg = f"{desc} not found => cannot verify hash => strict/hard => fail"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return
        import hashlib
        try:
            data = path.read_bytes()
            got_hash = hashlib.sha256(data).hexdigest().lower()
        except Exception as e:
            msg = f"Failed to read {desc} for hashing => {e}"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return

        if got_hash != expected_sha256.lower():
            msg = f"{desc} hash mismatch => got={got_hash}, expected={expected_sha256}"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)

    def _load_sentinelrc_pub_key(self) -> bytes:
        """
        Read sentinelrc_dilithium_pub.pem from runtime/keys. If missing in strict => raise, else degrade.
        """
        pub_path = resolve_path("keys", "sentinelrc_dilithium_pub.pem")
        if not pub_path.is_file():
            msg = "sentinelrc_dilithium_pub.pem not found => strict => fail"
            logger.warning(msg)
            if self._must_fail():
                raise ControllerError(msg)
            return b""
        try:
            return pub_path.read_bytes()
        except Exception as e:
            logger.warning("Failed reading sentinelrc_dilithium_pub: %s", e)
            if self._must_fail():
                raise ControllerError(str(e))
            return b""

    def _init_key_manager(self) -> None:
        """
        Instantiate the KeyManager to manage cryptographic keys. If fails in strict => raise, else degrade.
        """
        try:
            self.key_manager = KeyManager(self.config, self.license_mgr)
        except KeyManagerError as e:
            logger.warning("Key manager init fail => %s", e)
            if self._must_fail():
                raise ControllerError(f"Key manager error in strict: {e}")

    def _init_audit_chain(self) -> None:
        """
        Create the AuditChain with local PQC private keys for signing chain entries,
        and optionally an anchor config. Validate the chain on startup in strict => raise on fail.
        """
        chain_path = self.chain_dir or self.config.raw_dict.get("log_path", "/var/log/sentinel/")
        # fetch keys from the key manager
        if not self.key_manager:
            if self._must_fail():
                raise ControllerError("No key_manager => cannot init audit chain in strict/hard.")
            logger.warning("No KeyManager => chain partial init in permissive.")
            self.audit_chain = None
            return

        from aepok_sentinel.core.audit_chain import AuditChain
        local_keys = self.key_manager.fetch_current_keys()
        pqc_priv = {
            "dilithium": local_keys.get("dilithium_priv"),
            "rsa": local_keys.get("rsa_priv")
        }
        pqc_pub = {
            "dilithium": None,
            "rsa": None
        }

        anchor_config = {
            "anchor_export_path": self.config.raw_dict.get("anchor_export_path"),
            "enforcement_mode": self.config.enforcement_mode,
            "host_fingerprint": self._host_fingerprint,
            "license_uuid": self._license_uuid
        }

        self.audit_chain = AuditChain(
            pqc_priv_keys=pqc_priv,
            pqc_pub_keys=pqc_pub,
            max_size_bytes=100 * 1024 * 1024,
            background_verification_interval=0,
            anchor_config=anchor_config,
            chain_dir=chain_path
        )
        # validate chain
        try:
            self.audit_chain.validate_chain()
        except Exception as e:
            logger.warning("Audit chain invalid => %s", e)
            if self._must_fail():
                raise ControllerError(f"Chain invalid => strict mode fail: {e}")

    def _init_autoban(self) -> None:
        """
        Instantiate the AutobanManager to block suspicious sources. If fails => degrade or raise in strict.
        """
        from aepok_sentinel.core.autoban import AutobanManager
        try:
            self.autoban_mgr = AutobanManager(self.config, self.license_mgr, self.audit_chain)
        except Exception as e:
            logger.warning("Autoban init fail => %s", e)
            self.autoban_mgr = None
            if self._must_fail():
                raise ControllerError(f"Autoban init error => strict/hard fail: {e}")

    def _autoban_blocked_count(self) -> int:
        """
        Return the number of currently blocked IPs from AutobanManager, or 0 if unavailable.
        """
        if not self.autoban_mgr:
            return 0
        # older code suggests .blocked_ips might exist, so let's adapt:
        if hasattr(self.autoban_mgr, "blocked_data"):
            return len(self.autoban_mgr.blocked_data)
        return 0

    def _daemon_loop(self) -> None:
        """
        Starts the security daemon in its own thread, restarts once on crash if possible,
        then stops if it crashes again.
        """
        if not self.security_daemon:
            return
        try:
            self.security_daemon.start()
        except Exception as e:
            logger.error("Security daemon crashed first time => %s", e)
            try:
                self.security_daemon.stop()
                time.sleep(1)
                self.security_daemon.start()  # second chance
            except Exception as e2:
                logger.critical("Daemon crashed again => giving up. %s", e2)
                self._running = False
        logger.info("Security daemon loop ended or crashed => no further restarts.")
        self._running = False

    def _chain_event(self, event: EventCode, metadata: Dict[str, Any]) -> None:
        """
        Append an event to the audit chain, if available. Attaches enforcement_mode, host_fingerprint, license_uuid, and a UTC timestamp.
        """
        if self.config:
            metadata["enforcement_mode"] = getattr(self.config, "enforcement_mode", "UNKNOWN")
        else:
            metadata["enforcement_mode"] = "UNKNOWN"

        metadata["host_fingerprint"] = self._host_fingerprint
        metadata["license_uuid"] = self._license_uuid
        metadata["utc"] = self._utc_now()

        if self.audit_chain:
            try:
                self.audit_chain.append_event(event.value, metadata)
            except Exception as e:
                logger.error("Failed to append chain event %s => %s", event.value, e)
        else:
            logger.info("No audit chain => event %s with metadata %s", event.value, metadata)

    def _must_fail(self) -> bool:
        """
        Return True if we must fail on missing files or invalid states.
        This is True if enforcement_mode is STRICT/HARDENED or if license_required = True.
        """
        mode = "PERMISSIVE"
        if self.config and hasattr(self.config, "enforcement_mode"):
            mode = str(self.config.enforcement_mode).upper()
        if mode in ("STRICT", "HARDENED"):
            return True
        if self.config and self.config.raw_dict.get("license_required", False) is True:
            return True
        return False

    def _utc_now(self) -> str:
        """
        Returns current time in UTC isoformat without microseconds.
        """
        return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    def _save_state(self, extra: dict) -> None:
        """
        Update a small JSON with the given 'extra' fields, ignoring errors in permissive mode or raising in strict/hard if desired.
        """
        state = {}
        if os.path.isfile(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except Exception:
                pass

        state.update(extra)
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save controller state => %s", e)
            if self._must_fail():
                raise ControllerError(f"Cannot save controller state in strict/hard: {e}")