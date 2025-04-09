# audit_chain.py
"""
Aepok Sentinel - Audit Chain

Implements a cryptographically verifiable audit chain:
 1. Appends events with a Merkle path, linking to a final root.
 2. Optionally signs events if private keys are available.
 3. Employs atomic writes (.chain_tmp) with file locking.
 4. Triggers signed checkpoint files on rollover.
 5. Detects chain replay via a boot_hash file.
 6. Optionally performs background verification at intervals.
 7. Relies on directory_contract for the audit folder; no silent creation.

Usage:
  from aepok_sentinel.core.audit_chain import AuditChain

  chain = AuditChain(pqc_priv_keys, pqc_pub_keys, ...)
  chain.append_event("CONFIG_LOADED", {"file": ".sentinelrc"})

  # Later, chain.validate_chain() or chain.export_chain()
"""

import os
import json
import hashlib
import base64
import logging
import time
import threading
import platform
from datetime import datetime
from typing import Dict, Any, Optional, List, Union

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.pqc_crypto import (
    sign_content_bundle,
    verify_content_signature
)

logger = get_logger("audit_chain")

if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl


class ChainTamperDetectedError(Exception):
    """
    Raised if the chain fails validation (hash mismatch, signature mismatch, or
    a monotonic timestamp violation).
    """
    pass


class AuditChainError(Exception):
    """General error within AuditChain initialization or runtime."""


def _lock_file(file_obj):
    if platform.system() == "Windows":
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)


def _unlock_file(file_obj):
    if platform.system() == "Windows":
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def _utc_iso_now() -> str:
    dt = datetime.utcnow().replace(microsecond=0)
    return dt.isoformat() + "Z"


def _parse_iso8601(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", ""))


class AuditChain:
    """
    Manages an append-only, Merkle-based audit chain with optional signature,
    concurrency locks, rollover, external anchoring, and background verification.
    """

    def __init__(
        self,
        pqc_priv_keys: Dict[str, bytes],
        pqc_pub_keys: Dict[str, bytes],
        max_size_bytes: int = 100 * 1024 * 1024,
        background_verification_interval: int = 0,
        anchor_config: Optional[Dict[str, Any]] = None
    ):
        """
        :param pqc_priv_keys: e.g. {"dilithium": b"...", "rsa": b"..."} for signing new events
        :param pqc_pub_keys:  e.g. {"dilithium": b"...", "rsa": b"..."} for verifying if needed
        :param max_size_bytes: chain rollover threshold
        :param background_verification_interval: minutes between auto-verify attempts (0=off)
        :param anchor_config: optional config for external anchoring
        """
        # Resolve "audit" folder via directory_contract
        self.audit_dir = resolve_path("audit")
        if not self.audit_dir.is_dir():
            raise AuditChainError(
                f"Audit directory missing: {self.audit_dir}. Cannot proceed."
            )

        self.chain_file = self.audit_dir / "audit_chain.log"
        self.chain_tmp = self.audit_dir / "audit_chain_tmp.json"
        self.checkpoint_file_prefix = "chain_checkpoint_"
        self.boot_hash_file = self.audit_dir / "boot_hash.json"

        self.max_size_bytes = max_size_bytes
        self.background_verification_interval = background_verification_interval
        self.anchor_config = anchor_config

        self.pqc_priv_keys = pqc_priv_keys
        self.pqc_pub_keys = pqc_pub_keys

        self.leaf_hashes: List[str] = []
        self.tree_levels: List[List[str]] = []

        # Initialize boot_hash to detect chain replay.
        self.boot_hash = self._load_or_create_boot_hash()

        # Start background verification if configured
        self._stop_bg_thread = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None
        if self.background_verification_interval > 0:
            self._bg_thread = threading.Thread(target=self._bg_verify_loop, daemon=True)
            self._bg_thread.start()

    def stop(self):
        """Stops any background verification thread."""
        if self._bg_thread and self._bg_thread.is_alive():
            self._stop_bg_thread.set()
            self._bg_thread.join()

    def _bg_verify_loop(self):
        """Every N minutes, run validate_chain(). Logs issues on detection."""
        interval_sec = self.background_verification_interval * 60
        while not self._stop_bg_thread.is_set():
            time.sleep(interval_sec)
            if self._stop_bg_thread.is_set():
                break
            try:
                self.validate_chain(raise_on_fail=True)
                logger.info("Background chain verification passed.")
            except ChainTamperDetectedError as e:
                logger.error("Background chain verification failed: %s", e)

    def append_event(self, event: str, metadata: Dict[str, Any]) -> None:
        """
        Appends a new event:
          - Checks for replay mismatch in boot_hash
          - Builds & signs the record
          - Writes to .chain_tmp => atomically appends to the chain file
          - Possibly triggers rollover
        """
        if not self._check_boot_hash():
            logger.error("Chain replay suspected; mismatch with stored root.")
            try:
                self.append_event("CHAIN_REPLAY_SUSPECTED", {
                    "timestamp": _utc_iso_now(),
                    "reason": "boot_hash mismatch",
                    "expected_root": self.boot_hash.get("last_known_root", "unknown"),
                    "actual_root": self._get_current_merkle_root()
                })
            except Exception:
                pass
            raise ChainTamperDetectedError("Replay or tampering suspected.")

        with open(self.chain_file, "a+", encoding="utf-8") as chain_f:
            _lock_file(chain_f)
            try:
                self._build_in_memory_state()

                prev_hash = "GENESIS" if not self.leaf_hashes else self.leaf_hashes[-1]
                record = {
                    "timestamp": _utc_iso_now(),
                    "event": event,
                    "metadata": metadata,
                    "prev_hash": prev_hash
                }
                partial_json = json.dumps(record, sort_keys=True).encode("utf-8")
                entry_hash = hashlib.sha512(partial_json).hexdigest()
                record["entry_hash"] = entry_hash

                # Build Merkle path
                leaf_idx = len(self.leaf_hashes)
                merkle_path = self._compute_merkle_path(leaf_idx)
                record["merkle_path"] = merkle_path

                # Sign if keys are present
                record["signature"] = ""
                if self.pqc_priv_keys.get("dilithium"):
                    data_bytes = json.dumps(record, sort_keys=True).encode("utf-8")
                    sig_bundle = sign_content_bundle(
                        data_bytes,
                        None,
                        self.pqc_priv_keys.get("dilithium"),
                        self.pqc_priv_keys.get("rsa")
                    )
                    record["signature"] = base64.b64encode(json.dumps(sig_bundle).encode("utf-8")).decode("utf-8")

                # Write to .chain_tmp first
                tmp_data = json.dumps(record) + "\n"
                with open(self.chain_tmp, "w", encoding="utf-8") as tmp_f:
                    tmp_f.write(tmp_data)
                    tmp_f.flush()
                    os.fsync(tmp_f.fileno())

                # Read it back and confirm we can write it to chain
                with open(self.chain_tmp, "r", encoding="utf-8") as tmp_f:
                    contents = tmp_f.read()

                try:
                    chain_f.write(contents)
                    chain_f.flush()
                    os.fsync(chain_f.fileno())
                except Exception as e:
                    logger.error("Failed to write to audit_chain.log => skipping Merkle update: %s", e)
                    return  # Prevent in-memory desync

                # Only now update in-memory state
                self._insert_new_leaf(entry_hash)

            finally:
                _unlock_file(chain_f)

        # Check for rollover
        self._maybe_rollover()

    def validate_chain(self, raise_on_fail: bool = True) -> bool:
        """
        Full chain validation:
          - checks event linking, monotonic timestamps, merkle path correctness
          - optional signature verification if pub_keys exist
        Raises ChainTamperDetectedError if invalid and raise_on_fail=True; otherwise returns False.
        """
        with open(self.chain_file, "r", encoding="utf-8") as chain_f:
            _lock_file(chain_f)
            try:
                lines = chain_f.readlines()
            finally:
                _unlock_file(chain_f)

        if not lines:
            return True

        prev_hash = "GENESIS"
        last_ts = None
        self.leaf_hashes.clear()
        self.tree_levels.clear()

        for line_num, raw_line in enumerate(lines, start=1):
            line_str = raw_line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
            except Exception as e:
                return self._validation_fail(raise_on_fail, f"Line {line_num}: invalid JSON => {e}")

            for field in ["timestamp", "event", "metadata", "prev_hash", "entry_hash", "merkle_path", "signature"]:
                if field not in record:
                    return self._validation_fail(raise_on_fail, f"Line {line_num} missing '{field}'")

            rec_copy = dict(record)
            signature_val = rec_copy.pop("signature")
            merkle_val = rec_copy.pop("merkle_path")
            entry_h = rec_copy.pop("entry_hash")

            partial_json = json.dumps(rec_copy, sort_keys=True).encode("utf-8")
            computed_hash = hashlib.sha512(partial_json).hexdigest()
            if computed_hash != entry_h:
                return self._validation_fail(raise_on_fail, f"Line {line_num}: hash mismatch")

            if line_num == 1:
                if record["prev_hash"] != "GENESIS":
                    return self._validation_fail(raise_on_fail, "Line 1: prev_hash must be GENESIS")
            else:
                if record["prev_hash"] != prev_hash:
                    return self._validation_fail(raise_on_fail, f"Line {line_num}: linking error => prev_hash mismatch")

            ts_dt = _parse_iso8601(record["timestamp"])
            if last_ts and ts_dt <= last_ts:
                return self._validation_fail(raise_on_fail, f"Line {line_num}: non-monotonic timestamp")
            last_ts = ts_dt

            # If we have pub keys => verify signature if present
            if signature_val and self.pqc_pub_keys.get("dilithium"):
                try:
                    sig_json_bytes = base64.b64decode(signature_val)
                    sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
                    data_bytes = json.dumps(rec_copy, sort_keys=True).encode("utf-8")
                    ok = verify_content_signature(
                        data_bytes,
                        sig_dict,
                        None,
                        self.pqc_pub_keys["dilithium"],
                        self.pqc_pub_keys.get("rsa")
                    )
                    if not ok:
                        return self._validation_fail(raise_on_fail, f"Line {line_num}: signature verify failed")
                except Exception as e:
                    return self._validation_fail(raise_on_fail, f"Line {line_num}: signature parse or verify error => {e}")

            # Rebuild merkle
            self._insert_leaf_during_validation(entry_h)
            fresh_path = self._compute_merkle_path(len(self.leaf_hashes) - 1)
            if fresh_path != merkle_val:
                return self._validation_fail(raise_on_fail, f"Line {line_num}: merkle path mismatch")

            prev_hash = entry_h

        return True

    def stop(self):
        """Cleanly stops background verification if running."""
        if self._bg_thread and self._bg_thread.is_alive():
            self._stop_bg_thread.set()
            self._bg_thread.join()

    def _maybe_rollover(self):
        if not self.chain_file.is_file():
            return
        size = self.chain_file.stat().st_size
        if size < self.max_size_bytes:
            return

        logger.info("Audit chain size %d >= %d => rollover triggered.", size, self.max_size_bytes)
        self._rollover_chain()

    def _rollover_chain(self):
        valid = self.validate_chain(raise_on_fail=False)
        if not valid:
            logger.error("Chain invalid upon rollover => forced anyway.")

        final_root = self._get_current_merkle_root()
        cpoint_filename = f"{self.checkpoint_file_prefix}{time.strftime('%Y%m%d_%H%M%S')}.json"
        cpoint_path = self.audit_dir / cpoint_filename
        cpoint_data = {
            "previous_chain_file": self.chain_file.name,
            "final_merkle_root": final_root,
            "timestamp": _utc_iso_now()
        }

        if self.pqc_priv_keys.get("dilithium"):
            raw_bytes = json.dumps(cpoint_data, sort_keys=True).encode("utf-8")
            sig_bundle = sign_content_bundle(
                raw_bytes,
                None,
                self.pqc_priv_keys["dilithium"],
                self.pqc_priv_keys.get("rsa")
            )
            cpoint_data["signature"] = base64.b64encode(json.dumps(sig_bundle).encode("utf-8")).decode("utf-8")
        else:
            cpoint_data["signature"] = ""

        with open(cpoint_path, "w", encoding="utf-8") as f:
            json.dump(cpoint_data, f, indent=2)
        logger.info("Created signed checkpoint: %s", cpoint_path)

        stamp = time.strftime("old_chain_%Y%m%d_%H%M%S.log")
        rollover_path = self.audit_dir / stamp
        os.rename(self.chain_file, rollover_path)
        logger.info("Rollover complete. Old chain => %s", rollover_path)

        self.leaf_hashes.clear()
        self.tree_levels.clear()

        self._submit_to_external_anchor(final_root, cpoint_path)

        with open(self.chain_file, "w", encoding="utf-8"):
            pass

        self._store_boot_hash(final_root)

    def export_chain(self, output_path: str) -> None:
        if not self.validate_chain(raise_on_fail=False):
            logger.warning("Chain invalid; exporting anyway.")
        with open(self.chain_file, "r", encoding="utf-8") as cf:
            _lock_file(cf)
            try:
                content = cf.read()
            finally:
                _unlock_file(cf)

        with open(output_path, "w", encoding="utf-8") as out_f:
            out_f.write(content)

        sig_path = output_path + ".sig"
        prov_hash = hashlib.sha512(content.encode("utf-8")).hexdigest()
        if self.pqc_priv_keys.get("dilithium"):
            try:
                sig_bundle = sign_content_bundle(content.encode("utf-8"), None, self.pqc_priv_keys["dilithium"], self.pqc_priv_keys.get("rsa"))
                sig_b64 = base64.b64encode(json.dumps(sig_bundle).encode("utf-8"))
                with open(sig_path, "wb") as sf:
                    sf.write(sig_b64)
            except Exception as e:
                logger.warning("Failed to write export signature: %s", e)

        self.append_event("EXPORT_CHAIN", {
            "export_path": output_path,
            "signature_path": sig_path,
            "provenance_sha512": prov_hash
        })

    def compute_provenance_hash(self) -> str:
        with open(self.chain_file, "r", encoding="utf-8") as cf:
            _lock_file(cf)
            try:
                content = cf.read()
            finally:
                _unlock_file(cf)
        return hashlib.sha512(content.encode("utf-8")).hexdigest()

    def trigger_anchor_now(self) -> None:
        valid = self.validate_chain(raise_on_fail=False)
        if not valid:
            logger.warning("Manual anchor aborted: chain is not valid.")
            self.append_event("ANCHOR_EXPORT_FAILED", {"reason": "chain_invalid_on_manual_trigger"})
            return

        final_root = self._get_current_merkle_root()
        files = [f for f in os.listdir(self.audit_dir) if f.startswith("chain_checkpoint_") and f.endswith(".json")]
        if not files:
            self.append_event("ANCHOR_EXPORT_FAILED", {"reason": "no_checkpoint_file_found"})
            logger.warning("Manual anchor aborted: no checkpoint available.")
            return

        cpoint = os.path.join(self.audit_dir, sorted(files, reverse=True)[0])
        self._submit_to_external_anchor(final_root, cpoint)

    def stop(self):
        if self._bg_thread and self._bg_thread.is_alive():
            self._stop_bg_thread.set()
            self._bg_thread.join()

    # ------------------------------
    # Internal replay & boot hash
    # ------------------------------
    def _load_or_create_boot_hash(self) -> Dict[str, Any]:
        if not self.boot_hash_file.is_file():
            data = {
                "last_known_root": "EMPTY_CHAIN",
                "timestamp": _utc_iso_now()
            }
            if self.pqc_priv_keys.get("dilithium"):
                raw_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
                sig_bundle = sign_content_bundle(
                    raw_bytes,
                    None,
                    self.pqc_priv_keys["dilithium"],
                    self.pqc_priv_keys.get("rsa")
                )
                data["signature"] = base64.b64encode(json.dumps(sig_bundle).encode("utf-8")).decode("utf-8")
            else:
                data["signature"] = ""
            with open(self.boot_hash_file, "w", encoding="utf-8") as bf:
                json.dump(data, bf, indent=2)
            return data
        else:
            with open(self.boot_hash_file, "r", encoding="utf-8") as bf:
                content = json.load(bf)

            sig_val = content.get("signature", "")
            content_copy = dict(content)
            content_copy.pop("signature", None)
            raw_bytes = json.dumps(content_copy, sort_keys=True).encode("utf-8")
            if sig_val and self.pqc_pub_keys.get("dilithium"):
                try:
                    sig_json_bytes = base64.b64decode(sig_val)
                    sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
                    ok = verify_content_signature(
                        raw_bytes,
                        sig_dict,
                        None,
                        self.pqc_pub_keys["dilithium"],
                        self.pqc_pub_keys.get("rsa")
                    )
                    if not ok:
                        logger.error("boot_hash signature invalid => potential replay.")
                except Exception as e:
                    logger.error("Failed to verify boot_hash signature => %s", e)
            return content

    def _store_boot_hash(self, new_root: str):
        data = {
            "last_known_root": new_root,
            "timestamp": _utc_iso_now()
        }
        if self.pqc_priv_keys.get("dilithium"):
            raw_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
            sig_bundle = sign_content_bundle(
                raw_bytes,
                None,
                self.pqc_priv_keys["dilithium"],
                self.pqc_priv_keys.get("rsa")
            )
            data["signature"] = base64.b64encode(json.dumps(sig_bundle).encode("utf-8")).decode("utf-8")
        else:
            data["signature"] = ""
        with open(self.boot_hash_file, "w", encoding="utf-8") as bf:
            json.dump(data, bf, indent=2)

    def _check_boot_hash(self) -> bool:
        current_root = self._get_current_merkle_root()
        stored_root = self.boot_hash.get("last_known_root", "EMPTY_CHAIN")
        if current_root not in ("EMPTY_CHAIN", stored_root):
            return False
        return True

    # ------------------------------
    # Internal merkle logic
    # ------------------------------
    def _build_in_memory_state(self):
        """
        Rebuilds Merkle state from audit_chain.log,
        but halts if any line is corrupt, truncated, or incomplete.
        """
        self.leaf_hashes.clear()
        self.tree_levels.clear()
        if not self.chain_file.is_file():
            return

        with open(self.chain_file, "r", encoding="utf-8") as chain_f:
            lines = chain_f.readlines()

        for line_num, line_str in enumerate(lines, start=1):
            line_str = line_str.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
                if "entry_hash" not in record:
                    raise ValueError("Missing 'entry_hash' field")
                entry_hash = record["entry_hash"]
                self._insert_leaf_during_validation(entry_hash)
            except Exception as e:
                logger.error("Corrupt or partial line in audit chain at line %d => %s", line_num, e)
                raise ChainTamperDetectedError(
                    f"Invalid or incomplete entry in audit_chain.log at line {line_num} => {e}"
                )

    def _insert_leaf_during_validation(self, leaf_hash: str) -> None:
        if not self.tree_levels:
            self.tree_levels = [[leaf_hash]]
            self.leaf_hashes = [leaf_hash]
            return
        self.leaf_hashes.append(leaf_hash)
        self._rebuild_tree_levels()

    def _insert_new_leaf(self, leaf_hash: str) -> None:
        self.leaf_hashes.append(leaf_hash)
        if not self.tree_levels:
            self.tree_levels = [[leaf_hash]]
        else:
            self._rebuild_tree_levels()

    def _rebuild_tree_levels(self):
        leaves = self.leaf_hashes[:]
        levels = [leaves]
        while len(levels[-1]) > 1:
            prev_level = levels[-1]
            new_level = []
            for i in range(0, len(prev_level), 2):
                left = prev_level[i]
                right = prev_level[i + 1] if (i + 1 < len(prev_level)) else left
                pair_hash = hashlib.sha512((left + right).encode("utf-8")).hexdigest()
                new_level.append(pair_hash)
            levels.append(new_level)
        self.tree_levels = levels

    def _compute_merkle_path(self, leaf_idx: int) -> List[str]:
        path = []
        lvl = 0
        idx = leaf_idx
        while lvl < len(self.tree_levels) - 1:
            siblings = self.tree_levels[lvl]
            pair_index = idx ^ 1
            if pair_index < len(siblings):
                if idx % 2 == 0:
                    path.append("R:" + siblings[pair_index])
                else:
                    path.append("L:" + siblings[pair_index])
            idx //= 2
            lvl += 1
        return path

    def _get_current_merkle_root(self) -> str:
        if not self.tree_levels:
            return "EMPTY_CHAIN"
        top = self.tree_levels[-1]
        if not top:
            return "EMPTY_CHAIN"
        return top[0]

    @staticmethod
    def _validation_fail(raise_on_fail: bool, msg: str) -> bool:
        logger.error("CHAIN_BROKEN: %s", msg)
        if raise_on_fail:
            raise ChainTamperDetectedError(msg)
        return False

    def _submit_to_external_anchor(self, final_root: str, cpoint_path: Union[str, os.PathLike]) -> None:
        """
        If anchor_config has anchor_export_path, write anchor_submission_<UTC>.json with final root, etc.
        """
        export_dir = self.anchor_config.get("anchor_export_path") if self.anchor_config else None
        if not export_dir or not os.path.isdir(export_dir):
            try:
                self.append_event("ANCHOR_EXPORT_FAILED", {
                    "reason": "anchor_export_path invalid",
                    "path": export_dir or "undefined",
                    "final_root": final_root,
                    "checkpoint": str(cpoint_path)
                })
            except Exception:
                pass
            return

        from datetime import datetime
        utc_ts = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        fname = f"anchor_submission_{utc_ts.replace(':','').replace('-','').replace('Z','')}.json"
        full_path = os.path.join(export_dir, fname)

        payload = {
            "timestamp": utc_ts,
            "final_merkle_root": final_root,
            "checkpoint_filename": os.path.basename(cpoint_path),
            "enforcement_mode": self.anchor_config.get("enforcement_mode", "unspecified"),
            "host_fingerprint": self.anchor_config.get("host_fingerprint", "unknown"),
            "license_uuid": self.anchor_config.get("license_uuid", "unknown"),
            "source_chain_file": "audit_chain.log"
        }

        if self.pqc_priv_keys.get("dilithium"):
            try:
                raw = json.dumps(payload, sort_keys=True).encode("utf-8")
                sig_bundle = sign_content_bundle(
                    raw,
                    None,
                    self.pqc_priv_keys["dilithium"],
                    self.pqc_priv_keys.get("rsa")
                )
                import base64, json as j
                payload["signature"] = base64.b64encode(j.dumps(sig_bundle).encode("utf-8")).decode("utf-8")
            except Exception as e:
                self.append_event("ANCHOR_EXPORT_FAILED", {
                    "reason": "signature_failed",
                    "error": str(e),
                    "final_root": final_root
                })
                return
        else:
            payload["signature"] = ""

        try:
            with open(full_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self.append_event("ANCHOR_EXPORTED", {
                "path": full_path,
                "final_root": final_root,
                "checkpoint": os.path.basename(cpoint_path)
            })
        except Exception as e:
            self.append_event("ANCHOR_EXPORT_FAILED", {
                "reason": "write_failed",
                "error": str(e),
                "path": full_path
            })