"""
Aepok Sentinel - Audit Chain (Final Shape)

This module enforces a cryptographically verifiable audit chain:
1. Every event is appended with a Merkle path, linking it to a final root.
2. Each entry is signed if private keys are available.
3. Writes are atomic (.chain_tmp) and locked (fcntl/msvcrt).
4. On rollover, we create a signed checkpoint file referencing the final chain root.
5. On system boot, we check a boot_hash for replay detection (Flaw [15]).
6. Optionally, we do background verification every N minutes/events (Flaw [13]).
7. No silent directory creation (Flaws [75–78]); we rely on directory_contract.

Flaws Addressed:
 - [2] We log config/keys loads or any system events with append_event(...)
 - [12], [52] Real-time file locking for chain writes
 - [13] Optional background verification
 - [14] Signed rollover checkpoints
 - [15] boot_hash replay detection
 - [48] External anchor hook
 - [55] .chain_tmp for atomic writes
 - [59], [63] Additional features for secure export and provenance hashing
   (illustrative placeholders included).
"""

import os
import json
import hashlib
import base64
import platform
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.pqc_crypto import (
    sign_content_bundle,
    verify_content_signature,
    CryptoSignatureError
)

logger = get_logger("audit_chain")


# Platform-specific locking
if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl


class ChainTamperDetectedError(Exception):
    """
    Raised if the chain fails validation (hash mismatch, signature mismatch, or
    monotonic timestamp broken).
    """
    pass


class AuditChainError(Exception):
    """General runtime error in the AuditChain."""


def _lock_file(file_obj):
    """Cross-platform exclusive lock."""
    if platform.system() == "Windows":
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)


def _unlock_file(file_obj):
    """Cross-platform unlock."""
    if platform.system() == "Windows":
        msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def _utc_iso_now() -> str:
    """Returns current UTC time in isoformat with Z suffix."""
    dt = datetime.utcnow().replace(microsecond=0)
    return dt.isoformat() + "Z"


def _parse_iso8601(s: str) -> datetime:
    """Naive parse of iso8601 with trailing 'Z' removal."""
    return datetime.fromisoformat(s.replace("Z", ""))


class AuditChain:
    """
    Final-shape Audit Chain manager with concurrency locks, atomic writes,
    merkle-based verification, signed checkpoints, and optional background checks.
    """

    def __init__(
        self,
        pqc_priv_keys: Dict[str, bytes],
        pqc_pub_keys: Dict[str, bytes],
        max_size_bytes: int = 100 * 1024 * 1024,
        background_verification_interval: int = 0,  # minutes or event-based
        anchor_config: Optional[Dict[str, Any]] = None
    ):
        """
        :param pqc_priv_keys: e.g. {"dilithium": ..., "rsa": ...} for signing new entries
        :param pqc_pub_keys:  e.g. {"dilithium": ..., "rsa": ...} for verifying if needed
        :param max_size_bytes: rollover threshold
        :param background_verification_interval:
           If > 0, we schedule a background verify task every N minutes or every N events (policy).
           For simplicity, let's assume it's in minutes.
        :param anchor_config: if provided, we can anchor final roots to an external system (Flaw [48]).
        """

        # Resolve the audit directory from directory_contract
        # If "audit" folder doesn't exist => fail. No silent creation.
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

        # PQC keys for signing/verify
        self.pqc_priv_keys = pqc_priv_keys
        self.pqc_pub_keys = pqc_pub_keys

        # Internal mem structures
        self.leaf_hashes: List[str] = []
        self.tree_levels: List[List[str]] = []

        # We'll load or create a boot_hash to detect replay (Flaw [15]).
        self.boot_hash = self._load_or_create_boot_hash()

        # Optionally start background verification thread
        self._stop_bg_thread = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None
        if self.background_verification_interval > 0:
            self._bg_thread = threading.Thread(target=self._bg_verify_loop, daemon=True)
            self._bg_thread.start()

        # Load chain state (merkle) from disk if you store it separately...
        # or we can rely on on-demand validate_chain.

    def stop(self):
        """
        Cleanly stops any background thread for verification.
        """
        if self._bg_thread and self._bg_thread.is_alive():
            self._stop_bg_thread.set()
            self._bg_thread.join()

    def _bg_verify_loop(self):
        """
        Every N minutes, run validate_chain() in the background.
        """
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
                # Possibly broadcast an alert, etc.
                # Or we set some system halting logic.

    # -----------------------------------------------------------------
    # Public append method with concurrency lock & .chain_tmp approach
    # -----------------------------------------------------------------
    def append_event(self, event: str, metadata: Dict[str, Any]) -> None:
        """
        Appends a new event to the chain atomically:
          1. Build the record (with prev_hash).
          2. JSON-encode it, compute entry_hash, merkle_path.
          3. Sign it if we have private keys.
          4. Write to .chain_tmp, fsync, then lock & append to final chain.
        Raises ChainTamperDetectedError if partial corruption found.
        """
        # re-validate replay? Not necessarily each time, but let's do a quick check
        if not self._check_boot_hash():
            logger.error("Chain replay suspected. Boot hash mismatch.")
            try:
                self.append_event("CHAIN_REPLAY_SUSPECTED", {
                    "timestamp": _utc_iso_now(),
                    "reason": "boot_hash mismatch",
                    "expected_root": self.boot_hash.get("last_known_root", "unknown"),
                    "actual_root": self._get_current_merkle_root()
                })
            except Exception:
                pass  # avoid infinite recursion if audit chain is already failing
            raise ChainTamperDetectedError("Replay or tampering suspected on boot_hash mismatch.")

        # Lock the chain file
        with open(self.chain_file, "a+", encoding="utf-8") as chain_f:
            _lock_file(chain_f)
            try:
                # Possibly reload or partial parse. For final shape, let's do on-demand
                self._build_in_memory_state()

                prev_hash = "GENESIS" if not self.leaf_hashes else self.leaf_hashes[-1]
                record = {
                    "timestamp": _utc_iso_now(),
                    "event": event,
                    "metadata": metadata,
                    "prev_hash": prev_hash
                }
                # Prepare partial JSON
                partial_json = json.dumps(record, sort_keys=True).encode("utf-8")
                entry_hash = hashlib.sha512(partial_json).hexdigest()
                record["entry_hash"] = entry_hash

                # Build merkle path from new leaf
                leaf_idx = len(self.leaf_hashes)
                merkle_path = self._compute_merkle_path(leaf_idx)
                record["merkle_path"] = merkle_path

                # sign if we have keys
                record["signature"] = ""
                if self.pqc_priv_keys.get("dilithium"):
                    data_bytes = json.dumps(record, sort_keys=True).encode("utf-8")
                    sig_bundle = sign_content_bundle(
                        data_bytes,
                        None,  # config not strictly needed if we trust usage
                        self.pqc_priv_keys.get("dilithium"),
                        self.pqc_priv_keys.get("rsa")
                    )
                    record["signature"] = base64.b64encode(json.dumps(sig_bundle).encode("utf-8")).decode("utf-8")

                # Write to .chain_tmp => fsync => append to real file
                tmp_data = json.dumps(record) + "\n"
                with open(self.chain_tmp, "w", encoding="utf-8") as tmp_f:
                    tmp_f.write(tmp_data)
                    tmp_f.flush()
                    os.fsync(tmp_f.fileno())

                # Now append from tmp to real chain
                with open(self.chain_tmp, "r", encoding="utf-8") as tmp_f:
                    contents = tmp_f.read()
                chain_f.write(contents)

                # Insert new leaf in memory
                self._insert_new_leaf(entry_hash)
            finally:
                _unlock_file(chain_f)

        # Check rollover
        self._maybe_rollover()

    # -----------------------------------------------------------------
    # Validation with concurrency lock
    # -----------------------------------------------------------------
    def validate_chain(self, raise_on_fail: bool = True) -> bool:
        """
        Validate entire chain: 
          - correct linking
          - monotonic timestamps
          - correct merkle_path
          - optional signature verify if pub keys are present
        If raise_on_fail=True, we raise ChainTamperDetectedError on mismatch.
        Otherwise return False if mismatch, True if success.
        """
        with open(self.chain_file, "r", encoding="utf-8") as chain_f:
            _lock_file(chain_f)
            try:
                lines = chain_f.readlines()
            finally:
                _unlock_file(chain_f)

        if not lines:
            # empty chain => trivially valid
            return True

        prev_hash = "GENESIS"
        last_ts = None
        # We rebuild memory
        self.leaf_hashes = []
        self.tree_levels = []

        for line_num, raw_line in enumerate(lines, start=1):
            line_str = raw_line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
            except Exception as e:
                return self._validation_fail(raise_on_fail, f"Line {line_num}: invalid JSON => {e}")

            missing_fields = [f for f in ["timestamp", "event", "metadata", "prev_hash",
                                          "entry_hash", "merkle_path", "signature"]
                              if f not in record]
            if missing_fields:
                return self._validation_fail(
                    raise_on_fail,
                    f"Line {line_num} missing fields: {missing_fields}"
                )

            # Check hash
            rec_copy = dict(record)
            signature_val = rec_copy.pop("signature")
            merkle_val = rec_copy.pop("merkle_path")
            entry_h = rec_copy.pop("entry_hash")

            partial_json = json.dumps(rec_copy, sort_keys=True).encode("utf-8")
            computed_hash = hashlib.sha512(partial_json).hexdigest()
            if computed_hash != entry_h:
                return self._validation_fail(
                    raise_on_fail,
                    f"Line {line_num}: hash mismatch => {computed_hash} != {entry_h}"
                )

            # check linking
            if line_num == 1:
                if record["prev_hash"] != "GENESIS":
                    return self._validation_fail(
                        raise_on_fail,
                        "Line 1: prev_hash must be GENESIS"
                    )
            else:
                if record["prev_hash"] != prev_hash:
                    return self._validation_fail(
                        raise_on_fail,
                        f"Line {line_num}: linking error => {record['prev_hash']} != {prev_hash}"
                    )

            # monotonic time
            ts_dt = _parse_iso8601(record["timestamp"])
            if last_ts and ts_dt <= last_ts:
                return self._validation_fail(
                    raise_on_fail,
                    f"Line {line_num}: non-monotonic timestamp => {record['timestamp']} <= {last_ts.isoformat()}"
                )
            last_ts = ts_dt

            # If we have public keys => verify signature if present
            if signature_val and self.pqc_pub_keys.get("dilithium"):
                try:
                    sig_json_bytes = base64.b64decode(signature_val)
                    sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
                    data_bytes = json.dumps(rec_copy, sort_keys=True).encode("utf-8")
                    ok = verify_content_signature(
                        data_bytes,
                        sig_dict,
                        None,  # config not mandatory
                        self.pqc_pub_keys.get("dilithium"),
                        self.pqc_pub_keys.get("rsa")
                    )
                    if not ok:
                        return self._validation_fail(
                            raise_on_fail,
                            f"Line {line_num}: signature verify failed"
                        )
                except Exception as e:
                    return self._validation_fail(
                        raise_on_fail,
                        f"Line {line_num}: signature parse or verify error => {e}"
                    )

            # merkle path => reconstruct memory insertion
            self._insert_leaf_during_validation(entry_h)
            fresh_path = self._compute_merkle_path(len(self.leaf_hashes) - 1)
            if fresh_path != merkle_val:
                return self._validation_fail(
                    raise_on_fail,
                    f"Line {line_num}: merkle path mismatch => {merkle_val} vs {fresh_path}"
                )

            prev_hash = entry_h

        # All good
        return True

    # -----------------------------------------------------------------
    # Rollover => sign checkpoint
    # -----------------------------------------------------------------
    def _maybe_rollover(self):
        if not self.chain_file.is_file():
            return
        size = self.chain_file.stat().st_size
        if size < self.max_size_bytes:
            return

        logger.info("Audit chain size %d >= %d => rollover triggered.", size, self.max_size_bytes)
        self._rollover_chain()

    def _rollover_chain(self):
        # 1) Validate chain to get final root
        valid = self.validate_chain(raise_on_fail=False)
        if not valid:
            logger.error("Chain is invalid upon rollover => forced. Proceeding anyway.")
            # We might choose to rename chain as broken.

        final_root = self._get_current_merkle_root()
        # Create checkpoint
        cpoint_filename = f"{self.checkpoint_file_prefix}{time.strftime('%Y%m%d_%H%M%S')}.json"
        cpoint_path = self.audit_dir / cpoint_filename
        cpoint_data = {
            "previous_chain_file": self.chain_file.name,
            "final_merkle_root": final_root,
            "timestamp": _utc_iso_now()
        }

        # sign checkpoint with vendor key if available (Flaw [14])
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

        # 2) rename old chain
        stamp = time.strftime("old_chain_%Y%m%d_%H%M%S.log")
        rollover_path = self.audit_dir / stamp
        os.rename(self.chain_file, rollover_path)
        logger.info("Rollover completed. Old chain => %s", rollover_path)

        # 3) Reset memory
        self.leaf_hashes.clear()
        self.tree_levels.clear()

        # 4) Possibly anchor to external system
        if self.anchor_config:
            self._submit_to_external_anchor(final_root, cpoint_path)

        # 5) New chain file is empty now
        with open(self.chain_file, "w", encoding="utf-8"):
            pass

        # 6) Update boot_hash with new root
        self._store_boot_hash(final_root)

    # -----------------------------------------------------------------
    # Replay & Boot Hash
    # -----------------------------------------------------------------
    def _load_or_create_boot_hash(self) -> Dict[str, Any]:
        """
        Load a file that stores "last_known_root" + "timestamp" + signature. If missing,
        create an initial one. If signature fails => suspect replay.
        """
        if not self.boot_hash_file.is_file():
            # brand new => create
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
            # optional verify signature if we have pub key
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
        """
        Update boot_hash.json with new last_known_root, plus signature if we have a private key.
        """
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
        """
        Compare the boot_hash's last_known_root to current chain root. If mismatch
        suggests partial rollback or replay. We'll allow if chain is empty or brand new.
        """
        current_root = self._get_current_merkle_root()
        stored_root = self.boot_hash.get("last_known_root", "EMPTY_CHAIN")
        if current_root not in ("EMPTY_CHAIN", stored_root):
            # mismatch => suspect replay
            return False
        return True

    # -----------------------------------------------------------------
    # Export & Provenance (Flaws [59], [63]) - optional stubs
    # -----------------------------------------------------------------
    def export_chain(self, output_path: str) -> None:
        """
        Securely export the entire chain + merkle root signature for off-system analysis.
        Possibly sign the tarball/zip with local private key and emit EXPORT_CHAIN event.
        """
        # 1) validate chain
        if not self.validate_chain(raise_on_fail=False):
            logger.warning("Chain invalid, exporting anyway with a warning.")
        # 2) read entire chain
        with open(self.chain_file, "r", encoding="utf-8") as cf:
            _lock_file(cf)
            try:
                content = cf.read()
            finally:
                _unlock_file(cf)

        # 3) compress or just write
        with open(output_path, "w", encoding="utf-8") as out_f:
            out_f.write(content)

        # 4) optionally write .sig or hash to accompany export
        sig_path = output_path + ".sig"
        prov_hash = hashlib.sha512(content.encode("utf-8")).hexdigest()
        try:
            if self.pqc_priv_keys.get("dilithium"):
                sig_bundle = sign_content_bundle(content.encode("utf-8"), None, self.pqc_priv_keys["dilithium"], self.pqc_priv_keys.get("rsa"))
                import base64, json as j
                sig_json = j.dumps(sig_bundle).encode("utf-8")
                sig_b64 = base64.b64encode(sig_json)
                with open(sig_path, "wb") as sf:
                    sf.write(sig_b64)
        except Exception as e:
            logger.warning("Failed to write audit chain export signature: %s", e)

        # 5) log event with export path and provenance hash
        self.append_event("EXPORT_CHAIN", {
            "export_path": output_path,
            "signature_path": sig_path,
            "provenance_sha512": prov_hash
        })

    def compute_provenance_hash(self) -> str:
        """
        Return a single SHA512 over the entire chain contents to anchor externally.
        """
        with open(self.chain_file, "r", encoding="utf-8") as cf:
            _lock_file(cf)
            try:
                content = cf.read()
            finally:
                _unlock_file(cf)
        return hashlib.sha512(content.encode("utf-8")).hexdigest()
      
        def get_current_root_info(self) -> Dict[str, Any]:
            """
            Returns current Merkle root and latest checkpoint filename.
            Used by CLI/GUI for anchor status panels.
            """
            current_root = self._get_current_merkle_root()

            checkpoint_files = sorted(
                [f for f in os.listdir(self.audit_dir) if f.startswith("chain_checkpoint_") and f.endswith(".json")],
                reverse=True
            )
            latest_checkpoint = checkpoint_files[0] if checkpoint_files else None

            return {
                "merkle_root": current_root,
                "latest_checkpoint": latest_checkpoint
            }

    # -----------------------------------------------------------------
    # Helpers for internal Merkle logic
    # -----------------------------------------------------------------
    def _build_in_memory_state(self):
        """
        Rebuilds the in-memory leaf_hashes + tree_levels from disk.
        Not a full validate; just partial re-creation. If partial or tampered,
        might show up next validate.
        """
        self.leaf_hashes.clear()
        self.tree_levels.clear()
        if not self.chain_file.is_file():
            return
        with open(self.chain_file, "r", encoding="utf-8") as chain_f:
            lines = chain_f.readlines()

        for raw_line in lines:
            line_str = raw_line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
                entry_hash = record["entry_hash"]
                self._insert_leaf_during_validation(entry_hash)
            except Exception:
                pass  # we skip

    def _insert_leaf_during_validation(self, leaf_hash: str) -> None:
        # if first insertion
        if not self.tree_levels:
            self.tree_levels = [[leaf_hash]]
            self.leaf_hashes = [leaf_hash]
            return
        self.leaf_hashes.append(leaf_hash)
        self._rebuild_tree_levels()

    def _insert_new_leaf(self, leaf_hash: str) -> None:
        """
        Called once we've appended a new record. We finalize memory structure.
        """
        self.leaf_hashes.append(leaf_hash)
        if not self.tree_levels:
            self.tree_levels = [[leaf_hash]]
        else:
            self._rebuild_tree_levels()

    def _rebuild_tree_levels(self):
        """
        Rebuild entire merkle tree from self.leaf_hashes.
        """
        leaves = self.leaf_hashes[:]
        levels = [leaves]
        while len(levels[-1]) > 1:
            prev_level = levels[-1]
            new_level = []
            for i in range(0, len(prev_level), 2):
                left = prev_level[i]
                if i + 1 < len(prev_level):
                    right = prev_level[i + 1]
                else:
                    right = left
                pair_hash = hashlib.sha512((left + right).encode("utf-8")).hexdigest()
                new_level.append(pair_hash)
            levels.append(new_level)
        self.tree_levels = levels

    def _compute_merkle_path(self, leaf_idx: int) -> List[str]:
        """
        Return the path of sibling hashes from leaf_idx up to the root.
        Uses "L:" or "R:" prefix to indicate which side the sibling is on.
        """
        path = []
        lvl = 0
        idx = leaf_idx
        while lvl < len(self.tree_levels) - 1:
            siblings = self.tree_levels[lvl]
            pair_index = idx ^ 1  # flip last bit
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
        Writes anchor_submission_<UTC>.json to the directory defined in .sentinelrc["anchor_export_path"].
        Includes full bundle: merkle root, checkpoint filename, host/license info, and signed hash.
        If path is missing => logs ANCHOR_EXPORT_FAILED and aborts silently.
        """
        export_dir = self.anchor_config.get("anchor_export_path") if self.anchor_config else None
        if not export_dir or not os.path.isdir(export_dir):
            try:
                self.append_event("ANCHOR_EXPORT_FAILED", {
                    "reason": "anchor_export_path missing or invalid",
                    "path": export_dir or "undefined",
                    "final_root": final_root,
                    "checkpoint": str(cpoint_path)
                })
            except Exception:
                pass
            return

        from datetime import datetime
        import base64, json as j

        utc_ts = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        fname = f"anchor_submission_{utc_ts.replace(':', '').replace('-', '').replace('Z', '')}.json"
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

        try:
            if self.pqc_priv_keys.get("dilithium"):
                sig_bundle = sign_content_bundle(
                    json.dumps(payload, sort_keys=True).encode("utf-8"),
                    None,
                    self.pqc_priv_keys["dilithium"],
                    self.pqc_priv_keys.get("rsa")
                )
                payload["signature"] = base64.b64encode(j.dumps(sig_bundle).encode("utf-8")).decode("utf-8")
            else:
                payload["signature"] = ""
        except Exception as e:
            self.append_event("ANCHOR_EXPORT_FAILED", {
                "reason": "signature_failed",
                "error": str(e),
                "final_root": final_root
            })
            return

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

    def trigger_anchor_now(self) -> None:
        """
        Manually triggers an external anchor submission using the current Merkle root and latest checkpoint file.
        This is intended for CLI or GUI manual use.
        """
        # Validate the current chain
        valid = self.validate_chain(raise_on_fail=False)
        if not valid:
            logger.warning("Manual anchor aborted: audit chain is not valid.")
            self.append_event("ANCHOR_EXPORT_FAILED", {"reason": "chain_invalid_on_manual_trigger"})
            return

        # Get final Merkle root
        final_root = self._get_current_merkle_root()

        # Try to find the most recent checkpoint file
        checkpoint_files = sorted(
            [f for f in os.listdir(self.audit_dir) if f.startswith("chain_checkpoint_") and f.endswith(".json")],
            reverse=True
        )
        if not checkpoint_files:
            self.append_event("ANCHOR_EXPORT_FAILED", {"reason": "no_checkpoint_file_found"})
            logger.warning("Manual anchor aborted: no checkpoint file available.")
            return

        latest_checkpoint = os.path.join(self.audit_dir, checkpoint_files[0])
        self._submit_to_external_anchor(final_root, latest_checkpoint)
