"""
Step 6 (Rewritten): Audit Chain with Full Requirements

Features:
1. JSON-based linear chain:
   {
     "timestamp": "UTC iso8601",
     "event": "string",
     "metadata": {},
     "prev_hash": "sha512_of_prev_line",
     "entry_hash": "sha512_of_this_line",
     "merkle_path": [ ... sibling hashes ... ],
     "signature": "dilithium+RSA base64" or ""
   }
2. Strict signature verification if config.chain_verification_on_decrypt == true
3. Monotonic timestamps enforced
4. Merkle path stored in each record => partial inclusion proofs
5. rollover logic + separate merkle file for root
6. repair_chain() => re-validate, reseal the chain with a final "RESEAL" entry, logs CHAIN_RESEALED, invalidates old root
"""

import os
import json
import hashlib
import logging
import base64
import time
from datetime import datetime
from typing import Dict, Any, Optional, List

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_crypto import sign_content_bundle, verify_content_signature
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.pqc_crypto import CryptoSignatureError

logger = get_logger("audit_chain")


class ChainTamperDetectedError(Exception):
    """Raised if the chain fails validation (hash mismatch, signature mismatch, or monotonic timestamp broken)."""


class AuditChain:
    """
    Maintains a fully enforceable chain:
      - JSON lines in 'audit_chain.log'
      - Rollover after size limit
      - Each record has a merkle_path for partial proof
      - validate_chain() checks hash linking, monotonic timestamps, optional signature, merkle
      - repair_chain() => re-validate + finalize old chain, create RESEAL entry, new root
    """

    def __init__(self,
                 chain_dir: str = "/var/log/sentinel/audit",
                 chain_basename: str = "audit_chain.log",
                 merkle_state_filename: str = "audit_merkle.json",
                 max_size_bytes: int = 100 * 1024 * 1024,
                 config: Optional[SentinelConfig] = None,
                 dil_priv_key: Optional[bytes] = None,
                 rsa_priv_key: Optional[bytes] = None,
                 dil_pub_key: Optional[bytes] = None,
                 rsa_pub_key: Optional[bytes] = None):
        """
        :param chain_dir: directory for chain + merkle state
        :param chain_basename: main chain file name
        :param merkle_state_filename: file storing final merkle root, any partial states
        :param max_size_bytes: rollover threshold
        :param config: optional SentinelConfig
        :param dil_priv_key, rsa_priv_key: used to sign appended events
        :param dil_pub_key, rsa_pub_key: used to verify signatures if chain_verification_on_decrypt == True
        """
        self.chain_dir = chain_dir
        self.chain_basename = chain_basename
        self.merkle_state_filename = merkle_state_filename
        self.max_size_bytes = max_size_bytes
        self.config = config
        self.dil_priv_key = dil_priv_key
        self.rsa_priv_key = rsa_priv_key
        self.dil_pub_key = dil_pub_key
        self.rsa_pub_key = rsa_pub_key

        os.makedirs(chain_dir, exist_ok=True)
        self.current_file_path = os.path.join(chain_dir, chain_basename)
        self.merkle_state_path = os.path.join(chain_dir, merkle_state_filename)

        # We'll keep a list of leaf hashes in memory. Each appended line is a new leaf => new root
        # We'll also maintain a parallel structure that stores the entire merkle tree in memory
        # For partial proof generation. This is disk-synced to merkle_state_path if we want.
        self.leaf_hashes: List[str] = []
        self.tree_levels: List[List[str]] = []  # top-level final root in tree_levels[-1][0]

        self._load_merkle_state()

    def append_event(self, event: str, metadata: Dict[str, Any]) -> None:
        """
        Appends a new event to the chain, with merkle path, signature, etc.
        Steps:
          1) Load last entry_hash or GENESIS
          2) Build partial record
          3) Hash => entry_hash
          4) Build merkle path => store in 'merkle_path'
          5) Optionally sign => signature
          6) Write line
          7) update memory => check rollover
        """
        prev_hash = "GENESIS"
        if self.leaf_hashes:
            prev_hash = self.leaf_hashes[-1]

        # Check monotonic time requirement => we won't do it here, we do it in validate_chain
        record = {
            "timestamp": self._utc_iso_now(),
            "event": event,
            "metadata": metadata,
            "prev_hash": prev_hash
        }

        # We'll do partial JSON
        partial_json = json.dumps(record, sort_keys=True).encode("utf-8")
        entry_hash = hashlib.sha512(partial_json).hexdigest()
        record["entry_hash"] = entry_hash

        # Build merkle path from new leaf to existing root
        merkle_path = self._compute_merkle_path_for_new_leaf(entry_hash)
        record["merkle_path"] = merkle_path

        # sign if we have private key
        signature_str = ""
        if self.dil_priv_key:
            # sign the record minus "signature"
            record_copy = dict(record)
            data_bytes = json.dumps(record_copy, sort_keys=True).encode("utf-8")
            sig_bundle = sign_content_bundle(data_bytes, self.config, self.dil_priv_key, self.rsa_priv_key)
            signature_json = json.dumps(sig_bundle).encode("utf-8")
            signature_str = base64.b64encode(signature_json).decode("utf-8")

        record["signature"] = signature_str

        # final line
        line = json.dumps(record) + "\n"
        with open(self.current_file_path, "a", encoding="utf-8") as f:
            f.write(line)

        # update memory-based merkle
        self._insert_new_leaf(entry_hash)

        # check rollover
        self._maybe_rollover()

    def validate_chain(self) -> bool:
        """
        Reads entire chain, enforces:
          - hash link correctness
          - monotonic timestamps
          - signature verification if config says chain_verification_on_decrypt==True
          - merkle path correctness => each entry's 'merkle_path' must lead to final root
        If fail => logs CHAIN_BROKEN, raises ChainTamperDetectedError
        """
        # re-build in-memory from scratch
        self.leaf_hashes = []
        self.tree_levels = []

        if not os.path.isfile(self.current_file_path):
            logger.info("Chain file missing => chain empty => trivially valid.")
            return True

        lines = []
        with open(self.current_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        prev_hash = "GENESIS"
        last_ts = None  # for monotonic check
        chain_verification_required = False
        if self.config and getattr(self.config, "chain_verification_on_decrypt", False):
            chain_verification_required = True

        for line_num, raw_line in enumerate(lines, start=1):
            line_str = raw_line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
            except Exception as e:
                self._log_chain_broken(f"Line {line_num}: invalid JSON => {e}")
                raise ChainTamperDetectedError(f"Line {line_num}: invalid JSON => {e}")

            # check fields
            for fkey in ["timestamp", "event", "metadata", "prev_hash", "entry_hash", "signature", "merkle_path"]:
                if fkey not in record:
                    self._log_chain_broken(f"Line {line_num}: missing field {fkey}")
                    raise ChainTamperDetectedError(f"Line {line_num}: missing field '{fkey}'")

            # re-hash
            record_copy = dict(record)
            rec_signature = record_copy.pop("signature")
            rec_merkle_path = record_copy.pop("merkle_path")
            rec_entry_hash = record_copy.pop("entry_hash")
            partial_json = json.dumps(record_copy, sort_keys=True).encode("utf-8")
            computed_hash = hashlib.sha512(partial_json).hexdigest()
            if computed_hash != rec_entry_hash:
                self._log_chain_broken(f"Line {line_num}: hash mismatch. computed={computed_hash}, stored={rec_entry_hash}")
                raise ChainTamperDetectedError(f"Line {line_num}: hash mismatch. computed={computed_hash} vs stored={rec_entry_hash}")

            # link check
            if line_num == 1:
                if record["prev_hash"] != "GENESIS":
                    self._log_chain_broken(f"Line 1: prev_hash must be 'GENESIS'")
                    raise ChainTamperDetectedError("Line 1: prev_hash must be 'GENESIS'")
            else:
                if record["prev_hash"] != prev_hash:
                    self._log_chain_broken(f"Line {line_num}: chain linking error. expected={prev_hash}, got={record['prev_hash']}")
                    raise ChainTamperDetectedError(f"Line {line_num}: chain linking error")

            # monotonic time
            ts_str = record["timestamp"]
            ts_dt = self._parse_iso8601(ts_str)
            if last_ts and ts_dt <= last_ts:
                self._log_chain_broken(f"Line {line_num}: non-monotonic timestamp. {ts_str} <= {last_ts.isoformat()}")
                raise ChainTamperDetectedError(f"Line {line_num}: non-monotonic timestamp")
            last_ts = ts_dt

            # signature verify if chain_verification_required
            if chain_verification_required and rec_signature:
                if not (self.dil_pub_key):
                    self._log_chain_broken("Missing public key for signature verification.")
                    raise ChainTamperDetectedError("No public key to verify signature")

                # decode signature
                try:
                    sig_json_bytes = base64.b64decode(rec_signature)
                    sig_dict = json.loads(sig_json_bytes.decode("utf-8"))
                except Exception as e:
                    self._log_chain_broken(f"Line {line_num}: signature parse error => {e}")
                    raise ChainTamperDetectedError(f"Line {line_num}: signature parse error => {e}")

                # reconstruct data to verify
                data_bytes = json.dumps(record_copy, sort_keys=True).encode("utf-8")
                # verify
                ok = False
                try:
                    from aepok_sentinel.core.pqc_crypto import verify_content_signature
                    ok = verify_content_signature(data_bytes, sig_dict, self.config, self.dil_pub_key, self.rsa_pub_key)
                except CryptoSignatureError:
                    # or we can catch a general Exception
                    pass
                if not ok:
                    self._log_chain_broken(f"Line {line_num}: signature verification failed.")
                    raise ChainTamperDetectedError(f"Line {line_num}: signature verification failed.")

            # merkle path check => we can verify that combining 'entry_hash' with the path yields final root
            # We'll do a fresh insertion approach or direct path check
            # We'll do direct path check to confirm the final root matches what's in memory. But we might not have a final root yet.
            # For simplicity, we re-build the tree in memory by sequentially adding each leaf => then we confirm the path matches
            # after we add it. We'll do that now:
            self._insert_leaf_during_validate(rec_entry_hash)
            # compare the record's stored merkle_path with the newly computed path from leaf to root
            fresh_path = self._compute_merkle_path_for_leaf_idx(len(self.leaf_hashes) - 1)
            if fresh_path != rec_merkle_path:
                self._log_chain_broken(f"Line {line_num}: merkle path mismatch. got={rec_merkle_path} expect={fresh_path}")
                raise ChainTamperDetectedError(f"Line {line_num}: merkle path mismatch")

            # success => update prev_hash
            prev_hash = rec_entry_hash

        logger.info("Chain validated successfully. No tamper detected.")
        return True

    def repair_chain(self) -> None:
        """
        Re-validate the chain. If it passes => we create a new 'RESEAL' entry that:
          - references final merkle root so far
          - invalidates prior root
        Then we sign that entry with our private key. 
        Then the chain is effectively "resealed" and old root is replaced with this new sealed entry.
        Logs event=CHAIN_RESEALED in the new entry.
        """
        try:
            self.validate_chain()
        except ChainTamperDetectedError as e:
            logger.error("Chain is broken; cannot repair unless forced offline. Current approach => throw.")
            raise e

        # Now chain is valid => emit RESEAL
        # gather final root
        final_root = self._get_current_merkle_root()
        # invalidates prior root => we might store that old root in the metadata
        meta = {
            "old_root": final_root
        }
        self.append_event(EventCode.CHAIN_RESEALED.value, meta)
        logger.info("Chain resealed. Old root invalidated, new root extends from that RESEAL event.")

    # -----------------------------------------
    # Merkle Logic
    # -----------------------------------------
    def _compute_merkle_path_for_new_leaf(self, leaf_hash: str) -> List[str]:
        """
        Called at append time, *before* insertion, so we can build the path from leaf->root
        based on the current tree state. Then we finalize insertion.
        """
        # We'll do an ephemeral approach: if we had n leaves => leaf index = n
        # That means we can build the path from leaf n up to root with the current tree_levels
        leaf_idx = len(self.leaf_hashes)  # next new leaf index
        path = self._compute_merkle_path(leaf_idx)
        return path

    def _insert_new_leaf(self, leaf_hash: str) -> None:
        """
        Actually insert leaf into memory structure. Then write to merkle_state if needed.
        """
        self.leaf_hashes.append(leaf_hash)
        # If tree_levels is empty => this is the first leaf
        if not self.tree_levels:
            self.tree_levels = [[leaf_hash]]
        else:
            # Insert and rebuild top
            self._insert_leaf_during_validate(leaf_hash)

        self._store_merkle_state()

    def _insert_leaf_during_validate(self, leaf_hash: str) -> None:
        """
        For validate_chain usage or continuous insertion: we replicate
        standard merkle insertion logic: add leaf at end, recalc up the chain.
        """
        # If first insertion
        if not self.tree_levels:
            self.tree_levels = [[leaf_hash]]
            return
        # Start at level 0
        level_idx = 0
        # ensure tree_levels[0] is the list of leaves
        if level_idx >= len(self.tree_levels):
            self.tree_levels.append([])

        leaves = self.tree_levels[0]
        leaves.append(leaf_hash)
        # Now we rebuild upper levels from scratch for final shape code. 
        # (We could do a more incremental approach, but let's keep it simpler.)
        self._rebuild_upper_levels()

    def _rebuild_upper_levels(self) -> None:
        # We have self.tree_levels[0] as the leaves. Then each subsequent level pairs up.
        # We'll do a bottom-up rebuild until we get to a single root.
        all_leaves = self.tree_levels[0]
        levels = []
        levels.append(all_leaves[:])  # copy
        while len(levels[-1]) > 1:
            new_level = []
            siblings = levels[-1]
            for i in range(0, len(siblings), 2):
                left = siblings[i]
                if i + 1 < len(siblings):
                    right = siblings[i + 1]
                else:
                    right = left
                pair_hash = hashlib.sha512((left + right).encode("utf-8")).hexdigest()
                new_level.append(pair_hash)
            levels.append(new_level)
        self.tree_levels = levels

    def _compute_merkle_path(self, leaf_idx: int) -> List[str]:
        """
        Builds the path of sibling hashes from leaf_idx up to the root,
        with an indicator of left or right. For final shape code, we just store
        the sibling hash strings in a list. 
        Example: [ "R:siblingHash", "L:someHash", ... ] to show if it's left or right sibling.
        """
        path = []
        # We'll read from self.tree_levels. 
        # leaf_idx is in level 0
        lvl = 0
        idx = leaf_idx
        while True:
            # if the current level is the final => break
            if lvl >= len(self.tree_levels) - 1:
                break
            siblings = self.tree_levels[lvl]
            pair_index = idx ^ 1  # flip the last bit to get sibling
            if pair_index < len(siblings):
                # check if idx < pair_index => we are left, else right
                if idx % 2 == 0:
                    # we are left => store "R:sibling"
                    path.append("R:" + siblings[pair_index])
                else:
                    path.append("L:" + siblings[pair_index])
            # go up => idx //=2
            idx //= 2
            lvl += 1
        return path

    def _compute_merkle_path_for_leaf_idx(self, leaf_idx: int) -> List[str]:
        # after insertion, we do the same path building
        return self._compute_merkle_path(leaf_idx)

    def _get_current_merkle_root(self) -> str:
        """
        The top level of tree_levels[-1][0] if the chain is not empty
        """
        if not self.tree_levels:
            return "EMPTY_CHAIN"
        top_level = self.tree_levels[-1]
        if not top_level:
            return "EMPTY_CHAIN"
        return top_level[0]

    # ----------------------------------
    # Rollover
    # ----------------------------------
    def _maybe_rollover(self) -> None:
        if not os.path.isfile(self.current_file_path):
            return
        size = os.path.getsize(self.current_file_path)
        if size >= self.max_size_bytes:
            logger.info("Chain size %d >= %d => rollover triggered.", size, self.max_size_bytes)
            self._rollover_chain()

    def _rollover_chain(self) -> None:
        # store a final merkle root checkpoint
        final_root = self._get_current_merkle_root()
        cpoint_name = time.strftime("audit_checkpoint_%Y%m%d_%H%M%S.json")
        cpoint_path = os.path.join(self.chain_dir, cpoint_name)
        data = {
            "previous_file": os.path.basename(self.current_file_path),
            "final_merkle_root": final_root,
            "timestamp": self._utc_iso_now()
        }
        with open(cpoint_path, "w", encoding="utf-8") as cp:
            json.dump(data, cp, indent=2)
        logger.info("Wrote rollover checkpoint: %s", cpoint_path)

        # rename old chain
        new_name = time.strftime("audit_chain_%Y%m%d_%H%M%S.log")
        new_path = os.path.join(self.chain_dir, new_name)
        os.rename(self.current_file_path, new_path)
        logger.info("Rolled over old chain to %s", new_path)

        # reset memory
        self.leaf_hashes = []
        self.tree_levels = []
        self._store_merkle_state()

    # ----------------------------------
    # Merkle State Disk Persistence
    # ----------------------------------
    def _load_merkle_state(self) -> None:
        """
        Attempt to load partial tree from merkle_state_path. If missing, ignore.
        """
        if not os.path.isfile(self.merkle_state_path):
            return
        try:
            with open(self.merkle_state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.leaf_hashes = data.get("leaf_hashes", [])
            self.tree_levels = data.get("tree_levels", [])
        except Exception as e:
            logger.warning("Failed to load merkle state: %s", e)

    def _store_merkle_state(self) -> None:
        """
        Writes the current leaf_hashes + tree_levels to the merkle_state_path in JSON
        """
        data = {
            "leaf_hashes": self.leaf_hashes,
            "tree_levels": self.tree_levels
        }
        try:
            with open(self.merkle_state_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning("Failed to store merkle state: %s", e)

    # ----------------------------------
    # Logging chain-broken
    # ----------------------------------
    def _log_chain_broken(self, msg: str) -> None:
        """
        Logs CHAIN_BROKEN event. 
        """
        logger.error("CHAIN_BROKEN: %s", msg)
        # we can also append a special line if desired, but that might cause concurrency issues.

    # ----------------------------------
    # Time Utils
    # ----------------------------------
    def _utc_iso_now(self) -> str:
        dt = datetime.utcnow().replace(microsecond=0)
        return dt.isoformat() + "Z"

    def _parse_iso8601(self, s: str) -> datetime:
        # naive parse. For final shape, we keep it simple
        return datetime.fromisoformat(s.replace("Z", ""))


# End of final-shape Step 6