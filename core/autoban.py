# autoban.py
"""
Autoban Source Enforcement

This module implements an automated process to block sources identified as malicious
or suspicious, using platform-specific firewall commands. It stores the blocklist in
a JSON file accompanied by a signature, ensuring tamper-evident persistence. Key features:

 - If autoban is disabled or in watch-only mode, real blocking is skipped.
 - The blocklist must be located in an existing directory; no silent creation occurs.
 - Each source block can expire after a TTL (autoban_block_ttl_days).
 - Firewall commands are only invoked if the binary's SHA-256 hash is trusted.
 - Enforcement actions log relevant events to the audit chain (SOURCE_BLOCKED, AUTOBAN_TRIGGERED).
"""

import os
import sys
import json
import logging
import subprocess
import time
import datetime
from typing import Dict, Set, Optional

from shutil import which
from hashlib import sha256

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.directory_contract import resolve_path
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only
from aepok_sentinel.core.audit_chain import AuditChain
from aepok_sentinel.core.constants import EventCode
from aepok_sentinel.core.pqc_crypto import (
    sign_content_bundle,
    verify_content_signature,
    CryptoSignatureError,
    CryptoDecryptionError
)

logger = get_logger("autoban")


class AutobanError(Exception):
    """Raised if firewall blocking fails, or config disallows autoban operations."""


class AutobanManager:
    """
    Manages source autoban logic:
     - Maintains a blocklist in memory and on disk (signed JSON).
     - Executes firewall commands if not in watch-only mode.
     - Honors block TTL, automatically unblocking when expired.
     - Verifies firewall binaries are trusted (by SHA-256 hash) before running them.
    """

    def __init__(
        self,
        config: SentinelConfig,
        license_mgr: LicenseManager,
        audit_chain: AuditChain,
        blocklist_file: str = None,
        sign_priv_key_path: str = None
    ):
        self.config = config
        self.license_mgr = license_mgr
        self.audit_chain = audit_chain

        # FIX #48: The old defaults pointed to /var/lib/sentinel/ — a path
        # completely outside the directory contract.  The blocklist and its
        # signature lived outside the runtime security boundary, so an
        # attacker who could write to /var/lib/sentinel/ could replace them
        # without triggering any trust anchor violation.  Now we default to
        # paths inside the contracted runtime directory via resolve_path(),
        # placing the blocklist under "config" (validated at startup) and
        # the signing key under "keys" (also validated).
        if blocklist_file is None:
            self.blocklist_file = str(resolve_path("config", "blocked_ips.json"))
        else:
            self.blocklist_file = blocklist_file

        if sign_priv_key_path is None:
            self.sign_priv_key_path = str(resolve_path("keys", "autoban_dilithium_priv.bin"))
        else:
            self.sign_priv_key_path = sign_priv_key_path

        # Ensure directory for the blocklist file exists
        dir_path = os.path.dirname(self.blocklist_file)
        if not os.path.isdir(dir_path):
            raise RuntimeError(f"Directory for blocklist_file does not exist: {dir_path}")

        self.autoban_enabled = bool(self.config.raw_dict.get("autoban_enabled", False))
        self.ttl_days = int(self.config.raw_dict.get("autoban_block_ttl_days", 0))  # 0 => no expiration

        # Trusted firewall hashes from config
        self.trusted_hashes = self.config.raw_dict.get("trusted_firewall_hashes", [])
        if not self.trusted_hashes:
            self.trusted_hashes = self._get_fallback_trusted_hashes()

        # If autoban is enabled but we have no trusted hashes, fail
        if self.autoban_enabled and not self.trusted_hashes:
            raise RuntimeError("Autoban is enabled, but no trusted_firewall_hashes provided or found.")

        # Load blocklist (signed)
        self.blocked_data: Dict[str, Dict[str, str]] = {}
        self._load_blocklist()

    def _get_fallback_trusted_hashes(self) -> list:
        """
        FIX #49: The old implementation computed SHA-256 of firewall binaries
        at runtime and returned those as "trusted" hashes.  This is a security
        vulnerability: if the firewall binary is already compromised, hashing
        it at runtime and trusting that hash means you're trusting the
        compromised binary.  Trusted hashes MUST be provisioned from a
        known-good source (e.g. the config file, a signed manifest, or a
        build-time attestation), not computed from whatever happens to be on
        disk at runtime.

        Now returns an empty list so autoban will correctly refuse to run any
        firewall binary when no pre-provisioned hashes exist.  Operators must
        supply trusted_firewall_hashes in the config.
        """
        logger.warning(
            "No trusted_firewall_hashes in config. Firewall binary trust "
            "cannot be established at runtime — hashes must be provisioned "
            "from a known-good source. Autoban will be unable to execute "
            "firewall commands until trusted hashes are configured."
        )
        return []

    def record_bad_source(self, identifier: str, reason: str) -> None:
        """
        Called when we detect a suspicious source. 
         - If autoban_enabled=False => skip.
         - If watch_only => log SOURCE_BLOCKED but no actual firewall action.
         - If already blocked => skip duplicate.
         - Otherwise => enforce firewall block, log to audit chain, and save the blocklist.
        """
        if not self.autoban_enabled:
            logger.info("Autoban disabled => skip blocking source=%s reason=%s", identifier, reason)
            return

        self._purge_expired()

        if identifier in self.blocked_data:
            logger.debug("Source %s already blocked, skipping. reason=%s", identifier, reason)
            return

        if is_watch_only(self.license_mgr):
            self._append_chain_event(EventCode.SOURCE_BLOCKED, {"source": identifier, "reason": reason, "action": "watch-only"})
            return

        # normal blocking
        try:
            self.enforce_block(identifier)
            self.blocked_data[identifier] = {"blocked_on": str(int(time.time()))}
            self._save_blocklist()
            self._append_chain_event(
                EventCode.AUTOBAN_TRIGGERED,
                {"source": identifier, "reason": reason, "firewall_action": "blocked"}
            )
        except Exception as e:
            logger.error("Failed to block source %s: %s", identifier, e)
            raise AutobanError(f"Failed to block source {identifier}: {e}")

    def is_blocked(self, identifier: str) -> bool:
        """
        Checks if 'identifier' is in the in-memory blocklist. Also purges expired blocks first.
        """
        self._purge_expired()
        return identifier in self.blocked_data

    def enforce_block(self, identifier: str) -> None:
        """
        Runs a platform-specific firewall command to block 'identifier' after verifying the binary's trust.
        Raises AutobanError if no trusted firewall binary is found or the command fails.
        """
        platform_str = sys.platform
        if platform_str.startswith("linux"):
            candidates = ["ufw", "iptables"]
        elif platform_str.startswith("win"):
            candidates = ["netsh"]
        elif platform_str.startswith("darwin"):
            candidates = ["ipfw", "pfctl"]
        else:
            raise AutobanError(f"Unsupported platform '{platform_str}' for firewall blocking.")

        cmd_path = None
        for c in candidates:
            found = which(c)
            if found and self._verify_binary_trusted(found):
                cmd_path = found
                break

        if not cmd_path:
            raise AutobanError(f"No trusted firewall binary found among {candidates} on '{platform_str}'")

        cmd_args = self._build_firewall_command_args(platform_str, cmd_path, identifier)
        logger.info("Executing firewall block command: %s", " ".join(cmd_args))
        try:
            completed = subprocess.run(cmd_args, capture_output=True, text=True, check=False)
            if completed.returncode != 0:
                raise AutobanError(f"Command failed (rc={completed.returncode}): {completed.stderr.strip()}")
        except Exception as e:
            raise AutobanError(f"Failed to run firewall command: {e}")

    def enforce_unblock(self, identifier: str) -> None:
        """
        Removes the firewall rule for 'identifier'. In production, you'd store the exact rule ID or name.
        We do best-effort here. If removal fails, logs a warning but continues.
        """
        platform_str = sys.platform
        if platform_str.startswith("linux"):
            ufw_path = which("ufw")
            ipt_path = which("iptables")
            if ufw_path and self._verify_binary_trusted(ufw_path):
                cmd = [ufw_path, "delete", "deny", "from", identifier]
            elif ipt_path and self._verify_binary_trusted(ipt_path):
                cmd = [ipt_path, "-D", "INPUT", "-s", identifier, "-j", "DROP"]
            else:
                raise AutobanError("No valid/trusted firewall binary for unblocking on Linux.")
        elif platform_str.startswith("win"):
            # FIX #51: netsh expects "name=..." as a single token with no space
            # separation between the key and value.  The f-string already produces
            # a single element, but we also need to resolve the binary path through
            # the trust-check path (same as enforce_block) instead of hard-coding
            # "netsh".  Additionally, align the argument format with
            # _build_firewall_command_args so both block/unblock are consistent.
            netsh_path = which("netsh")
            if netsh_path and self._verify_binary_trusted(netsh_path):
                cmd = [netsh_path, "advfirewall", "firewall", "delete", "rule",
                       f"name=SentinelBlock {identifier}"]
            else:
                raise AutobanError("No valid/trusted netsh binary for unblocking on Windows.")
        elif platform_str.startswith("darwin"):
            ipfw_path = which("ipfw")
            if ipfw_path and self._verify_binary_trusted(ipfw_path):
                cmd = [ipfw_path, "delete", "deny", "ip", "from", identifier, "to", "any"]
            else:
                raise AutobanError("No valid/trusted firewall binary for unblocking on macOS.")
        else:
            raise AutobanError(f"Unsupported platform '{platform_str}' for unblocking source.")

        logger.info("Executing firewall unblock command: %s", " ".join(cmd))
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            logger.warning("Unblock command failed (rc=%d): %s", completed.returncode, completed.stderr.strip())

    # ------------------------
    # Expiration logic
    # ------------------------
    def _purge_expired(self) -> None:
        if self.ttl_days <= 0:
            return
        now_ts = int(time.time())
        expired = []
        for identifier, meta in self.blocked_data.items():
            blocked_on = int(meta.get("blocked_on", "0"))
            if blocked_on <= 0:
                continue
            if (now_ts - blocked_on) > (self.ttl_days * 86400):
                expired.append(identifier)
        if not expired:
            return
        logger.info("Purging %d expired source blocks (TTL=%d days).", len(expired), self.ttl_days)
        for identifier in expired:
            try:
                self.enforce_unblock(identifier)
            except Exception as e:
                logger.warning("Failed to unblock source %s during purge: %s", identifier, e)
            self.blocked_data.pop(identifier, None)
        self._save_blocklist()

    # ------------------------
    # Signed blocklist I/O
    # ------------------------
    def _load_blocklist(self) -> None:
        if not os.path.isfile(self.blocklist_file):
            return

        sig_file = self.blocklist_file + ".sig"
        if not os.path.isfile(sig_file):
            logger.warning("Blocklist signature file missing => ignoring stored blocklist.")
            return

        try:
            with open(self.blocklist_file, "r", encoding="utf-8") as f:
                content = f.read()
            with open(sig_file, "rb") as sf:
                sig_bytes = sf.read()
        except Exception as e:
            logger.warning("Failed to read blocklist or signature: %s", e)
            return

        try:
            pub_path = resolve_path("keys", "vendor_dilithium_pub.pem")
            dil_pub = pub_path.read_bytes()
        except Exception as e:
            logger.warning("Missing/unreadable vendor_dilithium_pub.pem for blocklist verify: %s", e)
            return

        import base64, json
        try:
            sig_dict = json.loads(base64.b64decode(sig_bytes).decode("utf-8"))
        except Exception as e:
            logger.warning("Blocklist signature is corrupted: %s", e)
            return

        if not verify_content_signature(content.encode("utf-8"), sig_dict, self.config, dil_pub, None):
            logger.warning("Blocklist signature invalid => ignoring blocklist.")
            return

        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("Blocklist content must be a dict {source: {...}}")
            self.blocked_data = data
            logger.info("Loaded %d blocked source entries from disk (signed).", len(self.blocked_data))
        except Exception as e:
            logger.warning("Failed to parse blocklist JSON: %s", e)

    def _save_blocklist(self) -> None:
        try:
            content_str = json.dumps(self.blocked_data, indent=2)
            with open(self.blocklist_file, "w", encoding="utf-8") as f:
                f.write(content_str)

            with open(self.sign_priv_key_path, "rb") as kf:
                dil_priv = kf.read()

            sig_bundle = sign_content_bundle(content_str.encode("utf-8"), self.config, dil_priv, None)
            import base64, json as j
            sig_b64 = base64.b64encode(j.dumps(sig_bundle).encode("utf-8"))

            with open(self.blocklist_file + ".sig", "wb") as sf:
                sf.write(sig_b64)
        except Exception as e:
            logger.warning("Failed to save blocklist or signature: %s", e)

    # ------------------------
    # Helpers
    # ------------------------
    def _append_chain_event(self, event_code: EventCode, metadata: dict) -> None:
        try:
            self.audit_chain.append_event(event_code.value, metadata)
        except Exception as e:
            logger.error("Failed to append chain event for %s: %s", event_code.value, e)

    def _build_firewall_command_args(self, platform_str: str, cmd_path: str, identifier: str) -> list:
        if platform_str.startswith("linux"):
            if os.path.basename(cmd_path) == "ufw":
                return [cmd_path, "deny", "from", identifier]
            else:
                return [cmd_path, "-I", "INPUT", "-s", identifier, "-j", "DROP"]
        elif platform_str.startswith("win"):
            return [
                cmd_path, "advfirewall", "firewall", "add", "rule",
                f"name=SentinelBlock {identifier}",
                "dir=in", "interface=any", "action=block", f"remoteip={identifier}"
            ]
        elif platform_str.startswith("darwin"):
            if os.path.basename(cmd_path) == "ipfw":
                return [cmd_path, "add", "deny", "ip", "from", identifier, "to", "any"]
            else:
                # FIX #50: The old code used `pfctl -f "block drop from <ip> to any"`.
                # pfctl -f expects a *file path* to a rules file, not an
                # inline rule string.  Passing the rule as an argument caused
                # pfctl to try to open a file literally named "block drop from
                # 1.2.3.4 to any", which always fails.
                #
                # The correct approach for pfctl is to use a persistent table.
                # `pfctl -t sentinel_blocked -T add <ip>` adds the IP to the
                # "sentinel_blocked" table.  The pf.conf must have a rule like
                # `block drop from <sentinel_blocked>` for this to take effect.
                # This is the standard pattern for dynamic IP blocking with pf.
                return [cmd_path, "-t", "sentinel_blocked", "-T", "add", identifier]
        else:
            raise AutobanError(f"Unsupported platform '{platform_str}'")

    def _verify_binary_trusted(self, bin_path: str) -> bool:
        """
        Checks if bin_path's sha256 is in our known set of trusted firewall hashes.
        Raises AutobanError if no such list is defined or mismatch occurs.
        """
        # For demonstration, a minimal approach:
        if not self.trusted_hashes:
            raise AutobanError("No trusted firewall binary hashes defined; cannot verify firewall binary.")

        try:
            with open(bin_path, "rb") as bf:
                data = bf.read()
            hash_val = sha256(data).hexdigest()
        except Exception as e:
            logger.warning("Failed to read firewall binary %s for trust check: %s", bin_path, e)
            return False

        if hash_val.lower() not in [h.lower() for h in self.trusted_hashes]:
            logger.warning("Binary %s hash not in trusted list => refusing to run it.", bin_path)
            return False

        return True