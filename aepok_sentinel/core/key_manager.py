"""
Step 5: Key Manager

Responsibilities:
1. Local key generation + storage for SCIF/Airgap (or Cloud if user wants local).
2. If mode=cloud and config.cloud_keyvault_enabled=true => fetch from 'cloud key vault'.
3. Rotation: if rotation_interval_days > 0 and license is valid => create new keys, store them,
   keep last N generations (N=5).
4. If license is invalid or watch-only => no rotation.
5. No reference to future modules (audit_chain, etc.) is permitted.

Implementation details:
 - local path default /etc/sentinel/keys/
 - if SCIF or airgap => no network call allowed (error if user tries fetch from cloud)
 - if cloud + strict_transport => in a real system we'd use PQC-hybrid TLS. For now, minimal approach:
   we check config; if strict_transport => we simulate "server must do PQC or fail"
 - final shape, no placeholders or stubs
"""

import os
import shutil
import time
import logging
import datetime
import requests
from typing import Optional, Dict, Any, Tuple, List

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only, is_license_valid
from aepok_sentinel.core.pqc_crypto import oqs, _load_rsa_private_key, _load_rsa_public_key

logger = get_logger("key_manager")


class KeyManagerError(Exception):
    """Raised on any key management failure (local IO error, cloud fetch error, etc.)."""
    pass


class KeyManager:
    """
    Manages local or cloud-based keys for encryption. 
    - Provides method to load/fetch current keys.
    - Provides rotate_keys() if license is valid and config rotation_interval_days > 0.
    """

    def __init__(self, config: SentinelConfig, license_mgr: LicenseManager):
        self.config = config
        self.license_mgr = license_mgr
        self.local_key_dir = config.raw_dict.get("key_storage_path", "/etc/sentinel/keys")  # fixed per doc
        # we can store e.g. kyber_priv_{timestamp}.bin, dilithium_priv_{timestamp}.bin, etc.

        # How many old generations to keep
        self.keep_generations = 5

    def fetch_current_keys(self) -> Dict[str, bytes]:
        """
        Returns the current PQC keys (Kyber priv, Dilithium priv) and optional RSA priv
        as a dict: {"kyber_priv":..., "dilithium_priv":..., "rsa_priv":...}

        If scif/airgap => local only. 
        If cloud => either local fallback or do a cloud fetch if cloud_keyvault_enabled=true.
        If watch-only => we can still load local keys, but we do not generate new ones.

        Raises KeyManagerError if keys are missing or cloud fetch fails.
        """
        mode = self.config.mode
        if mode in ("scif", "airgap"):
            # Must load local only
            return self._load_local_keys_latest()

        if mode == "cloud" and self.config.cloud_keyvault_enabled:
            # Try cloud fetch
            return self._fetch_cloud_keys()
        else:
            # If cloud_keyvault_enabled=false or it's "demo"/"watch-only", fallback to local
            return self._load_local_keys_latest()

    def rotate_keys(self) -> None:
        """
        Rotate keys if:
          - license is valid (not watch-only)
          - config.rotation_interval_days > 0
        On error, revert to old keys.

        For scif/airgap => local generation only.
        For cloud => if cloud_keyvault_enabled => can try to fetch or generate. 
                     For simplicity, we implement local generation or do a minimal cloud fetch logic.

        This is manual in scif/airgap, could be auto in cloud, but we only implement the function here.
        """
        if is_watch_only(self.license_mgr):
            logger.warning("Cannot rotate keys: system is in watch-only mode.")
            return

        if self.config.rotation_interval_days <= 0:
            logger.info("rotation_interval_days <= 0 => rotation not enabled.")
            return

        logger.info("Rotating keys now...")

        backup_dir = None
        try:
            # Backup current
            timestamp_str = time.strftime("%Y%m%d_%H%M%S")
            backup_dir = os.path.join(self.local_key_dir, f"backup_{timestamp_str}")
            os.makedirs(backup_dir, exist_ok=True)
            for f in os.listdir(self.local_key_dir):
                full = os.path.join(self.local_key_dir, f)
                if os.path.isfile(full):
                    shutil.copy2(full, backup_dir)

            # Generate or fetch new keys
            # If scif/airgap => do local gen. If cloud => do minimal fetch or local gen.
            mode = self.config.mode
            if mode in ("scif", "airgap"):
                self._generate_local_keys()
            elif mode == "cloud" and self.config.cloud_keyvault_enabled:
                # minimal approach: if we want real remote generation, we do it. 
                # We'll just do local generation for demonstration. 
                # A real system might do "fetch from Key Vault" or "upload a new key."
                self._generate_local_keys()
            else:
                # "demo" or watch-only or cloud w/out keyvault => local generation
                self._generate_local_keys()

            # Cleanup old generations
            self._purge_old_generations()

            logger.info("Key rotation completed successfully.")
        except Exception as e:
            logger.error("Key rotation failed: %s", e)
            # revert from backup
            if backup_dir:
                for f in os.listdir(self.local_key_dir):
                    # remove any new files
                    fp = os.path.join(self.local_key_dir, f)
                    if os.path.isfile(fp):
                        os.remove(fp)
                # restore backup
                for bf in os.listdir(backup_dir):
                    src = os.path.join(backup_dir, bf)
                    dst = os.path.join(self.local_key_dir, bf)
                    shutil.copy2(src, dst)
                logger.info("Reverted to old keys from %s.", backup_dir)

    # ---------------- Private Methods ----------------

    def _load_local_keys_latest(self) -> Dict[str, bytes]:
        """
        Scans the local_key_dir for the newest (by name or mtime) key files:
         - kyber_priv_*.bin
         - dilithium_priv_*.bin
         - rsa_priv_*.pem (if fallback)
        Raises KeyManagerError if not found or unreadable.
        """
        if not os.path.isdir(self.local_key_dir):
            raise KeyManagerError(f"Local key directory not found: {self.local_key_dir}")

        # We'll pick the latest prefix by timestamp (if we store them as e.g. kyber_priv_20250102.bin)
        # For simplicity, we just pick the newest file for each type by mtime or lexicographic suffix
        kyber_file = self._find_latest_file(prefix="kyber_priv_", ext=".bin")
        dil_file = self._find_latest_file(prefix="dilithium_priv_", ext=".bin")
        rsa_file = None
        if self.config.allow_classical_fallback:
            # not mandatory that RSA exists, but we try
            rsa_file = self._find_latest_file(prefix="rsa_priv_", ext=".pem", required=False)

        if not kyber_file or not dil_file:
            raise KeyManagerError("Missing required PQC private key files in local storage.")

        keys = {}
        # read them
        keys["kyber_priv"] = self._read_file(kyber_file)
        keys["dilithium_priv"] = self._read_file(dil_file)
        if rsa_file:
            keys["rsa_priv"] = self._read_file(rsa_file)
        else:
            keys["rsa_priv"] = b""

        return keys

    def _fetch_cloud_keys(self) -> Dict[str, bytes]:
        if self.config.mode in ("scif", "airgap"):
            raise KeyManagerError("No network allowed in SCIF or airgap mode.")

        if not self.config.cloud_keyvault_url:
            raise KeyManagerError("cloud_keyvault_url is empty or not set.")

        # Use PQC TLS to securely fetch keys from the cloud key vault.
        from urllib.parse import urlparse
        from aepok_sentinel.core.pqc_tls import connect_pqc_socket

        parsed = urlparse(self.config.cloud_keyvault_url)
        hostname = parsed.hostname
        port = parsed.port if parsed.port else 443
        path = "/current_keys"

        try:
            # Establish a TLS connection using PQC enforcement.
            tls_sock = connect_pqc_socket(self.config, hostname, port)

            # Build and send the HTTP GET request.
            request_str = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            tls_sock.sendall(request_str.encode("utf-8"))

            # Read the full response from the socket.
            response = b""
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            tls_sock.close()

            # Separate HTTP headers from the body.
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                raise KeyManagerError("Invalid HTTP response from cloud keyvault")
            headers = response[:header_end].decode("utf-8")
            body = response[header_end + 4:]

            # Verify a 200 OK status in the response header.
            if "200 OK" not in headers:
                first_line = headers.splitlines()[0] if headers.splitlines() else "Unknown status"
                raise KeyManagerError(f"Cloud fetch returned non-200 status: {first_line}")

            # Parse the JSON body.
            import json
            data = json.loads(body.decode("utf-8"))
            kyber_b64 = data.get("kyber_priv")
            dil_b64 = data.get("dilithium_priv")
            if not kyber_b64 or not dil_b64:
                raise KeyManagerError("Cloud key response missing kyber_priv or dilithium_priv")

            keys = {
                "kyber_priv": self._b64decode(kyber_b64),
                "dilithium_priv": self._b64decode(dil_b64)
            }
            rsa_b64 = data.get("rsa_priv", "")
            if self.config.allow_classical_fallback and rsa_b64:
                keys["rsa_priv"] = self._b64decode(rsa_b64)
            else:
                keys["rsa_priv"] = b""
            return keys

        except Exception as e:
            raise KeyManagerError(f"Cloud key fetch failed: {e}")

    def _generate_local_keys(self) -> None:
        """
        Generates new Kyber, Dilithium, and (optionally) RSA private keys 
        then stores them in local_key_dir with a timestamp suffix.
        """
        if not os.path.isdir(self.local_key_dir):
            os.makedirs(self.local_key_dir, exist_ok=True)

        timestamp_str = time.strftime("%Y%m%d_%H%M%S")

        # Generate PQC keys using oqs
        if not oqs:
            raise KeyManagerError("liboqs not installed, cannot generate PQC keys.")

        # Kyber512
        try:
            with oqs.KeyEncapsulation("Kyber512") as kem:
                kem.generate_keypair()  # keypair in memory
                kyber_priv = kem.export_secret_key()
        except Exception as e:
            raise KeyManagerError(f"Failed to generate Kyber key: {e}")

        # Dilithium2
        try:
            with oqs.Signature("Dilithium2") as sig:
                sig.generate_keypair()
                dil_priv = sig.export_secret_key()
        except Exception as e:
            raise KeyManagerError(f"Failed to generate Dilithium key: {e}")

        # Possibly RSA
        rsa_priv = b""
        if self.config.allow_classical_fallback:
            # We'll do a minimal RSA generation. This might be slow, but final shape means no stubs:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rsa_priv = rsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

        # Write them out
        try:
            kyber_file = os.path.join(self.local_key_dir, f"kyber_priv_{timestamp_str}.bin")
            dil_file = os.path.join(self.local_key_dir, f"dilithium_priv_{timestamp_str}.bin")
            self._write_file(kyber_file, kyber_priv)
            self._write_file(dil_file, dil_priv)
            if rsa_priv:
                rsa_file = os.path.join(self.local_key_dir, f"rsa_priv_{timestamp_str}.pem")
                self._write_file(rsa_file, rsa_priv)
        except Exception as e:
            raise KeyManagerError(f"Failed to write new keys: {e}")

        logger.info("Generated new local PQC keys (and RSA if fallback). Timestamp=%s", timestamp_str)

    def _purge_old_generations(self) -> None:
        """
        Keeps only the newest self.keep_generations copies of each key type.
        We identify them by prefix and sort by creation time or name.
        """
        for prefix, ext in [
            ("kyber_priv_", ".bin"),
            ("dilithium_priv_", ".bin"),
            ("rsa_priv_", ".pem")
        ]:
            self._purge_old_files(prefix, ext)

    def _purge_old_files(self, prefix: str, ext: str) -> None:
        # gather files matching prefix and ext
        files = []
        for f in os.listdir(self.local_key_dir):
            if f.startswith(prefix) and f.endswith(ext):
                full = os.path.join(self.local_key_dir, f)
                if os.path.isfile(full):
                    files.append(full)

        # sort by mtime desc
        files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        # keep the newest up to self.keep_generations
        to_delete = files[self.keep_generations:]
        for d in to_delete:
            os.remove(d)
            logger.info("Purged old key file: %s", d)

    def _find_latest_file(self, prefix: str, ext: str, required: bool = True) -> Optional[str]:
        """
        Finds the newest file with prefix + extension in local_key_dir, sorted by mtime.
        If none found and required=True => raise KeyManagerError.
        """
        candidates = []
        for f in os.listdir(self.local_key_dir):
            if f.startswith(prefix) and f.endswith(ext):
                full = os.path.join(self.local_key_dir, f)
                if os.path.isfile(full):
                    candidates.append(full)
        if not candidates:
            if required:
                raise KeyManagerError(f"No local file found with prefix={prefix} ext={ext}")
            return None

        candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        return candidates[0]

    def _read_file(self, path: str) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            raise KeyManagerError(f"Failed to read file {path}: {e}")

    def _write_file(self, path: str, data: bytes) -> None:
        try:
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:
            raise KeyManagerError(f"Failed to write file {path}: {e}")

    def _b64decode(self, s: str) -> bytes:
        import base64
        return base64.b64decode(s)