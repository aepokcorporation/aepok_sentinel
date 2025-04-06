"""
azure_clients.py

A minimal Azure Key Vault client supporting:
 - SCIF/airgap disallowed (raises error)
 - Watch-only => read-only
 - PQC-hybrid TLS usage if strict_transport or tls_mode != "classical"
 - Fallback to default TLS if non-strict and PQC context fails

No directory creation, no silent unverified paths.
No references to ephemeral future code.
"""

import logging
import requests
from typing import Optional

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only
from aepok_sentinel.core.pqc_tls import create_pqc_ssl_context, PQCTlsError

logger = get_logger("azure_clients")


class AzureClientError(Exception):
    """Raised for any Azure client transport errors."""


class AzureClient:
    """
    Minimal Azure Key Vault wrapper:
      - Only valid if config.mode='cloud' and config.cloud_keyvault_provider='azure'
      - SCIF/airgap => error
      - watch-only => read-only
      - PQC TLS if strict_transport or tls_mode in ('pqc-only','hybrid'), else default
    """

    def __init__(self, config: SentinelConfig, license_mgr: LicenseManager):
        self.config = config
        self.license_mgr = license_mgr

        # Disallow network in SCIF/airgap
        if self.config.mode in ("scif", "airgap"):
            raise AzureClientError("No network allowed in SCIF/airgap mode.")

        if not (self.config.mode == "cloud" and self.config.cloud_keyvault_provider == "azure"):
            raise AzureClientError("AzureClient used outside of cloud+azure context.")

        if not self.config.cloud_keyvault_url:
            raise AzureClientError("cloud_keyvault_url is empty or not set for Azure usage.")

        self.base_url = self.config.cloud_keyvault_url.rstrip("/")
        self._session = self._build_requests_session()

    def get_secret(self, secret_name: str) -> str:
        """
        Retrieves a secret (read is allowed even in watch-only).
        """
        url = f"{self.base_url}/secrets/{secret_name}"
        try:
            resp = self._session.get(url, timeout=10)
            if resp.status_code != 200:
                raise AzureClientError(f"GET {url} returned {resp.status_code}: {resp.text}")
            data = resp.json()
            return data.get("value", "")
        except Exception as e:
            raise AzureClientError(f"Failed to get secret '{secret_name}': {e}")

    def set_secret(self, secret_name: str, value: str) -> None:
        """
        Sets/updates a secret in Azure Key Vault.
        Denied if system is watch-only.
        """
        if is_watch_only(self.license_mgr):
            raise AzureClientError("Watch-only mode => cannot set secrets.")

        url = f"{self.base_url}/secrets/{secret_name}"
        try:
            resp = self._session.put(url, json={"value": value}, timeout=10)
            if resp.status_code not in (200, 201):
                raise AzureClientError(f"PUT {url} returned {resp.status_code}: {resp.text}")
            logger.info("Set secret '%s' in Azure Key Vault. status=%d", secret_name, resp.status_code)
        except Exception as e:
            raise AzureClientError(f"Failed to set secret '{secret_name}': {e}")

    def delete_secret(self, secret_name: str) -> None:
        """
        Deletes (soft-delete) a secret in Azure Key Vault.
        Denied if watch-only or allow_delete=false.
        """
        if is_watch_only(self.license_mgr):
            raise AzureClientError("Watch-only => cannot delete secrets.")
        if not self.config.allow_delete:
            raise AzureClientError("Deletion not allowed (allow_delete=false).")

        url = f"{self.base_url}/secrets/{secret_name}"
        try:
            resp = self._session.delete(url, timeout=10)
            if resp.status_code != 200:
                raise AzureClientError(f"DELETE {url} returned {resp.status_code}: {resp.text}")
            logger.info("Deleted secret '%s' in Azure Key Vault.", secret_name)
        except Exception as e:
            raise AzureClientError(f"Failed to delete secret '{secret_name}': {e}")

    def _build_requests_session(self) -> requests.Session:
        """
        Creates a requests Session. 
        If config.tls_mode != 'classical' or strict_transport => attempt PQC context.
        If strict => error if PQC context fails, else fallback to default.
        """
        sess = requests.Session()

        # If classical + not strict => normal TLS
        if self.config.tls_mode == "classical" and not self.config.strict_transport:
            logger.info(
                "AzureClient: Using classical TLS transport (tls_mode=%s, strict_transport=%s)",
                self.config.tls_mode,
                self.config.strict_transport
            )
            return sess

        # Attempt PQC
        try:
            ssl_ctx = create_pqc_ssl_context(self.config)
        except PQCTlsError as e:
            if self.config.strict_transport:
                raise AzureClientError(f"Strict transport => PQC context failed: {e}")
            logger.warning("PQC context failed, fallback to default TLS: %s", e)
            return sess

        # Attach an adapter with custom ssl_ctx
        from requests.adapters import HTTPAdapter
        from urllib3.poolmanager import PoolManager

        class PQCPoolManager(PoolManager):
            def __init__(self, ssl_context, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.ssl_context = ssl_context

            def _new_pool(self, scheme, host, port, request_context=None):
                pool = super()._new_pool(scheme, host, port, request_context=request_context)
                if scheme == "https":
                    pool.ssl_context = self.ssl_context
                return pool

        adapter = HTTPAdapter()
        adapter.init_poolmanager = lambda connections, maxsize, block=None, **kw: PQCPoolManager(
            ssl_context=ssl_ctx,
            num_pools=connections,
            maxsize=maxsize,
            block=block
        )
        sess.mount("https://", adapter)
        return sess