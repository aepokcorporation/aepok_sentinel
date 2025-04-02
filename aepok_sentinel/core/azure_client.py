"""
Step 5.2: Azure Client Transport

Implements a minimal Azure Key Vault client that:
  - Checks .sentinelrc for cloud mode + azure
  - For scif/airgap => raises error (no network)
  - Enforces watch-only => read calls allowed, writes fail
  - Uses PQC-hybrid TLS from core/pqc_tls if config.strict_transport or config.tls_mode != 'classical'
  - No placeholders or forward references to step 6+.

Methods:
  - get_secret(secret_name) -> str
  - set_secret(secret_name, value) -> None
  - delete_secret(secret_name) -> None (if config.allow_delete or in azure, etc.)
"""

import logging
import requests
from typing import Optional

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only
from aepok_sentinel.core.pqc_tls import create_pqc_ssl_context, PQCTlsError

logger = get_logger("azure_client")


class AzureClientError(Exception):
    """Raised for any Azure client transport errors."""


class AzureClient:
    """
    Minimal Azure Key Vault wrapper:
    - Must be used only if config.mode='cloud' and config.cloud_keyvault_provider='azure'
    - If scif/airgap => error
    - If watch-only => read-only
    - PQC TLS enforced if strict_transport or tls_mode in ('pqc-only', 'hybrid')
    """

    def __init__(self, config: SentinelConfig, license_mgr: LicenseManager):
        self.config = config
        self.license_mgr = license_mgr

        # Validate we can do azure calls
        if self.config.mode in ("scif", "airgap"):
            raise AzureClientError("No network allowed in SCIF/airgap mode.")

        if not (self.config.mode == "cloud" and self.config.cloud_keyvault_provider == "azure"):
            raise AzureClientError("AzureClient used in non-cloud or non-azure context.")

        if not self.config.cloud_keyvault_url:
            raise AzureClientError("cloud_keyvault_url is empty or not set for Azure usage.")

        self.base_url = self.config.cloud_keyvault_url.rstrip("/")
        self._session = self._build_requests_session()

    def get_secret(self, secret_name: str) -> str:
        """
        Retrieves a secret from Azure Key Vault. 
        If watch-only => read is still allowed.
        """
        url = f"{self.base_url}/secrets/{secret_name}"
        try:
            resp = self._session.get(url, timeout=10)
            if resp.status_code != 200:
                raise AzureClientError(f"GET {url} returned {resp.status_code}: {resp.text}")
            data = resp.json()
            # Typically Azure returns a JSON with 'value'
            return data.get("value", "")
        except Exception as e:
            raise AzureClientError(f"Failed to get secret '{secret_name}': {e}")

    def set_secret(self, secret_name: str, value: str) -> None:
        """
        Sets/updates a secret in Azure Key Vault.
        If watch-only => error (no write).
        """
        if is_watch_only(self.license_mgr):
            raise AzureClientError("System is watch-only; cannot set secret in Azure Key Vault.")

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
        Deletes a secret in Azure Key Vault (soft-delete).
        If watch-only => error
        If allow_delete=false => error
        """
        if is_watch_only(self.license_mgr):
            raise AzureClientError("System is watch-only; cannot delete secret.")
        if not self.config.allow_delete:
            raise AzureClientError("Deletion not allowed by config (allow_delete=false).")

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
        Creates a requests Session with a custom SSLContext from pqc_tls (if not classical).
        """
        sess = requests.Session()
        if self.config.tls_mode == "classical" and not self.config.strict_transport:
            # Just use default
            return sess

        try:
            ssl_ctx = create_pqc_ssl_context(self.config)
        except PQCTlsError as e:
            # If strict transport => we can't proceed
            if self.config.strict_transport:
                raise AzureClientError(f"Strict transport enforced but PQC context failed: {e}")
            # otherwise, fallback to default
            logger.warning("PQC context failed, falling back to default TLS: %s", e)
            return sess

        # attach a custom adapter that uses ssl_ctx
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
        # Patch its poolmanager
        adapter.init_poolmanager = lambda connections, maxsize, block=None, **kw: PQCPoolManager(
            ssl_context=ssl_ctx,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            strict=True,  # pass anything else needed
        )
        sess.mount("https://", adapter)
        return sess