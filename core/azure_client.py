# azure_client.py
"""
A minimal Azure Key Vault client supporting:
 - SCIF/airgap disallowed (raises AzureClientError if attempted)
 - Watch-only => read-only (no writes/deletes)
 - PQC-hybrid TLS usage if strict_transport or tls_mode != "classical"
 - Fallback to default TLS if PQC creation fails and strict_transport is False
 - No creation of or reference to Sentinel runtime directories.
"""

import requests
from typing import Optional

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only
from aepok_sentinel.core.pqc_tls import create_pqc_ssl_context, PQCTlsError

logger = get_logger("azure_client")


class AzureClientError(Exception):
    """
    Raised for any Azure Key Vault transport errors or violations
    of SCIF/airgap or watch-only constraints.
    """


class AzureClient:
    """
    Minimal Azure Key Vault wrapper:

    - Valid only if config.mode == "cloud" and config.cloud_keyvault_provider == "azure".
    - SCIF/airgap => immediately disallowed.
    - Watch-only => read-only (no set_secret or delete_secret).
    - PQC TLS if strict_transport=True or tls_mode != "classical".
      If PQC fails in strict mode => raise error;
      if PQC fails and not strict => log warning and fallback to classical TLS.
    """

    def __init__(self, config: SentinelConfig, license_mgr: LicenseManager):
        self.config = config
        self.license_mgr = license_mgr

        # Disallow network in SCIF or airgap
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
        Retrieves a secret from Azure Key Vault.
        This is permitted even if watch-only, since it's a read operation.
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
        Denied if watch-only or allow_delete=False.
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
        Creates a requests.Session that uses PQC TLS if strict_transport or tls_mode != 'classical',
        falling back to classical if not strict_transport and PQC fails.
        """
        sess = requests.Session()

        # If classical + not strict => normal TLS
        tls_mode = self.config.raw_dict.get("tls_mode", "classical")
        if tls_mode == "classical" and not self.config.strict_transport:
            logger.info(
                "AzureClient: Using classical TLS (tls_mode=%s, strict_transport=%s)",
                tls_mode,
                self.config.strict_transport
            )
            return sess

        # Attempt PQC
        try:
            ssl_ctx = create_pqc_ssl_context(self.config)
        except PQCTlsError as e:
            if self.config.strict_transport:
                # Strict => no fallback
                raise AzureClientError(f"Strict transport => PQC context failed: {e}")
            logger.warning("PQC context failed, fallback to classical TLS: %s", e)
            return sess

        # Attach a custom HTTPS adapter to use PQC SSL context
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