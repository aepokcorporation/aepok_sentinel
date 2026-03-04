# azure_client.py
"""
A minimal Azure Key Vault client supporting:
 - SCIF/airgap disallowed (raises AzureClientError if attempted)
 - Watch-only => read-only (no writes/deletes)
 - PQC-hybrid TLS usage if strict_transport or tls_mode != "classical"
 - Fallback to default TLS if PQC creation fails and strict_transport is False
 - No creation of or reference to Sentinel runtime directories.
 - Azure Managed Identity / DefaultAzureCredential for authentication.
"""

import requests

from aepok_sentinel.core.logging_setup import get_logger
from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.license import LicenseManager, is_watch_only
from aepok_sentinel.core.pqc_tls import create_pqc_ssl_context, PQCTlsError

# FIX #65: Azure Key Vault API version constant.  All REST calls to
# Azure Key Vault require an api-version query parameter; without it
# Azure returns 400 Bad Request.
AZURE_API_VERSION = "7.4"

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

        # FIX #65: The original code never set any authentication
        # headers on HTTP requests.  Azure Key Vault requires a Bearer
        # token for every API call — without one, every request returns
        # 401 Unauthorized, making the entire Azure integration
        # non-functional.
        #
        # We now acquire a token via azure.identity.DefaultAzureCredential
        # which supports managed identity (VMs, App Service, AKS),
        # environment variables, Azure CLI, and other credential sources.
        # The token is scoped to the Key Vault resource
        # (https://vault.azure.net/.default) and set as the
        # Authorization header on the session so all subsequent calls
        # are authenticated.
        self._authenticate_session()

    def get_secret(self, secret_name: str) -> str:
        """
        Retrieves a secret from Azure Key Vault.
        This is permitted even if watch-only, since it's a read operation.
        """
        # FIX #66: Added api-version query parameter.  The original URL
        # was just {base_url}/secrets/{name} with no API version.  Azure
        # Key Vault requires ?api-version=7.x on every REST call;
        # without it, the service returns 400 Bad Request or a redirect.
        url = f"{self.base_url}/secrets/{secret_name}"
        params = {"api-version": AZURE_API_VERSION}
        try:
            resp = self._session.get(url, params=params, timeout=10)
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

        # FIX #66: Added api-version query parameter (see get_secret).
        url = f"{self.base_url}/secrets/{secret_name}"
        params = {"api-version": AZURE_API_VERSION}
        try:
            resp = self._session.put(url, json={"value": value}, params=params, timeout=10)
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

        # FIX #66: Added api-version query parameter (see get_secret).
        url = f"{self.base_url}/secrets/{secret_name}"
        params = {"api-version": AZURE_API_VERSION}
        try:
            resp = self._session.delete(url, params=params, timeout=10)
            if resp.status_code != 200:
                raise AzureClientError(f"DELETE {url} returned {resp.status_code}: {resp.text}")
            logger.info("Deleted secret '%s' in Azure Key Vault.", secret_name)
        except Exception as e:
            raise AzureClientError(f"Failed to delete secret '{secret_name}': {e}")

    def _build_requests_session(self) -> requests.Session:
        """
        Creates a requests.Session that uses PQC TLS if strict_transport or tls_mode != 'classical',
        falling back to classical if not strict_transport and PQC fails.

        FIX #78/#79: Same fix as malware_db.py — replaced the fragile nested
        PQCPoolManager class + lambda init_poolmanager pattern with a proper
        HTTPAdapter subclass.  See malware_db.py _build_requests_session for
        the full rationale on why the old approach was broken.
        """
        sess = requests.Session()

        # If classical + not strict => normal TLS
        tls_mode = getattr(self.config, "tls_mode", "classical")
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

        from requests.adapters import HTTPAdapter

        class PQCHTTPAdapter(HTTPAdapter):
            """HTTPAdapter subclass that injects a PQC SSL context."""
            def __init__(self, pqc_ssl_context, **kwargs):
                self._pqc_ssl_context = pqc_ssl_context
                super().__init__(**kwargs)

            def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
                kwargs["ssl_context"] = self._pqc_ssl_context
                super().init_poolmanager(connections, maxsize, block=block, **kwargs)

        adapter = PQCHTTPAdapter(pqc_ssl_context=ssl_ctx)
        sess.mount("https://", adapter)
        return sess

    def _authenticate_session(self) -> None:
        """
        FIX #65: Acquire a Bearer token for Azure Key Vault and set it
        as the default Authorization header on the requests session.

        Uses azure.identity.DefaultAzureCredential which transparently
        supports managed identity (Azure VMs, App Service, AKS),
        environment-variable credentials, Azure CLI auth, and more.
        The token is scoped to https://vault.azure.net/.default, which
        is the resource scope required by Azure Key Vault REST API.

        If the azure-identity package is not installed or token
        acquisition fails, raises AzureClientError so the caller knows
        the client is non-functional (every call would 401 anyway).
        """
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise AzureClientError(
                "azure-identity package is not installed. "
                "Install it with: pip install azure-identity"
            )

        try:
            credential = DefaultAzureCredential()
            token = credential.get_token("https://vault.azure.net/.default")
            self._session.headers["Authorization"] = f"Bearer {token.token}"
            logger.info("AzureClient: Authenticated via DefaultAzureCredential.")
        except Exception as e:
            raise AzureClientError(
                f"Failed to acquire Azure Key Vault access token: {e}"
            )
