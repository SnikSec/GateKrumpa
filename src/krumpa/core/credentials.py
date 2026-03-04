"""
GateKrumpa — Credential provider chain.

Resolves secrets at runtime without storing them in plaintext.  Three
provider types are supported out of the box:

* **EnvProvider** — reads ``${VAR_NAME}`` references from ``os.environ``.
* **VaultProvider** — abstract base for vault backends (HashiCorp Vault,
  Azure Key Vault, AWS Secrets Manager).  Concrete subclasses implement
  :meth:`fetch`.
* **ChainProvider** — tries each provider in order; first non-``None`` wins.

Config interpolation
--------------------
YAML values may contain ``${ENV_VAR}`` references **or** ``vault://``
URIs.  Call :func:`resolve_config` on the loaded config dict to expand
them before passing config to modules::

    raw = yaml.safe_load(Path("config.yaml").read_text())
    config = resolve_config(raw, provider=chain)

Security guarantees
-------------------
* Secrets never appear in source / config files committed to the repo.
* ``ScanContext.clear_sensitive()`` already wipes ``auth_tokens`` after
  each scan — vault tokens are not cached beyond the scan lifetime.
* Environment variables are the **minimum viable** provider and work
  everywhere (local dev, CI, containers, orchestrators).
"""

from __future__ import annotations

import abc
import logging
import os
import re
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger("krumpa.credentials")

# Pattern for ${VAR_NAME} or ${VAR_NAME:-default}
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")

# Pattern for vault://path/to/secret[#field]
_VAULT_PATTERN = re.compile(r"^vault://(.+?)(?:#(.+))?$")


# ===================================================================
# Protocol
# ===================================================================

@runtime_checkable
class CredentialProvider(Protocol):
    """Resolve a credential key to its secret value."""

    def resolve(self, key: str) -> Optional[str]:
        """Return the secret for *key*, or ``None`` if not found."""
        ...  # pragma: no cover


# ===================================================================
# Environment variable provider
# ===================================================================

class EnvProvider:
    """Resolve credentials from environment variables.

    Supports ``${VAR}`` syntax.  If the variable is unset and no
    default is given (``${VAR:-fallback}``), returns ``None``.

    Parameters
    ----------
    prefix:
        Optional prefix prepended to every key lookup (e.g. ``GATEKRUMPA_``).
    """

    def __init__(self, *, prefix: str = "") -> None:
        self._prefix = prefix

    def resolve(self, key: str) -> Optional[str]:
        """Look up ``prefix + key`` in the process environment."""
        env_key = self._prefix + key
        value = os.environ.get(env_key)
        if value is not None:
            return value
        logger.debug("EnvProvider: %s not set", env_key)
        return None


# ===================================================================
# Vault provider (abstract)
# ===================================================================

class VaultProvider(abc.ABC):
    """Abstract base for secret-vault integrations.

    Subclasses implement :meth:`fetch` to talk to the vault API.
    The :meth:`resolve` wrapper handles ``vault://path#field`` URIs.
    """

    def resolve(self, key: str) -> Optional[str]:
        """Resolve a ``vault://`` URI or plain path."""
        m = _VAULT_PATTERN.match(key)
        if m:
            path, field = m.group(1), m.group(2)
            return self.fetch(path, field=field)
        # Plain key — treat as vault path
        return self.fetch(key)

    @abc.abstractmethod
    def fetch(self, path: str, *, field: Optional[str] = None) -> Optional[str]:
        """Fetch a secret from the vault.

        Parameters
        ----------
        path:
            Vault-specific path (e.g. ``secret/data/api-key``).
        field:
            Optional field within the secret (for vault backends that
            return dicts).
        """
        ...  # pragma: no cover


class HashiCorpVaultProvider(VaultProvider):
    """HashiCorp Vault (KV v2) provider.

    Reads ``VAULT_ADDR`` and ``VAULT_TOKEN`` from the environment.
    Falls back gracefully if vault is unreachable.
    """

    def __init__(
        self,
        *,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        mount: str = "secret",
    ) -> None:
        self._addr = (addr or os.environ.get("VAULT_ADDR", "")).rstrip("/")
        self._token = token or os.environ.get("VAULT_TOKEN", "")
        self._mount = mount

    def fetch(self, path: str, *, field: Optional[str] = None) -> Optional[str]:
        if not self._addr or not self._token:
            logger.debug("HashiCorpVaultProvider: VAULT_ADDR or VAULT_TOKEN not set")
            return None
        try:
            import httpx
            url = f"{self._addr}/v1/{self._mount}/data/{path}"
            resp = httpx.get(
                url,
                headers={"X-Vault-Token": self._token},
                timeout=10,
            )
            if resp.status_code != 200:
                logger.warning("Vault returned %d for %s", resp.status_code, path)
                return None
            data = resp.json().get("data", {}).get("data", {})
            if field:
                return data.get(field)
            # Return first value if no field specified
            return next(iter(data.values()), None) if data else None
        except Exception as exc:
            logger.warning("Vault fetch failed for %s: %s", path, exc)
            return None


class AzureKeyVaultProvider(VaultProvider):
    """Azure Key Vault provider.

    Reads ``AZURE_KEY_VAULT_URL`` from the environment.
    Requires ``azure-identity`` and ``azure-keyvault-secrets`` packages.
    """

    def __init__(self, *, vault_url: Optional[str] = None) -> None:
        self._vault_url = vault_url or os.environ.get("AZURE_KEY_VAULT_URL", "")

    def fetch(self, path: str, *, field: Optional[str] = None) -> Optional[str]:
        if not self._vault_url:
            logger.debug("AzureKeyVaultProvider: AZURE_KEY_VAULT_URL not set")
            return None
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
            from azure.keyvault.secrets import SecretClient  # type: ignore[import-untyped]
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=self._vault_url, credential=credential)
            secret = client.get_secret(path)
            return secret.value
        except ImportError:
            logger.warning("azure-identity / azure-keyvault-secrets not installed")
            return None
        except Exception as exc:
            logger.warning("Azure Key Vault fetch failed for %s: %s", path, exc)
            return None


class AwsSecretsManagerProvider(VaultProvider):
    """AWS Secrets Manager provider.

    Uses the default boto3 credential chain (env vars, IAM role, etc.).
    """

    def __init__(self, *, region: Optional[str] = None) -> None:
        self._region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    def fetch(self, path: str, *, field: Optional[str] = None) -> Optional[str]:
        try:
            import boto3  # type: ignore[import-untyped]
            import json as _json
            client = boto3.client("secretsmanager", region_name=self._region)
            resp = client.get_secret_value(SecretId=path)
            secret_string = resp.get("SecretString", "")
            if field:
                try:
                    data = _json.loads(secret_string)
                    return data.get(field)
                except (_json.JSONDecodeError, TypeError):
                    return secret_string
            return secret_string
        except ImportError:
            logger.warning("boto3 not installed")
            return None
        except Exception as exc:
            logger.warning("AWS Secrets Manager fetch failed for %s: %s", path, exc)
            return None


# ===================================================================
# Chain provider
# ===================================================================

class ChainProvider:
    """Try multiple providers in order; first non-None wins.

    Parameters
    ----------
    providers:
        Ordered list of :class:`CredentialProvider` instances.
    """

    def __init__(self, providers: Optional[List[CredentialProvider]] = None) -> None:
        self._providers: List[CredentialProvider] = list(providers or [])

    def add(self, provider: CredentialProvider) -> "ChainProvider":
        """Append a provider to the chain."""
        self._providers.append(provider)
        return self

    def resolve(self, key: str) -> Optional[str]:
        for p in self._providers:
            value = p.resolve(key)
            if value is not None:
                return value
        return None


# ===================================================================
# Config interpolation
# ===================================================================

def resolve_value(value: str, provider: CredentialProvider) -> str:
    """Resolve ``${VAR}`` and ``vault://`` references in a single string.

    Parameters
    ----------
    value:
        A string that may contain ``${VAR_NAME}``, ``${VAR:-default}``,
        or ``vault://path#field`` references.
    provider:
        The credential provider to resolve against.

    Returns
    -------
    str
        The resolved value.  Unresolvable ``${VAR}`` references with
        defaults use the default; without defaults they remain as-is
        and a warning is logged.
    """
    # Handle vault:// URIs (the entire value is a vault ref)
    if value.startswith("vault://"):
        result = provider.resolve(value)
        if result is not None:
            return result
        logger.warning("Could not resolve vault reference: %s", value)
        return value

    # Handle ${VAR} and ${VAR:-default} inline
    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        resolved = provider.resolve(var_name)
        if resolved is not None:
            return resolved
        if default is not None:
            return default
        logger.warning("Unresolved credential reference: ${%s}", var_name)
        return match.group(0)

    return _ENV_PATTERN.sub(_replace, value)


def resolve_config(
    config: Dict[str, Any],
    provider: Optional[CredentialProvider] = None,
) -> Dict[str, Any]:
    """Recursively resolve credential references in a config dict.

    Walks the entire config tree and resolves any string values that
    contain ``${VAR}`` or ``vault://`` references.

    Parameters
    ----------
    config:
        The raw config dict (e.g. from YAML).
    provider:
        Credential provider.  Defaults to :class:`EnvProvider` if not given.

    Returns
    -------
    dict
        A new dict with all references resolved.
    """
    if provider is None:
        provider = EnvProvider()
    return _resolve_dict(config, provider)


def _resolve_dict(d: Dict[str, Any], provider: CredentialProvider) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for k, v in d.items():
        result[k] = _resolve_any(v, provider)
    return result


def _resolve_any(value: Any, provider: CredentialProvider) -> Any:
    if isinstance(value, str):
        return resolve_value(value, provider)
    if isinstance(value, dict):
        return _resolve_dict(value, provider)
    if isinstance(value, list):
        return [_resolve_any(item, provider) for item in value]
    return value


# ===================================================================
# Factory
# ===================================================================

def build_provider(config: Dict[str, Any]) -> ChainProvider:
    """Build a :class:`ChainProvider` from a config dict.

    The config may contain a ``credentials`` section::

        credentials:
          env_prefix: "GATEKRUMPA_"
          vault:
            type: hashicorp   # or azure, aws
            addr: "https://vault.example.com"
            mount: secret

    If no ``credentials`` section exists, a default :class:`EnvProvider`
    is returned.
    """
    chain = ChainProvider()
    creds_config = config.get("credentials", {})

    # Always add env provider first
    prefix = creds_config.get("env_prefix", "")
    chain.add(EnvProvider(prefix=prefix))

    # Add vault if configured
    vault_config = creds_config.get("vault", {})
    vault_type = vault_config.get("type", "").lower()

    if vault_type == "hashicorp":
        chain.add(HashiCorpVaultProvider(
            addr=vault_config.get("addr"),
            token=vault_config.get("token"),
            mount=vault_config.get("mount", "secret"),
        ))
    elif vault_type == "azure":
        chain.add(AzureKeyVaultProvider(
            vault_url=vault_config.get("vault_url"),
        ))
    elif vault_type == "aws":
        chain.add(AwsSecretsManagerProvider(
            region=vault_config.get("region"),
        ))
    elif vault_type:
        logger.warning("Unknown vault type: %s", vault_type)

    return chain
