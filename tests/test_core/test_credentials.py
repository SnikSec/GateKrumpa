"""Tests for krumpa.core.credentials — credential provider chain."""

from __future__ import annotations

import os
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from krumpa.core.credentials import (
    AwsSecretsManagerProvider,
    AzureKeyVaultProvider,
    ChainProvider,
    CredentialProvider,
    EnvProvider,
    HashiCorpVaultProvider,
    VaultProvider,
    build_provider,
    resolve_config,
    resolve_value,
)


# ===================================================================
# EnvProvider
# ===================================================================

class TestEnvProvider:
    """EnvProvider reads from os.environ."""

    def test_resolve_existing_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_CRED_KEY", "secret123")
        prov = EnvProvider()
        assert prov.resolve("TEST_CRED_KEY") == "secret123"

    def test_resolve_missing_var(self) -> None:
        prov = EnvProvider()
        assert prov.resolve("NONEXISTENT_VAR_XYZ_12345") is None

    def test_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GK_TOKEN", "tok456")
        prov = EnvProvider(prefix="GK_")
        assert prov.resolve("TOKEN") == "tok456"

    def test_prefix_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GK_MISSING", raising=False)
        prov = EnvProvider(prefix="GK_")
        assert prov.resolve("MISSING") is None

    def test_empty_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PLAIN_VAR", "val")
        prov = EnvProvider(prefix="")
        assert prov.resolve("PLAIN_VAR") == "val"

    def test_satisfies_protocol(self) -> None:
        assert isinstance(EnvProvider(), CredentialProvider)


# ===================================================================
# VaultProvider (abstract)
# ===================================================================

class ConcreteVault(VaultProvider):
    """Minimal vault for testing the base class resolve() logic."""

    def __init__(self, data: dict[str, dict[str, str]]) -> None:
        self._data = data

    def fetch(self, path: str, *, field: Optional[str] = None) -> Optional[str]:
        entry = self._data.get(path)
        if entry is None:
            return None
        if field:
            return entry.get(field)
        return next(iter(entry.values()), None)


class TestVaultProvider:
    """VaultProvider.resolve() parses vault:// URIs."""

    def test_vault_uri_with_field(self) -> None:
        v = ConcreteVault({"secret/creds": {"password": "p@ss"}})
        assert v.resolve("vault://secret/creds#password") == "p@ss"

    def test_vault_uri_without_field(self) -> None:
        v = ConcreteVault({"secret/api": {"key": "k123"}})
        assert v.resolve("vault://secret/api") == "k123"

    def test_plain_path(self) -> None:
        v = ConcreteVault({"mypath": {"val": "v"}})
        assert v.resolve("mypath") == "v"

    def test_missing_path(self) -> None:
        v = ConcreteVault({})
        assert v.resolve("vault://nope") is None


# ===================================================================
# HashiCorpVaultProvider
# ===================================================================

class TestHashiCorpVault:
    """HashiCorpVaultProvider fetches from Vault KV v2 via HTTP."""

    def test_no_addr_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        prov = HashiCorpVaultProvider()
        assert prov.fetch("secret/foo") is None

    def test_fetch_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"data": {"api_key": "vault_secret_42"}}
        }

        with patch("httpx.get", return_value=mock_resp) as mock_get:
            prov = HashiCorpVaultProvider(addr="http://vault:8200", token="tok")
            result = prov.fetch("app/config", field="api_key")
            assert result == "vault_secret_42"
            mock_get.assert_called_once()

    def test_fetch_non_200(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("httpx.get", return_value=mock_resp):
            prov = HashiCorpVaultProvider(addr="http://vault:8200", token="tok")
            assert prov.fetch("forbidden/path") is None

    def test_fetch_exception(self) -> None:
        with patch("httpx.get", side_effect=ConnectionError("down")):
            prov = HashiCorpVaultProvider(addr="http://vault:8200", token="tok")
            assert prov.fetch("bad/path") is None


# ===================================================================
# AzureKeyVaultProvider
# ===================================================================

class TestAzureKeyVault:
    """AzureKeyVaultProvider requires azure packages."""

    def test_no_url_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AZURE_KEY_VAULT_URL", raising=False)
        prov = AzureKeyVaultProvider()
        assert prov.fetch("my-secret") is None

    def test_missing_packages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://kv.vault.azure.net")
        prov = AzureKeyVaultProvider()
        # Should return None gracefully (azure packages not installed in test)
        result = prov.fetch("my-secret")
        assert result is None


# ===================================================================
# AwsSecretsManagerProvider
# ===================================================================

class TestAwsSecretsManager:
    """AwsSecretsManagerProvider requires boto3."""

    def test_missing_boto3(self) -> None:
        prov = AwsSecretsManagerProvider(region="us-west-2")
        # Should return None gracefully (boto3 not installed in test)
        result = prov.fetch("my/secret")
        assert result is None


# ===================================================================
# ChainProvider
# ===================================================================

class TestChainProvider:
    """ChainProvider tries providers in order."""

    def test_first_wins(self) -> None:
        p1 = EnvProvider()
        p2 = EnvProvider()
        chain = ChainProvider([p1, p2])

        # Patch p1 to return a value
        p1.resolve = lambda k: "from_p1"  # type: ignore[assignment]
        assert chain.resolve("any") == "from_p1"

    def test_fallback_to_second(self) -> None:
        p1 = EnvProvider()
        p2 = EnvProvider()
        chain = ChainProvider([p1, p2])

        p1.resolve = lambda k: None  # type: ignore[assignment]
        p2.resolve = lambda k: "from_p2"  # type: ignore[assignment]
        assert chain.resolve("any") == "from_p2"

    def test_all_miss(self) -> None:
        p1 = EnvProvider()
        chain = ChainProvider([p1])
        p1.resolve = lambda k: None  # type: ignore[assignment]
        assert chain.resolve("any") is None

    def test_empty_chain(self) -> None:
        chain = ChainProvider()
        assert chain.resolve("key") is None

    def test_add_fluent(self) -> None:
        chain = ChainProvider()
        result = chain.add(EnvProvider())
        assert result is chain
        assert len(chain._providers) == 1  # pyright: ignore[reportPrivateUsage]

    def test_satisfies_protocol(self) -> None:
        assert isinstance(ChainProvider(), CredentialProvider)


# ===================================================================
# resolve_value
# ===================================================================

class TestResolveValue:
    """resolve_value() handles ${VAR}, ${VAR:-default}, and vault:// refs."""

    def test_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_TOKEN", "abc")
        result = resolve_value("Bearer ${MY_TOKEN}", EnvProvider())
        assert result == "Bearer abc"

    def test_env_var_with_default(self) -> None:
        prov = EnvProvider()
        result = resolve_value("${MISSING_VAR:-fallback}", prov)
        assert result == "fallback"

    def test_env_var_unresolved_no_default(self) -> None:
        prov = EnvProvider()
        result = resolve_value("keep ${MISSING_XYZ_999}", prov)
        assert "${MISSING_XYZ_999}" in result

    def test_vault_uri(self) -> None:
        vault = ConcreteVault({"secret/token": {"value": "vault_val"}})
        result = resolve_value("vault://secret/token", vault)
        assert result == "vault_val"

    def test_vault_uri_unresolved(self) -> None:
        vault = ConcreteVault({})
        result = resolve_value("vault://missing/path", vault)
        assert result == "vault://missing/path"

    def test_plain_string(self) -> None:
        result = resolve_value("hello world", EnvProvider())
        assert result == "hello world"

    def test_multiple_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOST", "prod.api.com")
        monkeypatch.setenv("PORT", "8443")
        result = resolve_value("https://${HOST}:${PORT}/v1", EnvProvider())
        assert result == "https://prod.api.com:8443/v1"

    def test_empty_default(self) -> None:
        result = resolve_value("${NOPE:-}", EnvProvider())
        assert result == ""


# ===================================================================
# resolve_config
# ===================================================================

class TestResolveConfig:
    """resolve_config() recursively resolves an entire config dict."""

    def test_simple_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY", "k123")
        config = {"http": {"auth": {"token": "${API_KEY}"}}}
        resolved = resolve_config(config, EnvProvider())
        assert resolved["http"]["auth"]["token"] == "k123"

    def test_nested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_PASS", "s3cret")
        config = {"deep": {"nested": {"password": "${DB_PASS}"}}}
        resolved = resolve_config(config, EnvProvider())
        assert resolved["deep"]["nested"]["password"] == "s3cret"

    def test_list_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("URL1", "http://a.com")
        config = {"targets": ["${URL1}", "http://b.com"]}
        resolved = resolve_config(config, EnvProvider())
        assert resolved["targets"] == ["http://a.com", "http://b.com"]

    def test_non_string_passthrough(self) -> None:
        config = {"timeout": 30, "verify": True, "tags": [1, 2, 3]}
        resolved = resolve_config(config, EnvProvider())
        assert resolved == config

    def test_default_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("X", "yes")
        config = {"key": "${X}"}
        resolved = resolve_config(config)
        assert resolved["key"] == "yes"


# ===================================================================
# build_provider
# ===================================================================

class TestBuildProvider:
    """build_provider() constructs a ChainProvider from config."""

    def test_empty_config(self) -> None:
        chain = build_provider({})
        assert isinstance(chain, ChainProvider)
        assert len(chain._providers) == 1  # pyright: ignore[reportPrivateUsage]
        assert isinstance(chain._providers[0], EnvProvider)  # pyright: ignore[reportPrivateUsage]

    def test_env_prefix(self) -> None:
        chain = build_provider({"credentials": {"env_prefix": "GK_"}})
        env_prov = chain._providers[0]  # pyright: ignore[reportPrivateUsage]
        assert isinstance(env_prov, EnvProvider)
        assert env_prov._prefix == "GK_"  # pyright: ignore[reportPrivateUsage]

    def test_hashicorp_vault(self) -> None:
        config = {
            "credentials": {
                "vault": {
                    "type": "hashicorp",
                    "addr": "http://vault:8200",
                    "mount": "kv",
                }
            }
        }
        chain = build_provider(config)
        assert len(chain._providers) == 2  # pyright: ignore[reportPrivateUsage]
        assert isinstance(chain._providers[1], HashiCorpVaultProvider)  # pyright: ignore[reportPrivateUsage]

    def test_azure_vault(self) -> None:
        config = {
            "credentials": {
                "vault": {
                    "type": "azure",
                    "vault_url": "https://kv.vault.azure.net",
                }
            }
        }
        chain = build_provider(config)
        assert len(chain._providers) == 2  # pyright: ignore[reportPrivateUsage]
        assert isinstance(chain._providers[1], AzureKeyVaultProvider)  # pyright: ignore[reportPrivateUsage]

    def test_aws_vault(self) -> None:
        config = {
            "credentials": {
                "vault": {
                    "type": "aws",
                    "region": "eu-west-1",
                }
            }
        }
        chain = build_provider(config)
        assert len(chain._providers) == 2  # pyright: ignore[reportPrivateUsage]
        assert isinstance(chain._providers[1], AwsSecretsManagerProvider)  # pyright: ignore[reportPrivateUsage]

    def test_unknown_vault_type(self) -> None:
        config = {"credentials": {"vault": {"type": "unknown_vault"}}}
        chain = build_provider(config)
        # Should only have the env provider (unknown is ignored)
        assert len(chain._providers) == 1  # pyright: ignore[reportPrivateUsage]


# ===================================================================
# Integration: ChainProvider + resolve_config
# ===================================================================

class TestIntegration:
    """End-to-end: env + vault chain resolving a full config."""

    def test_chain_env_then_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("API_KEY", "env_key")
        vault = ConcreteVault({"secret/db": {"password": "vault_pass"}})
        chain = ChainProvider([EnvProvider(), vault])

        config = {
            "http": {
                "auth": {
                    "token": "${API_KEY}",
                    "password": "vault://secret/db#password",
                }
            }
        }
        resolved = resolve_config(config, chain)
        assert resolved["http"]["auth"]["token"] == "env_key"
        assert resolved["http"]["auth"]["password"] == "vault_pass"

    def test_env_wins_over_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_SECRET", "from_env")
        vault = ConcreteVault({"MY_SECRET": {"value": "from_vault"}})
        chain = ChainProvider([EnvProvider(), vault])

        assert chain.resolve("MY_SECRET") == "from_env"
