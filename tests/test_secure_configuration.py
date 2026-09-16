"""Security-boundary tests for explicit v1 configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_unifi.clients.unifi import UniFiClient
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.server import _build_auth_provider


def _files(tmp_path: Path) -> tuple[Path, Path]:
    api_key = tmp_path / "api-key"
    bearer = tmp_path / "bearer-token"
    api_key.write_text("test-api-key\n", encoding="utf-8")
    bearer.write_text("test-bearer-token\n", encoding="utf-8")
    return api_key, bearer


def test_real_mode_requires_api_key_file() -> None:
    settings = Settings(
        stub_mode=False,
        controllers=[ControllerConfig(name="home", host="gateway.test")],
    )
    with pytest.raises(ValueError, match="api_key_file"):
        settings.validate_runtime()


def test_real_mode_reads_explicit_api_key_file_without_logging_value(tmp_path: Path) -> None:
    api_key, _ = _files(tmp_path)
    settings = Settings(
        stub_mode=False,
        mcp_transport="stdio",
        controllers=[ControllerConfig(name="home", host="gateway.test", api_key_file=api_key)],
    )
    settings.validate_runtime()
    assert settings.controllers[0].api_key is not None
    assert settings.controllers[0].api_key.get_secret_value() == "test-api-key"
    assert "test-api-key" not in str(settings.safe_repr())
    assert settings.controllers[0].verify_ssl is True


def test_real_mode_rejects_disabled_tls_verification(tmp_path: Path) -> None:
    api_key, _ = _files(tmp_path)
    settings = Settings(
        stub_mode=False,
        mcp_transport="stdio",
        controllers=[
            ControllerConfig(
                name="home",
                host="gateway.test",
                api_key_file=api_key,
                verify_ssl=False,
            )
        ],
    )
    with pytest.raises(ValueError, match="TLS certificate verification"):
        settings.validate_runtime()


def test_controller_yaml_inline_key_is_rejected_at_runtime(tmp_path: Path) -> None:
    config = tmp_path / "controllers.yaml"
    config.write_text(
        "- name: home\n  host: gateway.test\n  api_key: inline-secret\n",
        encoding="utf-8",
    )
    settings = Settings(stub_mode=False, controllers_file=config)
    with pytest.raises(ValueError, match="api_key_file"):
        settings.validate_runtime()


def test_bearer_file_derives_explicit_client_identity(tmp_path: Path) -> None:
    api_key, bearer = _files(tmp_path)
    settings = Settings(
        stub_mode=False,
        mcp_transport="streamable-http",
        auth_token_file=bearer,
        client_id="monitor-agent",
        controllers=[ControllerConfig(name="home", host="gateway.test", api_key_file=api_key)],
    )
    settings.validate_runtime()
    provider = _build_auth_provider(settings)
    assert provider is not None
    assert provider.tokens["test-bearer-token"]["client_id"] == "monitor-agent"


def test_real_http_rejects_raw_bearer_environment_value(tmp_path: Path) -> None:
    api_key, _ = _files(tmp_path)
    settings = Settings(
        stub_mode=False,
        mcp_transport="streamable-http",
        auth_tokens="monitor-agent:raw-token",
        client_id="monitor-agent",
        controllers=[ControllerConfig(name="home", host="gateway.test", api_key_file=api_key)],
    )
    with pytest.raises(ValueError, match="AUTH_TOKEN_FILE"):
        settings.validate_runtime()


def test_cwd_env_file_cannot_inject_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "STUB_MODE=false\nUNIFI_HOST=attacker.test\nUNIFI_API_KEY=/tmp/attacker-key\n",
        encoding="utf-8",
    )
    settings = Settings()
    assert settings.stub_mode is True
    assert settings.controllers[0].host == "stub"


def test_client_tls_verification_defaults_on() -> None:
    client = UniFiClient(host="gateway.test", api_key="test-key")
    try:
        assert client._client._transport._pool._ssl_context.verify_mode != 0  # type: ignore[attr-defined]
    finally:
        import asyncio

        asyncio.run(client.aclose())
