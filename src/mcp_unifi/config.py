"""Validated, env-driven configuration for mcp-unifi.

Loads values from environment variables (and a ``.env`` file when present),
validates types/ranges, and refuses to start in real mode without the bits it
needs to talk to a gateway. Stub mode requires no gateway settings at all.

v0.5 introduces multi-controller support. Sources of controller config, in
priority order:

  1. ``MCP_UNIFI_CONTROLLERS_FILE`` — YAML file with a list of named
     controllers. Used for >1 controller.
  2. Legacy single-controller env vars (``UNIFI_HOST``, ``UNIFI_API_KEY``,
     etc.) — auto-promoted to ``controllers=[ControllerConfig(name="default",
     ...)]``. Backward-compat path; existing 0.4.x deployments keep working
     unchanged.
  3. ``stub_mode=True`` with no controller config — synthesizes a single
     ``default`` stub controller so the server can boot.

Real mode with no controller config from any source is a hard validation
error.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ControllerConfig(BaseModel):
    """One UniFi controller endpoint.

    Multiple ``ControllerConfig`` instances live in ``Settings.controllers`` and
    are addressed by ``name`` from tool calls (e.g. ``controller="home"``).
    """

    name: str = Field(description="Stable identifier used by tools (e.g. 'default', 'home').")
    host: str = Field(description="UniFi gateway IP or hostname.")
    api_key: SecretStr = Field(description="API key. Wrapped in SecretStr; never logged.")
    port: int = Field(default=443, ge=1, le=65535)
    site: str = Field(default="default")
    verify_ssl: bool = Field(default=False)


class Settings(BaseSettings):
    """Runtime configuration for the MCP UniFi server.

    All fields can be overridden via environment variables. Names map 1:1 with
    the env var names (case-insensitive). Pydantic validates them at startup.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Mode toggle
    # ------------------------------------------------------------------
    stub_mode: bool = Field(
        default=True,
        description=(
            "If True, the server returns mock data from an in-memory state "
            "machine. If False, it talks to a real UniFi gateway."
        ),
    )

    # ------------------------------------------------------------------
    # Multi-controller config
    # ------------------------------------------------------------------
    controllers_file: Path | None = Field(
        default=None,
        description=(
            "Optional YAML file describing one or more controllers. Used "
            "when running against >1 site. See ControllerConfig for fields."
        ),
    )
    #: Populated by ``_assemble_controllers`` after model construction. Not
    #: bound directly to an env var — it's derived from one of three sources
    #: (YAML file, legacy env vars, or stub default). Tools read this list
    #: via the dispatcher (Step 3).
    controllers: list[ControllerConfig] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Legacy single-controller gateway connection
    # (deprecated v0.5; keep through v0.x for backward compat.
    # Removal is a v1.x decision, not a v0.5 decision.)
    # ------------------------------------------------------------------
    unifi_host: str = Field(default="", description="UniFi gateway IP or hostname (legacy).")
    unifi_port: int = Field(default=443, ge=1, le=65535)
    unifi_site: str = Field(default="default")
    unifi_api_key: str = Field(default="")
    unifi_verify_ssl: bool = Field(default=False)

    # ------------------------------------------------------------------
    # IoT defaults (used by create_iot_network)
    # ------------------------------------------------------------------
    iot_subnet_template: str = Field(
        default="10.0.{vlan_id}.0/24",
        description="Subnet template; {vlan_id} is substituted at call time.",
    )
    iot_dhcp_start_offset: int = Field(default=100, ge=2, le=254)
    iot_dhcp_stop_offset: int = Field(default=200, ge=2, le=254)

    # ------------------------------------------------------------------
    # MCP server settings
    # ------------------------------------------------------------------
    mcp_transport: Literal["stdio", "streamable-http"] = Field(
        default="streamable-http",
        description=(
            "MCP transport. 'stdio' for Claude Desktop / per-session "
            "subprocess installs (uvx, pipx). 'streamable-http' (default) "
            "for the long-running container, multi-client homelab pattern."
        ),
    )
    mcp_host: str = Field(default="0.0.0.0")
    mcp_port: int = Field(default=3714, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(
        default="json",
        description="Structured JSON logs (production) or human-readable text.",
    )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @field_validator("iot_subnet_template")
    @classmethod
    def _check_subnet_template(cls, v: str) -> str:
        if "{vlan_id}" not in v:
            raise ValueError("iot_subnet_template must contain the literal '{vlan_id}' placeholder")
        return v

    @model_validator(mode="after")
    def _check_dhcp_offsets(self) -> Settings:
        if self.iot_dhcp_stop_offset <= self.iot_dhcp_start_offset:
            raise ValueError("IOT_DHCP_STOP_OFFSET must be greater than IOT_DHCP_START_OFFSET")
        return self

    @model_validator(mode="after")
    def _assemble_controllers(self) -> Settings:
        """Build ``self.controllers`` from one of three sources, in priority order.

        Priority:
          (a) ``controllers_file`` (YAML)
          (b) legacy single-controller env vars (auto-promoted)
          (c) ``stub_mode=True`` default
          (d) real mode + no config → ValueError
        """
        # If callers passed `controllers=[...]` explicitly (e.g. tests), trust it
        # but still run uniqueness + non-empty checks below.
        if not self.controllers:
            if self.controllers_file is not None:
                self.controllers = _load_controllers_from_yaml(self.controllers_file)
            elif self.unifi_host and self.unifi_api_key:
                self.controllers = [
                    ControllerConfig(
                        name="default",
                        host=self.unifi_host,
                        api_key=SecretStr(self.unifi_api_key),
                        port=self.unifi_port,
                        site=self.unifi_site,
                        verify_ssl=self.unifi_verify_ssl,
                    )
                ]
                logger.info("single-controller env detected, promoted to controllers=[default]")
            elif self.stub_mode:
                self.controllers = [
                    ControllerConfig(
                        name="default",
                        host="stub",
                        api_key=SecretStr("stub"),
                        port=self.unifi_port,
                        site=self.unifi_site,
                        verify_ssl=self.unifi_verify_ssl,
                    )
                ]
            else:
                raise ValueError(
                    "Real mode requires controller config. Set either "
                    "MCP_UNIFI_CONTROLLERS_FILE (YAML) or the legacy "
                    "UNIFI_HOST + UNIFI_API_KEY env vars. "
                    "Set STUB_MODE=true to run with mock data instead."
                )

        # Uniqueness check (applies to all sources, including caller-provided lists).
        names = [c.name for c in self.controllers]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"Duplicate controller names: {duplicates}")

        # Real mode requires at least one controller. (Stub mode always
        # synthesizes a default above, so this only fires if a caller passed
        # an explicit empty list with stub_mode=False.)
        if not self.stub_mode and not self.controllers:
            raise ValueError("Real mode requires at least one controller.")

        return self

    def safe_repr(self) -> dict[str, object]:
        """Return a redacted dict suitable for logging at startup.

        Crucially: ``api_key`` values are NEVER included. Each controller
        gets an ``api_key_set`` boolean instead.
        """
        return {
            "stub_mode": self.stub_mode,
            "controllers_file": str(self.controllers_file) if self.controllers_file else None,
            "controllers": [
                {
                    "name": c.name,
                    "host": c.host,
                    "port": c.port,
                    "site": c.site,
                    "verify_ssl": c.verify_ssl,
                    "api_key_set": bool(c.api_key.get_secret_value()),
                }
                for c in self.controllers
            ],
            "iot_subnet_template": self.iot_subnet_template,
            "iot_dhcp_start_offset": self.iot_dhcp_start_offset,
            "iot_dhcp_stop_offset": self.iot_dhcp_stop_offset,
            "mcp_transport": self.mcp_transport,
            "mcp_host": self.mcp_host,
            "mcp_port": self.mcp_port,
            "log_level": self.log_level,
            "log_format": self.log_format,
        }


def _load_controllers_from_yaml(path: Path) -> list[ControllerConfig]:
    """Parse a YAML file into a list of ControllerConfig.

    Expected shape (top-level list, OR a dict with a 'controllers' key):

        - name: home
          host: 192.168.1.1
          api_key: abc123
          port: 443
          site: default
          verify_ssl: false
        - name: office
          host: 10.0.0.1
          api_key: def456

    Raises ValueError if the file can't be read or parsed.
    """
    if not path.exists():
        raise ValueError(f"controllers_file does not exist: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"controllers_file is not valid YAML ({path}): {exc}") from exc

    if isinstance(raw, dict) and "controllers" in raw:
        items: Any = raw["controllers"]
    else:
        items = raw

    if not isinstance(items, list):
        raise ValueError(
            f"controllers_file must contain a list (or a dict with 'controllers:' key): {path}"
        )

    return [ControllerConfig(**item) for item in items]


def load_settings() -> Settings:
    """Build a Settings instance from the environment. Raises on invalid config."""
    return Settings()
