"""Validated, env-driven configuration for mcp-unifi.

Loads values from environment variables (and a ``.env`` file when present),
validates types/ranges, and refuses to start in real mode without the bits it
needs to talk to a gateway. Stub mode requires no gateway settings at all.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    # Gateway connection (required when stub_mode=False)
    # ------------------------------------------------------------------
    unifi_host: str = Field(default="", description="UniFi gateway IP or hostname.")
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
    def _check_real_mode_requirements(self) -> Settings:
        if not self.stub_mode:
            missing = [
                name
                for name, value in (
                    ("UNIFI_HOST", self.unifi_host),
                    ("UNIFI_API_KEY", self.unifi_api_key),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "Real mode requires these env vars: "
                    + ", ".join(missing)
                    + ". Set STUB_MODE=true to run with mock data instead."
                )
        if self.iot_dhcp_stop_offset <= self.iot_dhcp_start_offset:
            raise ValueError("IOT_DHCP_STOP_OFFSET must be greater than IOT_DHCP_START_OFFSET")
        return self

    def safe_repr(self) -> dict[str, object]:
        """Return a redacted dict suitable for logging at startup."""
        return {
            "stub_mode": self.stub_mode,
            "unifi_host": self.unifi_host or "(stub)",
            "unifi_port": self.unifi_port,
            "unifi_site": self.unifi_site,
            "unifi_verify_ssl": self.unifi_verify_ssl,
            "unifi_api_key_set": bool(self.unifi_api_key),
            "iot_subnet_template": self.iot_subnet_template,
            "iot_dhcp_start_offset": self.iot_dhcp_start_offset,
            "iot_dhcp_stop_offset": self.iot_dhcp_stop_offset,
            "mcp_transport": self.mcp_transport,
            "mcp_host": self.mcp_host,
            "mcp_port": self.mcp_port,
            "log_level": self.log_level,
            "log_format": self.log_format,
        }


def load_settings() -> Settings:
    """Build a Settings instance from the environment. Raises on invalid config."""
    return Settings()
