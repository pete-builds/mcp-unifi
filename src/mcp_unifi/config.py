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
from pydantic import AliasChoices, BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Duplicated (intentionally) from dispatcher.KNOWN_MODULES to keep config a
# leaf module — importing dispatcher here would risk a circular via
# mcp_unifi.clients.*. The two must stay in sync; test_scoping.py's
# test_scope_names_match_known_modules enforces it.
_KNOWN_MODULE_SCOPES: frozenset[str] = frozenset({"network", "protect", "access"})

logger = logging.getLogger(__name__)


class ControllerConfig(BaseModel):
    """One UniFi controller endpoint.

    Multiple ``ControllerConfig`` instances live in ``Settings.controllers`` and
    are addressed by ``name`` from tool calls (e.g. ``controller="home"``).

    The ``access_*`` fields are optional and only consulted when the Access
    module is enabled. They describe the UniFi Access hub, which often runs
    on a separate IP / port (default ``12445``) with its own API key. If the
    hub is reachable on the same host as the gateway, set ``access_host`` to
    the same value and ``access_api_key`` to the Access-specific key.
    """

    name: str = Field(description="Stable identifier used by tools (e.g. 'default', 'home').")
    host: str = Field(description="UniFi gateway IP or hostname.")
    api_key: SecretStr = Field(description="API key. Wrapped in SecretStr; never logged.")
    port: int = Field(default=443, ge=1, le=65535)
    site: str = Field(default="default")
    verify_ssl: bool = Field(default=False)

    access_host: str = Field(
        default="",
        description="UniFi Access hub host. Empty disables the Access backend for this controller.",
    )
    access_api_key: SecretStr | None = Field(
        default=None,
        description="UniFi Access API key (separate from the Network API key).",
    )
    access_port: int = Field(default=12445, ge=1, le=65535)


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
        populate_by_name=True,
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
    # Legacy single-controller UniFi Access connection (v0.10+).
    # Promoted onto the ``default`` controller's ``access_*`` fields by
    # ``_assemble_controllers`` when set. Set ``unifi_access_host`` and
    # ``unifi_access_api_key`` to enable the Access backend without
    # writing a controllers YAML file.
    # ------------------------------------------------------------------
    unifi_access_host: str = Field(
        default="",
        description="UniFi Access hub host. Empty disables Access for the legacy controller.",
    )
    unifi_access_api_key: str = Field(
        default="",
        description="UniFi Access API key (legacy). Promoted onto ControllerConfig.access_api_key.",
    )
    unifi_access_port: int = Field(default=12445, ge=1, le=65535)

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
    # HTTP transport authentication (v0.9.0+)
    # ------------------------------------------------------------------
    auth_tokens: str = Field(
        default="",
        validation_alias=AliasChoices("MCP_UNIFI_AUTH_TOKENS", "auth_tokens"),
        description=(
            "Bearer tokens for HTTP transport. Comma-separated. Each entry "
            "is one of: a bare token (assigned client_id 'client-N', all "
            "modules allowed); 'client_id:token' (named client, all modules "
            "allowed); or 'client_id:token:module1|module2' (named client "
            "scoped to specific modules — known modules are 'network', "
            "'protect', 'access'; '*' means all). The pipe separator is "
            "used because comma is already the entry delimiter. Ignored on "
            "stdio. Env var: MCP_UNIFI_AUTH_TOKENS."
        ),
    )
    auth_required: bool = Field(
        default=True,
        validation_alias=AliasChoices("MCP_UNIFI_AUTH_REQUIRED", "auth_required"),
        description=(
            "If True (default), HTTP transport refuses to start without "
            "auth_tokens. Set False to opt out (NOT RECOMMENDED for any "
            "deployment beyond a single-host trusted boundary). Ignored on stdio. "
            "Env var: MCP_UNIFI_AUTH_REQUIRED."
        ),
    )

    @property
    def auth_token_map(self) -> dict[str, dict[str, Any]]:
        """Parse ``auth_tokens`` into the dict shape FastMCP's StaticTokenVerifier expects.

        Returns ``{token: {"client_id": str, "scopes": []}}``. Empty if no
        tokens configured. Each entry in the CSV is one of:

        * ``token`` — bare, client_id auto-assigned ``client-N``.
        * ``client_id:token`` — named client, all modules allowed.
        * ``client_id:token:module1|module2`` — named client, restricted to
          the listed modules (pipe-separated because comma is already the
          entry delimiter). ``*`` matches everything.

        Used by ``build_server`` to wire the auth provider. Per-client
        module allowlists live on :meth:`auth_client_scopes` alongside.
        """
        return {
            token: {"client_id": meta["client_id"], "scopes": []}
            for token, meta in self._auth_entries().items()
        }

    @property
    def auth_client_scopes(self) -> dict[str, set[str]]:
        """Return ``{client_id: allowed_modules}`` derived from ``auth_tokens``.

        A client with ``{"*"}`` (or a bare/2-part token) may call every tool
        the server registered. A client with a concrete set like
        ``{"network", "protect"}`` sees only tools tagged with one of those
        modules on ``tools/list``, and calls to any other tool return an
        auth error. The scope map is consumed by
        :class:`mcp_unifi.scoping.ScopeMiddleware`.
        """
        return {
            meta["client_id"]: meta["allowed_modules"] for meta in self._auth_entries().values()
        }

    def _auth_entries(self) -> dict[str, dict[str, Any]]:
        """Parse ``auth_tokens`` once. Internal helper for the two properties above."""
        raw = self.auth_tokens.strip()
        if not raw:
            return {}
        out: dict[str, dict[str, Any]] = {}
        seen_client_ids: set[str] = set()
        for idx, item in enumerate(raw.split(",")):
            item = item.strip()
            if not item:
                continue
            parts = item.split(":", 2)
            if len(parts) == 1:
                client_id, token, scope_str = f"client-{idx}", parts[0].strip(), "*"
            elif len(parts) == 2:
                client_id = parts[0].strip()
                token = parts[1].strip()
                scope_str = "*"
            else:
                client_id = parts[0].strip()
                token = parts[1].strip()
                scope_str = parts[2].strip()
                if not scope_str:
                    raise ValueError(
                        f"MCP_UNIFI_AUTH_TOKENS entry {idx}: three-part form "
                        f"'client_id:token:scopes' has an empty scope list; "
                        f"use the two-part form 'client_id:token' for "
                        f"wildcard access."
                    )
            if not token:
                raise ValueError(f"MCP_UNIFI_AUTH_TOKENS entry {idx} is missing a token value")
            if not client_id:
                raise ValueError(f"MCP_UNIFI_AUTH_TOKENS entry {idx} has an empty client_id")
            # ``:`` and ``|`` are the parser's structural delimiters. A token
            # containing either would be silently reinterpreted (colon → treated
            # as ``token:scope`` splitting the wrong way; pipe → parsed as
            # a module boundary). ``openssl rand -hex 32`` produces hex-only
            # output that is safe; other generators must avoid these chars.
            if ":" in token or "|" in token:
                raise ValueError(
                    f"MCP_UNIFI_AUTH_TOKENS entry {idx}: token value contains a "
                    f"reserved delimiter (':' or '|'). Use `openssl rand -hex 32` "
                    f"or another hex-only generator."
                )
            if client_id in seen_client_ids:
                raise ValueError(
                    f"MCP_UNIFI_AUTH_TOKENS entry {idx} reuses client_id={client_id!r}"
                )
            if token in out:
                raise ValueError(
                    f"MCP_UNIFI_AUTH_TOKENS entry {idx} reuses a token already "
                    f"assigned to client_id={out[token]['client_id']!r}"
                )
            allowed = {m.strip() for m in scope_str.split("|") if m.strip()}
            if "*" in allowed:
                allowed = {"*"}
            else:
                # Fail closed on unknown scope names. A typo like
                # ``networks,protect`` would otherwise silently produce a
                # client that matches no tool (empty intersection), which
                # both hides misconfig from the operator and can lock a
                # client out of tools they were supposed to reach.
                unknown = allowed - _KNOWN_MODULE_SCOPES
                if unknown:
                    raise ValueError(
                        f"MCP_UNIFI_AUTH_TOKENS entry {idx}: unknown "
                        f"module scope(s) {sorted(unknown)!r}. Known: "
                        f"{sorted(_KNOWN_MODULE_SCOPES)!r} or '*'."
                    )
            out[token] = {"client_id": client_id, "allowed_modules": allowed}
            seen_client_ids.add(client_id)
        return out

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
                        access_host=self.unifi_access_host,
                        access_api_key=(
                            SecretStr(self.unifi_access_api_key)
                            if self.unifi_access_api_key
                            else None
                        ),
                        access_port=self.unifi_access_port,
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
                        access_host=self.unifi_access_host or "stub",
                        access_api_key=SecretStr(self.unifi_access_api_key or "stub"),
                        access_port=self.unifi_access_port,
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
                    "access_host": c.access_host,
                    "access_port": c.access_port,
                    "access_api_key_set": bool(
                        c.access_api_key and c.access_api_key.get_secret_value()
                    ),
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
            "auth_required": self.auth_required,
            "auth_client_ids": sorted(meta["client_id"] for meta in self.auth_token_map.values()),
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
