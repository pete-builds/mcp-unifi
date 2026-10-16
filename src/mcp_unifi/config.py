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

Every secret (``api_key``, ``access_api_key``, ``os_password``, the HTTP
bearer tokens) also accepts a file-backed form (``api_key_file`` and so on,
``UNIFI_API_KEY_FILE`` / ``MCP_UNIFI_AUTH_TOKEN_FILE`` in the environment) for
Docker and Kubernetes secret mounts. The value form keeps working; the file
form is opt-in and, per ADR 0007, carries the hardened defaults inside it: a
controller configured by ``api_key_file`` verifies TLS unless told not to.
Design credit: the ``_default_tls_policy`` validator in PR #154 by
@Taltos-ch (Taltos GmbH).
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    Field,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_unifi import tls

# Duplicated (intentionally) from dispatcher.KNOWN_MODULES to keep config a
# leaf module — importing dispatcher here would risk a circular via
# mcp_unifi.clients.*. The two must stay in sync; test_scoping.py's
# test_scope_names_match_known_modules enforces it.
_KNOWN_MODULE_SCOPES: frozenset[str] = frozenset({"network", "protect", "access"})

logger = logging.getLogger(__name__)

#: Where the deprecation schedule for the legacy configuration shape is
#: written down. Named in the startup warning so an operator reads the
#: dated path rather than a bare "deprecated".
ADR_0007 = (
    "docs/decisions/0007-hardening-is-opt-in-unless-the-hole-has-no-legitimate-configuration.md"
)


def _path_or_none(path: Path | None) -> str | None:
    """Render an optional path for the startup line."""
    return str(path) if path else None


#: ``(value field, file field)`` pairs on :class:`ControllerConfig` that
#: accept a file-backed alternative. The file wins when both are set.
_CONTROLLER_SECRET_FILES: tuple[tuple[str, str], ...] = (
    ("api_key", "api_key_file"),
    ("access_api_key", "access_api_key_file"),
    ("os_password", "os_password_file"),
)


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
    api_key: SecretStr = Field(
        description=(
            "API key. Wrapped in SecretStr; never logged. Either this or "
            "api_key_file must be set; when both are set, api_key_file wins."
        )
    )
    api_key_file: Path | None = Field(
        default=None,
        description=(
            "Path to a file whose contents are the API key (a Docker or "
            "Kubernetes secret mount). Read once at startup; a missing, empty "
            "or unreadable file fails startup. Takes precedence over api_key "
            "when both are set, and turns verify_ssl on by default (ADR 0007)."
        ),
    )
    port: int = Field(default=443, ge=1, le=65535)
    site: str = Field(default="default")
    verify_ssl: bool = Field(
        default=False,
        description=(
            "Verify the gateway's TLS certificate. False by default (ADR 0003: "
            "consoles ship a self-signed certificate for an IP), except that a "
            "controller configured with api_key_file defaults to true (ADR "
            "0007). An explicit value always wins over either default. A "
            "controller with pinned_cert verifies against that pin instead."
        ),
    )
    pinned_cert: Path | None = Field(
        default=None,
        description=(
            "Path to the console's own certificate in PEM, recorded with "
            "mcp-unifi-pin-cert. When set it is the ONLY trust anchor for this "
            "controller: the console must present exactly that certificate, "
            "hostname matching is off because the pin is the identity, and a "
            "mismatch fails every request closed. Turns verify_ssl on; setting "
            "verify_ssl: false alongside it is a contradiction and fails startup. "
            "Applies to the Network, Protect and console-session clients on this "
            "host; the Access hub is a separate host and keeps verify_ssl."
        ),
    )
    protect_api: Literal["internal", "integration"] = Field(
        default="internal",
        description=(
            "Protect API surface. 'internal' uses /proxy/protect/api (existing "
            "behavior); 'integration' uses /proxy/protect/integration/v1 for "
            "UniFi OS 5.x API keys. The Integration API exposes cameras and "
            "snapshots but not event/recording endpoints."
        ),
    )

    access_host: str = Field(
        default="",
        description="UniFi Access hub host. Empty disables the Access backend for this controller.",
    )
    access_api_key: SecretStr | None = Field(
        default=None,
        description="UniFi Access API key (separate from the Network API key).",
    )
    access_api_key_file: Path | None = Field(
        default=None,
        description="Path to a file containing the Access API key. Wins over access_api_key.",
    )
    access_port: int = Field(default=12445, ge=1, le=65535)

    # UniFi OS console-session credentials. Separate from ``api_key`` on
    # purpose: the Network API key authenticates the Network application
    # *through* the UniFi OS proxy, but does NOT authenticate UniFi OS's own
    # ``/api/*`` endpoints (verified live — those answer 401 with a valid
    # Network key). Optional; console-session tools degrade with a clear
    # "not configured" message when these are absent.
    os_username: str = Field(
        default="",
        description="UniFi OS console local-admin username. Empty disables console-session tools.",
    )
    os_password: SecretStr | None = Field(
        default=None,
        description="UniFi OS console local-admin password. Wrapped in SecretStr; never logged.",
    )
    os_password_file: Path | None = Field(
        default=None,
        description=(
            "Path to a file containing the UniFi OS console password. Wins over "
            "os_password. The username is not a secret and has no file form."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _resolve_secret_files(cls, data: Any) -> Any:
        """Resolve every ``*_file`` secret and apply the file-backed TLS default.

        Runs before field validation on purpose: the value fields keep their
        types, ``api_key`` stays required, and every consumer keeps calling
        ``api_key.get_secret_value()`` unchanged. A file that is missing,
        empty or unreadable raises here, which surfaces as a validation error
        naming the controller and the field.

        ``verify_ssl`` left unset (absent or ``None``) resolves to ``True``
        when ``api_key_file`` is set and ``False`` otherwise, so opting into
        the file-backed shape does not require opting into each of its parts.
        That is corollary 1 of ADR 0007, and the validator it adopts is
        ``_default_tls_policy`` from PR #154 by @Taltos-ch.
        """
        if not isinstance(data, dict):
            return data
        resolved: dict[str, Any] = dict(data)
        name = resolved.get("name", "?")
        for path_field in (
            *(file_field for _, file_field in _CONTROLLER_SECRET_FILES),
            "pinned_cert",
        ):
            if resolved.get(path_field) is not None:
                resolved[path_field] = Path(resolved[path_field]).expanduser()
        for value_field, file_field in _CONTROLLER_SECRET_FILES:
            path = resolved.get(file_field)
            if path is not None:
                label = f"controller '{name}' {file_field}"
                resolved[value_field] = tls.read_text_file(path, label).strip()
        if resolved.get("verify_ssl") is None:
            resolved["verify_ssl"] = (
                resolved.get("api_key_file") is not None or resolved.get("pinned_cert") is not None
            )
        return resolved

    #: The pin's DER bytes, read once at validation. Everything that needs
    #: the pin afterwards (the fingerprint on the startup line, the TLS
    #: context every client shares) derives from these bytes, so what was
    #: checked at boot is exactly what is enforced.
    _pinned_der: bytes | None = PrivateAttr(default=None)
    _pinned_context: ssl.SSLContext | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _check_pinned_cert(self) -> ControllerConfig:
        """Fail startup on a pin that cannot be loaded or that contradicts verify_ssl.

        The pin is read and parsed here rather than at first request so a
        controller never boots configured for a pin it cannot honour. A
        pinned controller with ``verify_ssl: false`` is refused outright: the
        two settings name opposite intents and picking one silently is the
        shape ADR 0003 rejects.
        """
        if self.pinned_cert is None:
            return self
        self._pinned_der = tls.load_pinned_cert(
            self.pinned_cert, f"controller '{self.name}' pinned_cert"
        )
        if not self.verify_ssl:
            raise ValueError(
                f"controller '{self.name}': pinned_cert is set but verify_ssl is false. "
                f"A pin means verify against this certificate; remove one of the two."
            )
        return self

    @property
    def tls_verify(self) -> bool | ssl.SSLContext:
        """What the HTTP clients pass as ``verify``.

        A pinned controller gets one context, built on first use from the
        bytes the validator loaded and shared by every client for this
        controller (httpx never mutates a ``verify=`` context); anything
        else gets the plain ``verify_ssl`` flag.
        """
        if self._pinned_der is None:
            return self.verify_ssl
        if self._pinned_context is None:
            self._pinned_context = tls.build_pinned_context(self._pinned_der)
        return self._pinned_context

    @property
    def pinned_cert_sha256(self) -> str | None:
        """SHA-256 of the pinned certificate, or ``None``. Public material, safe to log."""
        if self._pinned_der is None:
            return None
        return tls.fingerprint_sha256(self._pinned_der)


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
    # Read-only write gate (v0.21.0+)
    # ------------------------------------------------------------------
    readonly: bool = Field(
        default=False,
        validation_alias=AliasChoices("MCP_UNIFI_READONLY", "readonly"),
        description=(
            "If True, every tool that changes state is hidden from tools/list "
            "and refused on tools/call. Defense in depth on top of a read-only "
            "UniFi API key: the key is the authority, this makes the server "
            "unable to try. Default False so existing deployments are "
            "unaffected. Env var: MCP_UNIFI_READONLY."
        ),
    )

    # ------------------------------------------------------------------
    # Default controller (issue #124, item 5)
    # ------------------------------------------------------------------
    default_controller: str = Field(
        default="",
        validation_alias=AliasChoices("MCP_UNIFI_DEFAULT_CONTROLLER", "default_controller"),
        description=(
            "Name of the controller a tool call targets when it omits "
            "``controller`` and no controller is literally named 'default'. "
            "With exactly one controller configured it is used automatically; "
            "with several, this must name one or every call has to pass "
            "``controller=`` explicitly. Deliberately no silent 'first in the "
            "list' fallback: a forgotten argument on a multi-site deployment "
            "must not write to whichever site happens to be listed first. "
            "Env var: MCP_UNIFI_DEFAULT_CONTROLLER."
        ),
    )

    # ------------------------------------------------------------------
    # Response shaping
    # ------------------------------------------------------------------
    force_full_text_responses: bool = Field(
        default=False,
        description=(
            "If True, always return the full JSON payload as the text block, "
            "even to clients that negotiated MCP 2025-06-18 or later. The "
            "escape hatch for a client that advertises structuredContent "
            "support but does not actually read it. Costs tokens; changes no "
            "data."
        ),
    )

    # ------------------------------------------------------------------
    # Multi-controller config
    # ------------------------------------------------------------------
    controllers_file: Path | None = Field(
        default=None,
        # The documented env var is MCP_UNIFI_CONTROLLERS_FILE (README, the
        # configuration reference, the multi-site guide, server.json). The
        # field name alone bound only the bare CONTROLLERS_FILE, so the
        # documented spelling was silently dropped by ``extra="ignore"`` and a
        # multi-site deployment fell through to the legacy single-controller
        # vars, or to "real mode + no config". Reported live in #124.
        validation_alias=AliasChoices("MCP_UNIFI_CONTROLLERS_FILE", "controllers_file"),
        description=(
            "Optional YAML file describing one or more controllers. Used "
            "when running against >1 site. See ControllerConfig for fields. "
            "Env var: MCP_UNIFI_CONTROLLERS_FILE."
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
    unifi_api_key_file: Path | None = Field(
        default=None,
        description=(
            "Path to a file containing the local API key (legacy). Promoted onto "
            "api_key_file; wins over UNIFI_API_KEY when both are set. Env var: "
            "UNIFI_API_KEY_FILE."
        ),
    )
    unifi_verify_ssl: bool | None = Field(
        default=None,
        description=(
            "Legacy verify_ssl. Unset resolves per controller: false, or true "
            "when UNIFI_API_KEY_FILE is set (ADR 0007). Env var: UNIFI_VERIFY_SSL."
        ),
    )
    unifi_protect_api: Literal["internal", "integration"] = Field(default="internal")
    unifi_pinned_cert: Path | None = Field(
        default=None,
        description=(
            "Path to the console's certificate in PEM, from mcp-unifi-pin-cert "
            "(legacy). Promoted onto pinned_cert. Env var: UNIFI_PINNED_CERT."
        ),
    )

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
    unifi_access_api_key_file: Path | None = Field(
        default=None,
        description=(
            "Path to a file containing the Access API key (legacy). Promoted onto "
            "access_api_key_file. Env var: UNIFI_ACCESS_API_KEY_FILE."
        ),
    )
    unifi_access_port: int = Field(default=12445, ge=1, le=65535)

    # ------------------------------------------------------------------
    # Legacy single-controller UniFi OS console credentials (v0.18+).
    # Promoted onto the ``default`` controller's ``os_*`` fields. Optional:
    # without them the console-session tools return a clear configuration
    # error, and the two-layer health verdict still works (it needs only the
    # Network API key plus unauthenticated console endpoints).
    # ------------------------------------------------------------------
    unifi_os_username: str = Field(
        default="",
        description="UniFi OS console username (legacy). Promoted onto os_username.",
    )
    unifi_os_password: str = Field(
        default="",
        description="UniFi OS console password (legacy). Promoted onto os_password.",
    )
    unifi_os_password_file: Path | None = Field(
        default=None,
        description=(
            "Path to a file containing the UniFi OS console password (legacy). "
            "Promoted onto os_password_file. Env var: UNIFI_OS_PASSWORD_FILE."
        ),
    )

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
    auth_token_file: Path | None = Field(
        default=None,
        validation_alias=AliasChoices("MCP_UNIFI_AUTH_TOKEN_FILE", "auth_token_file"),
        description=(
            "Path to a file holding bearer tokens for HTTP transport (a Docker "
            "or Kubernetes secret mount). The file holds either one bare token, "
            "named by MCP_UNIFI_CLIENT_ID, or the same comma-separated grammar "
            "as MCP_UNIFI_AUTH_TOKENS. Its entries are added alongside whatever "
            "MCP_UNIFI_AUTH_TOKENS defines; the two combine. Read once at "
            "startup; a missing, empty or unreadable file fails startup. "
            "Ignored on stdio. Env var: MCP_UNIFI_AUTH_TOKEN_FILE."
        ),
    )
    client_id: str = Field(
        default="",
        validation_alias=AliasChoices("MCP_UNIFI_CLIENT_ID", "client_id"),
        description=(
            "Client name for a bare token in MCP_UNIFI_AUTH_TOKEN_FILE, exactly "
            "as the inline 'client_id:token' form names one. Full module "
            "access; a scoped file-backed client writes the "
            "'client_id:token:modules' form into the file instead. Requires "
            "MCP_UNIFI_AUTH_TOKEN_FILE. Env var: MCP_UNIFI_CLIENT_ID."
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

    def _auth_file_fragment(self) -> str:
        """Return the CSV fragment ``auth_token_file`` contributes, or ``""``.

        A file with no ``:`` and no ``,`` is one bare token, named by
        ``client_id`` when that is set. Anything else is parsed with the
        ``MCP_UNIFI_AUTH_TOKENS`` grammar as-is, and ``client_id`` must then
        be empty: the file already carries its own names. The delimiter
        check on a bare token names the file, not an entry index, so the
        error points at the right variable.
        """
        if self.auth_token_file is None:
            if self.client_id.strip():
                raise ValueError(
                    "MCP_UNIFI_CLIENT_ID is set but MCP_UNIFI_AUTH_TOKEN_FILE is not; "
                    "the client name only applies to a file-backed token."
                )
            return ""
        contents = tls.read_text_file(self.auth_token_file, "MCP_UNIFI_AUTH_TOKEN_FILE").strip()
        client_id = self.client_id.strip()
        if ":" in contents or "," in contents:
            if client_id:
                raise ValueError(
                    "MCP_UNIFI_CLIENT_ID names a bare token, but MCP_UNIFI_AUTH_TOKEN_FILE "
                    "already carries client names (it contains ':' or ','). Set one or the "
                    "other."
                )
            return contents
        if "|" in contents:
            raise ValueError(
                "MCP_UNIFI_AUTH_TOKEN_FILE: token value contains a reserved delimiter "
                "('|'). Use `openssl rand -hex 32` or another hex-only generator."
            )
        if not client_id:
            return contents
        if ":" in client_id or "," in client_id or "|" in client_id:
            raise ValueError("MCP_UNIFI_CLIENT_ID must not contain ':', ',' or '|'.")
        return f"{client_id}:{contents}"

    def _auth_entries(self) -> dict[str, dict[str, Any]]:
        """Parse ``auth_tokens`` plus ``auth_token_file`` once.

        Internal helper for the two properties above. The file fragment is
        appended after the inline entries, so inline bare tokens keep the
        ``client-N`` names they have always had.
        """
        raw = ",".join(
            part for part in (self.auth_tokens.strip(), self._auth_file_fragment()) if part
        )
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
        # UNIFI_VERIFY_SSL left unset is passed through as "unset" so the
        # controller's own default (ADR 0003, or ADR 0007 with a key file)
        # applies; an explicit value is forwarded as given.
        legacy_tls: dict[str, Any] = (
            {} if self.unifi_verify_ssl is None else {"verify_ssl": self.unifi_verify_ssl}
        )
        if not self.controllers:
            if self.controllers_file is not None:
                self.controllers = _load_controllers_from_yaml(self.controllers_file)
            elif self.unifi_host and (self.unifi_api_key or self.unifi_api_key_file is not None):
                self.controllers = [
                    ControllerConfig(
                        name="default",
                        host=self.unifi_host,
                        api_key=SecretStr(self.unifi_api_key),
                        api_key_file=self.unifi_api_key_file,
                        pinned_cert=self.unifi_pinned_cert,
                        port=self.unifi_port,
                        site=self.unifi_site,
                        protect_api=self.unifi_protect_api,
                        access_host=self.unifi_access_host,
                        access_api_key=(
                            SecretStr(self.unifi_access_api_key)
                            if self.unifi_access_api_key
                            else None
                        ),
                        access_api_key_file=self.unifi_access_api_key_file,
                        access_port=self.unifi_access_port,
                        os_username=self.unifi_os_username,
                        os_password=(
                            SecretStr(self.unifi_os_password) if self.unifi_os_password else None
                        ),
                        os_password_file=self.unifi_os_password_file,
                        **legacy_tls,
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
                        protect_api=self.unifi_protect_api,
                        access_host=self.unifi_access_host or "stub",
                        access_api_key=SecretStr(self.unifi_access_api_key or "stub"),
                        access_port=self.unifi_access_port,
                        **legacy_tls,
                    )
                ]
            else:
                raise ValueError(
                    "Real mode requires controller config. Set either "
                    "MCP_UNIFI_CONTROLLERS_FILE (YAML) or the legacy "
                    "UNIFI_HOST + UNIFI_API_KEY (or UNIFI_API_KEY_FILE) env vars. "
                    "Set STUB_MODE=true to run with mock data instead."
                )

        # Uniqueness check (applies to all sources, including caller-provided lists).
        names = [c.name for c in self.controllers]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"Duplicate controller names: {duplicates}")

        if self.default_controller and self.default_controller not in names:
            raise ValueError(
                f"MCP_UNIFI_DEFAULT_CONTROLLER names '{self.default_controller}', which is "
                f"not a configured controller. Configured: {sorted(names)}"
            )

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
            "readonly": self.readonly,
            "controllers_file": _path_or_none(self.controllers_file),
            "default_controller": self.default_controller or None,
            "controllers": [
                {
                    "name": c.name,
                    "host": c.host,
                    "port": c.port,
                    "site": c.site,
                    "verify_ssl": c.verify_ssl,
                    "pinned_cert": _path_or_none(c.pinned_cert),
                    "pinned_cert_sha256": c.pinned_cert_sha256,
                    "protect_api": c.protect_api,
                    "api_key_set": bool(c.api_key.get_secret_value()),
                    "api_key_file": _path_or_none(c.api_key_file),
                    "os_username_set": bool(c.os_username),
                    "os_password_set": bool(c.os_password and c.os_password.get_secret_value()),
                    "os_password_file": _path_or_none(c.os_password_file),
                    "access_host": c.access_host,
                    "access_port": c.access_port,
                    "access_api_key_set": bool(
                        c.access_api_key and c.access_api_key.get_secret_value()
                    ),
                    "access_api_key_file": _path_or_none(c.access_api_key_file),
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
            "auth_token_file": _path_or_none(self.auth_token_file),
            "auth_client_ids": sorted(meta["client_id"] for meta in self.auth_token_map.values()),
        }


def log_legacy_shape_warnings(settings: Settings) -> None:
    """Warn once per boot for every controller still on the legacy shape.

    The legacy shape is an API key supplied as a value (environment variable
    or inline YAML) rather than ``api_key_file``, or ``verify_ssl`` off. Both
    keep working. This is the one-time startup warning ADR 0003 names as its
    unbuilt interim step, and step 1 of ADR 0007's reversal path: opt-in,
    then warn on every boot for a release, then flip at a major. Without the
    warning the path is a promise; with it, the schedule is running.

    Silent in stub mode, which talks to no gateway. One line per controller,
    naming it, plus one line when HTTP bearer tokens come from the
    environment.
    """
    if settings.stub_mode:
        return
    for c in settings.controllers:
        legacy: list[str] = []
        if c.api_key_file is None:
            legacy.append("API key supplied as a value (file-backed form: api_key_file)")
        if not c.verify_ssl:
            legacy.append(
                "TLS verification off (pin the console certificate with "
                f"{tls.PIN_COMMAND} and set pinned_cert, or set verify_ssl: true)"
            )
        if legacy:
            logger.warning(
                "controller '%s' runs the legacy configuration shape: %s. Supported "
                "through 0.x; it becomes mandatory only at a major release. See %s.",
                c.name,
                "; ".join(legacy),
                ADR_0007,
            )
    if settings.mcp_transport != "stdio" and settings.auth_tokens.strip():
        logger.warning(
            "HTTP bearer tokens supplied via MCP_UNIFI_AUTH_TOKENS (a value) is the legacy "
            "configuration shape; MCP_UNIFI_AUTH_TOKEN_FILE is the file-backed form. "
            "Supported through 0.x; it becomes mandatory only at a major release. See %s.",
            ADR_0007,
        )


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
        - name: datacenter
          host: unifi.example.com
          api_key_file: /run/secrets/unifi_api_key   # verify_ssl defaults to true here
        - name: home
          host: 192.168.1.1
          api_key: ghi789
          pinned_cert: /etc/mcp-unifi/pins/home.pem  # from mcp-unifi-pin-cert

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
