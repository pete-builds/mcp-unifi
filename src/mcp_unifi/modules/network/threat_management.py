"""Threat Management (IDS/IPS) tools.

UniFi Network exposes Threat Management as the ``ips`` per-key setting
(verified on UCG-Fiber fw 5.1.12.33296). The same record holds the IPS
mode, the active rule categories, and the Honeypot subsection — the
``honeypot.py`` module reads/writes the same record from a different lens.

Endpoints used (legacy controller API behind ``/proxy/network/api``):

* ``GET /rest/setting/ips`` — current state (one record, ``key="ips"``).
* ``POST /set/setting/ips`` — partial-update; the controller merges the
  patch onto the existing record. This is the same write path the web UI
  uses and is more forgiving than a full PUT.

Surface intentionally narrow: two tools (``get_threat_management``,
``set_threat_management``). The full ``ips`` record carries 20+ fields
(DNS filtering, ad blocking, geo IP, alerting). We project the three the
operator actually cares about (``enabled``, ``mode``, ``signature_categories``)
and pass the rest through untouched on write.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.threat_management")

#: Allowed values for ``set_threat_management(mode=...)``. UniFi's ``ips_mode``
#: field takes one of these three strings.
_ALLOWED_MODES: frozenset[str] = frozenset({"off", "ids", "ips"})


def _project_get(record: dict[str, Any]) -> dict[str, Any]:
    """Return the user-facing view of an ``ips`` setting record.

    Promotes the operator-relevant fields to the top level; everything else
    lands under ``raw`` so callers can drill into advanced fields without us
    leaking the entire 1KB envelope into normal use.
    """
    mode = str(record.get("ips_mode", "off"))
    enabled = mode in {"ids", "ips"}
    return {
        "enabled": enabled,
        "mode": mode,
        "enabled_signature_categories": list(record.get("enabled_categories", []) or []),
        "enabled_networks": list(record.get("enabled_networks", []) or []),
        "endpoint_scanning": bool(record.get("endpoint_scanning", False)),
        "ad_blocking_enabled": bool(record.get("ad_blocking_enabled", False)),
        "dns_filtering": bool(record.get("dns_filtering", False)),
        "honeypot_enabled": bool(record.get("honeypot_enabled", False)),
        "_id": record.get("_id"),
    }


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("get_threat_management")
    async def get_threat_management(controller: str = "default") -> str:
        """Return current Threat Management (IDS/IPS) configuration.

        Side effects: None (read-only).

        Reads the controller's ``ips`` setting record and projects it to the
        operator view: ``enabled`` (true when mode is ``ids`` or ``ips``),
        ``mode`` (one of ``off`` / ``ids`` / ``ips``),
        ``enabled_signature_categories`` (the IDS/IPS Emerging Threats rule
        groups that are turned on), ``enabled_networks`` (network IDs the
        engine inspects), plus the adjacent booleans for endpoint scanning,
        ad blocking, DNS filtering, and honeypot.

        Example: get_threat_management(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = registry.get(controller)
            record = await backend.get_setting("ips")
        except UniFiError as exc:
            logger.exception("get_threat_management failed")
            return err(str(exc))
        return format_json(_project_get(record))

    @mcp.tool()
    @audited("set_threat_management")
    async def set_threat_management(
        enabled: bool,
        mode: str = "ids",
        signature_categories: list[str] | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Update Threat Management (IDS/IPS) configuration.

        Side effects:
        - Patches the controller's ``ips`` setting record. When
          ``enabled=False`` the mode is forced to ``off``; the controller
          then disables packet inspection on every network. When
          ``enabled=True``, ``mode`` selects detection-only (``ids``) or
          inline blocking (``ips``).
        - Untouched fields (signature categories, network bindings, ad
          blocking, DNS filtering) are preserved by the controller's merge
          semantics. Supplying ``signature_categories`` replaces the active
          list wholesale; ``None`` leaves it unchanged.
        - Mutates controller state. Use dry_run=True to preview the change.

        Example: set_threat_management(enabled=True, mode="ips")

        Args:
            enabled: ``True`` activates inspection; ``False`` sets ``mode=off``
                and overrides any ``mode`` argument.
            mode: When ``enabled=True``, one of ``"ids"`` (detection-only,
                default) or ``"ips"`` (inline blocking). Ignored when
                ``enabled=False``.
            signature_categories: Optional replacement list of UniFi
                signature-category strings (e.g. ``["emerging-malware",
                "tor", "dshield"]``). Pass ``None`` to leave the active
                categories untouched.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted patch envelope.
        """
        if not enabled:
            effective_mode = "off"
        elif mode in _ALLOWED_MODES and mode != "off":
            effective_mode = mode
        else:
            return err(
                f"mode {mode!r} not allowed; expected one of {sorted(_ALLOWED_MODES - {'off'})}"
            )

        patch: dict[str, Any] = {"ips_mode": effective_mode}
        if signature_categories is not None:
            patch["enabled_categories"] = list(signature_categories)

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_patch": {"setting_key": "ips", "patch": patch},
                    "summary": (
                        f"Would set Threat Management mode={effective_mode}"
                        + (
                            f" with {len(patch['enabled_categories'])} categories"
                            if "enabled_categories" in patch
                            else ""
                        )
                    ),
                }
            )

        try:
            backend = registry.get(controller)
            record = await backend.set_setting("ips", patch)
        except UniFiError as exc:
            logger.exception("set_threat_management failed")
            return err(str(exc))
        return format_json(_project_get(record))


__all__ = ["register"]
