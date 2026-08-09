"""Guest portal (captive portal) tools, backed by the ``guest_access`` site setting.

THE THING EVERYONE GETS WRONG
-----------------------------
The guest captive portal is **not a WLAN field.** It is a *site setting*.

Flipping a WLAN from "Hotspot" to "Standard" sets ``is_guest: false`` on the
WLAN record and does **not** disable the portal — the click-through "Connect"
page keeps appearing, because it is driven by ``portal_enabled`` under the
site-level ``guest_access`` key, scoped to the guest network. Chasing this
through the WLAN record cost real debugging time on 2026-08-08, which is why
it is written down here rather than in a commit message.

``auth`` and ``portal_enabled`` are independent axes:

* ``portal_enabled: true`` + ``auth: "none"`` → the bare "click Connect" page,
  no credential required. This is the common annoyance.
* ``portal_enabled: false`` → no interstitial at all; clients associate and go.

WRITE PATH — endpoint discovery, verified live 2026-08-08
---------------------------------------------------------
Rejected by the controller::

    PUT /api/s/<site>/rest/setting/<_id>   (full object)
        -> {"rc": "error", "msg": "api.err.Invalid"}

Accepted (all returned ``{"rc": "ok"}`` and took effect)::

    POST /api/s/<site>/set/setting/guest_access        (full object, _id + site_id stripped)  <-- used here
    POST /api/s/<site>/set/setting/guest_access/<_id>  (full object)
    POST /api/s/<site>/set/setting/guest_access        {"portal_enabled": false}  (minimal)

We use the **read-modify-write full object** form, with ``_id`` and ``site_id``
stripped. The minimal-body form was observed to work, but it was not proven
non-destructive for untouched fields in the general case, and clobbering
someone's guest-access settings is unrecoverable without a backup. A verified
key-level and value-level diff of the full-object write showed exactly one
field changed (``portal_enabled: true -> false``), no keys lost, and one benign
default materialised (``redirect_url``).

Every write returns a before/after diff of what *actually* changed, so
collateral edits are visible to the caller rather than silent. That diff is
what made the live change safe to confirm.

CONFIRM RE-READS
----------------
Because the write is full-object and preview tokens live five minutes, the
record is re-read inside the confirm step rather than reused from the preview.
Writing back the preview-time snapshot would restore every stale field and
silently revert anything another admin changed in the meantime. This is the
only confirmable action with that exposure: the rest carry an id, not a whole
record.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.modules.network._pending import build_preview_envelope, get_pending_actions

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry
    from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.network.guest_portal")

#: Site-settings key holding the guest/captive-portal configuration.
SETTING_KEY = "guest_access"

#: Fields the controller assigns and rejects on write. Stripped before POST.
_SERVER_OWNED = ("_id", "site_id")

#: Authentication modes the portal supports. ``"none"`` is the click-through
#: page with no credential; the others gate access behind a check.
ALLOWED_AUTH = frozenset({"none", "hotspot", "custom"})

#: The subset surfaced by ``get_guest_portal``. The raw record carries ~37
#: fields, most of them customisation strings (fonts, colours, logos) that
#: bury the operationally interesting ones.
_PROJECTED = (
    "portal_enabled",
    "auth",
    "expire",
    "expire_number",
    "expire_unit",
    "portal_customized",
    "redirect_enabled",
    "redirect_url",
    "restricted_subnet_1",
    "restricted_subnet_2",
    "payment_enabled",
    "voucher_enabled",
    "facebook_wifi_enabled",
)


def _project(record: UniFiRecord) -> dict[str, Any]:
    """Return the operationally interesting subset of the settings record."""
    return {k: record.get(k) for k in _PROJECTED if k in record}


def _strip_server_owned(record: UniFiRecord) -> dict[str, Any]:
    """Copy ``record`` without the controller-assigned identity fields.

    ``PUT /rest/setting/<_id>`` with these present returns ``api.err.Invalid``;
    the accepted ``POST /set/setting/<key>`` form wants them gone.
    """
    return {k: v for k, v in record.items() if k not in _SERVER_OWNED}


def _diff(before: UniFiRecord, after: UniFiRecord) -> dict[str, Any]:
    """Key-level and value-level diff between two settings records.

    Surfaces three things a caller needs to trust a settings write: which
    values changed, which keys the controller dropped (data loss), and which
    keys it materialised (usually benign defaults).
    """
    changed = {
        key: {"before": before.get(key), "after": after.get(key)}
        for key in sorted(set(before) & set(after))
        if before.get(key) != after.get(key)
    }
    return {
        "changed": changed,
        "keys_lost": sorted(set(before) - set(after)),
        "keys_added": sorted(set(after) - set(before)),
    }


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("get_guest_portal")
    async def get_guest_portal(controller: str = "default") -> str:
        """Show the guest captive-portal configuration for the site.

        The portal is a **site setting** (``guest_access``), not a property of
        any WLAN. Turning a WLAN off "Hotspot" mode does not disable the
        portal — check and change it here.

        Side effects: None (read-only).

        Returns ``portal_enabled`` (the click-through page toggle), ``auth``
        (``"none"`` means a bare Connect button with no credential),
        ``expire``/``expire_number``/``expire_unit`` (how long an authorised
        guest session lasts before the page reappears), ``redirect_enabled``
        and ``redirect_url``, the ``restricted_subnet_*`` entries, and the
        payment/voucher/Facebook toggles. ``portal_enabled`` and ``auth`` are
        independent axes.

        Example: get_guest_portal(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            record = await backend.get_setting(SETTING_KEY)
        except UniFiError as exc:
            logger.exception("get_guest_portal failed")
            return err(str(exc))
        if not record:
            return err(
                "The controller returned no 'guest_access' setting record. "
                "This site may have no guest network configured."
            )
        return format_json(_project(record))

    @mcp.tool()
    @audited("set_guest_portal")
    async def set_guest_portal(
        portal_enabled: bool | None = None,
        auth: str | None = None,
        expire_minutes: int | None = None,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Change the guest captive-portal configuration.

        Set ``portal_enabled=False`` to remove the click-through "Connect"
        page that guests see on every reconnection.

        Side effects:
        - Read-modify-writes the site's ``guest_access`` setting. Only the
          fields you pass are altered; the rest of the record is written back
          unchanged (full-object write, never a partial body).
        - **Does not weaken network isolation** when isolation is enforced by
          firewall rules or a guest VLAN. The portal is an interstitial
          authorisation page, not a security boundary. Disabling it changes
          who sees a login screen, not who can reach what.
        - Guests already authorised keep their existing session until it
          expires; the change affects subsequent authorisations.
        - Returns a before/after diff so any collateral edit by the controller
          is visible rather than silent.
        - Mutates controller state. ``dry_run=True`` previews; otherwise this
          returns a confirmation token that must be passed to
          ``confirm_destructive_action`` to commit.

        Idempotent: applying the same values twice leaves the same state.

        Example: set_guest_portal(portal_enabled=False)

        Args:
            portal_enabled: ``False`` disables the captive portal entirely.
                ``True`` re-enables it. ``None`` (default) leaves it alone.
            auth: Portal authentication mode: ``"none"`` (click-through, no
                credential), ``"hotspot"``, or ``"custom"``. ``None``
                (default) leaves it alone. Independent of ``portal_enabled``.
            expire_minutes: How long an authorised guest session lasts before
                the portal reappears, in minutes (e.g. ``480`` for 8 hours).
                ``None`` (default) leaves it alone.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted patch and no confirmation token.
        """
        patch: dict[str, Any] = {}
        if portal_enabled is not None:
            patch["portal_enabled"] = portal_enabled
        if auth is not None:
            if auth not in ALLOWED_AUTH:
                return err(f"auth {auth!r} not allowed; expected one of {sorted(ALLOWED_AUTH)}")
            patch["auth"] = auth
        if expire_minutes is not None:
            if expire_minutes < 1:
                return err("expire_minutes must be a positive number of minutes")
            patch["expire"] = expire_minutes
            patch["expire_number"] = expire_minutes
            patch["expire_unit"] = 1
        if not patch:
            return err(
                "No changes requested. Pass at least one of portal_enabled, "
                "auth, or expire_minutes."
            )

        try:
            backend = resolve_backend(registry, controller)
            current = await backend.get_setting(SETTING_KEY)
        except UniFiError as exc:
            logger.exception("set_guest_portal read failed")
            return err(str(exc))
        if not current:
            return err(
                "The controller returned no 'guest_access' setting record to "
                "modify. This site may have no guest network configured."
            )

        summary = ", ".join(f"{k}={v!r}" for k, v in sorted(patch.items()))

        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_patch": {"setting_key": SETTING_KEY, "patch": patch},
                    "predicted_diff": _diff(current, {**current, **patch}),
                    "summary": f"Would set guest portal {summary}",
                }
            )

        async def _execute() -> str:
            # Re-read at confirm time rather than reusing the record captured
            # for the preview. Tokens live five minutes, and this is the only
            # confirmable action that writes the FULL object: reusing the
            # preview-time snapshot would restore every stale field and
            # silently discard whatever another admin changed in between,
            # while reporting an unrelated success. The full-object write is
            # deliberate (a partial body was never proven non-destructive for
            # untouched fields, and a settings clobber is unrecoverable
            # without a backup), so the window gets closed here instead.
            try:
                fresh = await backend.get_setting(SETTING_KEY)
            except UniFiError as exc:
                logger.exception("set_guest_portal confirm re-read failed")
                return err(str(exc))
            if not fresh:
                return err(
                    "The controller returned no 'guest_access' setting record "
                    "at confirm time. It may have been removed since the "
                    "preview was generated; nothing was written."
                )

            desired = {**_strip_server_owned(fresh), **patch}
            try:
                updated = await backend.set_setting(SETTING_KEY, desired)
            except UniFiError as exc:
                logger.exception("set_guest_portal write failed")
                return err(str(exc))
            return format_json(
                {
                    "setting_key": SETTING_KEY,
                    "applied": patch,
                    "diff": _diff(fresh, updated),
                    "current": _project(updated),
                }
            )

        pending = get_pending_actions().put(
            action="set_guest_portal",
            controller=controller,
            resource={
                "setting_key": SETTING_KEY,
                "patch": patch,
                "summary": f"Set guest portal {summary}",
            },
            executor=_execute,
        )
        return format_json(build_preview_envelope(pending))
