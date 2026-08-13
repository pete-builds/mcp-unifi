"""Device tools: list, restart, locate, set_port_state, radio tuning, rename.

Device records carry credentials, which is not obvious from the field names
and was not covered by the 0.19.2 sweep: ``x_authkey`` is the device's
management/inform key and ``x_vwirekey`` is the wireless-mesh uplink key.
Neither matched any entry in ``SENSITIVE_KEY_PATTERNS``, so this module was
swept and (wrongly) cleared — and wrapping ``list_devices`` in ``redact``
without first adding the patterns would have been a no-op that looked like a
fix. Both halves landed together in 0.19.3; see :mod:`mcp_unifi.redaction`.

Every path here that emits a controller-derived device record now redacts:
``list_devices`` (raw records), ``get_device_radios`` (a projection, which is
a guarantee only until someone adds a field to it), ``set_port_state`` (the
real backend returns the device record the PUT echoed back), and the
``before``/``after`` ``radio_table`` entries the ``set_radio_*`` tools show.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules._params import (
    BoundedName,
)
from mcp_unifi.modules.network._common import format_json, make_err
from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.backends import Backend
    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry
    from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.network.devices")

#: Friendly band name -> UniFi radio identifier. The reverse mapping feeds
#: ``get_device_radios`` so callers never need to know "na" means 5GHz.
_RADIO_BY_BAND: dict[str, str] = {"2g": "ng", "5g": "na", "6g": "6e"}
_BAND_BY_RADIO: dict[str, str] = {v: k for k, v in _RADIO_BY_BAND.items()}

_TX_POWER_MODES: frozenset[str] = frozenset({"auto", "high", "medium", "low", "custom"})
_CHANNEL_WIDTHS: frozenset[int] = frozenset({20, 40, 80, 160, 240, 320})


def _resolve_radio(band: str) -> str | None:
    """Map ``"2g"/"5g"/"6g"`` (or raw ``"ng"/"na"/"6e"``) to a radio id."""
    key = band.strip().lower()
    if key in _RADIO_BY_BAND:
        return _RADIO_BY_BAND[key]
    if key in _BAND_BY_RADIO:
        return key
    return None


def _merge_radio_patch(
    radio_table: list[Any], radio: str, patch: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]] | None:
    """Read-modify-write helper for ``radio_table``.

    UniFi's device PUT replaces array fields wholesale, so the new table must
    carry every existing entry untouched except the targeted radio, which gets
    ``patch`` merged in. Returns ``(new_table, before_entry, after_entry)``,
    or ``None`` when the device has no entry for ``radio``.
    """
    new_table: list[dict[str, Any]] = []
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    for raw in radio_table:
        if not isinstance(raw, dict):
            continue
        entry = dict(raw)
        if entry.get("radio") == radio:
            before = dict(entry)
            entry.update(patch)
            after = entry
        new_table.append(entry)
    if before is None or after is None:
        return None
    return new_table, before, after


def _project_radio_view(
    device_mac: str, device: dict[str, Any], radio_table: list[Any]
) -> dict[str, Any]:
    """Build the ``get_device_radios`` response from a device record.

    Split out of the tool body so the "the projection keeps secrets out"
    claim is testable: a test can monkeypatch this to a passthrough, which is
    what an innocent "surface one more field" edit amounts to, and assert the
    response still comes back redacted. The redaction has to hold on its own,
    not because this allowlist happens not to include a key today.
    """
    radios: list[dict[str, Any]] = []
    for raw in radio_table:
        if not isinstance(raw, dict):
            continue
        radio_id = raw.get("radio")
        radios.append(
            {
                "radio": radio_id,
                "band": _BAND_BY_RADIO.get(str(radio_id), "unknown"),
                "channel": raw.get("channel", "auto"),
                "ht": raw.get("ht"),
                "tx_power_mode": raw.get("tx_power_mode") or "auto",
                "tx_power": raw.get("tx_power"),
                "min_rssi_enabled": raw.get("min_rssi_enabled", False),
                "min_rssi": raw.get("min_rssi"),
                "min_txpower": raw.get("min_txpower"),
                "max_txpower": raw.get("max_txpower"),
            }
        )
    return {
        "mac": device_mac,
        "name": device.get("name"),
        "model": device.get("model"),
        "type": device.get("type"),
        "state": device.get("state"),
        "radios": radios,
    }


async def _fetch_device(backend: Backend, device_mac: str) -> tuple[UniFiRecord, str] | str:
    """Resolve a device record + its ``_id`` by MAC, or an error message."""
    device = await backend.get_device_by_mac(device_mac)
    if device is None:
        return f"device {device_mac} not found"
    device_id = device.get("_id")
    if not isinstance(device_id, str) or not device_id:
        return f"device {device_mac} has no _id"
    return device, device_id


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_devices", mutates=False)
    async def list_devices(controller: str = "default") -> str:
        """List every UniFi device adopted by this controller.

        Side effects: None (read-only).

        Returns one record per device (gateway, AP, switch) with ``_id``,
        ``mac``, ``type``, ``model``, ``name``, ``ip``, ``version``,
        ``state``, ``uptime``, ``num_sta``, and ``satisfaction``.

        Example: list_devices(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            # Device records carry x_authkey / x_vwirekey. See the module
            # docstring: the patterns had to be added before this wrapper
            # meant anything.
            return format_json(redact(await backend.list_devices()))
        except UniFiError as exc:
            logger.exception("list_devices failed")
            return err(str(exc))

    @mcp.tool()
    @audited("restart_device", mutates=True)
    async def restart_device(
        mac: str,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Restart an adopted UniFi device (gateway, AP, or switch).

        Side effects:
        - Issues a soft reboot. The device is unreachable for ~60 seconds.
        - Wireless clients on a restarted AP will be disconnected and must
          re-associate.
        - Restarting a gateway interrupts WAN/LAN traffic for the duration
          of the reboot.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: restart_device(mac="aa:bb:cc:00:00:01")

        Args:
            mac: Device MAC address (from ``list_devices``).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_apply": {"action": "restart", "mac": mac},
                    "summary": f"Would restart device {mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            ok = await backend.restart_device(mac)
            if not ok:
                return err(f"device {mac} not found")
            return format_json({"restarted": True, "mac": mac})
        except UniFiError as exc:
            logger.exception("restart_device failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    # Classified mutating: no configuration changes, but the device's status LED
    # physically starts flashing and stays that way until something turns it off.
    # A control that let an agent change what the hardware is doing in the room
    # while calling itself read-only would be misnamed.
    @audited("locate_device", mutates=True)
    async def locate_device(
        mac: str,
        on: bool = True,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Toggle the LED locate beacon on a device.

        Side effects:
        - The physical device flashes its status LED until ``on=False`` is
          sent (or it reboots). Helpful for finding which physical AP or
          switch maps to a controller record.
        - No traffic impact.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: locate_device(mac="aa:bb:cc:00:00:01", on=True)

        Args:
            mac: Device MAC address (from ``list_devices``).
            on: ``True`` (default) starts the flash; ``False`` stops it.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if dry_run:
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_apply": {"action": "locate", "mac": mac, "on": on},
                    "summary": f"Would set locate beacon on {mac} to {on}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            ok = await backend.locate_device(mac, on)
            if not ok:
                return err(f"device {mac} not found")
            return format_json({"locating": on, "mac": mac})
        except UniFiError as exc:
            logger.exception("locate_device failed", extra={"mac": mac})
            return err(str(exc))

    @mcp.tool()
    @audited("set_port_state", mutates=True)
    async def set_port_state(
        device_mac: str,
        port_idx: int,
        enable: bool | None = None,
        poe_mode: str = "",
        portconf_id: str = "",
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Override settings on a single switch port.

        Side effects:
        - Modifies one port's ``enable``, ``poe_mode``, and/or
          ``portconf_id`` on the named switch without touching the others.
        - Disabling a port immediately drops the link; powered devices on
          that port (PoE cameras, APs) will go offline.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: set_port_state(device_mac="aa:bb:cc:00:00:01", port_idx=5, enable=True, poe_mode="auto")

        Args:
            device_mac: Switch MAC address (from ``list_devices``).
            port_idx: 1-based port index.
            enable: ``True`` to bring the port up, ``False`` to disable.
                ``None`` (default) leaves it unchanged.
            poe_mode: ``"auto"``, ``"passive24v"``, ``"passthrough"``,
                ``"off"``, or empty to leave unchanged.
            portconf_id: ``_id`` of a port profile to apply, or empty to
                leave unchanged.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if enable is None and not poe_mode and not portconf_id:
            return err("set_port_state requires at least one of enable, poe_mode, portconf_id")
        if dry_run:
            override: dict[str, object] = {"port_idx": port_idx}
            if enable is not None:
                override["enable"] = enable
            if poe_mode:
                override["poe_mode"] = poe_mode
            if portconf_id:
                override["portconf_id"] = portconf_id
            return format_json(
                {
                    "dry_run": True,
                    "controller": controller,
                    "would_apply": {
                        "action": "set_port_state",
                        "device_mac": device_mac,
                        "override": override,
                    },
                    "summary": f"Would update port {port_idx} on {device_mac}",
                }
            )
        try:
            backend = resolve_backend(registry, controller)
            updated = await backend.set_port_state(
                device_mac,
                port_idx,
                enable=enable,
                poe_mode=poe_mode or None,
                portconf_id=portconf_id or None,
            )
            if updated is None:
                return err(f"device {device_mac} or port {port_idx} not found")
            # The real backend returns the device record the PUT echoed back,
            # not just the port. Credential fields ride along with it.
            return format_json(redact(updated))
        except UniFiError as exc:
            logger.exception(
                "set_port_state failed",
                extra={"mac": device_mac, "port_idx": port_idx},
            )
            return err(str(exc))

    @mcp.tool()
    @audited("get_device_radios", mutates=False)
    async def get_device_radios(device_mac: str, controller: str = "default") -> str:
        """Show per-radio RF settings for an access point.

        Side effects: None (read-only). Use this before any
        ``set_radio_*`` call to see the current values you are about to
        change.

        Returns the device identity plus one record per radio with
        ``radio`` (UniFi id: ``ng``=2.4GHz, ``na``=5GHz, ``6e``=6GHz), the
        friendly ``band``, ``channel``, ``ht`` (channel width MHz),
        ``tx_power_mode`` (``auto`` when unset), ``tx_power``,
        ``min_rssi_enabled``, ``min_rssi``, and the hardware
        ``min_txpower``/``max_txpower`` bounds.

        Example: get_device_radios(device_mac="aa:bb:cc:00:00:02")

        Args:
            device_mac: AP MAC address (from ``list_devices``).
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        try:
            backend = resolve_backend(registry, controller)
            fetched = await _fetch_device(backend, device_mac)
            if isinstance(fetched, str):
                return err(fetched)
            device, _ = fetched
            radio_table = device.get("radio_table")
            if not isinstance(radio_table, list) or not radio_table:
                return err(f"device {device_mac} has no radios (not an access point?)")
            # Redact after projecting, not instead of it. The projection is an
            # allowlist, and an allowlist that grows later is a leak that ships
            # quietly.
            return format_json(redact(_project_radio_view(device_mac, device, radio_table)))
        except UniFiError as exc:
            logger.exception("get_device_radios failed", extra={"mac": device_mac})
            return err(str(exc))

    async def _apply_radio_patch(
        action: str,
        device_mac: str,
        band: str,
        patch: dict[str, Any],
        controller: str,
        dry_run: bool,
        extra_validate: bool = True,
    ) -> str:
        """Shared read-modify-write body for the three set_radio_* tools.

        Fetches the live device record, merges ``patch`` into the targeted
        radio's ``radio_table`` entry (all other entries and fields preserved
        byte-for-byte), and PUTs the full table back. ``dry_run`` stops after
        the merge and returns the before/after diff without writing.
        """
        radio = _resolve_radio(band)
        if radio is None:
            return err(f"unknown band {band!r}: use 2g, 5g, or 6g")
        try:
            backend = resolve_backend(registry, controller)
            fetched = await _fetch_device(backend, device_mac)
            if isinstance(fetched, str):
                return err(fetched)
            device, device_id = fetched
            radio_table = device.get("radio_table")
            if not isinstance(radio_table, list) or not radio_table:
                return err(f"device {device_mac} has no radios (not an access point?)")
            merged = _merge_radio_patch(radio_table, radio, patch)
            if merged is None:
                return err(f"device {device_mac} has no {radio} ({_BAND_BY_RADIO[radio]}) radio")
            new_table, before, after = merged
            if extra_validate and "tx_power" in patch:
                lo = before.get("min_txpower")
                hi = before.get("max_txpower")
                power = patch["tx_power"]
                if (
                    isinstance(lo, int)
                    and isinstance(hi, int)
                    and isinstance(power, int)
                    and not lo <= power <= hi
                ):
                    return err(
                        f"power_dbm {power} outside the radio's supported range {lo}-{hi} dBm"
                    )
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_apply": redact(
                            {
                                "action": action,
                                "device_mac": device_mac,
                                "radio": radio,
                                # radio_table entries, emitted verbatim.
                                "before": before,
                                "after": after,
                            }
                        ),
                        "summary": f"Would update {radio} radio on {device_mac}",
                    }
                )
            updated = await backend.update_device(device_id, {"radio_table": new_table})
            if updated is None:
                return err(f"device {device_mac} not found")
            return format_json(
                {
                    "updated": True,
                    "mac": device_mac,
                    "radio": radio,
                    "band": _BAND_BY_RADIO[radio],
                    # radio_table entries, emitted verbatim.
                    **redact({"before": before, "after": after}),
                }
            )
        except UniFiError as exc:
            logger.exception("%s failed", action, extra={"mac": device_mac, "band": band})
            return err(str(exc))

    @mcp.tool()
    @audited("set_radio_tx_power", mutates=True)
    async def set_radio_tx_power(
        device_mac: str,
        band: str,
        mode: str,
        power_dbm: int = 0,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set the transmit power mode of one radio on an access point.

        Side effects:
        - Changes the AP's RF footprint. Lowering TX power shrinks coverage;
          clients at the cell edge may roam to another AP or drop to a lower
          PHY rate. The radio applies the change within seconds (brief
          client re-association possible).
        - Only the targeted radio changes; the device's other radios and
          settings are read first and written back unchanged.
        - Mutates controller state. Use dry_run=True to preview the change
          (including the current value) without applying.

        Read first: call ``get_device_radios`` to see the current mode and
        the radio's supported dBm range before changing it.

        Example: set_radio_tx_power(device_mac="aa:bb:cc:00:00:02", band="5g", mode="medium")

        Args:
            device_mac: AP MAC address (from ``list_devices``).
            band: ``"2g"``, ``"5g"``, or ``"6g"`` (raw UniFi ids ``ng``,
                ``na``, ``6e`` also accepted).
            mode: ``"auto"``, ``"high"``, ``"medium"``, ``"low"``, or
                ``"custom"`` (requires ``power_dbm``).
            power_dbm: Exact transmit power in dBm, only used with
                ``mode="custom"``. Validated against the radio's
                ``min_txpower``/``max_txpower`` bounds.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        mode_key = mode.strip().lower()
        if mode_key not in _TX_POWER_MODES:
            return err(f"invalid mode {mode!r}: use auto, high, medium, low, or custom")
        patch: dict[str, Any] = {"tx_power_mode": mode_key}
        if mode_key == "custom":
            if power_dbm == 0:
                return err("mode='custom' requires power_dbm (exact dBm value)")
            patch["tx_power"] = power_dbm
        return await _apply_radio_patch(
            "set_radio_tx_power", device_mac, band, patch, controller, dry_run
        )

    @mcp.tool()
    @audited("set_radio_min_rssi", mutates=True)
    async def set_radio_min_rssi(
        device_mac: str,
        band: str,
        enabled: bool,
        rssi_dbm: int = 0,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Enable, tune, or disable minimum RSSI on one radio of an AP.

        Side effects:
        - With min-RSSI enabled, the AP kicks clients whose signal drops
          below the threshold, forcing them to roam to a closer AP. A
          threshold set too aggressive (e.g. -60) causes disconnect loops
          for legitimately distant clients.
        - Only the targeted radio changes; everything else on the device is
          read first and written back unchanged.
        - Mutates controller state. Use dry_run=True to preview the change
          (including the current value) without applying.

        Read first: call ``get_device_radios`` to see the current state.
        Typical sticky-client thresholds are -75 to -70 dBm.

        Example: set_radio_min_rssi(device_mac="aa:bb:cc:00:00:02", band="5g", enabled=True, rssi_dbm=-75)

        Args:
            device_mac: AP MAC address (from ``list_devices``).
            band: ``"2g"``, ``"5g"``, or ``"6g"`` (raw UniFi ids ``ng``,
                ``na``, ``6e`` also accepted).
            enabled: ``True`` enforces the threshold; ``False`` turns
                min-RSSI off for this radio.
            rssi_dbm: Threshold in dBm (negative, e.g. ``-75``). Required
                when ``enabled=True``.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        patch: dict[str, Any] = {"min_rssi_enabled": enabled}
        if enabled:
            if rssi_dbm == 0:
                return err("enabled=True requires rssi_dbm (e.g. -75)")
            if not -100 <= rssi_dbm <= -1:
                return err(f"rssi_dbm {rssi_dbm} out of range: expected -100 to -1 dBm")
            patch["min_rssi"] = rssi_dbm
        return await _apply_radio_patch(
            "set_radio_min_rssi", device_mac, band, patch, controller, dry_run
        )

    @mcp.tool()
    @audited("set_radio_channel", mutates=True)
    async def set_radio_channel(
        device_mac: str,
        band: str,
        channel: str = "",
        width_mhz: int = 0,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Set the channel and/or channel width of one radio on an AP.

        Side effects:
        - The radio retunes immediately; wireless clients on that band
          briefly disconnect and re-associate.
        - On 5GHz, DFS channels (52-144) may add a radar-scan delay before
          the radio starts serving clients.
        - Only the targeted radio changes; everything else on the device is
          read first and written back unchanged.
        - Mutates controller state. Use dry_run=True to preview the change
          (including the current value) without applying.

        Read first: call ``get_device_radios`` to see the current channel
        and width.

        Example: set_radio_channel(device_mac="aa:bb:cc:00:00:02", band="5g", channel="36", width_mhz=80)

        Args:
            device_mac: AP MAC address (from ``list_devices``).
            band: ``"2g"``, ``"5g"``, or ``"6g"`` (raw UniFi ids ``ng``,
                ``na``, ``6e`` also accepted).
            channel: ``"auto"`` or a channel number as a string (e.g.
                ``"36"``). Empty (default) leaves the channel unchanged.
            width_mhz: Channel width: 20, 40, 80, 160, 240, or 320.
                ``0`` (default) leaves the width unchanged.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        if not channel and width_mhz == 0:
            return err("set_radio_channel requires at least one of channel, width_mhz")
        patch: dict[str, Any] = {}
        if channel:
            chan_key = channel.strip().lower()
            if chan_key == "auto":
                patch["channel"] = "auto"
            elif chan_key.isdigit():
                patch["channel"] = int(chan_key)
            else:
                return err(f"invalid channel {channel!r}: use 'auto' or a number")
        if width_mhz:
            if width_mhz not in _CHANNEL_WIDTHS:
                return err(f"invalid width_mhz {width_mhz}: use one of {sorted(_CHANNEL_WIDTHS)}")
            patch["ht"] = str(width_mhz)
        return await _apply_radio_patch(
            "set_radio_channel", device_mac, band, patch, controller, dry_run
        )

    @mcp.tool()
    # Classified mutating: the change is cosmetic (display name only, no RF or
    # traffic impact) but it is still a persisted PUT to the controller's
    # device record, and it is the identifier every other tool's output and
    # every dashboard reads back. Cosmetic writes are still writes.
    @audited("rename_device", mutates=True)
    async def rename_device(
        device_mac: str,
        name: BoundedName,
        controller: str = "default",
        dry_run: bool = False,
    ) -> str:
        """Rename an adopted UniFi device (AP, switch, or gateway).

        Side effects:
        - Cosmetic only: changes the display name in the controller and in
          tool output. No RF or traffic impact, no client disconnects.
        - Mutates controller state. Use dry_run=True to preview the change
          without applying.

        Example: rename_device(device_mac="aa:bb:cc:00:00:02", name="Bedroom AP")

        Args:
            device_mac: Device MAC address (from ``list_devices``).
            name: New display name. Must be non-empty.
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
            dry_run: Preview the change without applying it. Returns the
                predicted change set.
        """
        new_name = name.strip()
        if not new_name:
            return err("name must be non-empty")
        try:
            backend = resolve_backend(registry, controller)
            fetched = await _fetch_device(backend, device_mac)
            if isinstance(fetched, str):
                return err(fetched)
            device, device_id = fetched
            before_name = device.get("name")
            if dry_run:
                return format_json(
                    {
                        "dry_run": True,
                        "controller": controller,
                        "would_apply": {
                            "action": "rename_device",
                            "device_mac": device_mac,
                            "before": {"name": before_name},
                            "after": {"name": new_name},
                        },
                        "summary": f"Would rename {device_mac} to {new_name!r}",
                    }
                )
            updated = await backend.update_device(device_id, {"name": new_name})
            if updated is None:
                return err(f"device {device_mac} not found")
            return format_json(
                {
                    "updated": True,
                    "mac": device_mac,
                    "before": {"name": before_name},
                    "after": {"name": new_name},
                }
            )
        except UniFiError as exc:
            logger.exception("rename_device failed", extra={"mac": device_mac})
            return err(str(exc))
