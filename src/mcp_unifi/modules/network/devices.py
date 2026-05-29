"""Device tools: list, restart, locate, set_port_state."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.dispatcher import resolve_backend
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.devices")


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    @mcp.tool()
    @audited("list_devices")
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
            return format_json(await backend.list_devices())
        except UniFiError as exc:
            logger.exception("list_devices failed")
            return err(str(exc))

    @mcp.tool()
    @audited("restart_device")
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
    @audited("locate_device")
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
    @audited("set_port_state")
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
            return format_json(updated)
        except UniFiError as exc:
            logger.exception(
                "set_port_state failed",
                extra={"mac": device_mac, "port_idx": port_idx},
            )
            return err(str(exc))
