"""Backend protocol unifying stub and real UniFi controllers.

Tools call methods on a ``Backend`` instance instead of branching on
``settings.stub_mode``. ``StubBackend`` wraps an in-memory ``StubState`` and
``RealBackend`` wraps the async ``UniFiClient``. Both expose the same async
surface so tool bodies have one path.

This is the seam the dispatcher uses to route tool calls to the right
controller (single-site or multi-site), and the seam Step 4 will use to wrap
audit + dry-run uniformly.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from mcp_unifi.clients.access import AccessClient
from mcp_unifi.clients.access_stubs import AccessStubState
from mcp_unifi.clients.protect import ProtectClient
from mcp_unifi.clients.protect_stubs import ProtectStubState
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiClient, UniFiError
from mcp_unifi.models import UniFiRecord


@runtime_checkable
class Backend(Protocol):
    """Async surface every tool calls into.

    Implementations: :class:`StubBackend` (in-memory) and :class:`RealBackend`
    (HTTP via ``UniFiClient``). Methods mirror the existing tool actions —
    nothing new, nothing renamed.
    """

    # ----- Devices --------------------------------------------------------
    async def list_devices(self) -> list[UniFiRecord]: ...
    async def get_device_by_mac(self, mac: str) -> UniFiRecord | None: ...
    async def update_device(self, device_id: str, patch: dict[str, Any]) -> UniFiRecord | None: ...
    async def restart_device(self, mac: str) -> bool: ...
    async def locate_device(self, mac: str, on: bool) -> bool: ...
    async def set_port_state(
        self,
        device_mac: str,
        port_idx: int,
        *,
        enable: bool | None,
        poe_mode: str | None,
        portconf_id: str | None,
    ) -> UniFiRecord | None: ...

    # ----- Networks / VLANs -----------------------------------------------
    async def list_networks(self) -> list[UniFiRecord]: ...
    async def create_network(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_network(
        self, network_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None: ...
    async def delete_network(self, network_id: str) -> bool: ...

    # ----- WLANs ----------------------------------------------------------
    async def list_wlans(self) -> list[UniFiRecord]: ...
    async def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_wlan(self, wlan_id: str, patch: dict[str, Any]) -> UniFiRecord | None: ...
    async def delete_wlan(self, wlan_id: str) -> bool: ...

    # ----- Firewall -------------------------------------------------------
    async def list_firewall_rules(self) -> list[UniFiRecord]: ...
    async def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_firewall_rule(
        self, rule_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None: ...
    async def delete_firewall_rule(self, rule_id: str) -> bool: ...

    # ----- Firewall groups ------------------------------------------------
    async def list_firewall_groups(self) -> list[UniFiRecord]: ...
    async def create_firewall_group(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_firewall_group(
        self, group_id: str, payload: dict[str, Any]
    ) -> UniFiRecord | None: ...
    async def delete_firewall_group(self, group_id: str) -> bool: ...

    # ----- Static routes --------------------------------------------------
    async def list_routes(self) -> list[UniFiRecord]: ...
    async def create_route(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_route(self, route_id: str, patch: dict[str, Any]) -> UniFiRecord | None: ...
    async def delete_route(self, route_id: str) -> bool: ...

    # ----- Traffic rules (v2) ---------------------------------------------
    async def list_traffic_rules(self) -> list[UniFiRecord]: ...
    async def create_traffic_rule(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_traffic_rule(
        self, rule_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None: ...

    # ----- Traffic routes (v2) --------------------------------------------
    async def list_traffic_routes(self) -> list[UniFiRecord]: ...
    async def update_traffic_route(
        self, route_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None: ...

    # ----- Port profiles --------------------------------------------------
    async def list_port_profiles(self) -> list[UniFiRecord]: ...
    async def create_port_profile(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_port_profile(
        self, profile_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None: ...
    async def delete_port_profile(self, profile_id: str) -> bool: ...

    # ----- AP groups (read-only) ------------------------------------------
    async def list_ap_groups(self) -> list[UniFiRecord]: ...

    # ----- Clients --------------------------------------------------------
    async def list_clients(self) -> list[UniFiRecord]: ...
    async def block_client(self, mac: str) -> UniFiRecord | None: ...
    async def unblock_client(self, mac: str) -> UniFiRecord | None: ...
    async def reconnect_client(self, mac: str) -> bool: ...
    async def top_talkers(self, limit: int) -> list[UniFiRecord]: ...

    # ----- DHCP leases (static) -------------------------------------------
    async def list_dhcp_leases(self) -> list[UniFiRecord]: ...
    async def find_user_by_mac(self, mac: str) -> UniFiRecord | None: ...
    async def create_dhcp_lease(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_dhcp_lease(self, user_id: str, payload: dict[str, Any]) -> UniFiRecord: ...
    async def delete_dhcp_lease(self, lease_id: str) -> bool: ...

    # ----- Port forwarding ------------------------------------------------
    async def list_port_forwards(self) -> list[UniFiRecord]: ...
    async def create_port_forward(self, payload: dict[str, Any]) -> UniFiRecord: ...
    async def update_port_forward(
        self, forward_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None: ...
    async def delete_port_forward(self, forward_id: str) -> bool: ...

    # ----- Observability --------------------------------------------------
    async def get_site_health(self) -> list[UniFiRecord]: ...
    async def get_wan_status(self) -> UniFiRecord: ...
    async def list_events(self, limit: int) -> list[UniFiRecord]: ...
    async def list_alarms(self, limit: int, archived: bool) -> list[UniFiRecord]: ...
    async def trigger_speedtest(self) -> UniFiRecord: ...
    async def get_speedtest_results(self, limit: int) -> list[UniFiRecord]: ...

    # ----- Site settings (Threat Mgmt, Honeypot, Teleport) ---------------
    async def get_setting(self, key: str) -> UniFiRecord: ...
    async def set_setting(self, key: str, patch: dict[str, Any]) -> UniFiRecord: ...


class StubBackend:
    """In-memory backend wrapping a single :class:`StubState` instance.

    The state is per-controller so two controllers in stub mode have isolated
    state. Methods are ``async def`` to match the protocol; under the hood they
    delegate synchronously.
    """

    def __init__(self, state: StubState) -> None:
        self.state = state

    # ----- Devices --------------------------------------------------------
    async def list_devices(self) -> list[UniFiRecord]:
        return self.state.list_devices()

    async def get_device_by_mac(self, mac: str) -> UniFiRecord | None:
        return self.state.find_device_by_mac(mac)

    async def update_device(self, device_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_device(device_id, patch)

    async def restart_device(self, mac: str) -> bool:
        return self.state.restart_device(mac)

    async def locate_device(self, mac: str, on: bool) -> bool:
        return self.state.locate_device(mac, on)

    async def set_port_state(
        self,
        device_mac: str,
        port_idx: int,
        *,
        enable: bool | None,
        poe_mode: str | None,
        portconf_id: str | None,
    ) -> UniFiRecord | None:
        return self.state.set_port_state(
            device_mac,
            port_idx,
            enable=enable,
            poe_mode=poe_mode,
            portconf_id=portconf_id,
        )

    # ----- Networks / VLANs -----------------------------------------------
    async def list_networks(self) -> list[UniFiRecord]:
        return self.state.list_networks()

    async def create_network(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_network(payload)

    async def update_network(self, network_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_network(network_id, patch)

    async def delete_network(self, network_id: str) -> bool:
        return self.state.delete_network(network_id)

    # ----- WLANs ----------------------------------------------------------
    async def list_wlans(self) -> list[UniFiRecord]:
        return self.state.list_wlans()

    async def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_wlan(payload)

    async def update_wlan(self, wlan_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_wlan(wlan_id, patch)

    async def delete_wlan(self, wlan_id: str) -> bool:
        return self.state.delete_wlan(wlan_id)

    # ----- Firewall -------------------------------------------------------
    async def list_firewall_rules(self) -> list[UniFiRecord]:
        return self.state.list_firewall_rules()

    async def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_firewall_rule(payload)

    async def update_firewall_rule(self, rule_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_firewall_rule(rule_id, patch)

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        return self.state.delete_firewall_rule(rule_id)

    # ----- Firewall groups ------------------------------------------------
    async def list_firewall_groups(self) -> list[UniFiRecord]:
        return self.state.list_firewall_groups()

    async def create_firewall_group(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_firewall_group(payload)

    async def update_firewall_group(
        self, group_id: str, payload: dict[str, Any]
    ) -> UniFiRecord | None:
        return self.state.update_firewall_group(group_id, payload)

    async def delete_firewall_group(self, group_id: str) -> bool:
        return self.state.delete_firewall_group(group_id)

    # ----- Static routes --------------------------------------------------
    async def list_routes(self) -> list[UniFiRecord]:
        return self.state.list_routes()

    async def create_route(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_route(payload)

    async def update_route(self, route_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_route(route_id, patch)

    async def delete_route(self, route_id: str) -> bool:
        return self.state.delete_route(route_id)

    # ----- Traffic rules (v2) ---------------------------------------------
    async def list_traffic_rules(self) -> list[UniFiRecord]:
        return self.state.list_traffic_rules()

    async def create_traffic_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_traffic_rule(payload)

    async def update_traffic_rule(self, rule_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_traffic_rule(rule_id, patch)

    # ----- Traffic routes (v2) --------------------------------------------
    async def list_traffic_routes(self) -> list[UniFiRecord]:
        return self.state.list_traffic_routes()

    async def update_traffic_route(
        self, route_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None:
        return self.state.update_traffic_route(route_id, patch)

    # ----- Port profiles --------------------------------------------------
    async def list_port_profiles(self) -> list[UniFiRecord]:
        return self.state.list_port_profiles()

    async def create_port_profile(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_port_profile(payload)

    async def update_port_profile(
        self, profile_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None:
        return self.state.update_port_profile(profile_id, patch)

    async def delete_port_profile(self, profile_id: str) -> bool:
        return self.state.delete_port_profile(profile_id)

    # ----- AP groups ------------------------------------------------------
    async def list_ap_groups(self) -> list[UniFiRecord]:
        return self.state.list_ap_groups()

    # ----- Clients --------------------------------------------------------
    async def list_clients(self) -> list[UniFiRecord]:
        return self.state.list_clients()

    async def block_client(self, mac: str) -> UniFiRecord | None:
        return self.state.block_client(mac)

    async def unblock_client(self, mac: str) -> UniFiRecord | None:
        return self.state.unblock_client(mac)

    async def reconnect_client(self, mac: str) -> bool:
        return self.state.reconnect_client(mac)

    async def top_talkers(self, limit: int) -> list[UniFiRecord]:
        return self.state.top_talkers(limit)

    # ----- DHCP leases ----------------------------------------------------
    async def list_dhcp_leases(self) -> list[UniFiRecord]:
        return self.state.list_dhcp_leases()

    async def find_user_by_mac(self, mac: str) -> UniFiRecord | None:
        return self.state.find_user_by_mac(mac)

    async def create_dhcp_lease(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_dhcp_lease(payload)

    async def update_dhcp_lease(self, user_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.update_dhcp_lease(user_id, payload)

    async def delete_dhcp_lease(self, lease_id: str) -> bool:
        return self.state.delete_dhcp_lease(lease_id)

    # ----- Port forwarding ------------------------------------------------
    async def list_port_forwards(self) -> list[UniFiRecord]:
        return self.state.list_port_forwards()

    async def create_port_forward(self, payload: dict[str, Any]) -> UniFiRecord:
        return self.state.create_port_forward(payload)

    async def update_port_forward(
        self, forward_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None:
        return self.state.update_port_forward(forward_id, patch)

    async def delete_port_forward(self, forward_id: str) -> bool:
        return self.state.delete_port_forward(forward_id)

    # ----- Observability --------------------------------------------------
    async def get_site_health(self) -> list[UniFiRecord]:
        return self.state.get_site_health()

    async def get_wan_status(self) -> UniFiRecord:
        return self.state.get_wan_status()

    async def list_events(self, limit: int) -> list[UniFiRecord]:
        return self.state.list_events(limit)

    async def list_alarms(self, limit: int, archived: bool) -> list[UniFiRecord]:
        return self.state.list_alarms(limit, archived)

    async def trigger_speedtest(self) -> UniFiRecord:
        return self.state.trigger_speedtest()

    async def get_speedtest_results(self, limit: int) -> list[UniFiRecord]:
        return self.state.get_speedtest_results(limit)

    # ----- Site settings --------------------------------------------------
    async def get_setting(self, key: str) -> UniFiRecord:
        return self.state.get_setting(key)

    async def set_setting(self, key: str, patch: dict[str, Any]) -> UniFiRecord:
        return self.state.set_setting(key, patch)


class RealBackend:
    """Async backend wrapping a :class:`UniFiClient` for real HTTP calls.

    A few methods (``set_port_state``, ``get_wan_status``) need the same small
    composition the legacy server.py did: list devices to find the ``_id``,
    filter health to find the WAN subsystem record. The composition lives here
    once instead of inside every tool.
    """

    def __init__(self, client: UniFiClient) -> None:
        self.client = client

    # ----- Devices --------------------------------------------------------
    async def list_devices(self) -> list[UniFiRecord]:
        return await self.client.list_devices()

    async def get_device_by_mac(self, mac: str) -> UniFiRecord | None:
        devices = await self.client.list_devices()
        return next((d for d in devices if d.get("mac") == mac), None)

    async def update_device(self, device_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        record = await self.client.update_device(device_id, patch)
        return record or None

    async def restart_device(self, mac: str) -> bool:
        await self.client.restart_device(mac)
        return True

    async def locate_device(self, mac: str, on: bool) -> bool:
        await self.client.locate_device(mac, on)
        return True

    async def set_port_state(
        self,
        device_mac: str,
        port_idx: int,
        *,
        enable: bool | None,
        poe_mode: str | None,
        portconf_id: str | None,
    ) -> UniFiRecord | None:
        devices = await self.client.list_devices()
        target = next((d for d in devices if d.get("mac") == device_mac), None)
        if target is None:
            return None
        device_id = target.get("_id")
        if not device_id:
            raise UniFiError(f"device {device_mac} has no _id")
        existing = list(target.get("port_overrides") or [])
        override: dict[str, Any] = {"port_idx": port_idx}
        if enable is not None:
            override["enable"] = enable
        if poe_mode:
            override["poe_mode"] = poe_mode
        if portconf_id:
            override["portconf_id"] = portconf_id
        existing = [o for o in existing if o.get("port_idx") != port_idx]
        existing.append(override)
        return await self.client.set_port_state(device_id, existing)

    # ----- Networks / VLANs -----------------------------------------------
    async def list_networks(self) -> list[UniFiRecord]:
        return await self.client.list_networks()

    async def create_network(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_network(payload)

    async def update_network(self, network_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return await self.client.update_network(network_id, patch)

    async def delete_network(self, network_id: str) -> bool:
        return await self.client.delete_network(network_id)

    # ----- WLANs ----------------------------------------------------------
    async def list_wlans(self) -> list[UniFiRecord]:
        return await self.client.list_wlans()

    async def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_wlan(payload)

    async def update_wlan(self, wlan_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return await self.client.update_wlan(wlan_id, patch)

    async def delete_wlan(self, wlan_id: str) -> bool:
        return await self.client.delete_wlan(wlan_id)

    # ----- Firewall -------------------------------------------------------
    async def list_firewall_rules(self) -> list[UniFiRecord]:
        return await self.client.list_firewall_rules()

    async def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_firewall_rule(payload)

    async def update_firewall_rule(self, rule_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return await self.client.update_firewall_rule(rule_id, patch)

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        return await self.client.delete_firewall_rule(rule_id)

    # ----- Firewall groups ------------------------------------------------
    async def list_firewall_groups(self) -> list[UniFiRecord]:
        return await self.client.list_firewall_groups()

    async def create_firewall_group(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_firewall_group(payload)

    async def update_firewall_group(
        self, group_id: str, payload: dict[str, Any]
    ) -> UniFiRecord | None:
        return await self.client.update_firewall_group(group_id, payload)

    async def delete_firewall_group(self, group_id: str) -> bool:
        return await self.client.delete_firewall_group(group_id)

    # ----- Static routes --------------------------------------------------
    async def list_routes(self) -> list[UniFiRecord]:
        return await self.client.list_routes()

    async def create_route(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_route(payload)

    async def update_route(self, route_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return await self.client.update_route(route_id, patch)

    async def delete_route(self, route_id: str) -> bool:
        return await self.client.delete_route(route_id)

    # ----- Traffic rules (v2) ---------------------------------------------
    async def list_traffic_rules(self) -> list[UniFiRecord]:
        return await self.client.list_traffic_rules()

    async def create_traffic_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_traffic_rule(payload)

    async def update_traffic_rule(self, rule_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return await self.client.update_traffic_rule(rule_id, patch)

    # ----- Traffic routes (v2) --------------------------------------------
    async def list_traffic_routes(self) -> list[UniFiRecord]:
        return await self.client.list_traffic_routes()

    async def update_traffic_route(
        self, route_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None:
        return await self.client.update_traffic_route(route_id, patch)

    # ----- Port profiles --------------------------------------------------
    async def list_port_profiles(self) -> list[UniFiRecord]:
        return await self.client.list_port_profiles()

    async def create_port_profile(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_port_profile(payload)

    async def update_port_profile(
        self, profile_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None:
        return await self.client.update_port_profile(profile_id, patch)

    async def delete_port_profile(self, profile_id: str) -> bool:
        return await self.client.delete_port_profile(profile_id)

    # ----- AP groups ------------------------------------------------------
    async def list_ap_groups(self) -> list[UniFiRecord]:
        return await self.client.list_ap_groups()

    # ----- Clients --------------------------------------------------------
    async def list_clients(self) -> list[UniFiRecord]:
        return await self.client.list_clients()

    async def block_client(self, mac: str) -> UniFiRecord | None:
        return await self.client.block_client(mac)

    async def unblock_client(self, mac: str) -> UniFiRecord | None:
        return await self.client.unblock_client(mac)

    async def reconnect_client(self, mac: str) -> bool:
        await self.client.reconnect_client(mac)
        return True

    async def top_talkers(self, limit: int) -> list[UniFiRecord]:
        return await self.client.list_top_talkers(limit)

    # ----- DHCP leases ----------------------------------------------------
    async def list_dhcp_leases(self) -> list[UniFiRecord]:
        return await self.client.list_dhcp_leases()

    async def find_user_by_mac(self, mac: str) -> UniFiRecord | None:
        return await self.client.find_user_by_mac(mac)

    async def create_dhcp_lease(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_dhcp_lease(payload)

    async def update_dhcp_lease(self, user_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.update_dhcp_lease(user_id, payload)

    async def delete_dhcp_lease(self, lease_id: str) -> bool:
        return await self.client.delete_dhcp_lease(lease_id)

    # ----- Port forwarding ------------------------------------------------
    async def list_port_forwards(self) -> list[UniFiRecord]:
        return await self.client.list_port_forwards()

    async def create_port_forward(self, payload: dict[str, Any]) -> UniFiRecord:
        return await self.client.create_port_forward(payload)

    async def update_port_forward(
        self, forward_id: str, patch: dict[str, Any]
    ) -> UniFiRecord | None:
        return await self.client.update_port_forward(forward_id, patch)

    async def delete_port_forward(self, forward_id: str) -> bool:
        return await self.client.delete_port_forward(forward_id)

    # ----- Observability --------------------------------------------------
    async def get_site_health(self) -> list[UniFiRecord]:
        return await self.client.get_site_health()

    async def get_wan_status(self) -> UniFiRecord:
        health = await self.client.get_site_health()
        for h in health:
            if isinstance(h, dict) and h.get("subsystem") == "wan":
                return h
        return {"subsystem": "wan", "status": "unknown"}

    async def list_events(self, limit: int) -> list[UniFiRecord]:
        return await self.client.list_events(limit)

    async def list_alarms(self, limit: int, archived: bool) -> list[UniFiRecord]:
        return await self.client.list_alarms(limit, archived)

    async def trigger_speedtest(self) -> UniFiRecord:
        return await self.client.trigger_speedtest()

    async def get_speedtest_results(self, limit: int) -> list[UniFiRecord]:
        return await self.client.get_speedtest_results(limit)

    # ----- Site settings --------------------------------------------------
    async def get_setting(self, key: str) -> UniFiRecord:
        return await self.client.get_setting(key)

    async def set_setting(self, key: str, patch: dict[str, Any]) -> UniFiRecord:
        return await self.client.set_setting(key, patch)


@runtime_checkable
class ProtectBackend(Protocol):
    """Async surface every Protect tool calls into.

    Implementations: :class:`ProtectStubBackend` (in-memory) and
    :class:`ProtectRealBackend` (HTTP via :class:`ProtectClient`).
    """

    # ----- Cameras --------------------------------------------------------
    async def list_cameras(self) -> list[UniFiRecord]: ...
    async def get_camera(self, camera_id: str) -> UniFiRecord | None: ...
    async def update_camera(self, camera_id: str, patch: dict[str, Any]) -> UniFiRecord | None: ...

    # ----- Events ---------------------------------------------------------
    async def list_events(
        self, types: list[str], start_ms: int, end_ms: int, limit: int
    ) -> list[UniFiRecord]: ...

    # ----- Snapshots / thumbnails ----------------------------------------
    async def get_snapshot(self, camera_id: str) -> bytes: ...
    async def get_event_thumbnail(self, event_id: str) -> bytes: ...

    # ----- Recordings -----------------------------------------------------
    async def list_recordings(
        self, camera_id: str, start_ms: int, end_ms: int
    ) -> list[UniFiRecord]: ...


class ProtectStubBackend:
    """In-memory backend wrapping a single :class:`ProtectStubState` instance.

    Per-controller state isolation matches :class:`StubBackend`. Methods are
    ``async def`` to satisfy :class:`ProtectBackend`; under the hood they
    delegate synchronously to the state machine.
    """

    def __init__(self, state: ProtectStubState) -> None:
        self.state = state

    async def list_cameras(self) -> list[UniFiRecord]:
        return self.state.list_cameras()

    async def get_camera(self, camera_id: str) -> UniFiRecord | None:
        return self.state.get_camera(camera_id)

    async def update_camera(self, camera_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        return self.state.update_camera(camera_id, patch)

    async def list_events(
        self, types: list[str], start_ms: int, end_ms: int, limit: int
    ) -> list[UniFiRecord]:
        return self.state.list_events(types, start_ms, end_ms, limit)

    async def get_snapshot(self, camera_id: str) -> bytes:
        return self.state.get_snapshot(camera_id)

    async def get_event_thumbnail(self, event_id: str) -> bytes:
        return self.state.get_event_thumbnail(event_id)

    async def list_recordings(
        self, camera_id: str, start_ms: int, end_ms: int
    ) -> list[UniFiRecord]:
        return self.state.list_recordings(camera_id, start_ms, end_ms)


class ProtectRealBackend:
    """Async backend wrapping a :class:`ProtectClient` for real HTTP calls."""

    def __init__(self, client: ProtectClient) -> None:
        self.client = client

    async def list_cameras(self) -> list[UniFiRecord]:
        return await self.client.list_cameras()

    async def get_camera(self, camera_id: str) -> UniFiRecord | None:
        # Protect returns the camera dict directly; we coerce 404-like empties
        # to None so tools can render a clean "not found" error.
        record = await self.client.get_camera(camera_id)
        if not record:
            return None
        return record

    async def update_camera(self, camera_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        record = await self.client.update_camera(camera_id, patch)
        if not record:
            return None
        return record

    async def list_events(
        self, types: list[str], start_ms: int, end_ms: int, limit: int
    ) -> list[UniFiRecord]:
        return await self.client.list_events(types, start_ms, end_ms, limit)

    async def get_snapshot(self, camera_id: str) -> bytes:
        return await self.client.get_snapshot(camera_id)

    async def get_event_thumbnail(self, event_id: str) -> bytes:
        return await self.client.get_event_thumbnail(event_id)

    async def list_recordings(
        self, camera_id: str, start_ms: int, end_ms: int
    ) -> list[UniFiRecord]:
        return await self.client.list_recordings(camera_id, start_ms, end_ms)


@runtime_checkable
class AccessBackend(Protocol):
    """Async surface every Access tool calls into.

    Implementations: :class:`AccessStubBackend` (in-memory) and
    :class:`AccessRealBackend` (HTTP via :class:`AccessClient`). v0.10 ships
    read-only methods only — the write surface is gated by a future Option B
    decision (see ``docs/v0.10-access-module.md``).
    """

    # ----- Doors ----------------------------------------------------------
    async def list_doors(self) -> list[UniFiRecord]: ...
    async def get_door(self, door_id: str) -> UniFiRecord | None: ...
    async def list_door_groups(self) -> list[UniFiRecord]: ...

    # ----- Policies -------------------------------------------------------
    async def list_access_policies(self) -> list[UniFiRecord]: ...
    async def get_access_policy(self, policy_id: str) -> UniFiRecord | None: ...

    # ----- Credentials ----------------------------------------------------
    async def list_credentials(self) -> list[UniFiRecord]: ...
    async def get_credential(self, credential_id: str) -> UniFiRecord | None: ...

    # ----- Visitors -------------------------------------------------------
    async def list_visitors(self) -> list[UniFiRecord]: ...
    async def get_visitor(self, visitor_id: str) -> UniFiRecord | None: ...

    # ----- Events ---------------------------------------------------------
    async def list_events(
        self,
        start_ms: int,
        end_ms: int,
        limit: int,
        result: str = "",
        door_id: str = "",
    ) -> list[UniFiRecord]: ...

    # ----- Devices --------------------------------------------------------
    async def list_devices(self) -> list[UniFiRecord]: ...
    async def get_device(self, device_id: str) -> UniFiRecord | None: ...

    # ----- System ---------------------------------------------------------
    async def get_system_info(self) -> UniFiRecord: ...
    async def list_users(self) -> list[UniFiRecord]: ...


class AccessStubBackend:
    """In-memory backend wrapping a single :class:`AccessStubState` instance.

    Per-controller state isolation matches :class:`StubBackend` and
    :class:`ProtectStubBackend`. Methods are ``async def`` to satisfy
    :class:`AccessBackend`; under the hood they delegate synchronously to the
    state machine.
    """

    def __init__(self, state: AccessStubState) -> None:
        self.state = state

    async def list_doors(self) -> list[UniFiRecord]:
        return self.state.list_doors()

    async def get_door(self, door_id: str) -> UniFiRecord | None:
        return self.state.get_door(door_id)

    async def list_door_groups(self) -> list[UniFiRecord]:
        return self.state.list_door_groups()

    async def list_access_policies(self) -> list[UniFiRecord]:
        return self.state.list_access_policies()

    async def get_access_policy(self, policy_id: str) -> UniFiRecord | None:
        return self.state.get_access_policy(policy_id)

    async def list_credentials(self) -> list[UniFiRecord]:
        return self.state.list_credentials()

    async def get_credential(self, credential_id: str) -> UniFiRecord | None:
        return self.state.get_credential(credential_id)

    async def list_visitors(self) -> list[UniFiRecord]:
        return self.state.list_visitors()

    async def get_visitor(self, visitor_id: str) -> UniFiRecord | None:
        return self.state.get_visitor(visitor_id)

    async def list_events(
        self,
        start_ms: int,
        end_ms: int,
        limit: int,
        result: str = "",
        door_id: str = "",
    ) -> list[UniFiRecord]:
        return self.state.list_events(start_ms, end_ms, limit, result=result, door_id=door_id)

    async def list_devices(self) -> list[UniFiRecord]:
        return self.state.list_devices()

    async def get_device(self, device_id: str) -> UniFiRecord | None:
        return self.state.get_device(device_id)

    async def get_system_info(self) -> UniFiRecord:
        return self.state.get_system_info()

    async def list_users(self) -> list[UniFiRecord]:
        return self.state.list_users()


class AccessRealBackend:
    """Async backend wrapping an :class:`AccessClient` for real HTTP calls.

    The Access API surfaces ``GET /resource/{id}`` for every singular lookup;
    we coerce empty-object responses to ``None`` so tool error envelopes show
    a clean "not found" message instead of an empty record.
    """

    def __init__(self, client: AccessClient) -> None:
        self.client = client

    async def list_doors(self) -> list[UniFiRecord]:
        return await self.client.list_doors()

    async def get_door(self, door_id: str) -> UniFiRecord | None:
        record = await self.client.get_door(door_id)
        return record if record else None

    async def list_door_groups(self) -> list[UniFiRecord]:
        return await self.client.list_door_groups()

    async def list_access_policies(self) -> list[UniFiRecord]:
        return await self.client.list_access_policies()

    async def get_access_policy(self, policy_id: str) -> UniFiRecord | None:
        record = await self.client.get_access_policy(policy_id)
        return record if record else None

    async def list_credentials(self) -> list[UniFiRecord]:
        return await self.client.list_credentials()

    async def get_credential(self, credential_id: str) -> UniFiRecord | None:
        record = await self.client.get_credential(credential_id)
        return record if record else None

    async def list_visitors(self) -> list[UniFiRecord]:
        return await self.client.list_visitors()

    async def get_visitor(self, visitor_id: str) -> UniFiRecord | None:
        record = await self.client.get_visitor(visitor_id)
        return record if record else None

    async def list_events(
        self,
        start_ms: int,
        end_ms: int,
        limit: int,
        result: str = "",
        door_id: str = "",
    ) -> list[UniFiRecord]:
        return await self.client.list_events(
            start_ms, end_ms, limit, result=result, door_id=door_id
        )

    async def list_devices(self) -> list[UniFiRecord]:
        return await self.client.list_devices()

    async def get_device(self, device_id: str) -> UniFiRecord | None:
        record = await self.client.get_device(device_id)
        return record if record else None

    async def get_system_info(self) -> UniFiRecord:
        return await self.client.get_system_info()

    async def list_users(self) -> list[UniFiRecord]:
        return await self.client.list_users()


__all__ = [
    "AccessBackend",
    "AccessRealBackend",
    "AccessStubBackend",
    "Backend",
    "ProtectBackend",
    "ProtectRealBackend",
    "ProtectStubBackend",
    "RealBackend",
    "StubBackend",
]
