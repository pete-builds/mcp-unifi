"""Async UniFi controller client.

Talks to a self-hosted UniFi gateway (UCG-Fiber, UDM, etc.) using a local API
key sent via the ``X-API-Key`` header. UniFi OS gateways expose the legacy
controller API behind the ``/proxy/network/`` prefix.

This client is intentionally narrow: only the endpoints called by the server
tools are wrapped. It is not a port of any reference implementation.
"""

from __future__ import annotations

import logging
import ssl
import time
from collections.abc import Callable
from typing import Any

import httpx

from mcp_unifi.clients.errors import (
    UniFiError,
    UniFiUnsupportedError,
    describe_error_body,
    parse_json_body,
)
from mcp_unifi.clients.ids import path_segment
from mcp_unifi.clients.mac import normalize_mac, same_mac
from mcp_unifi.clients.retry import request_with_retry
from mcp_unifi.clients.stats_shape import shape_speedtest_results, shape_top_talkers
from mcp_unifi.clients.system_log import (
    MAX_SCAN_ROWS,
    client_matcher,
    detection_from_alert,
    detection_from_flow,
    finish_detections,
    ips_flow_body,
    iso_utc,
    parse_page,
    shape_log_entry,
    system_log_body,
)
from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.client")

#: Hard stop on pages for one paged v2 read, whatever the controller claims.
_MAX_PAGES = 50


#: Kept for existing imports; the helper now lives in ``clients.errors``.
_describe_error_body = describe_error_body


class UniFiClient:
    """Thin async wrapper around the UniFi controller REST API.

    Args:
        host: Gateway IP or hostname (no scheme).
        api_key: Local API key from Settings → Control Plane → Integrations.
        port: HTTPS port (default 443 for UniFi OS).
        site: Controller site identifier (default ``"default"``).
        verify_ssl: Verify the gateway's TLS cert. Self-hosted gateways ship
            with a self-signed cert, so this is False by default.
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        api_key: str,
        port: int = 443,
        site: str = "default",
        verify_ssl: bool | ssl.SSLContext = False,
        timeout: float = 15.0,
    ) -> None:
        self.host = host
        self.port = port
        self.site = site
        self._base = f"https://{host}:{port}/proxy/network"
        self._site_path = f"/api/s/{site}"
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_ssl,
            headers={
                "X-API-Key": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self._base}{path}"
        resp = await request_with_retry(
            self._client,
            method,
            url,
            logger=logger,
            service="UniFi",
            error_cls=UniFiError,
            json=json,
        )
        if resp.status_code >= 400:
            detail = describe_error_body(resp, json)
            error = UniFiError(f"UniFi {method} {path} returned {resp.status_code}{detail}")
            error.status = resp.status_code
            error.detail = detail
            raise error
        if not resp.content:
            return None
        body = parse_json_body(resp, f"UniFi {method} {path}")
        # Legacy UniFi controller wraps payloads in {"meta": {...}, "data": [...]}.
        if isinstance(body, dict) and "data" in body:
            return body["data"]
        return body

    async def _v2_request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
    ) -> Any:
        """Issue a request against the v2 controller API and normalise the body.

        The v2 surface (``/proxy/network/v2/api/site/<site>/...``) sits at a
        different prefix than the legacy ``/api/s/<site>/...`` paths and returns
        a **bare** JSON array or object rather than the legacy
        ``{"meta", "data"}`` envelope. Verified read-only against a UCG-Fiber on
        UniFi Network 10.4.57 (2026-06-12): ``GET .../trafficrules`` and
        ``GET .../trafficroutes`` both answer HTTP 200 with a bare list.

        ``path`` is the portion after ``/v2/api/site/<site>`` (e.g.
        ``"/trafficrules"`` or ``"/trafficrules/<id>"``). Returns the parsed
        body unchanged (list or dict), or ``None`` on an empty response.
        """
        url = f"{self._base}/v2/api/site/{self.site}{path}"
        resp = await request_with_retry(
            self._client,
            method,
            url,
            logger=logger,
            service="UniFi v2",
            error_cls=UniFiError,
            json=json,
        )
        if resp.status_code >= 400:
            detail = describe_error_body(resp, json)
            error = UniFiError(f"UniFi {method} (v2) {path} returned {resp.status_code}{detail}")
            error.status = resp.status_code
            error.detail = detail
            raise error
        if not resp.content:
            return None
        return parse_json_body(resp, f"UniFi {method} (v2) {path}")

    async def _get(self, path: str) -> Any:
        return await self._request("GET", f"{self._site_path}{path}")

    async def _post(self, path: str, payload: dict[str, Any]) -> Any:
        return await self._request("POST", f"{self._site_path}{path}", json=payload)

    async def _put(self, path: str, payload: dict[str, Any]) -> Any:
        return await self._request("PUT", f"{self._site_path}{path}", json=payload)

    async def _delete(self, path: str) -> Any:
        return await self._request("DELETE", f"{self._site_path}{path}")

    @staticmethod
    def _first_record(result: Any) -> UniFiRecord:
        """Normalise create/update results that may come back as a 1-item list."""
        if isinstance(result, list) and result:
            first = result[0]
            return first if isinstance(first, dict) else {}
        if isinstance(result, dict):
            return result
        return {}

    # ------------------------------------------------------------------
    # Public methods (one per MCP tool that needs a real call)
    # ------------------------------------------------------------------

    async def list_devices(self) -> list[UniFiRecord]:
        return await self._get("/stat/device") or []

    async def list_networks(self) -> list[UniFiRecord]:
        return await self._get("/rest/networkconf") or []

    async def create_network(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/networkconf", payload))

    async def update_network(self, network_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/networkconf/{path_segment(network_id, 'network_id')}", payload)
        )

    async def delete_network(self, network_id: str) -> bool:
        await self._delete(f"/rest/networkconf/{path_segment(network_id, 'network_id')}")
        return True

    async def list_wlans(self) -> list[UniFiRecord]:
        return await self._get("/rest/wlanconf") or []

    async def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/wlanconf", payload))

    async def update_wlan(self, wlan_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/wlanconf/{path_segment(wlan_id, 'wlan_id')}", payload)
        )

    async def delete_wlan(self, wlan_id: str) -> bool:
        await self._delete(f"/rest/wlanconf/{path_segment(wlan_id, 'wlan_id')}")
        return True

    async def list_firewall_rules(self) -> list[UniFiRecord]:
        return await self._get("/rest/firewallrule") or []

    async def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/firewallrule", payload))

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        await self._delete(f"/rest/firewallrule/{path_segment(rule_id, 'rule_id')}")
        return True

    # ----- Zone-Based Firewall (v2) -------------------------------------

    async def list_firewall_policies(self) -> list[UniFiRecord]:
        """List Zone-Based Firewall policies via the v2 API.

        Network 9.x introduced the Zone-Based Firewall. A site that has
        migrated to it keeps its policy under
        ``/v2/api/site/<site>/firewall-policies``, and the legacy
        ``/rest/firewallrule`` collection that :meth:`list_firewall_rules`
        reads answers ``[]`` for it (issue #112). Verified 2026-09-13 against
        a UCG-Fiber on Network 10.6.101 still on legacy rulesets: this route
        answers HTTP 200 with a bare empty list, so a legacy site reads as
        "no policies" rather than as an error, and the two reads can be
        taken together safely in either direction.
        """
        result = await self._v2_request("GET", "/firewall-policies")
        return result if isinstance(result, list) else []

    async def list_firewall_zones(self) -> list[UniFiRecord]:
        """List Zone-Based Firewall zones via the v2 API (``/firewall/zone``).

        Each zone carries ``_id``, ``name``, ``zone_key`` (``"wan"``,
        ``"lan"``, ...), ``default_zone`` and ``network_ids``. Policies refer
        to zones only by ``source.zone_id`` / ``destination.zone_id``, so this
        is what turns a policy record into "WAN to LAN". Same empty-list
        behaviour on a legacy-ruleset site as :meth:`list_firewall_policies`.
        """
        result = await self._v2_request("GET", "/firewall/zone")
        return result if isinstance(result, list) else []

    async def list_port_profiles(self) -> list[UniFiRecord]:
        return await self._get("/rest/portconf") or []

    async def list_ap_groups(self) -> list[UniFiRecord]:
        """List access-point groups configured on the controller.

        UniFi exposes AP groups via the v2 controller API:
        ``/v2/api/site/<site>/apgroups``. Returns one record per group with
        ``_id``, ``name``, ``device_macs``, and ``attr_hidden_id`` (the
        controller marks the built-in "default" group with
        ``attr_hidden_id == "default"``).

        The v2 endpoint sits at a different prefix than the legacy
        ``/api/s/<site>/...`` paths the rest of this client uses, so we build
        the URL manually.
        """
        url = f"{self._base}/v2/api/site/{self.site}/apgroups"
        resp = await request_with_retry(
            self._client,
            "GET",
            url,
            logger=logger,
            service="UniFi",
            error_cls=UniFiError,
        )
        if resp.status_code >= 400:
            raise UniFiError(
                f"UniFi GET apgroups returned {resp.status_code}{describe_error_body(resp)}"
            )
        if not resp.content:
            return []
        body = parse_json_body(resp, "UniFi GET apgroups")
        # v2 endpoint returns a bare list (not the legacy meta+data envelope).
        if isinstance(body, list):
            return body
        if isinstance(body, dict) and "data" in body:
            return body["data"] if isinstance(body["data"], list) else []
        return []

    async def list_clients(self) -> list[UniFiRecord]:
        """Return currently active wireless and wired clients on the gateway.

        Wraps the ``/stat/sta`` endpoint, which the controller uses to power the
        Insights → Clients view. Returns an empty list when no clients are
        connected (e.g. fresh deployment).
        """
        return await self._get("/stat/sta") or []

    # ------------------------------------------------------------------
    # Firewall (update)
    # ------------------------------------------------------------------

    async def update_firewall_rule(self, rule_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/firewallrule/{path_segment(rule_id, 'rule_id')}", payload)
        )

    # ------------------------------------------------------------------
    # Firewall groups (reusable address/port objects via /rest/firewallgroup)
    # ------------------------------------------------------------------

    async def list_firewall_groups(self) -> list[UniFiRecord]:
        """List reusable firewall groups (address-group / ipv6-address-group / port-group).

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET /rest/firewallgroup`` answers HTTP 200 with the
        standard ``{"meta", "data"}`` envelope (empty on a fresh gateway).
        """
        return await self._get("/rest/firewallgroup") or []

    async def create_firewall_group(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/firewallgroup", payload))

    async def update_firewall_group(self, group_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/firewallgroup/{path_segment(group_id, 'group_id')}", payload)
        )

    async def delete_firewall_group(self, group_id: str) -> bool:
        await self._delete(f"/rest/firewallgroup/{path_segment(group_id, 'group_id')}")
        return True

    # ------------------------------------------------------------------
    # Static routes (policy-free next-hop routing via /rest/routing)
    # ------------------------------------------------------------------

    async def list_routes(self) -> list[UniFiRecord]:
        """List user-defined static routes.

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET /rest/routing`` answers HTTP 200 with the standard
        ``{"meta", "data"}`` envelope (empty on a fresh gateway).
        """
        return await self._get("/rest/routing") or []

    async def create_route(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/routing", payload))

    async def update_route(self, route_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/routing/{path_segment(route_id, 'route_id')}", payload)
        )

    async def delete_route(self, route_id: str) -> bool:
        await self._delete(f"/rest/routing/{path_segment(route_id, 'route_id')}")
        return True

    # ------------------------------------------------------------------
    # Traffic rules (v2 policy engine via /v2/api/site/<site>/trafficrules)
    # ------------------------------------------------------------------

    async def list_traffic_rules(self) -> list[UniFiRecord]:
        """List v2 traffic rules (app/domain/IP-based allow/block policies).

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET .../trafficrules`` answers HTTP 200 with a bare
        JSON list (no legacy envelope).
        """
        result = await self._v2_request("GET", "/trafficrules")
        return result if isinstance(result, list) else []

    async def create_traffic_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        result = await self._v2_request("POST", "/trafficrules", json=payload)
        return self._first_record(result)

    async def update_traffic_rule(self, rule_id: str, payload: dict[str, Any]) -> UniFiRecord:
        result = await self._v2_request(
            "PUT", f"/trafficrules/{path_segment(rule_id, 'rule_id')}", json=payload
        )
        return self._first_record(result)

    # ------------------------------------------------------------------
    # Traffic routes (v2 policy-based routing via .../trafficroutes)
    # ------------------------------------------------------------------

    async def list_traffic_routes(self) -> list[UniFiRecord]:
        """List v2 traffic routes (policy-based routing, e.g. VPN client routes).

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET .../trafficroutes`` answers HTTP 200 with a bare
        JSON list (no legacy envelope).
        """
        result = await self._v2_request("GET", "/trafficroutes")
        return result if isinstance(result, list) else []

    async def update_traffic_route(self, route_id: str, payload: dict[str, Any]) -> UniFiRecord:
        result = await self._v2_request(
            "PUT", f"/trafficroutes/{path_segment(route_id, 'route_id')}", json=payload
        )
        return self._first_record(result)

    # ------------------------------------------------------------------
    # Content filtering (v2 DNS-category blocking via .../content-filtering)
    # ------------------------------------------------------------------

    async def list_content_filters(self) -> list[UniFiRecord]:
        """List DNS content-filtering profiles.

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET .../content-filtering`` answers HTTP 200 with a
        bare JSON list (no legacy envelope). A profile carries ``_id``,
        ``name``, ``enabled``, ``categories`` (blocked DNS category enum list),
        ``allow_list`` / ``block_list`` (per-domain overrides), ``client_macs``
        and ``network_ids`` (scope), ``safe_search``, and a ``schedule`` block.
        """
        result = await self._v2_request("GET", "/content-filtering")
        return result if isinstance(result, list) else []

    async def update_content_filter(self, filter_id: str, payload: dict[str, Any]) -> UniFiRecord:
        result = await self._v2_request(
            "PUT", f"/content-filtering/{path_segment(filter_id, 'filter_id')}", json=payload
        )
        return self._first_record(result)

    async def delete_content_filter(self, filter_id: str) -> bool:
        await self._v2_request(
            "DELETE", f"/content-filtering/{path_segment(filter_id, 'filter_id')}"
        )
        return True

    # ------------------------------------------------------------------
    # Dynamic DNS (legacy /rest/dynamicdns)
    # ------------------------------------------------------------------

    async def list_dynamic_dns(self) -> list[UniFiRecord]:
        """List Dynamic DNS update configurations.

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET /rest/dynamicdns`` answers HTTP 200 with the
        standard ``{"meta", "data"}`` envelope (empty on this gateway). A
        record carries ``service`` (provider), ``host_name`` (the FQDN to
        update), ``login`` / ``x_password`` (provider credentials),
        ``server`` (optional custom update URL), and ``interface`` (WAN to
        track, e.g. ``"wan"``).
        """
        return await self._get("/rest/dynamicdns") or []

    async def create_dynamic_dns(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/dynamicdns", payload))

    async def update_dynamic_dns(self, ddns_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/dynamicdns/{path_segment(ddns_id, 'ddns_id')}", payload)
        )

    async def delete_dynamic_dns(self, ddns_id: str) -> bool:
        await self._delete(f"/rest/dynamicdns/{path_segment(ddns_id, 'ddns_id')}")
        return True

    # ------------------------------------------------------------------
    # Port profiles (create/update/delete)
    # ------------------------------------------------------------------

    async def create_port_profile(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/portconf", payload))

    async def update_port_profile(self, profile_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/portconf/{path_segment(profile_id, 'profile_id')}", payload)
        )

    async def delete_port_profile(self, profile_id: str) -> bool:
        await self._delete(f"/rest/portconf/{path_segment(profile_id, 'profile_id')}")
        return True

    # ------------------------------------------------------------------
    # Client commands (block/unblock/reconnect via /cmd/stamgr)
    # ------------------------------------------------------------------

    async def _stamgr(self, cmd: str, mac: str) -> UniFiRecord:
        return self._first_record(await self._post("/cmd/stamgr", {"cmd": cmd, "mac": mac}))

    async def block_client(self, mac: str) -> UniFiRecord:
        return await self._stamgr("block-sta", mac)

    async def unblock_client(self, mac: str) -> UniFiRecord:
        return await self._stamgr("unblock-sta", mac)

    async def reconnect_client(self, mac: str) -> UniFiRecord:
        return await self._stamgr("kick-sta", mac)

    # ------------------------------------------------------------------
    # Device commands (restart, locate, set-poe-mode, port toggle via /cmd/devmgr)
    # ------------------------------------------------------------------

    async def restart_device(self, mac: str) -> UniFiRecord:
        return self._first_record(await self._post("/cmd/devmgr", {"cmd": "restart", "mac": mac}))

    async def locate_device(self, mac: str, on: bool) -> UniFiRecord:
        cmd = "set-locate" if on else "unset-locate"
        return self._first_record(await self._post("/cmd/devmgr", {"cmd": cmd, "mac": mac}))

    async def set_port_state(
        self,
        device_id: str,
        port_overrides: list[dict[str, Any]],
    ) -> UniFiRecord:
        """Patch a switch's per-port overrides.

        UniFi exposes per-port settings via the device PUT endpoint:
        ``/rest/device/<device_id>`` with ``{"port_overrides": [...]}``. The
        caller supplies the full list (the controller merges by ``port_idx``).
        """
        return self._first_record(
            await self._put(
                f"/rest/device/{path_segment(device_id, 'device_id')}",
                {"port_overrides": port_overrides},
            )
        )

    async def update_device(self, device_id: str, payload: dict[str, Any]) -> UniFiRecord:
        """Patch fields on a device config record.

        UniFi merges the supplied keys into the stored record via
        ``PUT /rest/device/<device_id>`` (the same endpoint
        :meth:`set_port_state` uses for ``port_overrides``). Array-valued
        fields like ``radio_table`` replace wholesale, so callers must send
        the full read-modify-written array, never a partial one.
        """
        return self._first_record(
            await self._put(f"/rest/device/{path_segment(device_id, 'device_id')}", payload)
        )

    async def get_device(self, device_id: str) -> UniFiRecord:
        result = await self._get(f"/stat/device/{path_segment(device_id, 'device_id')}")
        if isinstance(result, list) and result:
            first = result[0]
            return first if isinstance(first, dict) else {}
        return result if isinstance(result, dict) else {}

    # ------------------------------------------------------------------
    # Static DHCP leases (CRUD via /rest/user with use_fixedip)
    # ------------------------------------------------------------------

    async def list_dhcp_leases(self) -> list[UniFiRecord]:
        users = await self._get("/list/user") or []
        return [u for u in users if isinstance(u, dict) and u.get("use_fixedip")]

    async def find_user_by_mac(self, mac: str) -> UniFiRecord | None:
        """Find the user record for a MAC across known clients (online + offline).

        UniFi keeps a persistent user record per MAC at ``/list/user`` once a
        client has ever associated. Returns ``None`` if no record exists.
        """
        users = await self._get("/list/user") or []
        for u in users:
            if isinstance(u, dict) and same_mac(u.get("mac"), mac):
                return u
        return None

    async def create_dhcp_lease(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/user", payload))

    async def list_user_records(self) -> list[UniFiRecord]:
        """Every persistent user record (``/list/user``), reservation or not.

        One read for a caller that resolves many MACs at once, where
        :meth:`find_user_by_mac` would refetch the whole list per MAC.
        """
        users = await self._get("/list/user") or []
        return [u for u in users if isinstance(u, dict)]

    async def update_user(self, user_id: str, patch: dict[str, Any]) -> UniFiRecord:
        """Send ``patch`` as a partial update of one user record.

        ``PUT /rest/user/{id}`` with only the keys being changed, so a rename
        never carries ``use_fixedip``, ``fixed_ip`` or ``network_id`` and
        cannot create an IP reservation as a side effect. The controller
        merges the body into the stored record; that a body carrying only
        ``name``/``note``/``noted`` is merged rather than rejected matches the
        UI rename the issue #219 reporter captured on Network 11.0.99, and has
        not been verified on a controller this project's maintainer owns.
        """
        return self._first_record(
            await self._put(f"/rest/user/{path_segment(user_id, 'user_id')}", patch)
        )

    async def update_dhcp_lease(self, user_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/user/{path_segment(user_id, 'user_id')}", payload)
        )

    async def delete_dhcp_lease(self, lease_id: str) -> bool:
        """Remove the fixed-IP reservation from a user record.

        ``DELETE /rest/user/{id}`` answers 404 ``api.err.NotFound``: the
        collection accepts GET, POST and PUT only, so the previous
        implementation could never succeed against a controller. Reported and
        verified live on two UDM Pro Max (UniFi OS 5.1.31, Network 10.6.101)
        in issue #124; it has NOT been verified on a controller this project's
        maintainer owns. The working form clears the reservation with
        ``PUT ... {"use_fixedip": false}`` and keeps the client record and its
        history. ``POST /cmd/stamgr {"cmd": "forget-sta"}`` also works but
        erases the client entirely, which is more than "delete the lease"
        asks for.
        """
        await self._put(f"/rest/user/{path_segment(lease_id, 'lease_id')}", {"use_fixedip": False})
        return True

    # ------------------------------------------------------------------
    # Port forwarding (CRUD via /rest/portforward)
    # ------------------------------------------------------------------

    async def list_port_forwards(self) -> list[UniFiRecord]:
        return await self._get("/rest/portforward") or []

    async def create_port_forward(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/portforward", payload))

    async def update_port_forward(self, forward_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(
            await self._put(f"/rest/portforward/{path_segment(forward_id, 'forward_id')}", payload)
        )

    async def delete_port_forward(self, forward_id: str) -> bool:
        await self._delete(f"/rest/portforward/{path_segment(forward_id, 'forward_id')}")
        return True

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    async def get_site_health(self) -> list[UniFiRecord]:
        return await self._get("/stat/health") or []

    # ------------------------------------------------------------------
    # Event log, alarms and IPS detections (v2 system log)
    # ------------------------------------------------------------------
    #
    # HISTORY. ``list_events`` read ``GET /stat/event`` and ``list_alarms``
    # read ``GET /list/alarm``. Both are gone on UniFi Network 10.x (404 and
    # 400 ``api.err.InvalidObject``, probed live 2026-08-08 and recorded by
    # Art-of-WiFi and unpoller), and an earlier version of this client
    # turned that into ``[]``, so "this controller cannot show events" read
    # as "nothing happened". The replacement is the v2 system log; see
    # :mod:`mcp_unifi.clients.system_log` for the sources. Every failure
    # below raises with the full path and HTTP status, and the success
    # envelope names the route that answered, so one call says which
    # surface was read.
    #
    # PROBE RECORD (the old docstrings, kept). UCG-Fiber, Network 10.4.57
    # (2026-06-03): ``GET``/``POST /stat/event`` 404, ``/rest/event`` 400,
    # ``GET /list/alarm`` 200. Network 10.5.67 (2026-08-08, settled
    # controller, ``stat/sysinfo`` 200 as the control): ``GET``/``POST
    # /stat/event`` 404, ``GET``/``POST /rest/event`` 400, ``GET /list/event``
    # 400, ``GET /list/alarm`` (with or without ``?archived=``) 400,
    # ``GET /rest/alarm`` 400, ``POST /stat/alarm`` 404, and v2 ``/event``,
    # ``/events`` and ``/system-log`` 404. That last probe named no class
    # suffix and no method, so it says nothing about ``POST
    # /system-log/all``; whether that route accepts this server's API key is
    # NOT yet verified live. If it does not, the tools return the 404 or 401
    # as an error, which is the point.

    #: Statuses that mean "this route does not exist on this controller",
    #: the only case where a legacy fallback is tried. Anything else (401,
    #: 403, 400 on a body, 5xx, transport) is surfaced as it is, because a
    #: fallback would hide the real fault behind a second, older one.
    _ROUTE_ABSENT = frozenset({404, 405})

    def _v2_label(self, method: str, path: str) -> str:
        return f"{method} /proxy/network/v2/api/site/{self.site}{path}"

    def _legacy_label(self, method: str, path: str) -> str:
        return f"{method} /proxy/network{self._site_path}{path}"

    @staticmethod
    def _outcome(label: str, exc: UniFiError) -> str:
        """``label`` plus what went wrong, for an error message."""
        if exc.status is not None:
            return f"{label} answered HTTP {exc.status}{exc.detail}"
        text = str(exc)
        return text if label in text else f"{label} failed before any HTTP answer ({text})"

    @staticmethod
    def _window(hours: int) -> tuple[int, int]:
        end_ms = int(time.time() * 1000)
        return end_ms - hours * 3_600_000, end_ms

    async def _v2_pages(
        self,
        path: str,
        make_body: Callable[[int], dict[str, Any]],
        max_rows: int,
    ) -> tuple[list[dict[str, Any]], int | None, bool]:
        """POST a paged v2 read until it is exhausted or ``max_rows`` is reached.

        Returns ``(rows, total, more_available)``. ``more_available`` is
        ``True`` when the controller had rows past ``max_rows``, so a caller
        can say the window was cut rather than imply it was complete.
        """
        label = self._v2_label("POST", path)
        rows: list[dict[str, Any]] = []
        total: int | None = None
        for page in range(_MAX_PAGES):
            body = await self._v2_request("POST", path, json=make_body(page))
            page_rows, page_total, has_more = parse_page(body, label)
            if total is None:
                total = page_total
            rows.extend(page_rows)
            if len(rows) >= max_rows:
                return rows[:max_rows], total, has_more or len(rows) > max_rows
            if not has_more:
                return rows, total, False
        return rows, total, True

    async def _system_log(
        self,
        log_class: str,
        hours: int,
        limit: int,
    ) -> UniFiRecord:
        start_ms, end_ms = self._window(hours)
        path = f"/system-log/{log_class}"
        rows, total, more = await self._v2_pages(
            path,
            lambda page: system_log_body(log_class, start_ms, end_ms, page),
            limit,
        )
        entries = sorted(
            (shape_log_entry(r) for r in rows),
            key=lambda e: e.get("timestamp") or 0,
            reverse=True,
        )
        return {
            "source": self._v2_label("POST", path),
            "window": {"hours": hours, "from": iso_utc(start_ms), "to": iso_utc(end_ms)},
            "total": total,
            "returned": len(entries),
            "more_available": more,
            "entries": entries,
        }

    async def _legacy_list(self, path: str) -> list[UniFiRecord]:
        """GET a legacy log route and insist on a list."""
        records = await self._request("GET", f"{self._site_path}{path}")
        if not isinstance(records, list):
            raise UniFiError(
                f"{self._legacy_label('GET', path)} answered 200 with a "
                f"{type(records).__name__} instead of a list of records"
            )
        return [r for r in records if isinstance(r, dict)]

    @staticmethod
    def _legacy_envelope(source: str, v2_outcome: str, records: list[UniFiRecord]) -> UniFiRecord:
        return {
            "source": f"{source} (legacy fallback, because {v2_outcome})",
            "window": None,
            "total": None,
            "returned": len(records),
            "more_available": None,
            "entries": records,
        }

    async def list_events(self, limit: int, hours: int) -> UniFiRecord:
        """Return the controller event log for the last ``hours``, newest first.

        Reads ``POST /v2/api/site/<site>/system-log/all`` (Network 9.x and
        later; the Art-of-WiFi client documents it as the replacement for
        ``stat/event``). Only when that route is absent (404/405) does it try
        the legacy ``GET /stat/event`` that Network 10.x removed. Any other
        failure, or both routes failing, raises with each path and status.
        """
        v2_label = self._v2_label("POST", "/system-log/all")
        try:
            result = await self._system_log("all", hours, limit)
        except UniFiError as exc:
            if exc.status not in self._ROUTE_ABSENT:
                raise UniFiError(
                    f"list_events could not read the event log: "
                    f"{self._outcome(v2_label, exc)}, so this is an error and not "
                    f"an empty result"
                ) from exc
            v2_outcome = self._outcome(v2_label, exc)
            legacy_path = f"/stat/event?_limit={limit}&_sort=-time"
            legacy_label = self._legacy_label("GET", legacy_path)
            try:
                records = await self._legacy_list(legacy_path)
            except UniFiError as legacy_exc:
                raise UniFiUnsupportedError(
                    f"list_events could not read the event log: {v2_outcome}, and "
                    f"the legacy fallback {self._outcome(legacy_label, legacy_exc)}, "
                    f"so this is an error and not an empty result"
                ) from legacy_exc
            result = self._legacy_envelope(legacy_label, v2_outcome, records[:limit])
        result["events"] = result.pop("entries")
        return result

    async def list_alarms(self, limit: int, archived: bool, hours: int) -> UniFiRecord:
        """Return controller alarms: the v2 critical log, or legacy archived alarms.

        Active alarms (``archived=False``) come from ``POST
        /v2/api/site/<site>/system-log/critical``, which Art-of-WiFi
        documents as the replacement for ``list/alarm`` on Network 10.x and
        later, with a legacy ``GET /list/alarm?archived=false`` fallback only
        when the v2 route is absent. The v2 log has no archived state, so
        ``archived=True`` can only read the legacy route, which Network 10.x
        answers with 400; that surfaces as an error naming both facts.
        """
        archived_flag = "true" if archived else "false"
        legacy_path = f"/list/alarm?archived={archived_flag}"
        legacy_label = self._legacy_label("GET", legacy_path)

        async def legacy(reason: str) -> UniFiRecord:
            try:
                records = await self._legacy_list(legacy_path)
            except UniFiError as legacy_exc:
                raise UniFiUnsupportedError(
                    f"list_alarms could not read alarms: {reason}, and "
                    f"{self._outcome(legacy_label, legacy_exc)}, so this is an "
                    f"error and not an empty result"
                ) from legacy_exc
            filtered = [r for r in records if bool(r.get("archived", False)) == archived]
            return self._legacy_envelope(legacy_label, reason, filtered[:limit])

        if archived:
            envelope = await legacy(
                "archived alarms exist only on the legacy route (the v2 "
                "system-log/critical log that replaces it has no archived state)"
            )
        else:
            v2_label = self._v2_label("POST", "/system-log/critical")
            try:
                envelope = await self._system_log("critical", hours, limit)
            except UniFiError as exc:
                if exc.status not in self._ROUTE_ABSENT:
                    raise UniFiError(
                        f"list_alarms could not read alarms: "
                        f"{self._outcome(v2_label, exc)}, so this is an error and "
                        f"not an empty result"
                    ) from exc
                envelope = await legacy(self._outcome(v2_label, exc))
        envelope["alarms"] = envelope.pop("entries")
        return envelope

    async def list_threat_detections(self, hours: int, limit: int, client: str) -> UniFiRecord:
        """Return IPS/IDS detections for the last ``hours``, newest first.

        Reads two v2 sources and merges them (see
        :mod:`mcp_unifi.clients.system_log`): ``POST /traffic-flows`` filtered
        to intrusion prevention (ports, signature, action) and ``POST
        /system-log/threat-alert`` (the console's alert, plus honeypot hits).

        Both failing raises with each path and status. One failing still
        returns what the other read, with ``complete: false`` and a
        ``warning`` naming the failure first in the envelope, because a
        partial list must never read as a full one. ``client`` (an IP or MAC,
        or ``""``) keeps only detections with that address at either end.
        """
        start_ms, end_ms = self._window(hours)
        if client and client_matcher(client) is None:
            raise UniFiError(f"client must be an IP address or a MAC address, got {client!r}")

        flows_path = "/traffic-flows"
        alerts_path = "/system-log/threat-alert"
        sources: list[dict[str, Any]] = []
        failures: list[str] = []
        failed_statuses: list[int | None] = []
        flows: list[dict[str, Any]] = []
        alerts: list[dict[str, Any]] = []

        flows_label = self._v2_label("POST", flows_path)
        try:
            rows, total, more = await self._v2_pages(
                flows_path, lambda page: ips_flow_body(start_ms, end_ms, page), MAX_SCAN_ROWS
            )
        except UniFiError as exc:
            failures.append(self._outcome(flows_label, exc))
            failed_statuses.append(exc.status)
            sources.append({"endpoint": flows_label, "ok": False, "error": failures[-1]})
        else:
            shaped = [d for d in (detection_from_flow(r) for r in rows) if d is not None]
            flows.extend(shaped)
            sources.append(
                {
                    "endpoint": flows_label,
                    "ok": True,
                    "rows_read": len(rows),
                    "rows_skipped_not_ips": len(rows) - len(shaped),
                    "total": total,
                    "more_available": more,
                }
            )

        alerts_label = self._v2_label("POST", alerts_path)
        try:
            rows, total, more = await self._v2_pages(
                alerts_path,
                lambda page: system_log_body("threat-alert", start_ms, end_ms, page),
                MAX_SCAN_ROWS,
            )
        except UniFiError as exc:
            failures.append(self._outcome(alerts_label, exc))
            failed_statuses.append(exc.status)
            sources.append({"endpoint": alerts_label, "ok": False, "error": failures[-1]})
        else:
            alerts.extend(detection_from_alert(r) for r in rows)
            sources.append(
                {
                    "endpoint": alerts_label,
                    "ok": True,
                    "rows_read": len(rows),
                    "total": total,
                    "more_available": more,
                }
            )

        if len(failures) == 2:
            all_absent = all(status in self._ROUTE_ABSENT for status in failed_statuses)
            error_cls = UniFiUnsupportedError if all_absent else UniFiError
            raise error_cls(
                f"list_threat_detections could not read IPS detections: {failures[0]}; "
                f"{failures[1]}; so this is an error and not an empty result"
            )

        return finish_detections(
            flows,
            alerts,
            sources=sources,
            failures=failures,
            window=(hours, start_ms, end_ms),
            client=client,
            limit=limit,
        )

    async def trigger_speedtest(self) -> UniFiRecord:
        return self._first_record(await self._post("/cmd/devmgr", {"cmd": "speedtest"}))

    async def get_speedtest_results(self, limit: int) -> list[UniFiRecord]:
        """Return recent WAN speed-test runs.

        Verified against UCG-Fiber fw 5.1.12.33296 (UniFi Network 9.x): the
        legacy ``GET /stat/report/archive.speedtest?_limit=...`` form returns
        sparse records that only carry ``_id``, ``oid``, and ``o`` — the
        metric fields are not projected. The current contract is a
        ``POST`` to the same path with an ``attrs`` projection list. The
        controller returns ``xput_upload`` (not the older ``xput_up``); we
        normalise it to ``xput_up`` so callers see the documented field name
        regardless of the controller version.
        """
        attrs = ["time", "xput_upload", "xput_download", "latency", "server"]
        payload: dict[str, Any] = {"attrs": attrs, "limit": limit}
        records = await self._post("/stat/report/archive.speedtest", payload) or []
        # The controller does not promise order or honour ``limit`` for us, so
        # both are applied here (newest first, then cut).
        return shape_speedtest_results(records, limit)

    async def list_top_talkers(self, limit: int) -> list[UniFiRecord]:
        """Rank the currently connected clients by bytes moved this session.

        Reads ``/stat/sta``, the same list ``list_clients`` returns. This used
        to read ``/stat/sitedpi``, which is a site-wide per-application report
        with no client in it, and which the 2026-06-12 live probe found empty
        on a UCG-Fiber (see :mod:`mcp_unifi.modules.network.stats`), so the
        tool answered ``[]`` on a real console. ``/stat/sta`` rows were probed
        the same day and carry ``tx_bytes``/``rx_bytes`` (wireless) and
        ``wired-tx_bytes``/``wired-rx_bytes`` (wired). The rows come back
        unranked, so rank, cut and project them here.
        """
        results = await self._get("/stat/sta") or []
        return shape_top_talkers(results, limit)

    # ------------------------------------------------------------------
    # Stats & insights (read-only observability — Wave C)
    # ------------------------------------------------------------------

    async def get_system_info(self) -> UniFiRecord:
        """Return controller/system info from ``/stat/sysinfo``.

        Probed live read-only against a UCG-Fiber on UniFi Network 10.4.57
        (2026-06-12): ``GET /stat/sysinfo`` answers HTTP 200 with the standard
        ``{"meta", "data"}`` envelope wrapping a single record carrying
        ``version``, ``build``, ``previous_version``, ``hostname``, ``name``,
        ``uptime``, ``ubnt_device_type``, ``udm_version``,
        ``console_display_version``, ``update_available`` and ``timezone``.
        Returns ``{}`` if the controller answers with no record.
        """
        result = await self._get("/stat/sysinfo")
        if isinstance(result, list) and result:
            first = result[0]
            return first if isinstance(first, dict) else {}
        return result if isinstance(result, dict) else {}

    async def get_client_by_mac(self, mac: str) -> UniFiRecord | None:
        """Return a single active client record by MAC from ``/stat/sta``.

        Probed live (2026-06-12): a client record carries ``signal``,
        ``rssi``, ``satisfaction``/``satisfaction_avg``, ``uptime``,
        ``tx_bytes``/``rx_bytes``, ``tx_rate``/``rx_rate``, ``tx_retries``,
        ``anomalies``, ``wifi_tx_attempts`` (wireless) and ``wired-tx_bytes``
        / ``wired_rate_mbps`` (wired). Returns ``None`` when the client is
        not currently connected.
        """
        clients = await self._get("/stat/sta") or []
        if not isinstance(clients, list):
            return None
        for client in clients:
            if isinstance(client, dict) and same_mac(client.get("mac"), mac):
                return client
        return None

    async def get_client_sessions(
        self, mac: str, start: int, end: int, limit: int
    ) -> list[UniFiRecord]:
        """Return recent client connection sessions from ``POST /stat/session``.

        Probed live (2026-06-12): ``POST /stat/session`` with a JSON body of
        ``{"type": "all", "start": <epoch_s>, "end": <epoch_s>}`` (plus an
        optional ``"mac"`` filter) answers HTTP 200 with the standard
        ``{"meta", "data"}`` envelope. Each session carries ``mac``,
        ``hostname``, ``name``, ``ip``, ``assoc_time``, ``duration`` (seconds),
        ``rx_bytes``/``tx_bytes``, ``is_wired``, ``is_guest``, ``ap_mac``,
        ``satisfaction`` and ``roaming_sessions``. ``start``/``end`` are epoch
        **seconds**. Results are sorted newest-first by ``assoc_time`` and
        bounded to ``limit``.
        """
        body: dict[str, Any] = {"type": "all", "start": start, "end": end}
        if mac:
            body["mac"] = normalize_mac(mac)
        records = await self._post("/stat/session", body) or []
        if not isinstance(records, list):
            return []
        ordered = sorted(
            (r for r in records if isinstance(r, dict)),
            key=lambda r: r.get("assoc_time", 0),
            reverse=True,
        )
        return ordered[:limit]

    async def get_anomalies(self) -> list[UniFiRecord]:
        """Return client-impacting anomalies from ``/stat/anomalies``.

        Probed live (2026-06-12): ``GET /stat/anomalies`` answers HTTP 200
        with the standard ``{"meta", "data"}`` envelope. Each record carries
        ``anomaly`` (an enum string such as ``USER_HIGH_TCP_LATENCY``),
        ``mac`` (the affected client), and ``timestamps`` (a list of epoch-ms
        occurrence times). Returns an empty list on a clean network.
        """
        result = await self._get("/stat/anomalies") or []
        return result if isinstance(result, list) else []

    # ------------------------------------------------------------------
    # Site settings (Threat Management, Honeypot, Teleport)
    # ------------------------------------------------------------------

    async def get_setting(self, key: str) -> UniFiRecord:
        """Return the single setting record for the given key.

        UniFi exposes per-key settings at two paths; both return the same
        envelope. We use ``/rest/setting/<key>`` because it matches the rest
        of this client. Returns ``{}`` when the controller has no record for
        the key (some keys are only materialised after the first write).

        Verified against UCG-Fiber fw 5.1.12.33296: keys include ``ips``
        (Threat Management + Honeypot) and ``teleport``.
        """
        record = await self._get(f"/rest/setting/{path_segment(key, 'key')}")
        if isinstance(record, list) and record:
            first = record[0]
            return first if isinstance(first, dict) else {}
        if isinstance(record, dict):
            return record
        return {}

    async def set_setting(self, key: str, patch: dict[str, Any]) -> UniFiRecord:
        """Partial-update a per-key setting record.

        UniFi accepts ``POST /set/setting/<key>`` with a partial JSON body;
        the controller merges the patch onto the existing record and returns
        the resulting setting. This is the same pattern the web UI uses and
        is more forgiving than ``PUT /rest/setting/<key>/<_id>`` (which
        sometimes drops untouched fields on older firmware).
        """
        record = await self._post(f"/set/setting/{path_segment(key, 'key')}", patch)
        if isinstance(record, list) and record:
            first = record[0]
            return first if isinstance(first, dict) else {}
        if isinstance(record, dict):
            return record
        return {}


__all__ = ["UniFiClient", "UniFiError", "UniFiUnsupportedError"]
