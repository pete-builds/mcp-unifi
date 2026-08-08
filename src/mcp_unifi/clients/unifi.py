"""Async UniFi controller client.

Talks to a self-hosted UniFi gateway (UCG-Fiber, UDM, etc.) using a local API
key sent via the ``X-API-Key`` header. UniFi OS gateways expose the legacy
controller API behind the ``/proxy/network/`` prefix.

This client is intentionally narrow: only the endpoints called by the server
tools are wrapped. It is not a port of any reference implementation.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_unifi.clients.retry import request_with_retry
from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.client")


class UniFiError(RuntimeError):
    """Raised on any non-2xx response or transport failure."""


class UniFiUnsupportedError(UniFiError):
    """Raised when the controller firmware does not expose the requested route.

    Distinct from a generic :class:`UniFiError` so callers can tell "this
    controller version cannot answer that question" apart from "the call
    failed". Both surface to the operator as an error — which is the entire
    point. See :meth:`UniFiClient._get_or_unsupported` for why.
    """


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
        verify_ssl: bool = False,
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
            raise UniFiError(
                f"UniFi {method} {path} returned {resp.status_code}: {resp.text[:300]}"
            )
        if not resp.content:
            return None
        body = resp.json()
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
            raise UniFiError(
                f"UniFi {method} (v2) {path} returned {resp.status_code}: {resp.text[:300]}"
            )
        if not resp.content:
            return None
        return resp.json()

    async def _get(self, path: str) -> Any:
        return await self._request("GET", f"{self._site_path}{path}")

    async def _get_or_unsupported(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        feature: str = "",
    ) -> Any:
        """GET a route, raising :class:`UniFiUnsupportedError` if it is absent.

        HISTORY — do not revert this to returning ``[]``. This helper used to
        swallow 404 (``api.err.NotFound``) and 400 (``api.err.InvalidObject``)
        and return an empty list, on the theory that "no working alternative"
        justified a benign-looking answer. It does not. During the 2026-08-08
        outage ``list_events`` reported "no events" while the real answer was
        "this endpoint no longer exists on 10.5.67" — a plausible negative that
        cost real debugging time, because an empty result is indistinguishable
        from a quiet network.

        A tool that cannot answer must say so. Fabricating a successful-looking
        empty result is worse than failing loudly: the caller cannot tell the
        difference between "nothing happened" and "I cannot see anything".

        Genuine transport and auth failures propagate as before.
        """
        query = ""
        if params:
            query = "?" + "&".join(f"{k}={v}" for k, v in params.items())
        try:
            return await self._request("GET", f"{self._site_path}{path}{query}")
        except UniFiError as exc:
            text = str(exc)
            if " returned 404" in text or " returned 400" in text:
                label = feature or path
                logger.warning(
                    "UniFi route not exposed by this controller version",
                    extra={"path": path, "error": text[:200]},
                )
                raise UniFiUnsupportedError(
                    f"{label} is not available on this UniFi Network version. "
                    f"The controller answered: {text[:200]}. This is a "
                    f"firmware limitation, not an empty result — do not read "
                    f"it as 'nothing found'."
                ) from exc
            raise

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
        return self._first_record(await self._put(f"/rest/networkconf/{network_id}", payload))

    async def delete_network(self, network_id: str) -> bool:
        await self._delete(f"/rest/networkconf/{network_id}")
        return True

    async def list_wlans(self) -> list[UniFiRecord]:
        return await self._get("/rest/wlanconf") or []

    async def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/wlanconf", payload))

    async def update_wlan(self, wlan_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._put(f"/rest/wlanconf/{wlan_id}", payload))

    async def delete_wlan(self, wlan_id: str) -> bool:
        await self._delete(f"/rest/wlanconf/{wlan_id}")
        return True

    async def list_firewall_rules(self) -> list[UniFiRecord]:
        return await self._get("/rest/firewallrule") or []

    async def create_firewall_rule(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/firewallrule", payload))

    async def delete_firewall_rule(self, rule_id: str) -> bool:
        await self._delete(f"/rest/firewallrule/{rule_id}")
        return True

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
            raise UniFiError(f"UniFi GET apgroups returned {resp.status_code}: {resp.text[:300]}")
        if not resp.content:
            return []
        body = resp.json()
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
        return self._first_record(await self._put(f"/rest/firewallrule/{rule_id}", payload))

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
        return self._first_record(await self._put(f"/rest/firewallgroup/{group_id}", payload))

    async def delete_firewall_group(self, group_id: str) -> bool:
        await self._delete(f"/rest/firewallgroup/{group_id}")
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
        return self._first_record(await self._put(f"/rest/routing/{route_id}", payload))

    async def delete_route(self, route_id: str) -> bool:
        await self._delete(f"/rest/routing/{route_id}")
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
        result = await self._v2_request("PUT", f"/trafficrules/{rule_id}", json=payload)
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
        result = await self._v2_request("PUT", f"/trafficroutes/{route_id}", json=payload)
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
        result = await self._v2_request("PUT", f"/content-filtering/{filter_id}", json=payload)
        return self._first_record(result)

    async def delete_content_filter(self, filter_id: str) -> bool:
        await self._v2_request("DELETE", f"/content-filtering/{filter_id}")
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
        return self._first_record(await self._put(f"/rest/dynamicdns/{ddns_id}", payload))

    async def delete_dynamic_dns(self, ddns_id: str) -> bool:
        await self._delete(f"/rest/dynamicdns/{ddns_id}")
        return True

    # ------------------------------------------------------------------
    # Port profiles (create/update/delete)
    # ------------------------------------------------------------------

    async def create_port_profile(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/portconf", payload))

    async def update_port_profile(self, profile_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._put(f"/rest/portconf/{profile_id}", payload))

    async def delete_port_profile(self, profile_id: str) -> bool:
        await self._delete(f"/rest/portconf/{profile_id}")
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
                f"/rest/device/{device_id}",
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
        return self._first_record(await self._put(f"/rest/device/{device_id}", payload))

    async def get_device(self, device_id: str) -> UniFiRecord:
        result = await self._get(f"/stat/device/{device_id}")
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
        target = mac.lower()
        for u in users:
            if isinstance(u, dict) and str(u.get("mac", "")).lower() == target:
                return u
        return None

    async def create_dhcp_lease(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/user", payload))

    async def update_dhcp_lease(self, user_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._put(f"/rest/user/{user_id}", payload))

    async def delete_dhcp_lease(self, lease_id: str) -> bool:
        await self._delete(f"/rest/user/{lease_id}")
        return True

    # ------------------------------------------------------------------
    # Port forwarding (CRUD via /rest/portforward)
    # ------------------------------------------------------------------

    async def list_port_forwards(self) -> list[UniFiRecord]:
        return await self._get("/rest/portforward") or []

    async def create_port_forward(self, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._post("/rest/portforward", payload))

    async def update_port_forward(self, forward_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._first_record(await self._put(f"/rest/portforward/{forward_id}", payload))

    async def delete_port_forward(self, forward_id: str) -> bool:
        await self._delete(f"/rest/portforward/{forward_id}")
        return True

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    async def get_site_health(self) -> list[UniFiRecord]:
        return await self._get("/stat/health") or []

    async def list_events(self, limit: int) -> list[UniFiRecord]:
        """Return recent controller events, newest first.

        Probed live against a UCG-Fiber on UniFi Network 10.4.57 (2026-06-03):
        the legacy event log route is **not exposed** on this firmware via the
        local API-key surface. ``GET``/``POST /stat/event`` both return HTTP 404
        (``api.err.NotFound``), the v2 (``/v2/api/site/default/...``) tree has no
        event path, and the official Integration API (``/integration/v1/...``)
        has no events resource. ``/rest/event`` answers 400
        (``api.err.InvalidObject``) — it is a config collection, not a log
        reader. The 404 is route-absence, not a scope gate: sibling ``stat/*``
        routes (``stat/sta``, ``stat/rogueap``, ``stat/health``) all return 200
        with the same key.

        Re-probed live on **UniFi Network 10.5.67** (2026-08-08), on a settled
        controller (not mid-restart), with a valid key and ``stat/sysinfo``
        answering 200 as the control:

        * ``GET  /stat/event``            → 404 ``api.err.NotFound``
        * ``POST /stat/event``            → 404 ``api.err.NotFound``
        * ``GET  /rest/event``            → 400 ``api.err.InvalidObject``
        * ``POST /rest/event``            → 400 ``api.err.InvalidObject``
        * ``GET  /list/event``            → 400 ``api.err.InvalidObject``
        * v2 ``/event``, ``/events``, ``/system-log`` → 404

        The 400 ``InvalidObject`` on ``rest/event`` is UniFi's "that is not a
        REST collection" error, not a request-shape complaint — the whole
        event surface is gone from the local API-key interface on this version.

        We still attempt ``GET /stat/event`` for forward compatibility, but a
        missing route now raises :class:`UniFiUnsupportedError` instead of
        returning ``[]``. Reporting "no events" when the truth is "I cannot
        see events" is a fabricated negative; see
        :meth:`_get_or_unsupported`.
        """
        records = await self._get_or_unsupported(
            "/stat/event",
            params={"_limit": limit, "_sort": "-time"},
            feature="Controller event log (list_events)",
        )
        return records if isinstance(records, list) else []

    async def list_alarms(self, limit: int, archived: bool) -> list[UniFiRecord]:
        """Return controller alarms, active or archived, newest first.

        Probed live against a UCG-Fiber on UniFi Network 10.4.57 (2026-06-03):
        the working route is ``GET /proxy/network/api/s/{site}/list/alarm``,
        which returns HTTP 200 with the standard ``{"meta", "data"}`` envelope
        and honours a server-side ``?archived=<bool>`` filter. The previously
        shipped ``POST /stat/alarm`` form returns HTTP 404 on this firmware and
        is abandoned.

        We pass ``archived`` through as the server-side query filter and also
        apply a defensive client-side filter, then bound the result to
        ``limit``. Alarm records carry the originating client MAC
        (``user`` / ``sta``), AP MAC (``ap``), ``ssid``, ``subsystem``,
        ``key``, ``msg``, and ``time`` / ``datetime`` fields, which pass
        straight through to callers.

        REGRESSION on **UniFi Network 10.5.67** (re-probed 2026-08-08 on a
        settled controller, ``stat/sysinfo`` 200 as the control): the route
        that worked on 10.4.57 now answers 400 ``api.err.InvalidObject``:

        * ``GET  /list/alarm``            → 400 ``api.err.InvalidObject``
        * ``GET  /list/alarm?archived=…`` → 400 ``api.err.InvalidObject``
        * ``GET  /rest/alarm``            → 400 ``api.err.InvalidObject``
        * ``POST /stat/alarm``            → 404 ``api.err.NotFound``

        No working alarm route was found on this version. The call therefore
        raises :class:`UniFiUnsupportedError` rather than returning ``[]`` —
        "zero alarms" and "I cannot read alarms" must not look identical to
        the caller.
        """
        archived_flag = "true" if archived else "false"
        records = (
            await self._get_or_unsupported(
                f"/list/alarm?archived={archived_flag}",
                feature="Controller alarm log (list_alarms)",
            )
            or []
        )
        if not isinstance(records, list):
            return []
        filtered = [
            rec
            for rec in records
            if isinstance(rec, dict) and bool(rec.get("archived", False)) == archived
        ]
        return filtered[:limit]

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
        if not isinstance(records, list):
            return []
        normalised: list[UniFiRecord] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            entry = dict(rec)
            if "xput_upload" in entry and "xput_up" not in entry:
                entry["xput_up"] = entry["xput_upload"]
            normalised.append(entry)
        return normalised

    async def list_top_talkers(self, limit: int) -> list[UniFiRecord]:
        # DPI by-station report; aggregated bytes per client.
        results = await self._get("/stat/sitedpi") or []
        return results[:limit] if isinstance(results, list) else []

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
        target = mac.lower()
        for client in clients:
            if isinstance(client, dict) and str(client.get("mac", "")).lower() == target:
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
            body["mac"] = mac.lower()
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
        record = await self._get(f"/rest/setting/{key}")
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
        record = await self._post(f"/set/setting/{key}", patch)
        if isinstance(record, list) and record:
            first = record[0]
            return first if isinstance(first, dict) else {}
        if isinstance(record, dict):
            return record
        return {}
