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

from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.client")


class UniFiError(RuntimeError):
    """Raised on any non-2xx response or transport failure."""


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
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                resp = await self._client.request(method, url, json=json)
            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt == 0:
                    logger.warning(
                        "UniFi connection error, retrying once",
                        extra={"method": method, "path": path, "error": str(exc)},
                    )
                    continue
                raise UniFiError(f"UniFi connection failed: {exc}") from exc
            except httpx.HTTPError as exc:
                raise UniFiError(f"UniFi transport error: {exc}") from exc

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

        # Defensive — the loop above should always return or raise.
        raise UniFiError(f"UniFi request exhausted retries: {last_exc}")  # pragma: no cover

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
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                resp = await self._client.request("GET", url)
            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt == 0:
                    logger.warning(
                        "UniFi connection error, retrying once",
                        extra={"method": "GET", "path": "/v2/.../apgroups", "error": str(exc)},
                    )
                    continue
                raise UniFiError(f"UniFi connection failed: {exc}") from exc
            except httpx.HTTPError as exc:
                raise UniFiError(f"UniFi transport error: {exc}") from exc

            if resp.status_code >= 400:
                raise UniFiError(
                    f"UniFi GET apgroups returned {resp.status_code}: {resp.text[:300]}"
                )
            if not resp.content:
                return []
            body = resp.json()
            # v2 endpoint returns a bare list (not the legacy meta+data envelope).
            if isinstance(body, list):
                return body
            if isinstance(body, dict) and "data" in body:
                return body["data"] if isinstance(body["data"], list) else []
            return []

        raise UniFiError(  # pragma: no cover
            f"UniFi apgroups request exhausted retries: {last_exc}"
        )

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
        return await self._get(f"/stat/event?_limit={limit}") or []

    async def list_alarms(self, limit: int, archived: bool) -> list[UniFiRecord]:
        archived_str = "true" if archived else "false"
        return await self._get(f"/stat/alarm?archived={archived_str}&_limit={limit}") or []

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
