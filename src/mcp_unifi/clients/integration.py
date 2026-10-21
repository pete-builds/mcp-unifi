"""Route network and WLAN writes through the official Integration API (ADR 0008).

The tools above this layer keep speaking the private API's shape: private
``_id`` values in, private ``networkconf``/``wlanconf`` records out. This
class sits behind :class:`~mcp_unifi.backends.RealBackend` and, per write,
either sends it through ``/proxy/network/integration/v1`` or hands it to the
private client unchanged. Callers cannot tell which surface ran, by design:
every return value is re-read from the private API.

The two surfaces share one identity. Each private record carries an
``external_id`` equal to its Integration API UUID (verified for every network
and WLAN on a UCG-Fiber, UniFi Network 10.6.106, 2026-10-17), so a private
``_id`` resolves to a v1 id through a private list read, with no second
lookup table to drift.

When the private path is used instead:

- ``write_api="private"`` on the controller.
- The payload does not map exactly (see :mod:`integration_translate`).
- The record has no ``external_id``, or its v1 site cannot be resolved.
- The Integration API answers with a definitive 4xx. A 4xx means the console
  refused the request and changed nothing, so the private write is safe.
- A v1 collection route answers 404, which means this firmware predates it.
  That is remembered for the life of the process.

When it is not: a 5xx, a timeout, or a dropped connection after the request
was sent. Those leave the outcome unknown, and replaying the write on the
other surface could apply it twice, so the error propagates exactly as a
private-path failure would.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Literal

from mcp_unifi.clients import integration_translate as tr
from mcp_unifi.clients.errors import UniFiError
from mcp_unifi.clients.ids import path_segment
from mcp_unifi.clients.retry import request_with_retry
from mcp_unifi.models import UniFiRecord

if TYPE_CHECKING:  # avoids an import cycle with clients.unifi
    from mcp_unifi.clients.unifi import UniFiClient

logger = logging.getLogger("mcp_unifi.integration")

WriteApi = Literal["auto", "private"]
ZoneFirewallState = Literal["configured", "legacy", "unsupported", "disabled"]

#: The 400 code a site still on legacy rulesets returns from v1 firewall routes.
ZBF_NOT_CONFIGURED = "api.firewall.zone-based-firewall-not-configured"


class IntegrationRejectedError(UniFiError):
    """The Integration API answered 4xx: the console refused and changed nothing."""

    def __init__(self, message: str, status: int, code: str | None, detail: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        #: The console's own ``message`` field: names the fields it wanted.
        self.detail = detail


class IntegrationWrites:
    """Per-controller router for network and WLAN writes, plus zone policies.

    Zone policies (ADR 0009) are Integration-API-only; see that section.
    """

    def __init__(self, client: UniFiClient, write_api: WriteApi = "auto") -> None:
        self.client = client
        self.write_api = write_api
        self._site_id: str | None = None
        #: Collections whose v1 route answered 404 on this firmware.
        self._absent: set[str] = set()

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def _request(self, method: str, path: str, json: dict[str, Any] | None = None) -> Any:
        url = f"{self.client._base}/integration/v1{path}"
        resp = await request_with_retry(
            self.client._client,
            method,
            url,
            logger=logger,
            service="UniFi Integration",
            error_cls=UniFiError,
            json=json,
        )
        if 400 <= resp.status_code < 500:
            code: str | None = None
            detail = ""
            try:
                body = resp.json()
                if isinstance(body, dict):
                    if isinstance(body.get("code"), str):
                        code = body["code"]
                    if isinstance(body.get("message"), str):
                        detail = body["message"][:300]
            except ValueError:
                pass
            raise IntegrationRejectedError(
                f"UniFi Integration {method} {path} returned {resp.status_code}: {resp.text[:300]}",
                resp.status_code,
                code,
                detail,
            )
        if resp.status_code >= 500:
            raise UniFiError(
                f"UniFi Integration {method} {path} returned {resp.status_code}: {resp.text[:300]}"
            )
        if not resp.content:
            return None
        return resp.json()

    async def _site(self) -> str | None:
        if self._site_id is None:
            body = await self._request("GET", "/sites?limit=200")
            sites = body.get("data", []) if isinstance(body, dict) else []
            for site in sites:
                if isinstance(site, dict) and site.get("internalReference") == self.client.site:
                    sid = site.get("id")
                    if isinstance(sid, str):
                        self._site_id = sid
        return self._site_id

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    @staticmethod
    def _external_id(records: list[UniFiRecord], private_id: str) -> str | None:
        for record in records:
            if record.get("_id") == private_id:
                ext = record.get("external_id")
                return ext if isinstance(ext, str) and ext else None
        return None

    @staticmethod
    def _by_external(records: list[UniFiRecord], external_id: str) -> UniFiRecord | None:
        for record in records:
            if record.get("external_id") == external_id:
                return record
        return None

    async def _default_ap_group(self) -> str | None:
        for group in await self.client.list_ap_groups():
            if isinstance(group, dict) and group.get("attr_hidden_id") == "default":
                gid = group.get("_id")
                return gid if isinstance(gid, str) else None
        return None

    def _enabled(self, collection: str) -> bool:
        return self.write_api == "auto" and collection not in self._absent

    def _fallback(self, op: str, exc: IntegrationRejectedError, collection: str) -> None:
        if exc.status == 404 and op == "create":
            self._absent.add(collection)
        logger.warning(
            "Integration API refused %s %s; using the private API",
            op,
            collection,
            extra={"status": exc.status, "code": exc.code, "detail": exc.detail},
        )

    def _used(self, op: str, collection: str, v1_id: str) -> None:
        logger.info(
            "%s %s via the Integration API",
            op,
            collection,
            extra={"write_api": "integration", "v1_id": v1_id},
        )

    # ------------------------------------------------------------------
    # Networks
    # ------------------------------------------------------------------

    async def create_network(self, payload: dict[str, Any]) -> UniFiRecord:
        body = tr.network_create_body(payload) if self._enabled("networks") else None
        if body is not None:
            try:
                site = await self._site()
                if site is not None:
                    created = await self._request("POST", f"/sites/{site}/networks", json=body)
                    v1_id = created.get("id") if isinstance(created, dict) else None
                    if isinstance(v1_id, str):
                        self._used("create", "networks", v1_id)
                        record = self._by_external(await self.client.list_networks(), v1_id)
                        return record if record is not None else {"external_id": v1_id, **payload}
            except IntegrationRejectedError as exc:
                self._fallback("create", exc, "networks")
        return await self.client.create_network(payload)

    async def update_network(self, network_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        if self._enabled("networks"):
            try:
                v1_id = self._external_id(await self.client.list_networks(), network_id)
                site = await self._site() if v1_id else None
                if v1_id and site:
                    url = f"/sites/{site}/networks/{path_segment(v1_id, 'network_id')}"
                    current = await self._request("GET", url)
                    body = (
                        tr.network_put_body(current, patch) if isinstance(current, dict) else None
                    )
                    if body is not None:
                        await self._request("PUT", url, json=body)
                        self._used("update", "networks", v1_id)
                        for record in await self.client.list_networks():
                            if record.get("_id") == network_id:
                                return record
                        return None
            except IntegrationRejectedError as exc:
                self._fallback("update", exc, "networks")
        return await self.client.update_network(network_id, patch)

    async def delete_network(self, network_id: str) -> bool:
        if self._enabled("networks"):
            try:
                v1_id = self._external_id(await self.client.list_networks(), network_id)
                site = await self._site() if v1_id else None
                if v1_id and site:
                    seg = path_segment(v1_id, "network_id")
                    await self._request("DELETE", f"/sites/{site}/networks/{seg}")
                    self._used("delete", "networks", v1_id)
                    return True
            except IntegrationRejectedError as exc:
                self._fallback("delete", exc, "networks")
        return await self.client.delete_network(network_id)

    # ------------------------------------------------------------------
    # WLANs
    # ------------------------------------------------------------------

    async def create_wlan(self, payload: dict[str, Any]) -> UniFiRecord:
        if self._enabled("wifi"):
            try:
                net_id = payload.get("networkconf_id")
                v1_net = (
                    self._external_id(await self.client.list_networks(), net_id)
                    if isinstance(net_id, str)
                    else None
                )
                body = tr.wlan_create_body(
                    payload,
                    v1_network_id=v1_net,
                    default_ap_group_id=await self._default_ap_group() if v1_net else None,
                )
                site = await self._site() if body is not None else None
                if body is not None and site is not None:
                    created = await self._request(
                        "POST", f"/sites/{site}/wifi/broadcasts", json=body
                    )
                    v1_id = created.get("id") if isinstance(created, dict) else None
                    if isinstance(v1_id, str):
                        self._used("create", "wifi", v1_id)
                        record = self._by_external(await self.client.list_wlans(), v1_id)
                        return record if record is not None else {"external_id": v1_id, **payload}
            except IntegrationRejectedError as exc:
                self._fallback("create", exc, "wifi")
        return await self.client.create_wlan(payload)

    async def update_wlan(self, wlan_id: str, patch: dict[str, Any]) -> UniFiRecord | None:
        if self._enabled("wifi"):
            try:
                v1_id = self._external_id(await self.client.list_wlans(), wlan_id)
                site = await self._site() if v1_id else None
                v1_net: str | None = None
                if isinstance(patch.get("networkconf_id"), str):
                    v1_net = self._external_id(
                        await self.client.list_networks(), patch["networkconf_id"]
                    )
                if v1_id and site:
                    url = f"/sites/{site}/wifi/broadcasts/{path_segment(v1_id, 'wlan_id')}"
                    current = await self._request("GET", url)
                    body = (
                        tr.wlan_put_body(current, patch, v1_network_id=v1_net)
                        if isinstance(current, dict)
                        else None
                    )
                    if body is not None:
                        await self._request("PUT", url, json=body)
                        self._used("update", "wifi", v1_id)
                        for record in await self.client.list_wlans():
                            if record.get("_id") == wlan_id:
                                return record
                        return None
            except IntegrationRejectedError as exc:
                self._fallback("update", exc, "wifi")
        return await self.client.update_wlan(wlan_id, patch)

    async def delete_wlan(self, wlan_id: str) -> bool:
        if self._enabled("wifi"):
            try:
                v1_id = self._external_id(await self.client.list_wlans(), wlan_id)
                site = await self._site() if v1_id else None
                if v1_id and site:
                    seg = path_segment(v1_id, "wlan_id")
                    await self._request("DELETE", f"/sites/{site}/wifi/broadcasts/{seg}")
                    self._used("delete", "wifi", v1_id)
                    return True
            except IntegrationRejectedError as exc:
                self._fallback("delete", exc, "wifi")
        return await self.client.delete_wlan(wlan_id)

    # ------------------------------------------------------------------
    # Zone-Based Firewall (ADR 0009)
    # ------------------------------------------------------------------
    #
    # Unlike networks and WLANs, nothing here falls back to the private API.
    # The private v2 write payloads for zone policies are undocumented, and a
    # site with no zones cannot be probed for them, so a fallback would be a
    # guess. A 4xx propagates with the console's own message instead.

    async def zone_firewall_state(self) -> ZoneFirewallState:
        """Whether this site runs the Zone-Based Firewall, read from v1.

        ``configured`` when ``firewall/zones`` answers 200; ``legacy`` when it
        answers 400 ``api.firewall.zone-based-firewall-not-configured`` (seen
        live on Network 10.6.106 before migration); ``unsupported`` when the
        route or the site is missing; ``disabled`` under ``write_api=private``,
        which never sends the request. Not cached: a site can migrate while the
        server runs. A 5xx or timeout raises, so a caller about to write
        stops before writing anything.
        """
        if self.write_api != "auto":
            return "disabled"
        site = await self._site()
        if site is None:
            return "unsupported"
        try:
            await self._request("GET", f"/sites/{site}/firewall/zones?limit=1")
        except IntegrationRejectedError as exc:
            if exc.code == ZBF_NOT_CONFIGURED:
                return "legacy"
            if exc.status == 404:
                return "unsupported"
            raise
        return "configured"

    async def _zbf_site(self) -> str:
        if self.write_api != "auto":
            raise UniFiError(
                "Zone-Based Firewall writes go through the Integration API only, "
                "and this controller is set to write_api=private"
            )
        site = await self._site()
        if site is None:
            raise UniFiError(
                f"Integration API has no site with internalReference {self.client.site!r}"
            )
        return site

    async def _list_all(self, path: str) -> list[UniFiRecord]:
        records: list[UniFiRecord] = []
        offset = 0
        while True:
            body = await self._request("GET", f"{path}?limit=200&offset={offset}")
            page = body.get("data", []) if isinstance(body, dict) else []
            records.extend(r for r in page if isinstance(r, dict))
            total = body.get("totalCount") if isinstance(body, dict) else None
            offset += len(page)
            if not page or not isinstance(total, int) or offset >= total:
                return records

    async def list_firewall_zones(self) -> list[UniFiRecord]:
        site = await self._zbf_site()
        return await self._list_all(f"/sites/{site}/firewall/zones")

    async def list_firewall_policies(self) -> list[UniFiRecord]:
        site = await self._zbf_site()
        return await self._list_all(f"/sites/{site}/firewall/policies")

    async def get_firewall_policy(self, policy_id: str) -> UniFiRecord | None:
        site = await self._zbf_site()
        seg = path_segment(policy_id, "policy_id")
        try:
            record = await self._request("GET", f"/sites/{site}/firewall/policies/{seg}")
        except IntegrationRejectedError as exc:
            if exc.status == 404:
                return None
            raise
        return record if isinstance(record, dict) else None

    async def create_firewall_policy(self, body: dict[str, Any]) -> UniFiRecord:
        site = await self._zbf_site()
        created = await self._request("POST", f"/sites/{site}/firewall/policies", json=body)
        if not isinstance(created, dict) or not isinstance(created.get("id"), str):
            raise UniFiError("Integration API created a firewall policy but returned no id")
        self._used("create", "firewall/policies", created["id"])
        return created

    async def update_firewall_policy(self, policy_id: str, body: dict[str, Any]) -> UniFiRecord:
        site = await self._zbf_site()
        seg = path_segment(policy_id, "policy_id")
        updated = await self._request("PUT", f"/sites/{site}/firewall/policies/{seg}", json=body)
        self._used("update", "firewall/policies", policy_id)
        return updated if isinstance(updated, dict) else {}

    async def delete_firewall_policy(self, policy_id: str) -> bool:
        site = await self._zbf_site()
        seg = path_segment(policy_id, "policy_id")
        await self._request("DELETE", f"/sites/{site}/firewall/policies/{seg}")
        self._used("delete", "firewall/policies", policy_id)
        return True
