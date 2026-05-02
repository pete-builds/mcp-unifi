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

    async def list_clients(self) -> list[UniFiRecord]:
        """Return currently active wireless and wired clients on the gateway.

        Wraps the ``/stat/sta`` endpoint, which the controller uses to power the
        Insights → Clients view. Returns an empty list when no clients are
        connected (e.g. fresh deployment).
        """
        return await self._get("/stat/sta") or []
