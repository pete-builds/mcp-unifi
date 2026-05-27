"""Async UniFi Access client.

Talks to the UniFi Access service (door controllers, NFC readers, credentials,
visitor passes, badge-scan events). Uses the local Access API key on port
``12445`` via the ``X-API-Key`` header, mirroring the Network and Protect
clients. Base path is ``/proxy/access/api/v2``.

The v0.10 surface is read-only by design: the Access API key only authorises
GETs; door unlocks, credential issuance, and visitor-pass creation require a
separate session-token flow that v0.10 does not implement (see the spec doc
``docs/v0.10-access-module.md``, Option B is the deferred write path).

Like :class:`ProtectClient`, responses are NOT wrapped in a ``{"meta":...,
"data":...}`` envelope. Each method returns either a list of records or a
single record. Retries one ``ConnectError`` and surfaces transport faults as
:class:`UniFiError` so all three module clients share one exception class.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.access_client")


class AccessClient:
    """Thin async wrapper around the UniFi Access REST API.

    Args:
        host: Access hub / gateway IP or hostname (no scheme).
        api_key: Local Access API key. Sent as ``X-API-Key`` on every request.
        port: HTTPS port. Defaults to 12445 (the direct Access app port).
        verify_ssl: Verify the controller's TLS cert. Access hubs ship with a
            self-signed cert; defaults to ``False`` to match Network/Protect.
        timeout: Per-request timeout in seconds. Reads are fast so 15s is
            plenty; longer timeouts only matter for the write path that
            v0.10 does not expose.
    """

    def __init__(
        self,
        host: str,
        api_key: str,
        port: int = 12445,
        verify_ssl: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.host = host
        self.port = port
        self._base = f"https://{host}:{port}/proxy/access/api/v2"
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
        """Issue a JSON-returning request with one retry on ConnectError.

        Errors and transport faults surface as :class:`UniFiError` so callers
        share one exception class with the Network and Protect clients.
        """
        url = f"{self._base}{path}"
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                resp = await self._client.request(method, url, json=json)
            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt == 0:
                    logger.warning(
                        "Access connection error, retrying once",
                        extra={"method": method, "path": path, "error": str(exc)},
                    )
                    continue
                raise UniFiError(f"Access connection failed: {exc}") from exc
            except httpx.HTTPError as exc:
                raise UniFiError(f"Access transport error: {exc}") from exc

            if resp.status_code >= 400:
                raise UniFiError(
                    f"Access {method} {path} returned {resp.status_code}: {resp.text[:300]}"
                )
            if not resp.content:
                return None
            return resp.json()

        raise UniFiError(f"Access request exhausted retries: {last_exc}")  # pragma: no cover

    @staticmethod
    def _ensure_record(result: Any) -> UniFiRecord:
        if isinstance(result, list) and result:
            first = result[0]
            return first if isinstance(first, dict) else {}
        if isinstance(result, dict):
            return result
        return {}

    @staticmethod
    def _ensure_list(result: Any) -> list[UniFiRecord]:
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
        return []

    # ------------------------------------------------------------------
    # Doors
    # ------------------------------------------------------------------

    async def list_doors(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/doors"))

    async def get_door(self, door_id: str) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", f"/doors/{door_id}"))

    async def list_door_groups(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/door_groups"))

    # ------------------------------------------------------------------
    # Access policies
    # ------------------------------------------------------------------

    async def list_access_policies(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/access_policies"))

    async def get_access_policy(self, policy_id: str) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", f"/access_policies/{policy_id}"))

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    async def list_credentials(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/credentials"))

    async def get_credential(self, credential_id: str) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", f"/credentials/{credential_id}"))

    # ------------------------------------------------------------------
    # Visitors
    # ------------------------------------------------------------------

    async def list_visitors(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/visitors"))

    async def get_visitor(self, visitor_id: str) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", f"/visitors/{visitor_id}"))

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    async def list_events(
        self,
        start_ms: int,
        end_ms: int,
        limit: int,
        result: str = "",
        door_id: str = "",
    ) -> list[UniFiRecord]:
        """List badge-scan / door events with optional filters.

        ``result`` filters by outcome (``"granted"``, ``"denied"``); empty
        returns both. ``door_id`` narrows to one door; empty returns events
        across every door. ``start_ms`` / ``end_ms`` are epoch milliseconds.
        """
        parts = [f"start={start_ms}", f"end={end_ms}", f"limit={limit}"]
        if result:
            parts.append(f"result={result}")
        if door_id:
            parts.append(f"door_id={door_id}")
        query = "&".join(parts)
        return self._ensure_list(await self._request("GET", f"/events?{query}"))

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    async def list_devices(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/devices"))

    async def get_device(self, device_id: str) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", f"/devices/{device_id}"))

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    async def get_system_info(self) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", "/system/info"))

    async def list_users(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/users"))


__all__ = ["AccessClient"]
