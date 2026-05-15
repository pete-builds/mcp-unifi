"""Async UniFi Protect client.

Talks to the Protect service running on a UniFi OS gateway (UDM Pro, UCG-Fiber
in NVR mode, etc.) using the same local API key as the Network client, sent
via the ``X-API-Key`` header. Modern UniFi OS 3.x accepts a single API key
across both Network (``/proxy/network``) and Protect (``/proxy/protect/api``).

Unlike the Network API, Protect responses are NOT wrapped in a
``{"meta": ..., "data": ...}`` envelope: endpoints return raw JSON objects
and arrays. Snapshot / thumbnail endpoints return binary JPEG bytes, so a
separate :meth:`_request_bytes` helper exists for those.

This client is intentionally narrow: only the endpoints called by the Protect
module tools are wrapped. Same retry shape as :class:`UniFiClient` (one retry
on ``ConnectError``).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.models import UniFiRecord

logger = logging.getLogger("mcp_unifi.protect_client")


class ProtectClient:
    """Thin async wrapper around the UniFi Protect REST API.

    Args:
        host: Gateway / NVR IP or hostname (no scheme).
        api_key: Local API key from Settings -> Control Plane -> Integrations.
        port: HTTPS port (default 443 for UniFi OS).
        verify_ssl: Verify the gateway's TLS cert. Self-hosted gateways ship
            with a self-signed cert, so this is False by default.
        timeout: Per-request timeout in seconds. Protect snapshots can take
            a moment, so the default is bumped to 30s.
    """

    def __init__(
        self,
        host: str,
        api_key: str,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self._base = f"https://{host}:{port}/proxy/protect/api"
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

        Protect responses are raw JSON (no ``{"data": ...}`` envelope). Errors
        and transport faults surface as :class:`UniFiError` so callers share
        one exception class with the Network client.
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
                        "Protect connection error, retrying once",
                        extra={"method": method, "path": path, "error": str(exc)},
                    )
                    continue
                raise UniFiError(f"Protect connection failed: {exc}") from exc
            except httpx.HTTPError as exc:
                raise UniFiError(f"Protect transport error: {exc}") from exc

            if resp.status_code >= 400:
                raise UniFiError(
                    f"Protect {method} {path} returned {resp.status_code}: {resp.text[:300]}"
                )
            if not resp.content:
                return None
            return resp.json()

        # Defensive — the loop above should always return or raise.
        raise UniFiError(f"Protect request exhausted retries: {last_exc}")  # pragma: no cover

    async def _request_bytes(self, method: str, path: str) -> bytes:
        """Issue a binary-returning request (snapshots, thumbnails) with one retry.

        Same retry shape as :meth:`_request` but does not call ``resp.json``.
        """
        url = f"{self._base}{path}"
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                resp = await self._client.request(method, url)
            except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt == 0:
                    logger.warning(
                        "Protect connection error (bytes), retrying once",
                        extra={"method": method, "path": path, "error": str(exc)},
                    )
                    continue
                raise UniFiError(f"Protect connection failed: {exc}") from exc
            except httpx.HTTPError as exc:
                raise UniFiError(f"Protect transport error: {exc}") from exc

            if resp.status_code >= 400:
                raise UniFiError(
                    f"Protect {method} {path} returned {resp.status_code}: {resp.text[:300]}"
                )
            return resp.content

        raise UniFiError(f"Protect bytes request exhausted retries: {last_exc}")  # pragma: no cover

    @staticmethod
    def _ensure_record(result: Any) -> UniFiRecord:
        """Normalise a response that may come back as a 1-item list (rare on Protect)."""
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
    # Cameras
    # ------------------------------------------------------------------

    async def list_cameras(self) -> list[UniFiRecord]:
        return self._ensure_list(await self._request("GET", "/cameras"))

    async def get_camera(self, camera_id: str) -> UniFiRecord:
        return self._ensure_record(await self._request("GET", f"/cameras/{camera_id}"))

    async def update_camera(self, camera_id: str, payload: dict[str, Any]) -> UniFiRecord:
        return self._ensure_record(
            await self._request("PATCH", f"/cameras/{camera_id}", json=payload)
        )

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    async def list_events(
        self, types: list[str], start_ms: int, end_ms: int, limit: int
    ) -> list[UniFiRecord]:
        """List events filtered by type and time window.

        UniFi Protect's event endpoint accepts repeated ``types[]`` query
        params (e.g. ``types[]=motion&types[]=smartDetectZone``) plus
        ``start`` / ``end`` (epoch milliseconds) and ``limit``.
        """
        parts: list[str] = []
        for t in types:
            parts.append(f"types[]={t}")
        parts.append(f"start={start_ms}")
        parts.append(f"end={end_ms}")
        parts.append(f"limit={limit}")
        query = "&".join(parts)
        return self._ensure_list(await self._request("GET", f"/events?{query}"))

    # ------------------------------------------------------------------
    # Snapshots / thumbnails (binary)
    # ------------------------------------------------------------------

    async def get_snapshot(self, camera_id: str) -> bytes:
        return await self._request_bytes("GET", f"/cameras/{camera_id}/snapshot")

    async def get_event_thumbnail(self, event_id: str) -> bytes:
        return await self._request_bytes("GET", f"/events/{event_id}/thumbnail")

    # ------------------------------------------------------------------
    # Recordings
    # ------------------------------------------------------------------

    async def list_recordings(
        self, camera_id: str, start_ms: int, end_ms: int
    ) -> list[UniFiRecord]:
        query = f"camera={camera_id}&start={start_ms}&end={end_ms}"
        return self._ensure_list(await self._request("GET", f"/recordings?{query}"))


__all__ = ["ProtectClient"]
