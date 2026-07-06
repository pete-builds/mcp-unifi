"""Shared HTTP retry policy for the UniFi service clients.

Two transient-failure retries are layered here, both intentionally narrow:

1. **Connection blips** (``ConnectError`` / ``RemoteProtocolError``) are retried
   exactly once, preserving the original single-retry behaviour of every client.

2. **5xx responses on idempotent GET reads** are retried with exponential
   backoff (a couple of attempts). This covers the transient ``503`` a UniFi
   gateway hands back under load or during a firmware upgrade.

Writes and mutations are **never** retried on a 5xx. The server drives every
change through a dry-run/confirm/rollback model, and a blindly retried
``POST``/``PUT``/``DELETE`` could double-apply. Only ``GET`` — the idempotent
read verb — is eligible for the 5xx retry.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

# The only HTTP method whose 5xx responses are safe to replay: an idempotent
# read. Writes go through the dry-run/confirm/rollback path and are never
# retried on 5xx.
_RETRYABLE_5XX_METHOD = "GET"

# Extra GET attempts after the first on a 5xx (so total attempts = 1 + this).
MAX_5XX_RETRIES = 2

# Exponential backoff base, in seconds. The sleep before retry ``n`` (0-indexed)
# is ``BACKOFF_BASE_SECONDS * 2 ** n`` → 0.25s then 0.50s with the default base.
# Exposed as a module attribute so the test suite can monkeypatch it to 0 and
# keep 5xx-path tests fast.
BACKOFF_BASE_SECONDS = 0.25


def _is_retryable_5xx(method: str, status_code: int) -> bool:
    """True only for a 5xx on an idempotent GET read."""
    return method.upper() == _RETRYABLE_5XX_METHOD and 500 <= status_code < 600


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    logger: logging.Logger,
    service: str,
    error_cls: type[Exception],
    json: dict[str, Any] | None = None,
) -> httpx.Response:
    """Issue an HTTP request, retrying only transient, safe-to-repeat failures.

    Retries applied:
      * One retry on ``ConnectError`` / ``RemoteProtocolError`` (network blip),
        matching every client's original single-retry behaviour.
      * Up to :data:`MAX_5XX_RETRIES` extra attempts on a 5xx response, but ONLY
        for idempotent ``GET`` requests, with exponential backoff. Non-GET verbs
        return their 5xx response immediately (the caller raises) so a write is
        never replayed.

    Returns the final :class:`httpx.Response` unconditionally on any status; the
    caller owns turning a ``>= 400`` status into ``error_cls`` so route-specific
    messages and 404-tolerant handling stay at the call site. ``error_cls`` is
    raised here only when the connection retry is exhausted or a non-connection
    transport error occurs.

    Args:
        client: Shared async httpx client (carries auth headers + pooling).
        method: HTTP verb. Only ``GET`` is eligible for the 5xx retry.
        url: Fully-qualified request URL.
        logger: Client logger used for retry warnings.
        service: Human label for log/error messages ("UniFi", "Protect", ...).
        error_cls: Exception type raised on transport failure (e.g. ``UniFiError``).
        json: Optional JSON body for write verbs.

    Example:
        resp = await request_with_retry(
            self._client, "GET", url,
            logger=logger, service="UniFi", error_cls=UniFiError,
        )
    """
    connect_retried = False
    fivexx_attempt = 0
    while True:
        try:
            resp = await client.request(method, url, json=json)
        except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            if not connect_retried:
                connect_retried = True
                logger.warning(
                    "%s connection error, retrying once",
                    service,
                    extra={"method": method, "url": url, "error": str(exc)},
                )
                continue
            raise error_cls(f"{service} connection failed: {exc}") from exc
        except httpx.HTTPError as exc:
            raise error_cls(f"{service} transport error: {exc}") from exc

        if _is_retryable_5xx(method, resp.status_code) and fivexx_attempt < MAX_5XX_RETRIES:
            delay = BACKOFF_BASE_SECONDS * (2**fivexx_attempt)
            logger.warning(
                "%s %s returned %s; retrying idempotent read in %.2fs (attempt %d of %d)",
                service,
                method,
                resp.status_code,
                delay,
                fivexx_attempt + 1,
                MAX_5XX_RETRIES,
                extra={"url": url, "status": resp.status_code},
            )
            fivexx_attempt += 1
            await asyncio.sleep(delay)
            continue

        return resp


__all__ = ["BACKOFF_BASE_SECONDS", "MAX_5XX_RETRIES", "request_with_retry"]
