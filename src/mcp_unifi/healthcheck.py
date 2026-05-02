"""Health check used by the Docker HEALTHCHECK directive.

Streamable HTTP exposes a single ``/mcp`` endpoint that responds to a bare
GET with HTTP 405/406 (the transport rejects non-streaming requests). Treat
that as healthy: it confirms the FastMCP server is listening and routing.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

_HEALTHY_NON_OK_CODES: frozenset[int] = frozenset({400, 405, 406})


def check() -> int:
    """Return 0 if the server is healthy, 1 otherwise. Pure function for tests."""
    port = os.getenv("MCP_PORT", "3714")
    url = f"http://localhost:{port}/mcp"
    try:
        urllib.request.urlopen(url, timeout=5)  # noqa: S310 - localhost only
        return 0
    except urllib.error.HTTPError as exc:
        return 0 if exc.code in _HEALTHY_NON_OK_CODES else 1
    except Exception:
        return 1


def main() -> None:
    sys.exit(check())


if __name__ == "__main__":
    main()
