"""Health check used by the Docker HEALTHCHECK directive.

Hits the dedicated ``/health`` endpoint exposed by ``build_server``. The
endpoint returns 200 with a small JSON body (``{"status": "ok", "version":
...}``) and is intentionally separate from ``/mcp`` so the streamable-http MCP
transport doesn't log noise on every healthcheck interval. This check gates on
the 200 status code only, never the body, so the response shape can evolve
without breaking the Docker HEALTHCHECK.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request


def check() -> int:
    """Return 0 if the server is healthy, 1 otherwise. Pure function for tests."""
    port = os.getenv("MCP_PORT", "3714")
    url = f"http://localhost:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - localhost only
            return 0 if resp.status == 200 else 1
    except urllib.error.HTTPError:
        return 1
    except Exception:
        return 1


def main() -> None:
    sys.exit(check())


if __name__ == "__main__":
    main()
