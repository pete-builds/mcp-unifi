"""Probe which resources the official UniFi Integration API exposes on a console.

ADR 0005 keeps every write on the private Network API because, when it was
written, the official Integration API (``/proxy/network/integration/v1``)
exposed only devices and clients. Its reversal condition is a live re-probe,
not release notes. This script is that re-probe, made repeatable.

It is read-only by construction: every request it sends is a GET. It never
prints the API key or a response body. What it prints is status codes, item
counts, the first item's field names, the error ``code`` from a 4xx envelope,
and network and firewall-zone names for the cross-check against the private
API this server uses today.

Two controls run first, because without them a 404 and a missing feature look
identical:

- a request with a deliberately wrong API key must be rejected (401/403);
- a request to a route that cannot exist must return 404.

If either control fails, the results are not trustworthy and the script exits 2.

Configuration uses the single-controller env vars the server reads:
``UNIFI_HOST``, ``UNIFI_PORT`` (default 443), ``UNIFI_SITE`` (default
``default``), ``UNIFI_API_KEY`` or ``UNIFI_API_KEY_FILE``, ``UNIFI_VERIFY_SSL``
(default false, per ADR 0003) and ``UNIFI_PINNED_CERT``. It depends only on the
standard library and ``httpx``, so it runs from a checkout or piped into a
running container, which already holds the env vars:

    python scripts/probe_integration_api.py
    python scripts/probe_integration_api.py --json
    docker exec -i mcp-unifi python - < scripts/probe_integration_api.py

Exit codes: 0 probe ran and both controls held; 1 configuration error or the
site could not be resolved; 2 a control failed.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
from pathlib import Path
from typing import Any

import httpx

#: Official v1 list endpoints, relative to ``/v1/sites/{siteId}/``. Taken from
#: developer.ui.com for UniFi Network 10.6.106. ``devices`` and ``clients`` are
#: the two ADR 0005 found on 10.4.57; the rest are what a re-probe looks for.
V1_RESOURCES: tuple[str, ...] = (
    "devices",
    "clients",
    "networks",
    "wifi/broadcasts",
    "firewall/zones",
    "firewall/policies",
    "acl-rules",
    "dns/policies",
    "traffic-matching-lists",
    "wans",
    "vpn/servers",
    "vpn/site-to-site-tunnels",
    "radius/profiles",
    "device-tags",
    "hotspot/vouchers",
)

CONTROL_KEY = "invalid-control-key"  # deliberately wrong, never a secret
CONTROL_ROUTE = "definitely-not-a-route"

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_CONTROL_FAILED = 2


class ProbeError(Exception):
    """Configuration or site-resolution failure; the probe cannot run."""


def classify(status: int) -> str:
    """Name what a status code says about whether a resource exists.

    A 4xx other than 401/403/404 means the route answered and refused this
    request, for example ``api.firewall.zone-based-firewall-not-configured``.
    That is a route that exists, which is the distinction the 404 control is
    there to make.
    """
    if status == 200:
        return "present"
    if status == 404:
        return "absent"
    if status in (401, 403):
        return "denied"
    if 400 <= status < 500:
        return "present-not-configured"
    return "error"


def _json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


def _items(body: Any) -> tuple[list[dict[str, Any]], int | None]:
    """Pull the record list and total out of either envelope shape.

    The Integration API pages as ``{"data": [...], "totalCount": N}``; the
    private API wraps as ``{"data": [...]}``; some v2 routes return a bare list.
    """
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)], len(body)
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        data = [x for x in body["data"] if isinstance(x, dict)]
        total = body.get("totalCount")
        return data, total if isinstance(total, int) else len(data)
    return [], None


def _error_code(body: Any) -> str | None:
    if isinstance(body, dict):
        code = body.get("code")
        if isinstance(code, str):
            return code
    return None


def _names(records: list[dict[str, Any]]) -> set[str]:
    return {r["name"] for r in records if isinstance(r.get("name"), str)}


def probe(client: httpx.Client, base: str, site: str) -> dict[str, Any]:
    """Run the controls, the v1 sweep and the private-API cross-check.

    ``client`` must already carry the real ``X-API-Key`` header. ``base`` is
    ``https://<host>:<port>/proxy/network``. Returns a JSON-serialisable report
    holding no response bodies and no key.
    """
    v1 = f"{base}/integration/v1"
    report: dict[str, Any] = {"controls": {}, "v1": {}, "cross_check": {}}
    controls = report["controls"]

    bogus = client.get(f"{v1}/info", headers={"X-API-Key": CONTROL_KEY})
    controls["bogus_key_status"] = bogus.status_code
    controls["bogus_key_rejected"] = bogus.status_code in (401, 403)

    info = client.get(f"{v1}/info")
    info_body = _json(info)
    report["info_status"] = info.status_code
    report["application_version"] = (
        info_body.get("applicationVersion") if isinstance(info_body, dict) else None
    )

    sites_resp = client.get(f"{v1}/sites", params={"limit": 200})
    sites, _ = _items(_json(sites_resp))
    site_id = next(
        (s.get("id") for s in sites if s.get("internalReference") == site),
        None,
    )
    if not isinstance(site_id, str):
        raise ProbeError(
            f"GET /v1/sites returned {sites_resp.status_code} with {len(sites)} site(s); "
            f"none has internalReference {site!r}. The Integration API addresses sites "
            f"by UUID, so nothing past this point can be probed."
        )

    route = client.get(f"{v1}/sites/{site_id}/{CONTROL_ROUTE}")
    controls["bogus_route_status"] = route.status_code
    controls["bogus_route_absent"] = route.status_code == 404
    controls["passed"] = controls["bogus_key_rejected"] and controls["bogus_route_absent"]

    records: dict[str, list[dict[str, Any]]] = {}
    for resource in V1_RESOURCES:
        resp = client.get(f"{v1}/sites/{site_id}/{resource}", params={"limit": 200})
        body = _json(resp)
        items, total = _items(body) if resp.status_code == 200 else ([], None)
        records[resource] = items
        report["v1"][resource] = {
            "status": resp.status_code,
            "verdict": classify(resp.status_code),
            "total": total,
            "error_code": None if resp.status_code == 200 else _error_code(body),
            "fields": sorted(items[0].keys()) if items else [],
        }

    cross = report["cross_check"]
    priv = f"{base}/api/s/{site}"
    v2 = f"{base}/v2/api/site/{site}"

    resp = client.get(f"{priv}/rest/networkconf")
    nets, _ = _items(_json(resp))
    a, b = _names(records["networks"]), _names(nets)
    cross["networks"] = {
        "private_status": resp.status_code,
        "v1": len(records["networks"]),
        "private": len(nets),
        "only_in_v1": sorted(a - b),
        "only_in_private": sorted(b - a),
    }

    # WLAN names only as a match flag and an overlap count. SSIDs are not
    # secret, but there is no diagnostic need to print them.
    resp = client.get(f"{priv}/rest/wlanconf")
    wlans, _ = _items(_json(resp))
    a, b = _names(records["wifi/broadcasts"]), _names(wlans)
    cross["wlans"] = {
        "private_status": resp.status_code,
        "v1": len(records["wifi/broadcasts"]),
        "private": len(wlans),
        "same_names": a == b,
        "overlap": len(a & b),
    }

    resp = client.get(f"{v2}/firewall/zone")
    zones, _ = _items(_json(resp))
    a, b = _names(records["firewall/zones"]), _names(zones)
    cross["firewall_zones"] = {
        "private_status": resp.status_code,
        "v1": len(records["firewall/zones"]),
        "private": len(zones),
        "only_in_v1": sorted(a - b),
        "only_in_private": sorted(b - a),
    }

    resp = client.get(f"{v2}/firewall-policies")
    policies, _ = _items(_json(resp))
    cross["firewall_policies"] = {
        "private_status": resp.status_code,
        "v1": len(records["firewall/policies"]),
        "private": len(policies),
    }
    return report


def render(report: dict[str, Any]) -> str:
    """Format a report for a terminal. Holds only what ``probe`` put in it."""
    c = report["controls"]
    lines = [
        f"UniFi Network {report['application_version']} (GET /v1/info -> {report['info_status']})",
        "",
        "controls",
        f"  wrong key   -> {c['bogus_key_status']} "
        f"({'rejected' if c['bogus_key_rejected'] else 'NOT REJECTED'}, expect 401/403)",
        f"  fake route  -> {c['bogus_route_status']} "
        f"({'absent' if c['bogus_route_absent'] else 'NOT 404'}, expect 404)",
        "",
        "official Integration API v1, /v1/sites/{siteId}/...",
    ]
    for resource, r in report["v1"].items():
        detail = f"total={r['total']}" if r["status"] == 200 else f"code={r['error_code']}"
        lines.append(f"  {r['status']}  {resource:26s} {r['verdict']:23s} {detail}")
    x = report["cross_check"]
    lines += [
        "",
        "cross-check against the private API this server uses",
        f"  networks  v1={x['networks']['v1']} private={x['networks']['private']} "
        f"only-in-v1={x['networks']['only_in_v1']} "
        f"only-in-private={x['networks']['only_in_private']}",
        f"  wlans     v1={x['wlans']['v1']} private={x['wlans']['private']} "
        f"same-names={x['wlans']['same_names']} overlap={x['wlans']['overlap']}",
        f"  zones     v1={x['firewall_zones']['v1']} private={x['firewall_zones']['private']} "
        f"only-in-v1={x['firewall_zones']['only_in_v1']} "
        f"only-in-private={x['firewall_zones']['only_in_private']}",
        f"  policies  v1={x['firewall_policies']['v1']} "
        f"private={x['firewall_policies']['private']}",
    ]
    if not c["passed"]:
        lines += ["", "CONTROLS FAILED: the results above cannot be trusted."]
    return "\n".join(lines)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _api_key() -> str:
    key_file = os.environ.get("UNIFI_API_KEY_FILE")
    if key_file:
        return Path(key_file).read_text(encoding="utf-8").strip()
    key = os.environ.get("UNIFI_API_KEY", "").strip()
    if not key:
        raise ProbeError("set UNIFI_API_KEY or UNIFI_API_KEY_FILE")
    return key


def _tls_verify() -> bool | ssl.SSLContext:
    pinned = os.environ.get("UNIFI_PINNED_CERT")
    if pinned:
        try:
            from mcp_unifi.tls import build_pinned_context
        except ImportError as exc:
            raise ProbeError(
                "UNIFI_PINNED_CERT is set but mcp_unifi is not importable here; "
                "run inside the container or an installed checkout"
            ) from exc
        return build_pinned_context(Path(pinned))
    return _env_flag("UNIFI_VERIFY_SSL", default=False)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    as_json = "--json" in args
    try:
        host = os.environ.get("UNIFI_HOST", "").strip()
        if not host:
            raise ProbeError("set UNIFI_HOST")
        port = os.environ.get("UNIFI_PORT", "443").strip() or "443"
        site = os.environ.get("UNIFI_SITE", "default").strip() or "default"
        base = f"https://{host}:{port}/proxy/network"
        headers = {"X-API-Key": _api_key(), "Accept": "application/json"}
        with httpx.Client(verify=_tls_verify(), timeout=20, headers=headers) as client:
            report = probe(client, base, site)
    except ProbeError as exc:
        print(f"probe could not run: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    print(json.dumps(report, indent=2) if as_json else render(report))
    return EXIT_OK if report["controls"]["passed"] else EXIT_CONTROL_FAILED


if __name__ == "__main__":
    sys.exit(main())
