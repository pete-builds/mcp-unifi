"""Tests for ``scripts/probe_integration_api.py``.

The fake console below mirrors what a UCG-Fiber on UniFi Network 10.6.106
returned to the live probe on 2026-10-17: networks and WLANs present on v1,
the zone-based firewall routes answering 400 because the site has not
migrated, and the WAN and VPN entries the private ``networkconf`` folds into
its network list.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "probe_integration_api.py"

_spec = importlib.util.spec_from_file_location("_probe_integration_api", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
probe_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe_mod)

BASE = "https://console.test:443/proxy/network"
REAL_KEY = "real-key-0123456789abcdef"
PASSPHRASE = "correct-horse-battery-staple"
SITE_UUID = "88f7af54-98f8-306a-a1c7-c9349722b1f6"


def _page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"offset": 0, "limit": 200, "count": len(items), "totalCount": len(items), "data": items}


ZBF_NOT_CONFIGURED = {
    "statusCode": 400,
    "statusName": "BAD_REQUEST",
    "code": "api.firewall.zone-based-firewall-not-configured",
    "message": "Zone-based firewall is not configured",
}

V1_NETWORKS = [
    {"id": f"n{i}", "name": name, "vlanId": vlan, "enabled": True, "management": "GATEWAY"}
    for i, (name, vlan) in enumerate([("Default", 1), ("TRUSTED", 20), ("IoT", 30), ("GUEST", 40)])
]
V1_WLANS = [
    {
        "id": f"w{i}",
        "name": name,
        "type": "STANDARD",
        "enabled": True,
        "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": PASSPHRASE},
    }
    for i, name in enumerate(["home", "home-iot", "home-guest", "home-5g"])
]
PRIVATE_NETWORKS = [{"_id": n["id"], "name": n["name"]} for n in V1_NETWORKS] + [
    {"_id": "wan1", "name": "Internet 1"},
    {"_id": "wan2", "name": "Internet 2"},
    {"_id": "wg", "name": "WireGuard Server 1"},
]
PRIVATE_WLANS = [{"_id": w["id"], "name": w["name"], "x_passphrase": PASSPHRASE} for w in V1_WLANS]


def _console(
    *,
    bogus_key_status: int = 401,
    bogus_route_status: int = 404,
    sites: list[dict[str, Any]] | None = None,
    seen: list[httpx.Request] | None = None,
) -> httpx.MockTransport:
    """Build a fake console. Records every request into ``seen`` when given."""
    site_list = sites if sites is not None else [{"id": SITE_UUID, "internalReference": "default"}]
    v1_site = f"/proxy/network/integration/v1/sites/{SITE_UUID}"
    routes: dict[str, tuple[int, Any]] = {
        "/proxy/network/integration/v1/info": (200, {"applicationVersion": "10.6.106"}),
        "/proxy/network/integration/v1/sites": (200, _page(site_list)),
        f"{v1_site}/devices": (200, _page([{"id": "d1", "model": "UCG-Fiber", "name": "gw"}])),
        f"{v1_site}/clients": (200, _page([{"id": "c1", "name": "laptop", "type": "WIRED"}])),
        f"{v1_site}/networks": (200, _page(V1_NETWORKS)),
        f"{v1_site}/wifi/broadcasts": (200, _page(V1_WLANS)),
        f"{v1_site}/firewall/zones": (400, ZBF_NOT_CONFIGURED),
        f"{v1_site}/firewall/policies": (400, ZBF_NOT_CONFIGURED),
        f"{v1_site}/wans": (200, _page([{"id": "wan1", "name": "Internet 1"}])),
        f"{v1_site}/{probe_mod.CONTROL_ROUTE}": (
            bogus_route_status,
            {"statusCode": bogus_route_status, "code": "api.request.not-found"},
        ),
        "/proxy/network/api/s/default/rest/networkconf": (
            200,
            {"meta": {"rc": "ok"}, "data": PRIVATE_NETWORKS},
        ),
        "/proxy/network/api/s/default/rest/wlanconf": (
            200,
            {"meta": {"rc": "ok"}, "data": PRIVATE_WLANS},
        ),
        "/proxy/network/v2/api/site/default/firewall/zone": (200, []),
        "/proxy/network/v2/api/site/default/firewall-policies": (200, []),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.headers.get("X-API-Key") != REAL_KEY:
            return httpx.Response(bogus_key_status, json={"code": "api.authentication.invalid"})
        status, body = routes.get(request.url.path, (200, _page([])))
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def _client(transport: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=transport, headers={"X-API-Key": REAL_KEY})


def _run(**console: Any) -> dict[str, Any]:
    with _client(_console(**console)) as client:
        result: dict[str, Any] = probe_mod.probe(client, BASE, "default")
        return result


# ---------------------------------------------------------------------------
# Classification: the distinction the 404 control exists to make
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "verdict"),
    [
        (200, "present"),
        (404, "absent"),
        (401, "denied"),
        (403, "denied"),
        (400, "present-not-configured"),
        (409, "present-not-configured"),
        (500, "error"),
    ],
)
def test_classify(status: int, verdict: str) -> None:
    assert probe_mod.classify(status) == verdict


def test_live_shape_is_reported_as_the_probe_saw_it() -> None:
    report = _run()

    assert report["application_version"] == "10.6.106"
    assert report["controls"] == {
        "bogus_key_status": 401,
        "bogus_key_rejected": True,
        "bogus_route_status": 404,
        "bogus_route_absent": True,
        "passed": True,
    }
    v1 = report["v1"]
    assert v1["networks"]["verdict"] == "present"
    assert v1["networks"]["total"] == 4
    assert v1["wifi/broadcasts"]["total"] == 4
    assert v1["firewall/zones"]["verdict"] == "present-not-configured"
    assert v1["firewall/zones"]["error_code"] == ZBF_NOT_CONFIGURED["code"]
    assert v1["firewall/policies"]["verdict"] == "present-not-configured"
    assert set(v1) == set(probe_mod.V1_RESOURCES)

    cross = report["cross_check"]
    assert cross["networks"]["only_in_v1"] == []
    assert cross["networks"]["only_in_private"] == [
        "Internet 1",
        "Internet 2",
        "WireGuard Server 1",
    ]
    assert cross["wlans"] == {
        "private_status": 200,
        "v1": 4,
        "private": 4,
        "same_names": True,
        "overlap": 4,
    }
    assert cross["firewall_zones"]["v1"] == 0
    assert cross["firewall_zones"]["private"] == 0


def test_site_is_addressed_by_uuid_not_internal_reference() -> None:
    seen: list[httpx.Request] = []
    with _client(_console(seen=seen)) as client:
        probe_mod.probe(client, BASE, "default")

    v1_site_paths = [r.url.path for r in seen if "/integration/v1/sites/" in r.url.path]
    assert v1_site_paths
    assert all(f"/sites/{SITE_UUID}/" in p for p in v1_site_paths)


# ---------------------------------------------------------------------------
# Read-only and no-leak guarantees
# ---------------------------------------------------------------------------


def test_every_request_is_a_get() -> None:
    seen: list[httpx.Request] = []
    with _client(_console(seen=seen)) as client:
        probe_mod.probe(client, BASE, "default")

    assert len(seen) > len(probe_mod.V1_RESOURCES)
    assert {r.method for r in seen} == {"GET"}


def test_output_never_carries_the_key_or_a_body_secret() -> None:
    report = _run()
    text = probe_mod.render(report)
    blob = json.dumps(report)

    for out in (text, blob):
        assert REAL_KEY not in out
        assert PASSPHRASE not in out
        assert "passphrase" not in out.lower()


def test_wlan_names_are_not_printed() -> None:
    text = probe_mod.render(_run())
    for wlan in V1_WLANS:
        assert wlan["name"] not in text


# ---------------------------------------------------------------------------
# Controls failing must fail the run
# ---------------------------------------------------------------------------


def test_wrong_key_accepted_fails_the_controls() -> None:
    report = _run(bogus_key_status=200)
    assert report["controls"]["bogus_key_rejected"] is False
    assert report["controls"]["passed"] is False
    assert "CONTROLS FAILED" in probe_mod.render(report)


def test_fake_route_answering_fails_the_controls() -> None:
    report = _run(bogus_route_status=200)
    assert report["controls"]["bogus_route_absent"] is False
    assert report["controls"]["passed"] is False


def test_unresolvable_site_raises_rather_than_probing_the_wrong_path() -> None:
    with (
        _client(_console(sites=[{"id": SITE_UUID, "internalReference": "other"}])) as client,
        pytest.raises(probe_mod.ProbeError, match="internalReference 'default'"),
    ):
        probe_mod.probe(client, BASE, "default")


# ---------------------------------------------------------------------------
# main(): exit codes and configuration
# ---------------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in (
        "UNIFI_HOST",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_API_KEY",
        "UNIFI_API_KEY_FILE",
        "UNIFI_VERIFY_SSL",
        "UNIFI_PINNED_CERT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("UNIFI_HOST", "console.test")
    monkeypatch.setenv("UNIFI_API_KEY", REAL_KEY)
    return monkeypatch


def _patch_transport(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    real_client = httpx.Client

    def fake_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("verify", None)
        return real_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(probe_mod.httpx, "Client", fake_client)


def test_main_exits_zero_when_controls_hold(
    env: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_transport(env, _console())
    assert probe_mod.main([]) == probe_mod.EXIT_OK
    out = capsys.readouterr().out
    assert "UniFi Network 10.6.106" in out
    assert REAL_KEY not in out


def test_main_exits_two_when_a_control_fails(env: pytest.MonkeyPatch) -> None:
    _patch_transport(env, _console(bogus_key_status=200))
    assert probe_mod.main([]) == probe_mod.EXIT_CONTROL_FAILED


def test_main_json_is_parseable(
    env: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_transport(env, _console())
    assert probe_mod.main(["--json"]) == probe_mod.EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["controls"]["passed"] is True


def test_main_reads_the_key_file(env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_text(REAL_KEY + "\n", encoding="utf-8")
    env.delenv("UNIFI_API_KEY")
    env.setenv("UNIFI_API_KEY_FILE", str(key_file))
    _patch_transport(env, _console())
    assert probe_mod.main([]) == probe_mod.EXIT_OK


def test_main_without_host_is_a_config_error(
    env: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env.delenv("UNIFI_HOST")
    assert probe_mod.main([]) == probe_mod.EXIT_CONFIG
    assert "UNIFI_HOST" in capsys.readouterr().err


def test_main_without_key_is_a_config_error(env: pytest.MonkeyPatch) -> None:
    env.delenv("UNIFI_API_KEY")
    assert probe_mod.main([]) == probe_mod.EXIT_CONFIG
