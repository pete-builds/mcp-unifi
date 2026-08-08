"""Console-layer tools: two-layer health, console identity, firmware state.

Why this file exists
--------------------
Every other tool in this server wraps ``/proxy/network/api/s/<site>/...``,
which *is* the UniFi Network application. On 2026-08-08 the Network app on
Pete's UCG-Fiber died while UniFi OS stayed up and kept routing traffic. All
~130 tools returned the same opaque upstream error, so the MCP was useless in
exactly the scenario a troubleshooting tool exists for — and an unauthenticated
probe of ``/proxy/network/*`` returned 401, which was misread as "recovered"
when the app was still down.

:func:`get_console_health` closes that gap: one call, both layers, a
plain-language verdict, and an authenticated Network probe so the proxy cannot
short-circuit the answer. See :mod:`mcp_unifi.clients.unifi_os` for the full
endpoint map and the proxy short-circuit warning.

Registration note
-----------------
These tools register as part of the ``network`` module rather than a new
module name. That is deliberate: they are Network-app troubleshooting tools,
and gating them behind a new ``MCP_UNIFI_MODULES_ENABLED`` entry would mean the
health tool is missing from any deployment that has not opted in — which is the
same failure mode this file was written to fix. The console credentials
themselves stay optional, so no deployment needs a config change to gain the
health verdict.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from mcp_unifi.clients.unifi_os import (
    FIRMWARE_UPDATE_PATH,
    ProbeResult,
    UniFiOSAuthError,
    UniFiOSClient,
    UniFiOSError,
)
from mcp_unifi.modules._audit import audited
from mcp_unifi.modules.network._common import format_json, make_err

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import ControllerConfig, Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.console")


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------

#: Every value ``get_console_health`` can return in ``state``. Callers should
#: branch on this, not on raw HTTP status codes.
CONSOLE_STATES = (
    "healthy",  # UniFi OS up + Network app up and serving
    "network_app_starting",  # UniFi OS up, Network app booting or migrating its DB
    "network_app_down",  # UniFi OS up, Network app dead (today's outage)
    "credentials_invalid",  # UniFi OS up, but our API key was rejected
    "console_unreachable",  # No answer at all: box down, cable, wrong host
    "unknown",  # Reached the console but could not classify the app state
)


def _classify(
    console: ProbeResult,
    network: ProbeResult,
    serving: ProbeResult | None = None,
) -> dict[str, Any]:
    """Turn the probe results into a single plain-language verdict.

    ``console`` is the unauthenticated ``/api/system`` probe (UniFi OS layer).
    ``network`` is the **authenticated** ``/proxy/network/status`` probe
    (Network app layer). ``serving`` is an optional **authenticated** call to a
    real Network API route (``stat/sysinfo``), used to corroborate the status
    envelope with hard evidence that the app is actually answering queries.

    CRITICAL — do not "simplify" this by dropping the API key from the network
    probe. Unauthenticated ``/proxy/network/*`` always answers 401 from the
    proxy without ever consulting the backend, so an unauthenticated probe
    cannot distinguish a healthy app from a dead one. That mistake produced a
    false all-clear during the 2026-08-08 outage.
    """
    # --- Layer 1: is the console itself answering? ---------------------
    if not console.reachable and not network.reachable:
        return {
            "state": "console_unreachable",
            "unifi_os": "unreachable",
            "network_app": "unknown",
            "summary": (
                "The UniFi OS console did not respond at all. The gateway is "
                "powered off, unreachable on the network, or the configured "
                "host is wrong. Nothing about the Network application can be "
                "determined from here."
            ),
            "next_step": (
                "Check that the gateway is powered on and that the configured "
                "host/port is reachable (ping, then curl the console URL)."
            ),
        }

    # --- Layer 2: what did the authenticated Network probe say? --------
    status = network.status

    if not network.reachable:
        # The status endpoint itself timed out. That is not automatically
        # "unknown": a crash-looping app often hangs its own status handler
        # while the proxy still returns a clean 5xx for real API routes. If
        # the corroboration probe reached a verdict, use it — evidence from a
        # real API call outranks a missing self-report.
        if serving is not None and serving.status is not None and serving.status >= 500:
            starting = serving.status == 503
            return {
                "state": "network_app_starting" if starting else "network_app_down",
                "unifi_os": "up",
                "network_app": "starting" if starting else "down",
                "summary": (
                    f"UniFi OS is UP and healthy. The Network application's "
                    f"status endpoint did not respond, and a live Network API "
                    f"call returned HTTP {serving.status}, so the application "
                    f"is {'still starting up' if starting else 'DOWN'}. "
                    f"Routing and internet access are unaffected — UniFi OS "
                    f"handles the dataplane."
                ),
                "next_step": (
                    "Wait for the application to finish starting, then re-run."
                    if starting
                    else "Restart the Network application from the console UI "
                    "(Settings → System). If it starts and dies repeatedly it is "
                    "crash-looping; check storage from the console UI or over SSH."
                ),
            }
        return {
            "state": "unknown",
            "unifi_os": "up",
            "network_app": "unknown",
            "summary": (
                "UniFi OS answered, but the authenticated probe of the Network "
                "application timed out or failed at the transport layer, so its "
                "state could not be determined."
            ),
            "next_step": "Re-run in a few seconds; if it persists, check the console UI.",
        }

    if status == 401:
        # We SENT a key and still got 401 → the key is bad. This is a
        # different condition from the unauthenticated 401 the proxy returns
        # to anonymous callers, which says nothing about anything.
        return {
            "state": "credentials_invalid",
            "unifi_os": "up",
            "network_app": "unknown",
            "summary": (
                "UniFi OS is up, but it rejected the configured API key "
                "(HTTP 401 on an authenticated request). The Network "
                "application's health cannot be read without a valid key — "
                "this is an auth problem, not necessarily an outage."
            ),
            "next_step": (
                "Regenerate the local API key under Settings → Control Plane → "
                "Integrations and update UNIFI_API_KEY."
            ),
        }

    if status == 403:
        return {
            "state": "credentials_invalid",
            "unifi_os": "up",
            "network_app": "unknown",
            "summary": (
                "UniFi OS is up and accepted the API key, but the key lacks "
                "permission to read the Network application's status "
                "(HTTP 403)."
            ),
            "next_step": "Grant the API key full site access, or issue a new admin-scoped key.",
        }

    if status is not None and status >= 500:
        # 502 = proxy authenticated us and forwarded, backend is not there.
        # 503 = backend is there but refusing to serve (typically mid-restart).
        starting = status == 503
        return {
            "state": "network_app_starting" if starting else "network_app_down",
            "unifi_os": "up",
            "network_app": "starting" if starting else "down",
            "summary": (
                f"UniFi OS is UP and healthy, but the UniFi Network "
                f"application is {'still starting up' if starting else 'DOWN'} "
                f"(HTTP {status} on an authenticated request). Routing and "
                f"internet access are unaffected by this — UniFi OS handles "
                f"the dataplane. Every Network tool in this server will fail "
                f"until the application is serving again."
            ),
            "next_step": (
                "Wait for the application to finish starting, then re-run."
                if starting
                else "Restart the Network application from the console UI "
                "(Settings → System). If it starts and dies repeatedly, the "
                "usual cause is a full data partition — check storage from the "
                "console UI or over SSH; this API exposes no disk metric."
            ),
        }

    if status is not None and 200 <= status < 300:
        meta = {}
        if isinstance(network.body, dict):
            raw_meta = network.body.get("meta")
            if isinstance(raw_meta, dict):
                meta = raw_meta

        # ------------------------------------------------------------------
        # Reading this envelope correctly is subtle. Verified live 2026-08-08
        # across both a crash-looping and a settled UCG-Fiber on 10.5.67:
        #
        #   HEALTHY  -> {"meta": {"rc": "ok", "uuid": "..."}, "data": []}
        #               ...that is ALL. No `up`, no `server_running`, no
        #               `server_version`, no `app_context_status`.
        #   UNHEALTHY-> {"meta": {"rc": "ok", "server_version": "10.5.67",
        #                "server_running": false, "db_migrating": false,
        #                "up": false, "app_context_status": "UniFi Network
        #                Application is starting up...", ...}, "data": []}
        #
        # The diagnostic fields materialise ONLY while the app is not ready.
        # So `meta.get("up")` is None on a perfectly healthy controller, and
        # treating a missing key as False reports a healthy app as DOWN.
        # Confirmed by correlating 10 consecutive samples against a real
        # `stat/sysinfo` call: minimal envelope <=> sysinfo HTTP 200.
        #
        # We therefore branch on PRESENCE, and — rather than rely on that
        # inference alone — corroborate with `serving`, an actual authenticated
        # Network API call. Evidence beats inference.
        # ------------------------------------------------------------------
        reported_up = meta.get("up")
        running = meta.get("server_running")
        migrating = bool(meta.get("db_migrating"))
        context = str(meta.get("app_context_status") or "").strip()
        declares_state = reported_up is not None or running is not None

        serving_ok = serving is not None and serving.status is not None and serving.status < 300

        if serving_ok or (not declares_state and serving is None):
            return {
                "state": "healthy",
                "unifi_os": "up",
                "network_app": "up",
                "summary": (
                    "UniFi OS is up and the UniFi Network application is "
                    "running and serving requests. All Network tools should "
                    "work normally."
                ),
                "next_step": None,
            }

        starting = migrating or "start" in context.lower()
        detail = f" The console reports: {context!r}." if context else ""
        observed = (
            f"up={reported_up}, server_running={running}, db_migrating={migrating}"
            if declares_state
            else "the status endpoint reported no readiness fields"
        )
        serving_note = (
            f" A live Network API call returned HTTP {serving.status}."
            if serving is not None and serving.status is not None
            else ""
        )
        return {
            "state": "network_app_starting" if starting else "network_app_down",
            "unifi_os": "up",
            "network_app": "starting" if starting else "down",
            "summary": (
                f"UniFi OS is UP and healthy, but the UniFi Network "
                f"application is NOT serving ({observed}).{detail}"
                f"{serving_note} Routing and internet access are unaffected — "
                f"UniFi OS handles the dataplane. Every Network tool in this "
                f"server will fail until the application finishes coming up."
            ),
            "next_step": (
                "Wait and re-run — the application is mid-start. If it never "
                "reaches running, it is crash-looping; check storage and the "
                "application logs from the console UI."
                if starting
                else "Restart the Network application from the console UI (Settings → System)."
            ),
        }

    return {
        "state": "unknown",
        "unifi_os": "up",
        "network_app": "unknown",
        "summary": (
            f"UniFi OS answered, but the Network status probe returned an "
            f"unexpected HTTP {status} that this tool does not know how to "
            f"classify."
        ),
        "next_step": "Inspect the raw probe output in the 'checks' field.",
    }


def _stub_health() -> dict[str, Any]:
    """Canned healthy verdict for stub mode (no gateway on the network)."""
    return {
        "state": "healthy",
        "unifi_os": "up",
        "network_app": "up",
        "summary": (
            "UniFi OS is up and the UniFi Network application is running and "
            "serving requests. All Network tools should work normally."
        ),
        "next_step": None,
        "checks": [
            {"path": "/api/system", "status": 200},
            {"path": "/proxy/network/status", "status": 200},
        ],
        "network_app_version": "10.5.67",
        "stub_mode": True,
    }


def register(mcp: FastMCP, settings: Settings, registry: ControllerRegistry) -> None:
    err = make_err(settings)

    def _controller_config(name: str) -> ControllerConfig:
        for ctrl in settings.controllers:
            if ctrl.name == name:
                return ctrl
        available = ", ".join(sorted(c.name for c in settings.controllers)) or "(none)"
        raise KeyError(f"Unknown controller '{name}'. Available: {available}.")

    def _client(name: str) -> UniFiOSClient:
        """Build a per-call UniFi OS client for the named controller.

        Constructed per call rather than pooled: these tools run rarely (they
        are diagnostics), and a short-lived client guarantees a health probe is
        never answered from a stale connection to a gateway that has since
        rebooted.
        """
        ctrl = _controller_config(name)
        return UniFiOSClient(
            host=ctrl.host,
            api_key=ctrl.api_key.get_secret_value(),
            port=ctrl.port,
            username=(ctrl.os_username or ""),
            password=(ctrl.os_password.get_secret_value() if ctrl.os_password else ""),
            verify_ssl=ctrl.verify_ssl,
        )

    @mcp.tool()
    @audited("get_console_health")
    async def get_console_health(controller: str = "default") -> str:
        """Diagnose the gateway's two layers separately: UniFi OS and Network.

        Start here when anything UniFi-related is failing. Every other tool in
        this server talks to the UniFi Network *application*; this one also
        checks the UniFi OS *console* underneath it, so it can tell you whether
        the box is down, the application is down, or your credentials are wrong
        — three very different problems that otherwise look identical.

        Side effects: None (read-only, two GET probes).

        Returns a record with:
        - ``state``: one of ``healthy``, ``network_app_starting``,
          ``network_app_down``, ``credentials_invalid``,
          ``console_unreachable``, ``unknown``.
        - ``unifi_os`` / ``network_app``: per-layer status words.
        - ``summary``: plain-language explanation of what is wrong.
        - ``next_step``: the recommended action, or ``null`` when healthy.
        - ``checks``: the raw probe results (path + HTTP status) behind the
          verdict, so the reasoning is auditable.
        - ``network_app_version``: the Network app version, when it reported one.

        Note on the ``network_app_down`` verdict: UniFi OS handles routing, so
        the Network application being down does **not** mean the internet is
        down. It means configuration and monitoring are unavailable.

        Example: get_console_health(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if settings.stub_mode:
            return format_json(_stub_health())
        try:
            client = _client(controller)
        except KeyError as exc:
            return err(str(exc))
        site = _controller_config(controller).site
        try:
            console = await client.probe_console()
            network = await client.probe_network_app_status()
            serving = await client.probe_network_serving(site)
        finally:
            await client.aclose()

        verdict = _classify(console, network, serving)
        verdict["checks"] = [console.as_dict(), network.as_dict(), serving.as_dict()]

        # The Network app only reports its version in the status envelope while
        # it is unhealthy; when healthy, read it from the sysinfo record the
        # corroboration probe already fetched.
        version = None
        if isinstance(network.body, dict):
            meta = network.body.get("meta")
            if isinstance(meta, dict):
                version = meta.get("server_version")
        if version is None and isinstance(serving.body, dict):
            data = serving.body.get("data")
            if isinstance(data, list) and data and isinstance(data[0], dict):
                version = data[0].get("version")
        verdict["network_app_version"] = version
        return format_json(verdict)

    @mcp.tool()
    @audited("get_console_info")
    async def get_console_info(controller: str = "default") -> str:
        """Show UniFi OS console identity and connectivity, independent of Network.

        Answers from the UniFi OS layer, so it keeps working while the UniFi
        Network application is down. Useful for confirming the box itself is
        alive, which model it is, and whether it still has internet and cloud
        connectivity.

        Side effects: None (read-only).

        Returns ``model`` (hardware short name), ``name``, ``mac``,
        ``device_state``, ``device_error_code``, ``has_internet``,
        ``cloud_connected``, ``remote_access_enabled``, ``sso_enabled``, and
        ``installed_apps`` (application inventory reported by the console).

        This firmware's UniFi OS API exposes **no CPU, memory, or disk
        metrics** — those fields are absent by design here rather than
        fabricated. Read storage from the console UI if you need it.

        Example: get_console_info(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if settings.stub_mode:
            return format_json(
                {
                    "model": "UCGF",
                    "name": "Cloud Gateway Fiber",
                    "device_state": "setup",
                    "has_internet": True,
                    "cloud_connected": True,
                    "stub_mode": True,
                }
            )
        try:
            client = _client(controller)
        except KeyError as exc:
            return err(str(exc))
        try:
            system = await client.probe_console()
            apps = await client.probe_apps()
        finally:
            await client.aclose()

        if not system.reachable:
            return err(f"UniFi OS console is unreachable: {system.error}")
        if not isinstance(system.body, dict):
            return err(f"UniFi OS /api/system returned HTTP {system.status} with no JSON body.")

        body = system.body
        hardware = body.get("hardware") if isinstance(body.get("hardware"), dict) else {}
        return format_json(
            {
                "model": hardware.get("shortname"),
                "name": body.get("name"),
                "mac": body.get("mac"),
                "device_state": body.get("deviceState"),
                "device_error_code": body.get("deviceErrorCode"),
                "has_internet": body.get("hasInternet"),
                "cloud_connected": body.get("cloudConnected"),
                "remote_access_enabled": body.get("remoteAccessEnabled"),
                "sso_enabled": body.get("isSsoEnabled"),
                "installed_apps": apps.body if isinstance(apps.body, dict) else None,
            }
        )

    @mcp.tool()
    @audited("get_console_firmware")
    async def get_console_firmware(controller: str = "default") -> str:
        """Show UniFi OS firmware and available-update state.

        Requires a **console session**, not the Network API key: UniFi OS's own
        endpoints do not accept ``X-API-Key``. Set ``UNIFI_OS_USERNAME`` and
        ``UNIFI_OS_PASSWORD`` to enable this tool. Without them it returns a
        clear configuration error rather than a bare 401.

        UNVERIFIED RESPONSE SHAPE: the endpoint is confirmed to exist on
        UCG-Fiber / UniFi OS 5.1.19 (it answers 401 rather than 404 without a
        session), but its response body has not been observed — no console
        credentials were available when this tool was written. The raw body is
        passed through untransformed rather than reshaped against a guessed
        schema.

        Side effects: None (read-only, plus a login if no session is active).

        Returns the console's raw firmware/update record under ``firmware``.

        Example: get_console_firmware(controller="default")

        Args:
            controller: Name of the UniFi controller to target. Defaults to
                ``"default"``.
        """
        if settings.stub_mode:
            return format_json({"firmware": {"version": "5.1.19"}, "stub_mode": True})
        try:
            client = _client(controller)
        except KeyError as exc:
            return err(str(exc))
        try:
            body = await client.get_session_json(FIRMWARE_UPDATE_PATH)
        except UniFiOSAuthError as exc:
            return err(str(exc))
        except UniFiOSError as exc:
            logger.warning("get_console_firmware failed", extra={"controller": controller})
            return err(str(exc))
        finally:
            await client.aclose()
        return format_json({"firmware": body, "shape": "unverified-passthrough"})
