"""UniFi error bodies are summarised, not pasted into a tool result.

The message reaches a tool result, which goes straight into an agent's context.
UniFi's own shape -- {"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}}
-- carries exactly what an operator needs, so it is kept. A controller
mid-upgrade serves an HTML page, and a reverse proxy in front of it serves its
own; neither is worth 300 characters of an agent's context.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_unifi.clients.unifi import UniFiClient, UniFiError, _describe_error_body


def _resp(status: int, body: str, content_type: str = "application/json") -> httpx.Response:
    return httpx.Response(
        status,
        content=body.encode(),
        headers={"content-type": content_type},
        request=httpx.Request("GET", "https://unifi.invalid/v2/api/site/default/apgroups"),
    )


def test_the_unifi_error_code_is_kept():
    body = json.dumps({"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}})
    assert _describe_error_body(_resp(400, body)) == ": api.err.NoSiteContext"


def test_an_html_upgrade_page_reports_its_shape_not_its_markup():
    html = "<html><head><title>UniFi OS updating</title></head>" + "x" * 4000
    detail = _describe_error_body(_resp(503, html, "text/html"))

    assert "<html>" not in detail
    assert "text/html" in detail
    assert str(len(html)) in detail


def test_a_sensitive_value_in_an_error_body_is_redacted():
    """Belt and braces, not a known leak.

    A UniFi error envelope carries a code, not a record. But this is the one
    repo in the fleet whose payloads routinely contain WPA keys, and an error
    path that reads a controller response WITHOUT redacting it is the wrong
    shape to leave lying around for the next endpoint added here.
    """
    body = json.dumps(
        {
            "meta": {"rc": "error"},
            "x_passphrase": "correct-horse-battery-staple",
            "message": "rejected",
        }
    )
    detail = _describe_error_body(_resp(400, body))

    assert "correct-horse-battery-staple" not in detail
    assert detail == ": rejected"


def test_a_long_message_is_bounded():
    body = json.dumps({"meta": {"rc": "error", "msg": "z" * 5000}})
    assert len(_describe_error_body(_resp(400, body))) == 202


def test_an_empty_body_adds_nothing():
    """The raise site already renders the endpoint and status."""
    assert _describe_error_body(_resp(500, "", "text/plain")) == ""


AP_GROUPS_URL = "https://gateway.test:443/proxy/network/v2/api/site/default/apgroups"


@respx.mock
async def test_the_request_path_actually_uses_the_helper():
    """Guards the call site, not just the helper.

    Testing _describe_error_body alone would keep passing if someone put
    `resp.text[:300]` back at the raise site: the helper would still be correct
    and still be dead code. That exact weakness showed up in the sibling
    strava-mcp-vault fix and was only caught by attempting the revert.
    """
    html = "<html><head><title>UniFi OS updating</title></head><body>wait</body></html>"
    respx.get(AP_GROUPS_URL).mock(
        return_value=httpx.Response(
            503, content=html.encode(), headers={"content-type": "text/html"}
        )
    )

    client = UniFiClient(host="gateway.test", api_key="test-key", verify_ssl=False)
    try:
        with pytest.raises(UniFiError) as caught:
            await client.list_ap_groups()
    finally:
        await client.aclose()

    assert "<html>" not in str(caught.value)
    assert "text/html" in str(caught.value)
