"""Tests for the Docker healthcheck script."""

from __future__ import annotations

import urllib.error
from unittest.mock import patch

from mcp_unifi.healthcheck import check


def test_healthcheck_ok_on_200() -> None:
    class FakeResp:
        status = 200

    with patch("urllib.request.urlopen", return_value=FakeResp()):
        assert check() == 0


def test_healthcheck_ok_on_405() -> None:
    err = urllib.error.HTTPError("u", 405, "method not allowed", None, None)  # type: ignore[arg-type]
    with patch("urllib.request.urlopen", side_effect=err):
        assert check() == 0


def test_healthcheck_ok_on_400() -> None:
    err = urllib.error.HTTPError("u", 400, "bad request", None, None)  # type: ignore[arg-type]
    with patch("urllib.request.urlopen", side_effect=err):
        assert check() == 0


def test_healthcheck_fails_on_500() -> None:
    err = urllib.error.HTTPError("u", 500, "ise", None, None)  # type: ignore[arg-type]
    with patch("urllib.request.urlopen", side_effect=err):
        assert check() == 1


def test_healthcheck_fails_on_connection_error() -> None:
    with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError):
        assert check() == 1
