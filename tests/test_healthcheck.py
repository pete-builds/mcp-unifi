"""Tests for the Docker healthcheck script."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

from mcp_unifi.healthcheck import check


def test_healthcheck_ok_on_200() -> None:
    resp = MagicMock()
    resp.status = 200
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=resp):
        assert check() == 0


def test_healthcheck_fails_on_non_200() -> None:
    resp = MagicMock()
    resp.status = 503
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=resp):
        assert check() == 1


def test_healthcheck_fails_on_http_error() -> None:
    err = urllib.error.HTTPError("u", 500, "ise", None, None)  # type: ignore[arg-type]
    with patch("urllib.request.urlopen", side_effect=err):
        assert check() == 1


def test_healthcheck_fails_on_404() -> None:
    err = urllib.error.HTTPError("u", 404, "not found", None, None)  # type: ignore[arg-type]
    with patch("urllib.request.urlopen", side_effect=err):
        assert check() == 1


def test_healthcheck_fails_on_connection_error() -> None:
    with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError):
        assert check() == 1
