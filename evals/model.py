"""Model access for the classes that need a model, and graceful absence for the rest.

Configuration is entirely by environment variable. Nothing here reads a
credential from a file in the repo, and no code path prints or logs a key: the
only thing ever written to a scoreboard or the console is ``target.label``,
which carries the provider and model id and never the secret.

Two providers are supported, checked in this order:

1. **OpenAI-compatible endpoint.** ``MCP_UNIFI_EVAL_BASE_URL`` plus
   ``MCP_UNIFI_EVAL_API_KEY`` plus ``MCP_UNIFI_EVAL_MODEL``. This is the path
   for a self-hosted gateway (LiteLLM, vLLM, Ollama's OpenAI shim) and it is
   how the committed baseline scoreboards were produced.
2. **Anthropic Messages API.** ``ANTHROPIC_API_KEY`` plus
   ``MCP_UNIFI_EVAL_MODEL``. The model id is required rather than defaulted,
   because a hardcoded default goes stale and would quietly grade a different
   model than the one a reader assumes.

With neither configured, :func:`discover_target` returns ``None`` and the
model-dependent class skips with a printed reason. That is the required
behavior: no credentials must never mean a stack trace.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

import httpx

from evals.catalog import ToolSpec

ENV_BASE_URL = "MCP_UNIFI_EVAL_BASE_URL"
ENV_API_KEY = "MCP_UNIFI_EVAL_API_KEY"
ENV_MODEL = "MCP_UNIFI_EVAL_MODEL"
ENV_ANTHROPIC_KEY = "ANTHROPIC_API_KEY"

ANTHROPIC_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"

REQUEST_TIMEOUT_SECONDS = 120.0

#: Retries applied to throttling and upstream faults only. A shared gateway
#: returning 429 is noise about the gateway, not a result about the model.
RETRY_ATTEMPTS = 4
RETRY_BACKOFF_SECONDS = 8.0


@dataclass(frozen=True, slots=True)
class ModelTarget:
    """Where to send a request, and what to call it in a report."""

    provider: str
    model: str
    base_url: str
    _api_key: str

    @property
    def label(self) -> str:
        """Safe-to-print identifier: provider and model id, never the key."""
        return f"{self.provider}:{self.model}"


@dataclass(frozen=True, slots=True)
class ToolChoice:
    """What the model did when shown a catalog and a request.

    ``tool_name`` is ``None`` when the model answered in prose instead of
    calling a tool. That is a distinct outcome from picking the wrong tool and
    the scoreboard keeps them apart.
    """

    tool_name: str | None
    arguments: dict[str, Any]
    text: str
    error: str | None = None


def discover_target(model_override: str | None = None) -> tuple[ModelTarget | None, str]:
    """Return ``(target, reason)``. ``target`` is ``None`` when unconfigured.

    ``reason`` always explains the outcome in one line, suitable for printing
    and for the ``skip_reason`` field of a scoreboard.
    """
    model = model_override or os.environ.get(ENV_MODEL, "").strip()
    base_url = os.environ.get(ENV_BASE_URL, "").strip().rstrip("/")
    api_key = os.environ.get(ENV_API_KEY, "").strip()
    anthropic_key = os.environ.get(ENV_ANTHROPIC_KEY, "").strip()

    if base_url and api_key:
        if not model:
            return None, f"{ENV_BASE_URL} is set but {ENV_MODEL} is not; nothing to grade"
        return ModelTarget("openai-compatible", model, base_url, api_key), (
            f"using OpenAI-compatible endpoint for {model}"
        )
    if anthropic_key:
        if not model:
            return None, f"{ENV_ANTHROPIC_KEY} is set but {ENV_MODEL} is not; nothing to grade"
        return ModelTarget("anthropic", model, ANTHROPIC_BASE_URL, anthropic_key), (
            f"using the Anthropic Messages API for {model}"
        )
    return None, (
        f"no model configured: set {ENV_BASE_URL} + {ENV_API_KEY} + {ENV_MODEL}, "
        f"or {ENV_ANTHROPIC_KEY} + {ENV_MODEL}"
    )


async def call_with_tools(
    target: ModelTarget,
    *,
    system: str,
    user: str,
    tools: list[ToolSpec],
    client: httpx.AsyncClient,
) -> ToolChoice:
    """Send one request with a tool catalog and report what came back.

    Rate limits and 5xx responses are retried with a linear backoff, because a
    shared gateway throttling one request is not a finding about the model and
    should not land in a scoreboard as one. Transport and provider errors that
    survive the retries are returned inside :class:`ToolChoice` as ``error``,
    never raised: one unreachable model must degrade a single case to
    ``error``, not abort a whole run.
    """
    last = ToolChoice(None, {}, "", error="no attempt was made")
    for attempt in range(RETRY_ATTEMPTS):
        try:
            if target.provider == "anthropic":
                last = await _call_anthropic(
                    target, system=system, user=user, tools=tools, http=client
                )
            else:
                last = await _call_openai(
                    target, system=system, user=user, tools=tools, http=client
                )
        except httpx.HTTPError as exc:
            last = ToolChoice(None, {}, "", error=f"transport error: {type(exc).__name__}")
        if not _is_retryable(last.error):
            return last
        if attempt < RETRY_ATTEMPTS - 1:
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
    return last


def _is_retryable(error: str | None) -> bool:
    """True for throttling, upstream faults, and transport hiccups."""
    if not error:
        return False
    return (
        error.startswith("transport error")
        or error.startswith("HTTP 429")
        or error.startswith("HTTP 5")
    )


async def _call_openai(
    target: ModelTarget,
    *,
    system: str,
    user: str,
    tools: list[ToolSpec],
    http: httpx.AsyncClient,
) -> ToolChoice:
    response = await http.post(
        f"{target.base_url}/chat/completions",
        headers={"Authorization": f"Bearer {target._api_key}"},
        json={
            "model": target.model,
            "temperature": 0,
            "max_tokens": 512,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "tools": [t.as_openai_tool() for t in tools],
            "tool_choice": "auto",
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return ToolChoice(None, {}, "", error=_provider_error(response))
    body = response.json()
    choices = body.get("choices") or []
    if not choices:
        return ToolChoice(None, {}, "", error="provider returned no choices")
    message = choices[0].get("message") or {}
    calls = message.get("tool_calls") or []
    text = str(message.get("content") or "")
    if not calls:
        return ToolChoice(None, {}, text)
    fn = calls[0].get("function") or {}
    return ToolChoice(str(fn.get("name") or ""), _as_dict(fn.get("arguments")), text)


async def _call_anthropic(
    target: ModelTarget,
    *,
    system: str,
    user: str,
    tools: list[ToolSpec],
    http: httpx.AsyncClient,
) -> ToolChoice:
    response = await http.post(
        f"{target.base_url}/v1/messages",
        headers={
            "x-api-key": target._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        json={
            "model": target.model,
            "max_tokens": 512,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "tools": [t.as_anthropic_tool() for t in tools],
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return ToolChoice(None, {}, "", error=_provider_error(response))
    body = response.json()
    text_parts: list[str] = []
    for block in body.get("content") or []:
        if block.get("type") == "tool_use":
            args = block.get("input")
            return ToolChoice(
                str(block.get("name") or ""),
                args if isinstance(args, dict) else {},
                "\n".join(text_parts),
            )
        if block.get("type") == "text":
            text_parts.append(str(block.get("text") or ""))
    return ToolChoice(None, {}, "\n".join(text_parts))


def _provider_error(response: httpx.Response) -> str:
    """Summarise a provider error without echoing request headers.

    The body is truncated hard. Some gateways reflect part of the request back
    in an error payload, and an unbounded copy of that into a committed
    scoreboard is exactly how a key ends up in git.
    """
    return f"HTTP {response.status_code}: {response.text[:200]}"


def _as_dict(raw: Any) -> dict[str, Any]:
    """Parse a tool-call argument payload, which may arrive as a JSON string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        import json

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


__all__ = [
    "ENV_ANTHROPIC_KEY",
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "ENV_MODEL",
    "ModelTarget",
    "ToolChoice",
    "call_with_tools",
    "discover_target",
]
