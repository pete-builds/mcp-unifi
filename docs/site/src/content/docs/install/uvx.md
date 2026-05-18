---
draft: false
title: uvx / pipx
description: Run mcp-unifi straight from the GitHub repo with no install footprint.
---

`uvx` (from [uv](https://docs.astral.sh/uv/)) is the fastest way to try mcp-unifi on a machine that already has Python tooling. The server runs over **stdio** so it works directly with Claude Desktop and Claude Code's stdio path. Nothing is installed system-wide; `uvx` caches the package in its own directory.

## One-off run

```bash
uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

That command resolves the repo, builds a venv, installs the package, and starts the server on stdio. Use `Ctrl+C` to stop it.

To pin a release, append `@v0.5.0-rc.2` (or any tag) to the git URL:

```bash
uvx --from git+https://github.com/pete-builds/mcp-unifi@v0.5.0-rc.2 mcp-unifi
```

## Wire into Claude Code

Add it as a stdio MCP server in Claude Code (user scope):

```bash
claude mcp add --transport stdio --scope user unifi \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

Set `STUB_MODE=true` for hardware-free testing, or pass real-mode env vars:

```bash
claude mcp add --transport stdio --scope user unifi \
  --env STUB_MODE=false \
  --env UNIFI_HOST=192.168.1.1 \
  --env UNIFI_API_KEY=<your-local-api-key> \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

Verify with `claude mcp list` — the `unifi` entry should report `Connected`.

## pipx

`pipx` works too if you don't have `uv` installed:

```bash
pipx install git+https://github.com/pete-builds/mcp-unifi
mcp-unifi
```

`pipx` installs the package globally for your user; remove it later with `pipx uninstall mcp-unifi`.

## Notes

- The uvx and pipx paths default to **stdio transport** (`MCP_TRANSPORT=stdio` is set automatically when launched as `mcp-unifi`'s console script and not overridden). If you need Streamable HTTP, use the [Docker install](/mcp-unifi/install/docker/) instead.
- Multi-controller config via `MCP_UNIFI_CONTROLLERS_FILE` works the same as in Docker; point the env var at a YAML file the uvx process can read.
- The audit log path defaults to `audit.jsonl` in the CWD of wherever `uvx` ran. Set `MCP_UNIFI_AUDIT_PATH=/path/to/audit.jsonl` to override.
