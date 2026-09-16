# Explicit secure configuration

Real-mode startup accepts references, not secret values. Set `STUB_MODE=false`, point
`MCP_UNIFI_CONTROLLERS_FILE` at a read-only YAML file, and provide one local API-key file
per controller:

```yaml
- name: home
  host: unifi.example.internal
  port: 443
  site: default
  verify_ssl: true
  api_key_file: /run/secrets/unifi-home-api-key
```

The HTTP transport also requires an explicit bearer-token file and client identity:

```text
MCP_UNIFI_AUTH_TOKEN_FILE=/run/secrets/mcp-bearer-token
MCP_UNIFI_CLIENT_ID=monitor-agent
```

Secret files contain only the secret plus an optional trailing newline. The service never
loads `.env` from the current directory, accepts inline `api_key` values in controller
YAML, or falls back to username/password/cloud authentication. TLS verification defaults
to enabled. Real-mode configuration rejects `verify_ssl: false`; insecure TLS is not an
available production configuration. Tests that need a self-signed endpoint must opt out
at the client-construction layer rather than through the runtime configuration file.

Missing files, empty files, inline keys, raw bearer-token environment values, missing
client identity, and missing controller configuration fail startup with stable errors
that do not include secret contents.
