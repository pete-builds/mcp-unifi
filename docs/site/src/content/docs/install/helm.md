---
draft: false
title: Helm
description: Kubernetes deployment via the published Helm chart.
---

The Helm chart deploys mcp-unifi as a `Deployment` + `Service` + optional `Ingress` + optional `NetworkPolicy`. The chart is published from this repo to GitHub Pages.

## Add the Helm repo

```bash
helm repo add mcp-unifi https://pete-builds.github.io/mcp-unifi/
helm repo update
```

## Install (stub mode)

The chart ships `auth.required: true` with `auth.tokens: ""`, so the pod will not start until you set a bearer token (or explicitly `--set auth.required=false`, which is only appropriate for a trusted single-tenant cluster). See the [Authentication guide](/mcp-unifi/guides/auth/) for the model.

```bash
export MCP_UNIFI_TOKEN=$(openssl rand -hex 32)
helm install unifi mcp-unifi/mcp-unifi \
  --set unifi.stubMode=true \
  --set auth.tokens="$MCP_UNIFI_TOKEN"
```

The chart defaults to `unifi.stubMode: false`, but if you don't set `unifi.host` and `unifi.apiKey` the server falls back to stub mode at runtime. The `--set unifi.stubMode=true` above makes that explicit.

## Install (real mode)

Create a small `values.yaml`:

```yaml
unifi:
  host: 192.168.1.1
  apiKey: <your-local-api-key>
  port: 443
  site: default
  verifySSL: false
  stubMode: false

modulesEnabled: "network,protect,access"

auth:
  required: true
  tokens: "<paste-token-from-openssl-rand-hex-32>"
```

Generate the API key in the gateway UI under **Settings → Control Plane → Integrations → Create API Key**. Generate the bearer token with `openssl rand -hex 32`.

Install with the override:

```bash
helm install unifi mcp-unifi/mcp-unifi -f values.yaml
```

For a production deployment, prefer an `existingSecret` over plaintext values in `values.yaml`. The Secret must expose at least `UNIFI_API_KEY` and `MCP_UNIFI_AUTH_TOKENS`:

```bash
kubectl create secret generic unifi-creds \
  --from-literal=UNIFI_API_KEY=<your-local-api-key> \
  --from-literal=MCP_UNIFI_AUTH_TOKENS=$(openssl rand -hex 32)

helm install unifi mcp-unifi/mcp-unifi \
  --set unifi.host=192.168.1.1 \
  --set existingSecret=unifi-creds
```

When `existingSecret` is set, the chart does not render its own Secret; the referenced Secret must expose the keys listed above.

## Verify

Port-forward the service and send a `tools/list` request. Include the bearer token you set above:

```bash
kubectl port-forward svc/unifi-mcp-unifi 3714:3714

curl -sS -X POST http://localhost:3714/mcp \
  -H "Authorization: Bearer $MCP_UNIFI_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

You should see the Network tools listed (Protect and Access tools appear when `modulesEnabled` includes them). The always-current per-module tool count is in the [Tool Manifest](/mcp-unifi/tools/).

## Defaults worth knowing

- Pod runs as **UID 1000**, non-root, read-only filesystem, all capabilities dropped.
- Service is `ClusterIP` on port `3714`. Flip `service.type` to `NodePort` or `LoadBalancer` for cluster-external access.
- Ingress is off by default. Enable via `ingress.enabled: true` and configure `ingress.hosts`.
- NetworkPolicy is off by default. Opt in via `networkPolicy.enabled: true` plus your own `ingressRules` / `egressRules`.
- Liveness and readiness probes hit `/health` on port `3714`.

## Upgrade

```bash
helm repo update
helm upgrade unifi mcp-unifi/mcp-unifi -f values.yaml
```

To pin a specific app version, set `image.tag` in `values.yaml`.
