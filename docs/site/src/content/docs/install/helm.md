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

The chart defaults to `unifi.stubMode: false`, which is real mode. In real mode the server needs controller config (`unifi.host` plus an API key, or a controllers file; see below), and without it the pod exits at startup with `Real mode requires controller config`. It does not fall back to stub mode. To run on mock data with no gateway, set `unifi.stubMode=true`, as the command above does.

## Install (real mode)

Create a small `values.yaml`:

```yaml
unifi:
  host: 192.168.1.1
  apiKey: <your-local-api-key>
  port: 443
  site: default
  stubMode: false

modulesEnabled: "network,protect,access"

auth:
  required: true
  tokens: "<paste-token-from-openssl-rand-hex-32>"
```

`unifi.verifySSL` is left unset on purpose: the server then verifies the gateway certificate only when the key comes from a file or the certificate is pinned. Set `verifySSL: true` if the gateway has a certificate your cluster trusts.

Generate the API key in the gateway UI under **Settings → Control Plane → Integrations → Create API Key**. Generate the bearer token with `openssl rand -hex 32`.

Install with the override:

```bash
helm install unifi mcp-unifi/mcp-unifi -f values.yaml
```

For a production deployment, prefer an `existingSecret` over plaintext values in `values.yaml`. The Secret should expose `UNIFI_API_KEY` (required when `unifi.host` is set, ignored in stub mode) and `MCP_UNIFI_AUTH_TOKENS` (the server will not start in HTTP mode without a token unless `auth.required` is false):

```bash
kubectl create secret generic unifi-creds \
  --from-literal=UNIFI_API_KEY=<your-local-api-key> \
  --from-literal=MCP_UNIFI_AUTH_TOKENS=$(openssl rand -hex 32)

helm install unifi mcp-unifi/mcp-unifi \
  --set unifi.host=192.168.1.1 \
  --set existingSecret=unifi-creds
```

When `existingSecret` is set, the chart does not render its own Secret; the referenced Secret must expose the keys listed above.

## Several controllers, Access, and other settings

The `unifi.*` values cover one controller on the Network module. Everything else is set through four escape hatches, all empty by default and rendered only when you set them: `extraEnv` (a list of container environment entries), `extraEnvFrom` (a ConfigMap or Secret whose keys all become variables), `extraVolumes` and `extraVolumeMounts`. Between them you can set any environment variable the server reads, for example `UNIFI_PROTECT_API`, `UNIFI_WRITE_API`, `UNIFI_PINNED_CERT`, the `*_FILE` secret variables, `LOG_LEVEL` and `LOG_FORMAT`. The root filesystem is read-only, so a file the server must read is mounted through `extraVolumes`.

Do not use `extraEnv` for a variable the chart already sets from its own values (`STUB_MODE`, `UNIFI_HOST`, `UNIFI_PORT`, `UNIFI_SITE`, `UNIFI_VERIFY_SSL`, `MCP_UNIFI_MODULES_ENABLED`, `MCP_UNIFI_AUTH_REQUIRED`, `MCP_UNIFI_READONLY`, `MCP_UNIFI_COMPACT_RESPONSES`, `MCP_UNIFI_AUDIT_SINK`, `MCP_PORT`). Set those through their values.

### Multiple controllers

Put the controllers YAML in a Secret (it holds API keys), mount it, and point `MCP_UNIFI_CONTROLLERS_FILE` at it. The file format is in the [Multi-Site Setup guide](/mcp-unifi/guides/multi-site/).

```bash
kubectl create secret generic unifi-controllers \
  --from-file=controllers.yaml=./controllers.yaml
```

```yaml
auth:
  tokens: "<paste-token-from-openssl-rand-hex-32>"

extraEnv:
  - name: MCP_UNIFI_CONTROLLERS_FILE
    value: /etc/mcp-unifi/controllers/controllers.yaml

extraVolumes:
  - name: controllers
    secret:
      secretName: unifi-controllers

extraVolumeMounts:
  - name: controllers
    mountPath: /etc/mcp-unifi/controllers
    readOnly: true
```

When the controllers file is set it wins over `unifi.host` and `unifi.apiKey`, so leave those empty.

### UniFi Access

Add `access` to `modulesEnabled` and give the server the Access hub address and its own API key (separate from the Network key):

```yaml
modulesEnabled: "network,access"

extraEnv:
  - name: UNIFI_ACCESS_HOST
    value: 192.168.1.20
  - name: UNIFI_ACCESS_API_KEY
    valueFrom:
      secretKeyRef:
        name: unifi-access
        key: UNIFI_ACCESS_API_KEY
```

The Access port defaults to `12445`. See the [Access setup guide](/mcp-unifi/guides/access-setup/).

## Audit log

The pod's root filesystem is read-only, so the server's own default (a file at `audit.jsonl` under `/app`) cannot be written. The chart sets `audit.sink: stdout`, which sends every audit line to the container log:

```bash
kubectl logs deploy/unifi-mcp-unifi
```

`/tmp` is an `emptyDir` for scratch space; it is not where the audit log lives. To write a file instead, set `audit.sink: file` and `audit.path`, and make the path land on a volume you mount writable for UID 1000 with `extraVolumes` and `extraVolumeMounts`. `audit.sink: syslog` reads its address from `MCP_UNIFI_AUDIT_SYSLOG_ADDRESS`, which you set with `extraEnv`.

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

- Pod runs as **UID 1000**, non-root, read-only filesystem, all capabilities dropped. The memory limit is `256Mi`.
- Service is `ClusterIP` on port `3714`. Flip `service.type` to `NodePort` or `LoadBalancer` for cluster-external access.
- Ingress is off by default. Enable via `ingress.enabled: true` and configure `ingress.hosts`.
- NetworkPolicy is off by default. Opt in via `networkPolicy.enabled: true` plus your own `ingressRules` / `egressRules`. With both lists empty the policy denies all ingress and all egress, including DNS, so the pod can neither be reached nor resolve and contact the gateway; `values.yaml` has an example that allows the ingress controller in and DNS plus the gateway out.
- Liveness and readiness probes hit `/health` on the container port, which follows `service.port`.
- Changing `unifi.apiKey` or `auth.tokens` restarts the pod, because the chart records a checksum of its own Secret on the pod. A Secret you supply with `existingSecret` is not tracked: restart the pod yourself after changing it.

## Upgrade

```bash
helm repo update
helm upgrade unifi mcp-unifi/mcp-unifi -f values.yaml
```

To pin a specific app version, set `image.tag` in `values.yaml`.
