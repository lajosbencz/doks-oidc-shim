# Setup

## Prerequisites

- A DigitalOcean Kubernetes cluster
- An OIDC provider (Dex, Keycloak, Auth0, etc.) with a client configured for your dashboard
- `kubectl` with cluster-admin access
- `kustomize` (bundled in `kubectl` ≥ 1.14)

---

## 1. Configure your OIDC provider

The shim maps the **first value** of a JWT claim to a role name. The claim name defaults to `groups`; change it with `GROUPS_CLAIM`.

Your provider must include a claim like:

```json
{
  "sub": "alice",
  "groups": ["admin"]
}
```

Available roles out of the box: `view`, `edit`, `admin`. Each must match a subdirectory under `TOKEN_DIR` — see [role-mapping.md](role-mapping.md). Users with no matching claim default to `view`.

---

## 2. Deploy

Edit `deploy/deployment.yaml` and set your OIDC values in the ConfigMap:

```yaml
data:
  OIDC_ISSUER: "https://your-oidc-issuer.example.com"
  OIDC_CLIENT_ID: "your-client-id"
```

Then apply:

```sh
kubectl apply -k deploy/
```

Verify the pods are running:

```sh
kubectl -n oidc-shim rollout status deployment/doks-oidc-shim
```

---

## 3. Point your dashboard at the shim

Configure Headlamp (or any compatible dashboard) to use the shim's in-cluster address as the API server:

```
https://doks-oidc-shim.oidc-shim.svc.cluster.local
```

Set the OIDC client to authenticate against your provider. The dashboard sends its OIDC bearer token to the shim, which swaps it for the appropriate ServiceAccount token before forwarding to the real API server.

---

## 4. Add or remove roles

See [role-mapping.md](role-mapping.md) for the step-by-step checklist. In short: create a ServiceAccount, bind it to a ClusterRole, create a token Secret, mount it in the Deployment, and register the role name in your OIDC provider's group list.

---

## Configuration reference

All options are settable via CLI flag, environment variable, or config file (plain `key value` format, one per line). Priority: CLI > env > file.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--oidc-issuer` | `OIDC_ISSUER` | — | OIDC issuer URL **required** |
| `--oidc-client-id` | `OIDC_CLIENT_ID` | — | OIDC client ID **required** |
| `--groups-claim` | `GROUPS_CLAIM` | `groups` | JWT claim mapped to SA role |
| `--k8s-api` | `K8S_API` | auto-detected in-cluster¹ | Kubernetes API server URL |
| `--k8s-ca-file` | `K8S_CA_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | K8s cluster CA certificate |
| `--token-dir` | `TOKEN_DIR` | `/var/run/secrets/tokens` | Per-role SA token directory |
| `--listen` | `LISTEN` | `:8080` | Address to listen on |
| `--read-header-timeout` | `READ_HEADER_TIMEOUT` | `10s` | Max time to read request headers |
| `--read-timeout` | `READ_TIMEOUT` | `30s` | Max time to read an entire request |
| `--write-timeout` | `WRITE_TIMEOUT` | `60s` | Max time to write a response |
| `--idle-timeout` | `IDLE_TIMEOUT` | `120s` | Keep-alive idle timeout |
| `--dial-timeout` | `DIAL_TIMEOUT` | `10s` | TCP connect timeout to upstream |
| `--dial-keep-alive` | `DIAL_KEEP_ALIVE` | `30s` | TCP keep-alive interval to upstream |
| `--tls-handshake-timeout` | `TLS_HANDSHAKE_TIMEOUT` | `10s` | Upstream TLS handshake timeout |
| `--response-header-timeout` | `RESPONSE_HEADER_TIMEOUT` | `30s` | Upstream response header timeout |
| `--idle-conn-timeout` | `IDLE_CONN_TIMEOUT` | `90s` | Idle upstream connection pool timeout |
| `--max-idle-conns` | `MAX_IDLE_CONNS` | `100` | Max idle upstream connections |
| `--shutdown-timeout` | `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown grace period |
| `--config` | `CONFIG` | — | Path to config file |

¹ When `K8S_API` is unset the shim falls back to `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT`, which Kubernetes injects automatically into every pod.

---

## Security model

See [request-flow.md](request-flow.md) and [auth-logic.md](auth-logic.md).
