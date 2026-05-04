# Setup

## Prerequisites

- A DigitalOcean Kubernetes cluster
- An OIDC provider (Dex, Keycloak, Auth0, etc.) with a client configured for your dashboard
- `kubectl` with cluster-admin access
- `kustomize` (bundled in `kubectl` ≥ 1.14)

---

## 1. Configure your OIDC provider

The shim maps the **first matching value** of a JWT claim to a role name. The claim name defaults to `groups`; change it with `GROUPS_CLAIM`.

Your provider must include a claim like:

```json
{
  "sub": "alice",
  "groups": ["k8s-admin"]
}
```

Role names must match the subdirectory names under `TOKEN_DIR`. See [role-mapping.md](role-mapping.md).

---

## 2. Deploy

### Minimal (no TLS, no dashboard)

[`examples/deploy/`](../examples/deploy/) is the simplest starting point — no TLS, no cert-manager. The shim runs in the `oidc-shim` namespace and listens on plain HTTP. Suitable for testing or when TLS is terminated upstream (e.g. at an ingress).

```sh
kubectl apply -k examples/deploy/
kubectl -n oidc-shim rollout status deployment/doks-oidc-shim
```

### With Headlamp

[`examples/headlamp/`](../examples/headlamp/) — shim with TLS, co-located with Headlamp in the `headlamp` namespace. Uses cert-manager to issue a namespace-local certificate trusted only by Headlamp.

```sh
kubectl apply -k examples/headlamp/
kubectl -n headlamp wait certificate/doks-oidc-shim-tls --for=condition=Ready --timeout=60s
kubectl -n headlamp create secret generic oidc \
  --from-literal=clientID=headlamp \
  --from-literal=clientSecret=<your-client-secret> \
  --from-literal=issuerURL=https://your-oidc-issuer.example.com \
  --from-literal=scopes=openid,email,groups
helm upgrade --install headlamp headlamp/headlamp \
  --namespace headlamp \
  -f examples/headlamp/headlamp-values.yaml
```


---

## 3. TLS

The shim supports TLS via `TLS_CERT_FILE` and `TLS_KEY_FILE`. Both must be set together or both left unset.

When running alongside Headlamp in-cluster, TLS is required because Headlamp's in-cluster client validates the server certificate. The recommended approach uses cert-manager to issue a namespace-scoped certificate signed by a local CA (see `examples/headlamp/cert-manager.yaml`).

---

## 4. Allow passthrough

By default the shim rejects any token it cannot verify as a valid OIDC token. Set `ALLOW_PASSTHROUGH=true` to forward unrecognised tokens unchanged to the real k8s API.

This is required when running alongside Headlamp in `-in-cluster` mode: Headlamp uses its own projected ServiceAccount token for some internal API calls (e.g. reading its own namespace). Those tokens are opaque SA tokens, not OIDC tokens, so without passthrough they would be rejected with 401.

---

## 5. Add or remove roles

See [role-mapping.md](role-mapping.md). In short: create a ServiceAccount, bind it to a ClusterRole, create a token Secret, mount it in the Deployment, and register the role name in your OIDC provider's group list.

---

## Configuration reference

All options are settable via CLI flag, environment variable, or config file (plain `key value` format, one per line). Priority: CLI > env > file.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--oidc-issuer` | `OIDC_ISSUER` | — | OIDC issuer URL **required** |
| `--oidc-client-id` | `OIDC_CLIENT_ID` | — | OIDC client ID **required** |
| `--oidc-init-timeout` | `OIDC_INIT_TIMEOUT` | `30s` | Max time to fetch OIDC discovery and JWKS at startup |
| `--oidc-skip-client-id-check` | `OIDC_SKIP_CLIENT_ID_CHECK` | `false` | Skip validating the token audience against the client ID; accepts tokens from any client of the issuer |
| `--groups-claim` | `GROUPS_CLAIM` | `groups` | JWT claim mapped to SA role |
| `--allow-passthrough` | `ALLOW_PASSTHROUGH` | `false` | Forward non-OIDC bearer tokens unchanged; required for Headlamp in-cluster mode |
| `--follow-redirects` | `FOLLOW_REDIRECTS` | `false` | Follow same-host 3xx redirects inside the transport |
| `--k8s-api` | `K8S_API` | auto-detected in-cluster¹ | Kubernetes API server URL |
| `--k8s-ca-file` | `K8S_CA_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | K8s cluster CA certificate |
| `--token-dir` | `TOKEN_DIR` | `/var/run/secrets/tokens` | Per-role SA token directory |
| `--listen` | `LISTEN` | `:8080` | Address to listen on |
| `--tls-cert-file` | `TLS_CERT_FILE` | — | Path to TLS certificate; enables TLS when set with `--tls-key-file` |
| `--tls-key-file` | `TLS_KEY_FILE` | — | Path to TLS private key; enables TLS when set with `--tls-cert-file` |
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
| `--max-header-bytes` | `MAX_HEADER_BYTES` | `262144` | Max request header size in bytes (256 KiB) |
| `--shutdown-timeout` | `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown grace period |
| `--config` | `CONFIG` | — | Path to config file |

¹ When `K8S_API` is unset the shim falls back to `KUBERNETES_SERVICE_HOST` / `KUBERNETES_SERVICE_PORT`, which Kubernetes injects automatically into every pod.

---

## Security model

See [request-flow.md](request-flow.md) and [auth-logic.md](auth-logic.md).
