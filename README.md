# doks-oidc-shim

DigitalOcean Kubernetes does not support OIDC authentication on the API server. This makes it impossible to use identity-provider-backed dashboards like [Headlamp](https://headlamp.dev) out of the box.

`doks-oidc-shim` is a stateless reverse proxy that sits in front of the Kubernetes API server. It verifies incoming OIDC bearer tokens, maps the groups claim to a pre-provisioned ServiceAccount role, and swaps the token before forwarding the request. Non-OIDC tokens (in-cluster SA tokens, liveness probes) pass through unchanged.

```
Browser / Headlamp  ->  doks-oidc-shim  ->  Kubernetes API
   OIDC token                  |               SA token
                        verify + swap
```

## Docs

- [Setup & configuration reference](docs/SETUP.md)
- [Request flow](docs/request-flow.md)
- [Auth decision logic](docs/auth-logic.md)
- [Role mapping](docs/role-mapping.md)

## Quick start

### Minimal (no TLS, no dashboard)

```sh
# edit examples/deploy/deployment.yaml — set OIDC_ISSUER and OIDC_CLIENT_ID
kubectl apply -k examples/deploy/
kubectl -n oidc-shim rollout status deployment/doks-oidc-shim
```

### Headlamp

[`examples/headlamp/`](examples/headlamp/) — shim with TLS via cert-manager, co-located with Headlamp.

```sh
kubectl apply -k examples/headlamp/
kubectl -n headlamp wait certificate/doks-oidc-shim-tls --for=condition=Ready --timeout=60s
helm upgrade --install headlamp headlamp/headlamp \
  --namespace headlamp \
  -f examples/headlamp/headlamp-values.yaml
```

See [docs/SETUP.md](docs/SETUP.md) for the full guide.

## Images

```
ghcr.io/lajosbencz/doks-oidc-shim:latest         # scratch (smallest)
ghcr.io/lajosbencz/doks-oidc-shim:latest-alpine  # alpine  (includes shell)
```
