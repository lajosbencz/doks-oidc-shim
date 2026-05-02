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

```sh
# 1. edit examples/deploy/deployment.yaml — set OIDC_ISSUER and OIDC_CLIENT_ID
# 2. apply
kubectl apply -k examples/deploy/

# 3. point your dashboard at the shim
#    https://doks-oidc-shim.oidc-shim.svc.cluster.local
```

## Images

```
ghcr.io/lajosbencz/doks-oidc-shim:latest         # scratch (smallest)
ghcr.io/lajosbencz/doks-oidc-shim:latest-alpine  # alpine  (includes shell)
```
