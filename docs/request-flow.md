# Request Flow

Two paths through the shim: one for OIDC users (e.g. Headlamp), one for in-cluster callers that already hold a ServiceAccount token (e.g. liveness probes, operators).

## OIDC user request

```mermaid
sequenceDiagram
    actor User as User (Headlamp)
    participant Shim as doks-oidc-shim
    participant JWKS as OIDC Issuer<br/>(JWKS endpoint)
    participant K8s as Kubernetes API

    User->>Shim: GET /api/v1/pods<br/>Authorization: Bearer <OIDC token>

    note over Shim: strip X-Remote-User / Impersonate-* headers

    Shim->>JWKS: verify token signature<br/>(JWKS cached at startup)
    JWKS-->>Shim: valid / invalid

    Shim->>Shim: extract groups claim → role name
    Shim->>Shim: read /var/run/secrets/tokens/<role>/token

    Shim->>K8s: GET /api/v1/pods<br/>Authorization: Bearer <SA token>
    K8s-->>Shim: 200 OK (pod list)
    Shim-->>User: 200 OK (pod list)
```

## In-cluster / pass-through request

Non-OIDC tokens (operators, health checks, the k8s client inside Headlamp's own pod) are forwarded unchanged. The shim cannot verify them — they are authorized entirely by the k8s API server.

```mermaid
sequenceDiagram
    actor Op as In-cluster caller<br/>(operator / probe)
    participant Shim as doks-oidc-shim
    participant K8s as Kubernetes API

    Op->>Shim: GET /healthz<br/>Authorization: Bearer <SA token>

    note over Shim: token fails OIDC verification → pass through

    Shim->>K8s: GET /healthz<br/>Authorization: Bearer <SA token>
    K8s-->>Shim: 200 OK
    Shim-->>Op: 200 OK
```
