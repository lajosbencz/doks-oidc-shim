# Auth Decision Logic

```mermaid
flowchart TD
    A([Inbound request]) --> B{Bearer token?}

    B -- No --> PT[Proxy as-is]
    B -- Yes --> C[Strip impersonation headers]

    C --> D{Valid OIDC token?}

    D -- No --> PT
    D -- Yes --> E[Extract groups claim]

    E --> F{Claim present?}
    F -- No --> G[role = view]
    F -- Yes --> H[role = first claim value]

    G --> I[Read token file from disk]
    H --> I

    I --> J{Token file found?}
    J -- No --> K([403 Forbidden])
    J -- Yes --> L[Swap Authorization header]

    L --> PT
    PT --> M([Proxy to k8s API])
```

Key points:

- **Impersonation headers are always stripped**, even on pass-through requests. A client cannot trick k8s into running a request as a different user by injecting these headers.
- **The role name comes from the OIDC token** (signed by the issuer), not from the client request. The client cannot choose its own role.
- **Missing token file → 403**, not a fallback to a lower-privilege role. A misconfigured deployment fails loudly.
