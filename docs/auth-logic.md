# Auth Decision Logic

```mermaid
flowchart TD
    A([Inbound request]) --> B{Bearer token?}

    B -- No --> PT[Proxy as-is]
    B -- Yes --> C[Strip impersonation headers]

    C --> D{Valid OIDC token?}

    D -- Yes --> E[Extract groups claim]
    D -- No, issuer matches --> U1([401 Unauthorized])
    D -- No, issuer mismatch --> P{ALLOW_PASSTHROUGH?}
    P -- No --> U2([401 Unauthorized])
    P -- Yes --> PT

    E --> F{Groups claim present?}
    F -- No --> K([403 Forbidden])
    F -- Yes --> H[Iterate groups in order]

    H --> I[Read token file from disk]
    I --> J{Token file found?}
    J -- No, try next --> H
    J -- None matched --> K
    J -- Yes --> L[Swap Authorization header]

    L --> PT
    PT --> M([Proxy to k8s API])
```

Key points:

- **Impersonation headers are always stripped**, even on pass-through requests. A client cannot trick k8s into running a request as a different user by injecting these headers.
- **The role name comes from the OIDC token** (signed by the issuer), not from the client request. The client cannot choose its own role.
- **Missing or unmatched groups → 403**, not a fallback to a lower-privilege role. A misconfigured deployment fails loudly.
- **Expired/invalid token from our issuer → 401 always**, even if passthrough is enabled. The issuer match is detected without verifying the signature.
