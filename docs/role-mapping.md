# Role Mapping

How an OIDC identity becomes a set of Kubernetes permissions.

## From claim to ClusterRole

```mermaid
flowchart LR
    subgraph OIDC Token
        C["groups: admin, dev"]
    end

    subgraph Shim
        R["role = admin"]
        F["reads token file"]
    end

    subgraph Kubernetes
        SA["ServiceAccount: shim-admin"]
        CRB["ClusterRoleBinding"]
        CR["ClusterRole: cluster-admin"]
    end

    C --> R --> F --> SA --> CRB --> CR
```

The shim iterates the groups claim in order and uses the **first group that has a matching token file** under `TOKEN_DIR`. This means a user with multiple groups gets the highest-priority role whose token is mounted — priority is determined by claim order.

## Token directory layout

Each role has its own ServiceAccount in k8s. A long-lived token for that SA is mounted into the shim pod at a predictable path:

```
TOKEN_DIR/                         # default: /var/run/secrets/tokens
├── view/
│   └── token                      ← shim-view SA token  (ClusterRole: view)
├── edit/
│   └── token                      ← shim-edit SA token  (ClusterRole: edit)
└── admin/
    └── token                      ← shim-admin SA token (ClusterRole: cluster-admin)
```

## Adding a new role

```mermaid
flowchart TD
    A["1. Create ServiceAccount: shim-myrole"] --> B
    B["2. Create SA token Secret"] --> C
    C["3. Create ClusterRoleBinding"] --> D
    D["4. Mount secret at TOKEN_DIR/myrole/token"] --> E
    E["5. Add myrole to OIDC groups"]
```

Role names must match `[a-zA-Z0-9_-]` — the shim rejects any role name with path characters to prevent directory traversal.
