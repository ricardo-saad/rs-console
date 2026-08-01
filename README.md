# rs-console

Rust control plane for rs-platform identity, VPN enrollment, access policy,
gateway reconciliation, health, and runtime placement.

This first implementation slice is intentionally pre-cluster. It establishes
the human VPN domain and the transport-neutral side of the gateway's outbound
control-plane protocol without choosing a datastore, HTTP framework, runtime,
or deployment topology.

## Current scope

- `policy/` owns human VPN users, per-device peers, stable `wg-users` `/32`
  allocation, mandatory `egress`, additive `games`, complete desired
  generations, and the canonical SHA-256 manifest digest.
- `api/` compares a gateway's reported applied state with desired state,
  returns an idempotent delivery when convergence is needed, and validates
  exact acknowledgements.
- The in-memory API adapter exists for tests and local composition only. It is
  not a persistence or production-runtime decision.

The wire contract matches the platform gateway contract: schema version 1,
`wg-users`, opaque per-device peer IDs, client-generated public keys, unique
`10.100.0.0/24` `/32`s, `on_demand` or `required` health policy, and
`["egress"]` or `["egress", "games"]` permissions.

## Explicitly deferred

- Cluster, Kubernetes, Talos, and deployment manifests.
- Durable datastore and migrations.
- HTTP framework, routes, mTLS termination, and workload identity.
- Email, passkeys, enrollment capabilities, and the browser setup client.
- `wg-nodes`, placement, fencing, health intake, and media reconciliation.
- A product UI; the canonical browser shell remains outside this repository.

## Development

The workspace pins Rust 1.85.1 and records 1.85 as its MSRV.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

The deployment target is `aarch64-unknown-linux-gnu`, but this slice has no
deployment artifact yet.

## Trust boundary

The console owns desired identity and policy. The gateway remains the packet
enforcement point and initiates outbound authenticated sessions. This
repository contains no private keys, live inventory, infrastructure code,
GitHub-writing credentials, or cluster-administration authority.

