# rs-console

Rust control plane for rs-platform identity, VPN enrollment, access policy,
gateway reconciliation, health, and runtime placement.

The console contains the transport-neutral VPN and gateway policy domains plus
the production human-authentication vertical slice accepted in ADR-0037.

## Current scope

- `policy/` owns human VPN users, per-device peers, stable `wg-users` `/32`
  allocation, mandatory `egress`, additive `games`, complete desired
  generations, and the canonical SHA-256 manifest digest.
- `api/` compares a gateway's reported applied state with desired state,
  returns an idempotent delivery when convergence is needed, and validates
  exact acknowledgements.
- The in-memory API adapter exists for tests and local composition only. It is
  not a persistence or production-runtime decision.
- `auth/` owns token hashing, session and ceremony semantics, service/store
  separation, capability consumption, recovery invalidation, and the
  authenticator-independent ceremony interface.
- `server/` supplies the SQLx PostgreSQL repository, `webauthn-rs` adapter,
  independently bound Axum public and private routers, and the audited
  operator break-glass command.

The wire contract matches the platform gateway contract: schema version 1,
`wg-users`, opaque per-device peer IDs, client-generated public keys, unique
`10.100.0.0/24` `/32`s, `on_demand` or `required` health policy, and
`["egress"]` or `["egress", "games"]` permissions.

## Authentication architecture

Production is frozen to relying-party ID `ricardosaad.com`, browser origin
`https://ricardosaad.com`, and API host `platform-api.ricardosaad.com`.
Development may use an explicitly configured local origin and a separate
database. Wildcard origins are rejected.

The runtime binds two sockets and constructs two route inventories:

- public (`RS_PUBLIC_LISTEN`, default `0.0.0.0:8080`): liveness/readiness,
  capability and session discovery, passkey login, logout, first-passkey
  setup, and recovery request;
- private (`RS_PRIVATE_LISTEN`, default `0.0.0.0:8081`): liveness/readiness,
  operator bootstrap, pending recovery review/setup issuance, and read-only
  operator capabilities.

Operator routes are absent from the public `Router`; source addresses and
forwarded headers never select a role. Kubernetes Services and ingress remain
owned by `rs-cloud`.

PostgreSQL migrations in `server/migrations` store random WebAuthn handles,
public passkey data, one-use ceremony state, SHA-256 token/session/CSRF hashes,
idle and absolute session expiries, authentication epochs, and append-only
audit events. No authenticator private key, biometric material, setup token,
recovery token, session token, or CSRF token is stored in plaintext.

All authenticated and capability responses use `Cache-Control: no-store`.
Browser mutations require the exact configured `Origin` and
`application/json`; authenticated mutations additionally require the
session-bound token in `X-CSRF-Token`. Sessions use the host-only
`__Host-rs_session` cookie with `Secure`, `HttpOnly`, and `SameSite=Strict`.

## Configuration and startup

Non-secret runtime configuration is supplied through:

- `RS_PUBLIC_LISTEN`, `RS_PRIVATE_LISTEN`;
- `RS_RP_ID`, `RS_BROWSER_ORIGIN`;
- `RS_ENVIRONMENT` (`production` or `development`);
- `RS_DATABASE_MAX_CONNECTIONS`.

The database URL is intentionally not accepted as a plaintext environment
value. Mount it as a file and set `RS_DATABASE_URL_FILE` (default
`/run/secrets/database-url`).

```sh
rs-console serve
```

Migrations run at startup. `/health/live` reports process liveness and
`/health/ready` checks PostgreSQL.

## Operator break glass

Run only from the accepted AWS/SSM private recovery path. The command requires
both `RS_BREAK_GLASS_ENABLED=true` and the exact confirmation phrase, revokes
the selected operator credential, invalidates operator sessions and
ceremonies, advances the authentication epoch, opens a 1–15 minute private
registration window, and appends an audit event.

```sh
RS_BREAK_GLASS_ENABLED=true rs-console break-glass \
  --operator-user-id operator \
  --revoke-credential 00000000-0000-0000-0000-000000000000 \
  --window-minutes 10 \
  --reason "lost platform passkey" \
  --confirm "INVALIDATE OPERATOR AUTH"
```

The command never prints token material. The private bootstrap endpoint
detects the active database-backed recovery window.

## First operator seed

Create the first operator row only from the accepted AWS/SSM private path.
The command requires `RS_SEED_OPERATOR_ENABLED=true` and the exact
confirmation phrase. It refuses when any operator already exists. Register
the passkey through the private bootstrap endpoint afterward.

```sh
RS_SEED_OPERATOR_ENABLED=true rs-console seed-operator \
  --operator-user-id operator \
  --email operator@example.test \
  --display-name "Platform Operator" \
  --confirm "SEED FIRST OPERATOR"
```

## Approve a human user

Authenticated operators on the private listener create approved users and
receive a one-time setup fragment:

`POST /v1/operator/users` with `{ "user_id", "email", "display_name" }`.

Deliver the returned `#setup=` fragment out of band. The public setup routes
consume it once.

## Restore auth-epoch rotation

After a PostgreSQL restore, rotate every authentication epoch so restored
sessions, ceremonies, and setup/recovery capabilities fail closed:

```sh
RS_ROTATE_AUTH_EPOCH_ENABLED=true rs-console rotate-auth-epoch \
  --reason "restored primary from encrypted backup" \
  --confirm "ROTATE ALL AUTH EPOCHS"
```

## Still deferred

- Cluster, Kubernetes, Talos, ingress, and deployment manifests.
- Email delivery and the browser client (the canonical shell remains in
  `ricardosaad`).
- `wg-nodes` host-agent enrollment, Proxmox capacity scheduling/allocations
  (ADR-0039), exclusive-writer fencing, health intake, and media
  reconciliation.

## Development

The workspace pins Rust 1.85.1 and records 1.85 as its MSRV.

```sh
cargo fmt --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

The multi-stage `Dockerfile` builds an ARM64-compatible Debian image and runs
as UID/GID 10001 with no root privileges. SQLx uses runtime-checked queries,
so no live database or SQLx offline metadata is required to compile.

## Trust boundary

The console owns desired identity and policy. The gateway remains the packet
enforcement point and initiates outbound authenticated sessions. This
repository contains no private keys, live inventory, infrastructure code,
GitHub-writing credentials, or cluster-administration authority.

