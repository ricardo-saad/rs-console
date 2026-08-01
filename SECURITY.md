# Security

Do not open a public issue for a suspected vulnerability. Report it privately
through GitHub's security-advisory flow for this repository.

Never commit WireGuard private keys, enrollment tokens, live user data,
gateway credentials, secret values, private inventory, or production
configuration. Test fixtures must use synthetic identities and public keys.

The baseline security invariants are:

- possession of a request or operator-notification link grants no access;
- WireGuard private keys are generated and retained by the client;
- every human peer has `egress`, while `games` is additive and exact;
- peer membership and permissions converge as one complete generation;
- stale, conflicting, or mismatched generations fail closed;
- gateway acknowledgements bind gateway, delivery, generation, and digest.

Human authentication additionally enforces:

- production WebAuthn uses RP ID `ricardosaad.com` and exact origin
  `https://ricardosaad.com`; wildcard and API-host origins are invalid;
- credentials are discoverable and user-verifying; only public credential
  material and metadata are stored;
- ceremony state is server-side, short-lived, and consumed transactionally
  with its successful result;
- setup, recovery, session, and CSRF values are random 256-bit tokens and only
  their SHA-256 hashes enter PostgreSQL;
- the session cookie is host-only, `Secure`, `HttpOnly`, and
  `SameSite=Strict`, with both idle and absolute expiry;
- every browser mutation requires exact Origin and JSON content type, while
  authenticated mutations also require a session-bound CSRF header;
- the public and private Axum routers are separate route inventories; no
  operator route may be added to the public router;
- recovery approval and authentication-epoch changes invalidate existing
  sessions, ceremonies, and older setup/recovery capabilities;
- audit events are append-only application records and must be exported to
  durable operational logging in deployment;
- database URLs and other secret values are mounted from files, never passed
  through ordinary environment variables or committed configuration.

The operator break-glass command is authorized only from the accepted
MFA-backed AWS and SSM recovery path. It requires explicit enablement and
confirmation, has a maximum 15-minute registration window, and never emits
the generated capability. Treat any unexpected break-glass audit event as a
security incident.

Do not log WebAuthn responses, cookies, CSRF values, setup/recovery
capabilities, database URLs, or complete request headers. A plaintext token
found in PostgreSQL, logs, telemetry, or a commit is compromised and must be
invalidated; deleting the copy is not remediation.

