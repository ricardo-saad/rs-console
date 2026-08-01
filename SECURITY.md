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

