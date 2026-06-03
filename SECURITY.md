# Security Policy

## Reporting a vulnerability

Konstruct does not currently operate a security email inbox. Report
security issues privately through **GitHub Security Advisories** on the
repository whose code is affected:

| Issue area | Repository | Report here |
|---|---|---|
| Crypto core (X3DH, Double Ratchet, PQXDH, key derivation, ML-KEM-768) | construct-core | [Open advisory](https://github.com/konstruct-msg/construct-core/security/advisories/new) |
| iOS / macOS client | construct-ios | [Open advisory](https://github.com/konstruct-msg/construct-ios/security/advisories/new) |
| Server-side (message routing, auth, federation) | construct-server | [Open advisory](https://github.com/konstruct-msg/construct-server/security/advisories/new) |
| VEIL anti-censorship transport (obfs4, WebTunnel, veil-front) | construct-veil | [Open advisory](https://github.com/konstruct-msg/construct-veil/security/advisories/new) |
| QUIC transport (ConstructEngine) | construct-engine | [Open advisory](https://github.com/konstruct-msg/construct-engine/security/advisories/new) |
| **This specification** — wrong / contradictory / dangerous protocol text | construct-protocol | [Open advisory](https://github.com/konstruct-msg/construct-protocol/security/advisories/new) |

The disclosure metadata in RFC 9116 format lives at
[konstruct.cc/.well-known/security.txt](https://konstruct.cc/.well-known/security.txt).

## What we ask of reporters

- **No public disclosure** while we work on a fix.
- **A concrete reproduction** if at all possible — sample input, the
  expected and observed behaviour, and which repository / file you
  believe is at fault.
- **Patience.** Konstruct is run by a tiny team, not a 24/7 security
  response organisation. We will acknowledge within a reasonable time
  but cannot guarantee a same-day reply.

## What you can expect from us

- Acknowledgement of receipt.
- An honest assessment of severity and exploitability.
- A target timeline for the fix (or, if we decide not to fix, an
  explanation of why and what you can do to protect yourself).
- Public credit in the changelog when the fix ships, unless you
  prefer to remain anonymous.

## Scope

In scope: anything that breaks the security properties claimed in
[this specification](https://konstruct-msg.github.io/construct-protocol/).

Out of scope while the project is in single-server alpha:

- Denial-of-service against the single production server (we know;
  the federation roadmap is the fix).
- Mis-configuration of the deployment server that does not affect
  client-side security guarantees.
- Lack of public bug-bounty payouts — there is no bounty programme
  at this stage. Credit and public acknowledgement are what's on
  offer.
