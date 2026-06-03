# Disclosure & Contact

## Reporting a security issue

Konstruct does not operate a security inbox. Use GitHub's private
vulnerability reporting on any of the relevant repositories — your
report will be visible only to maintainers until a fix is published.

- [construct-core](https://github.com/konstruct-msg/construct-core/security/advisories/new) — cryptographic core
- [construct-ios](https://github.com/konstruct-msg/construct-ios/security/advisories/new) — iOS / macOS client
- [construct-server](https://github.com/konstruct-msg/construct-server/security/advisories/new) — server-side
- [construct-veil](https://github.com/konstruct-msg/construct-veil/security/advisories/new) — anti-censorship transport
- [construct-engine](https://github.com/konstruct-msg/construct-engine/security/advisories/new) — QUIC engine
- [construct-protocol](https://github.com/konstruct-msg/construct-protocol/security/advisories/new) — issues with **this specification**

The canonical disclosure metadata file (RFC 9116) is at
[konstruct.cc/.well-known/security.txt](https://konstruct.cc/.well-known/security.txt).

## Scope

Cryptographic, transport, or implementation issues in any of the
public repositories listed above are in scope.

Server infrastructure issues (denial-of-service, mis-configuration of
the single deployment server) are **out of scope** while the project
is in single-server alpha — the whole network depends on one trusted
operator today, and infrastructure hardening is part of the
federation roadmap rather than something a disclosure can usefully
fix.

## Project updates

Project updates and ad-hoc technical posts are at
[@maxeliseyev on X](https://x.com/maxeliseyev).
