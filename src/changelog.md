# Changelog

The Konstruct Protocol Specification follows
[Semantic Versioning](https://semver.org/) at the document level:

- **MAJOR** — a wire-incompatible protocol change.
- **MINOR** — a backwards-compatible normative addition (new field,
  new optional behaviour, new normative requirement that an existing
  implementation already satisfies).
- **PATCH** — editorial corrections that do not change implementer
  obligations.

## v0.1.0 — *unreleased*

Initial public draft. All seven content chapters and the introduction
are present at full depth: RFC 2119 normative language, byte-level
wire layouts, mathematical handshake notation (DH₁..DH₄, INITIATOR /
RESPONDER role separation), and verified-against-code parameter values.

- [Introduction](./introduction.md) — project scope, conventions,
  honest current status table.
- [Threat Model](./01-threat-model.md) — adversary classes (network,
  server, historical-device, spam/Sybil), explicit non-goals, trust
  assumptions.
- [Cryptographic Primitives](./02-cryptographic-primitives.md) —
  Suite 1 (X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA-256, PBKDF2,
  Argon2id) and Suite 2 (adds ML-KEM-768, FIPS 203). Constants summary
  table, randomness rules, zeroization requirements.
- [Identity & Key Hierarchy](./03-identity-key-hierarchy.md) — six key
  types, sizes, rotation cadence, storage classes, registration bundle
  wire format.
- [Session Handshake](./04-session-handshake.md) — X3DH initiator and
  responder paths with full math; PQXDH deferred contribution at RK₁;
  tie-break rule for concurrent initiation.
- [Message Encryption](./05-message-encryption.md) — Double Ratchet
  state machine, KDF helpers, AD v3 layout (with v2 fallback), DH
  ratchet step, mandatory DoS guards, PKCS#7 padding (mod 255).
- [Transport Layer](./06-transport.md) — WirePayload binary header
  (52 B fixed + variable KEM), CFE envelope (16 B header + MessagePack),
  gRPC service surface, VEIL anti-censorship tier.
- [Implementation Status](./07-implementation-status.md) — honest
  component matrix (what's implemented, what's stubbed, what's open
  security issue), platform support matrix, open issue tracker
  (`BS-3`, `BS-6`, `SEC-005`, `SEC-006`, `SEC-009`).
- [Appendix A — Error Registry](./appendix-a-errors.md) — every error
  variant a conforming client can observe, organised by surface
  (FFI / CFE / WirePayload / padding / internal / MLS / VEIL / gRPC).
  Includes the auth-disposal rules that prevent accidental device-key
  deletion on transient transport failures.
- [Disclosure & Contact](./disclosure.md) — GitHub Security Advisories
  per repository; no email inbox.

### Editorial decisions in this revision

- **Konstruct (Latin) / Конструкт (Cyrillic)** as the canonical brand
  spellings.
- **NIST FIPS names** for PQ algorithms (`ML-KEM-768`, `ML-DSA-65`),
  with the informal name (`Kyber-768`, `Dilithium-3`) in parentheses
  for first mention.
- **Code-grounded claims** — every algorithm and constant cites its
  source file in `construct-core`. The editorial rule for this repo
  is "code wins" (see `AGENTS.md`).
- **No self-graded "security score"** — replaced with a concrete
  open-issues table in [Implementation Status](./07-implementation-status.md#73-open-security-issues).
- **Federation, P2P, sealed sender, MLS** — explicitly marked as
  not-yet-implemented rather than present-tense claims.

## v0.1.1 — *unreleased*

- **ML-DSA-65 hybrid signatures** — status updated from "Not implemented"
  to "Implemented (optional, feature-gated)" in the component matrix.
  Server-side wire verification activated (`construct-server` `e2e.rs:318`),
  closing the last gap that kept PQ signatures decorative.

### Known gaps for v0.2

- Published test vectors for the X3DH and Double Ratchet operations.
- MLS group-chat protocol (the code is in `construct-core/src/group/`
  but not yet documented at protocol-spec level).
- Federation (server-to-server) protocol — currently single-server.
- Wire-format reference appendix with hex-dumped example handshakes.

### Removed from this revision compared with the internal draft

Content from the internal whitepaper draft that did not meet the
"verified against code" editorial bar was deferred rather than
copied:

- Self-rated "security score 8.5 / 10 → 10/10" — no industry-standard
  rubric exists for such a score.
- "First messenger with formally verified Rust Signal Protocol
  implementation" — aspirational, not done.
- Some roadmap dates from the internal draft, which belong on the
  marketing site rather than in a normative specification.
