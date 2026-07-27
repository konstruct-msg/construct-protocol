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

## v0.1.2 — *unreleased*

- **New [Architecture Overview](./architecture-overview.md) chapter** — an
  orientation map of the whole system: the always-on E2EE floor, the layered
  model (transport, entry discovery, route, overlay, delivery) and its offline
  mesh foundation, and how the system degrades gracefully across censorship
  tiers (free → DPI blacklist → national allowlist → blackout). Descriptive
  architecture; normative detail stays in the per-component chapters.
- **Status reconciliation against current code.** Several component statuses
  that were accurate at v0.1.0 have since shipped:
  - **Federation (server-to-server)** — "not implemented" → **implemented**
    (inbound + outbound sealed delivery, Ed25519-signed; multi-node
    interoperability test outstanding).
  - **Sealed sender** — "not implemented" → **implemented** (sealed path
    carries no `sender_id` at rest; enforced-default rollout in progress).
  - **VEIL transport** — **veil-front** is now the production obfuscation
    transport; **obfs4 / WebTunnel** are **retired** (were "deployed" /
    "proof-of-concept").
  - **QUIC / HTTP-3** (`construct-transport`) — recorded as a production
    transport with HTTP/2 fallback; not yet normatively specified.

  Federation and sealed sender, listed as v0.2 gaps under v0.1.1, are now
  implemented.
- **Accuracy pass (2026-07-27) — code-verified corrections.** Fixed
  claims that had drifted from the reference implementation:
  - **Sealed sender / threat model** — resolved a contradiction where
    [Chapter 1](./01-threat-model.md) still said sealed sender was "not yet
    deployed" while [Chapter 7](./07-implementation-status.md) said
    "implemented". Sealed sender is **on by default**; the server-adversary
    section now states the server cannot read `sender_id` for sealed
    traffic, lists the true residual metadata, and cites the masking code
    (`messaging-service/src/envelope.rs:38`, `StealthPolicy.swift:42`,
    `SessionCoordinator.swift` / `MessagingServiceClient.swift`).
  - **Session-control channel** — documented that `session_ready` / ping /
    `SESSION_RESET_INIT` / `END_SESSION` are now sealed (fail-closed).
  - **Client IP minimisation** — new status entry: the server stores no raw
    IP, only a salted hash (`construct-utils/src/lib.rs:92`).
  - **Privacy Pass enforcement** — clarified it runs in `warn`, not
    `enforce` (deferred past 1.0).
  - **Keychain accessibility** — corrected
    `WhenUnlockedThisDeviceOnly` → `AfterFirstUnlockThisDeviceOnly` for
    crypto/session state (`KeychainManager.swift:21`).
  - **Media AEAD** — documented AES-256-GCM (per-file key, delivered E2E)
    for attachments, distinct from the Double Ratchet's ChaCha20-Poly1305
    (`MediaUploadService.swift:83`).
- **New [Metadata Privacy & Sealed Sender](./08-metadata-privacy.md)
  chapter** — the sealed-envelope wire structures (`SealedSenderEnvelope`,
  `SealedInner`, `SenderCertificate` from `core/envelope.proto`), what each
  server role sees vs. cannot, recipient-side sender verification (KT /
  signature vouching, unvouched-but-delivered), the always-on fail-closed
  invariant and sealed/excluded scope, Privacy Pass anti-abuse (`warn`
  status, verifiable-VOPRF in progress), IP minimisation, and an honest
  residual-metadata table. All claims code-cited.
- **New [Anti-Abuse: Privacy Pass Tokens](./09-privacy-pass.md) chapter** —
  the anonymous-token VOPRF over Ristretto255 (blind → evaluate → unblind →
  redeem, `verify_token`), age-tiered issuance caps, redemption + double-spend
  + the `off`/`warn`/`enforce` policy switch (production is `warn`), and the
  verifiable-issuance **batched Chaum–Pedersen DLEQ** (full transcript,
  malicious-issuer key-tagging defence, client key-pinning, KAT). Honest
  claim boundary: honest-but-curious today, malicious once `enforce` relies
  on the DLEQ. All claims code-cited.
- **Chapter 6 (Transport) deepened + corrected.** Fixed stale
  non-guarantee rows (sealed sender is on-by-default; obfs4 is retired, not
  an "in-progress fix"; raw IPs not persisted). New §6.5.3 — the
  direct-first `.auto` connection ladder and graceful degradation across
  censorship tiers, with the honest limit that obfuscation does not cross a
  national allowlist and VEIL is not itself a metadata-hiding layer.
- **New [Voice and Video Calls](./10-calls.md) chapter** — call signalling
  (SDP/ICE) rides the E2EE message path (`content_type = 12`, sealed);
  media is WebRTC DTLS-SRTP keyed via that E2EE signalling, so a 1:1 call is
  end-to-end encrypted (no SFrame needed); audio shipped, video disabled;
  honest connectivity-metadata table (ICE address exchange, TURN).
- **New [Account Recovery](./11-account-recovery.md) chapter** — BIP39
  12-word account re-access (Ed25519 recovery keypair, server stores only
  the public key; restores account, not history) and SLIP-39 `t`-of-`n`
  social recovery of the identity vault (Shamir over GF(2⁸), 28-word
  mnemonics). No server-side key escrow. All claims code-cited.
- **New [Group Messaging (MLS)](./12-group-messaging.md) chapter
  (designed / partial)** — the MLS group engine (OpenMLS, ciphersuite
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, epoch/Commit/Welcome
  model, per-device CFE-persisted store). Clearly marked: core implemented,
  no shipping surface, not yet a normative interop spec.
- **New [Key Transparency](./13-key-transparency.md) chapter (designed /
  client-ready)** — RFC 6962 append-only key log, Signed Tree Head,
  inclusion + consistency proofs; the client verifier is implemented and
  tested, the server log is not yet deployed. Honest boundary stated.
