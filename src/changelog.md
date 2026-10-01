# Changelog

The Konstruct Protocol Specification follows
[Semantic Versioning](https://semver.org/) at the document level:

- **MAJOR** — a wire-incompatible protocol change.
- **MINOR** — a backwards-compatible normative addition (new field,
  new optional behaviour, new normative requirement that an existing
  implementation already satisfies).
- **PATCH** — editorial corrections that do not change implementer
  obligations.

## v0.3.0 — *unreleased* (2026-09-30)

Wire-incompatible. Reconciles the specification with construct-core 0.24.0 (PQR-2,
`decisions/pq-ratchet-per-message-chain.md`) and 0.24.1 (PQR-1). Suite 3 (the sparse continuous PQ
ratchet as it existed through core 0.23) is retired without a compatibility path, as PQXDH v1 was
before it: builds speaking Suite 3 cannot exchange PQ-ratchet messages with builds speaking Suite
4, and a stored Suite-3 session is not carried forward — the next send simply opens a Suite-4 one.
This revision also corrects a description that had been stale since PQXDH v2 (2026-09-25, core
0.18): the book still described the PQ ratchet as bundle-negotiated with a downgrade refusal,
which that same cutover removed.

- **Calls are post-quantum** (2026-10-01, `PQC-4` resolved;
  [Ch. 10 §10.3](./10-calls.md), [Ch. 1 — Post-quantum coverage](./01-threat-model.md#post-quantum-coverage)).
  The DTLS handshake of a call is DTLS 1.3 with X25519MLKEM768: libwebrtc's field trial
  `WebRTC-EnableDtlsPqc`, turned on by the iOS client on webrtc-sdk 150.7871.01. Observed on the
  wire: key shares of 1216 and 1120 bytes. Not frame encryption: for a two-party call the DTLS
  exchange is what keys the media, and it now needs ML-KEM-768 broken as well as X25519. Limit:
  the endpoints choose the group, and a peer without the trial gets X25519 silently.

- **PQR-1 has no remaining gap** (2026-10-01, construct-core `68cd63c`, test only;
  [Ch. 2 §2.4.3](./02-cryptographic-primitives.md#243-cadence-and-retention),
  [§2.4.4 rule 6](./02-cryptographic-primitives.md#244-normative-rules-for-the-sparse-exchange),
  [Ch. 7 §7.3](./07-implementation-status.md#73-open-security-issues)). The book said a
  conversation only the responder writes could not rekey and that closing it needed roles that
  alternate per epoch. The initiator's delivery receipts are sends: they run the age check and
  carry the proposal, so such a conversation reaches a new epoch in three round trips. Role
  alternation would not have helped any case — every exchange needs both sides to send once.
  New normative rule 6: a client answers every decrypted message with a receipt on the session
  and offers no switch to turn receipts off; both clients already do, so no implementation
  changes.

- **What is and is not post-quantum, layer by layer** (2026-10-01,
  [Ch. 1 — Post-quantum coverage](./01-threat-model.md#post-quantum-coverage)). The threat model
  promised quantum-recording resistance "for sessions that used Suite 2 (PQXDH)" — a suite no
  session negotiates — and named no exception. It now says what is true: the content of
  one-to-one messages and attachments is protected, every session being PQXDH v2. It also lists
  the layers that are still classical: the sealed-sender box (who sent a message), other X25519
  sealed boxes, server-signed certificates and tree heads, device and recovery authentication,
  calls (DTLS-SRTP), MLS groups, Privacy Pass, and transport TLS (not established). Each one has
  a source line and a §7.3 row, `PQC-1`…`PQC-6`. Chapters 8, 10 and 12 and the introduction say
  the same where they describe those layers. The "Identity unforgeability" goal names the hybrid
  Ed25519 + ML-DSA-65 bundle signatures that PQXDH requires, not Ed25519 alone.
- **The first flight sealed whole** (construct-core 0.27.0, 2026-10-01; Ch. 8, "First flight";
  `SealedInner.first_flight = 22`). Found while preparing the anonymous bundle fetch: until the
  peer answers, every message an initiator writes carried its ML-KEM identity key in the clear
  handshake header, and an own-device copy ties that key to the account — the server could read
  the sender of a sealed first contact off it (`FF-1`, resolved in the same revision). The
  certificate and the whole header are now sealed under X25519 plus the handshake's ML-KEM
  secret; only the recipient's Kyber prekey id and the ciphertext stay outside. `BF-1`
  corrected: the iOS client already fetches bundles over the sealed channel, the Android client
  does not. `PQC-1` narrows to two rare boxes. Wire-incompatible with core 0.26; sessions of it
  still in their first flights are refused and renew. With it (0.27.1): an initiator does not
  write on a handshake its peer has not answered in 7 days, so no first flight outlives the
  prekey it was sealed to — handshake age 7 + queue 7 ≤ prekey retention 14, checked at compile
  time. Retired envelope pairs are kept for the queue window, 7 days; the 30 written before was
  the receipt-routing TTL, mistaken for the queue.
- **The session envelope** (construct-core 0.26.0, 2026-10-01; Ch. 8, "Session envelope";
  `SealedInner.session_envelope = 21`). After first contact a sealed message carries no
  certificate and no readable wire payload. It carries an envelope keyed from the session's
  PQXDH v2 root, and the recipient finds who wrote it by a tag. Who sent an established-session
  message is post-quantum, and the server no longer sees the ratchet header that linked a
  chain's messages. A pair outlives its ratchet (retired for the queue window), so a reader that reset
  still answers the writer along it. The coverage table and `PQC-1` are updated. New `BF-1`:
  the authenticated bundle fetch names a first message's sender to the server, which is why the
  first flight's box is not the next thing to make post-quantum. Wire-incompatible with core
  ≤ 0.25; stored sessions from it are refused and renew on the next send.
- **§7.3 brought up to date** (2026-10-01). `SEC-006` resolved (construct-core 0.24.2: the AD v2
  fallback decrypt removed); `DE-2` resolved (the sealed-copy id map is persisted on both
  clients); `PQR-4` now describes the loss it is about and the measurement that will settle it
  (construct-core 0.25.0, `ReorderStats`); `SEC-009` says CFE records, not session JSON.

- **The post-quantum half of the ratchet gets per-message forward secrecy**
  ([Ch. 2 §2.4](./02-cryptographic-primitives.md#24-suite-4--sparse-continuous-pq-ratchet-per-message-chains),
  [Ch. 5 §5.1](./05-message-encryption.md#51-session-state),
  [Ch. 5 §5.8.3](./05-message-encryption.md#583-pq-ratchet-retention-suite-4)). Until now, a
  completed PQ epoch's ML-KEM-768 secret was stored and mixed unchanged into every message key of
  the epoch (`pq_epoch_secret`, up to 4 epochs retained); the classical half of the ratchet
  already had per-message forward secrecy, the post-quantum half only per-epoch. A completed
  epoch's secret is now spent at once into two directional chain keys
  (`HKDF-SHA-256(salt = ∅, IKM = epoch_secret, info = "construct-pqr-chains-v2" ‖ epoch, L = 64)`)
  and never stored; each message takes the next key of its sender's chain
  (`info = "construct-pqr-step-v2"`), mixed into the Double Ratchet key exactly as before
  (`info = "construct-pqr-msg-v2"`, the PQ key as the HKDF salt). The receiver advances its
  chain to the message's index, keeping passed-over keys as skipped PQ keys under the same
  count/jump/age bounds as classical skipped keys; a failed decrypt rolls back all PQ state via
  the existing snapshot mechanism, so a forged index consumes nothing. Only the current epoch's
  send chain is live; `PQ_CHAIN_RETENTION = 2` (current + previous epoch's receive chains)
  replaces the old 4-epoch-secret retention and is the new answer to `PQR-4`
  ([Ch. 7 §7.3](./07-implementation-status.md#73-open-security-issues)) — the bound is the
  skipped-key window, not an independently-sized epoch count. `PQR-2` is resolved by this change.
- **Suite 4 = `PQ_RATCHET`** (`0x0004`); Suite 3 (`0x0003`) is retired. The WirePayload PQ section
  ([Ch. 5 §5.3](./05-message-encryption.md#53-wire-format-wirepayload-header)) gains
  `pq_key_index`, encoded as **minimal unsigned LEB128** (1 byte below 128) directly after
  `pq_message_epoch`; a non-minimal encoding, an index without an epoch, or a frame still claiming
  suite 3 is refused (`NonCanonicalKeyIndex`, `PqKeyIndexWithoutEpoch`, `RetiredSuite` — Appendix A
  §A.4). The AD ([Ch. 5 §5.4](./05-message-encryption.md#54-associated-data-construction-ad)) now
  binds `pq_message_epoch ‖ pq_key_index` (both `u32` BE): 133 bytes for a Suite 4 UUID session,
  up from Suite 3's 129. `WirePayload.pq_key_index` added to the UniFFI record.
- **Known-answer vectors** for the three new derivations (secret = `0x42`×32, epoch = 1, DR key =
  `0x07`×32), recomputed independently against RFC 5869 and pinned in
  [Ch. 2 §2.4.2](./02-cryptographic-primitives.md#242-known-answer-vectors): the initiator's send
  and receive chain keys, the send chain's keys at index 0 and 1, and the message key mixed from
  index 0. To be published to `construct-protos/conformance` alongside the existing content-type
  vectors.
- **`CfePqRatchetStateV2`** (CFE key `pqr2`: epoch chains, skipped PQ keys, provisional chains
  in place of a provisional secret) replaces `CfePqRatchetStateV1` (CFE key `pqr`)
  ([Ch. 3 §3.7](./03-identity-key-hierarchy.md#37-per-session-keys-double-ratchet)). The old key
  is not migrated — a Suite-3 session is refused at restore, not upgraded in place.
- [Appendix B §B.6](./appendix-b-pq-comparison.md#b6-granularity-of-the-post-quantum-guarantee)
  rewritten: Konstruct's post-quantum forward secrecy now matches Signal SPQR's in kind
  (per-message). The comparison describes Konstruct's own mechanism (two chains reseeded from a
  fresh KEM secret every epoch) without characterising SPQR's internal chain structure, which this
  book has not independently verified against a primary source. The earlier per-epoch asymmetry is
  kept in the text as a dated "changed" note, not silently rewritten away.
- **PQR-1 resolved** (construct-core 0.24.1). An epoch used to rekey only on a count of
  DH-ratchet turns, so a one-sided conversation — one side always writing, the other always
  reading — never took a turn and so never rekeyed. `pq_ratchet_max_age_seconds` (7 days, the
  floor Apple PQ3 guarantees) is now checked on every `encrypt`: past it, the exchange initiator
  proposes a new epoch on its next send regardless of the turn count
  (`maybe_start_pq_exchange_by_age`); the turn-counted path checks the same age. `pq_epoch_since`
  is the clock, persisted as CFE `CfePqRatchetStateV2.since`; a blob without it reads as
  maximally old. **Remaining gap, stated in the code and here:** only the exchange initiator ever
  proposes, so a conversation in which only the *responder* writes still cannot rekey by either
  path — closing that needs roles that alternate per epoch, not a parameter change. See
  [Ch. 2 §2.4.3](./02-cryptographic-primitives.md#243-cadence-and-retention),
  [Appendix B §B.3](./appendix-b-pq-comparison.md#b3-rekey-cadence), and
  [Ch. 7 §7.3](./07-implementation-status.md#73-open-security-issues).
- **Correction: the PQ ratchet has not been bundle-negotiated since PQXDH v2** (2026-09-25, core
  0.18), and this book kept describing it as if it still were. The unsigned `supports_pq_ratchet`
  bundle capability and its downgrade refusal (`PQ_DOWNGRADE_REFUSED`) were removed the same
  commit that made PQXDH v2 — and with it the PQ ratchet — mandatory wherever the core's
  `post-quantum` feature is built; a first message on any other suite is refused
  (`PQXDH_REQUIRED`). Corrected in [Ch. 2 §2.4](./02-cryptographic-primitives.md#24-suite-4--sparse-continuous-pq-ratchet-per-message-chains),
  [Ch. 3 §3.7](./03-identity-key-hierarchy.md#37-per-session-keys-double-ratchet),
  [Ch. 4 §4.3/§4.6/§4.7](./04-session-handshake.md), [Ch. 7 §7.1](./07-implementation-status.md#71-component-matrix),
  and [Appendix A §A.2.1](./appendix-a-errors.md#a21-session-refusal-prefixes). The field (proto
  field 24) is not removed from the wire schema, only deprecated, so a stale value from an old
  client is read and ignored rather than misparsed.
- Every "Suite 3" naming elsewhere in this book (§2.1 suite table, §2.7 constants, Ch. 4 §4.6,
  Ch. 6 §6.2, Ch. 7 §7.1/§7.3, Appendix A's `KemEncapsulationError` row, the introduction) now
  reads Suite 4, with a historical note where the old numbering still matters.

## v0.2.0 — *unreleased* (2026-09-28)

Wire-incompatible. Reconciles the specification with construct-core
0.18–0.20. Builds speaking v0.1 cannot open sessions with builds
speaking v0.2; there is no compatibility path before 1.0.

- **PQXDH v2, mandatory** ([Ch. 2 §2.3](./02-cryptographic-primitives.md),
  [Ch. 4 §4.3](./04-session-handshake.md#43-initiator-path)). The ML-KEM
  secret enters the initial root key
  (`info = "Construct-PQXDH-RootKey-v2" || SHA-256(KEM_pub) || SHA-256(kem_ct)`)
  instead of being mixed in after the first DH ratchet step, so the first
  chain is no longer classical only. Prekeys move from ML-KEM-768 to
  ML-KEM-1024 (1568-byte key and ciphertext); ML-KEM-768 remains only in the
  Suite 3 ratchet. A session is not created without a validly signed Kyber
  prekey and a hybrid identity. Removed: `construct-pqxdh-v1`, the deferred
  contribution store (`KyberSessionState`), the classical fallback.
- **Kyber prekey signatures v2** ([Ch. 3](./03-identity-key-hierarchy.md)):
  suite byte `0x11`, signed `created_at`, Ed25519 and hybrid, on one-time
  Kyber prekeys too; a KEM-SPK older than 30 days is refused with no
  stale override. Bundle fields 25–28.
- **PQ-ratchet downgrade refusal**: a device that advertised or used Suite 3
  and stops advertising it is refused.
- **Handshake header on the whole first flight, and it opens at any message
  number** ([Ch. 4 §4.4.1](./04-session-handshake.md#441-what-opens-a-session)).
  Wire `suite_id` bit `0x0100` marks it.
- **The responder opens from the sender certificate**
  ([Ch. 4 §4.4.2](./04-session-handshake.md#442-opening-without-the-server)),
  with its server signature required; no bundle fetch to receive.
- **No tie-break** ([Ch. 4 §4.5](./04-session-handshake.md#45-simultaneous-opening)).
  Simultaneous openings keep both states.
- **Previous states** ([Ch. 5 §5.9](./05-message-encryption.md#59-previous-states)):
  up to three per peer device for seven days; one that decrypts is promoted.
- **DECRYPTION_ERROR replaces END_SESSION and healing**
  ([Ch. 5 §5.10](./05-message-encryption.md#510-decryption_error)): content
  type 28, a fixed 191-byte sealed box naming the ratchet key of the unread
  message; the writer retires that state only if it is current and resends
  once. Content types 21 (END_SESSION) and 24 (SESSION_RESET_INIT) are
  retired, as are `session_ready`, the handshake ping and the heal queue.
- A DECRYPTION_ERROR is sealed only to a writer whose certificate passes the server-signature
  and device checks, on every path ([Ch. 5 §5.10.3](./05-message-encryption.md#5103-receiver));
  `DE-1`, found while writing this revision, was fixed in construct-core 0.20.1.
- **The responder proves the initiator post-quantum**
  ([Ch. 4 §4.4.4](./04-session-handshake.md#444-the-initiator-proves-its-kem-identity-key)):
  every device has an ML-KEM-1024 identity key derived from its hybrid key's ML-DSA seed; the
  first flight names it (wire bit `0x0200`), bound into the root key (`RootKey-v3`); the
  responder pins it, encapsulates to it and mixes the secret into its first sending chain, and
  carries the ciphertext (bit `0x0400`) until the initiator sends on a later chain. Before this,
  only the initiator had post-quantum authentication of its peer. No signature is added.
- Open issue added: `DE-2` ([Ch. 7](./07-implementation-status.md)).
  Corrected: the test-coverage table overstated the integration tests.
- Platform matrix ([Ch. 7 §7.2](./07-implementation-status.md#72-platform-matrix)) and
  the introduction brought up to date: Android is a working client on the current core, not
  Phase 0; macOS links the core directly (the `construct-engine` path was retired 2026-07-28);
  `construct-tui` is paused and does not interoperate. Transport references point at
  `construct-transport`.

## v0.1.0 — *unreleased*

Initial public draft. The core protocol chapters and the introduction
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
  security issue), platform support matrix, and open issue tracker.
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
  - **QUIC / HTTP-3** — recorded as the production engine-QUIC direct path
    with HTTP/2 fallback; not yet normatively specified.

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
  (SDP/ICE) rides the E2EE message path and is sealed; the real call type
  lives inside the encrypted KNST frame for ordinary sends. Media is WebRTC
  DTLS-SRTP keyed via that E2EE signalling, so a 1:1 call is end-to-end
  encrypted (no SFrame needed); audio shipped, video disabled; honest
  connectivity-metadata table (ICE address exchange, TURN).
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
- **New [Key Transparency](./13-key-transparency.md) chapter** — RFC
  6962-style append-only key log, Signed Tree Head, inclusion proofs,
  and the honest deployment boundary: per-bundle inclusion proofs are
  live, while public monitoring, consistency checking, and STH gossip
  remain open.
- **Key Transparency status corrected (2026-07-27).** A code audit found the
  earlier "server not yet publishing the log" claim was **wrong**: the server
  maintains an append-only Merkle log and returns a Signed Tree Head +
  inclusion proof inline with every pre-key bundle (`key-service/src/kt.rs`,
  migrations 044/054), and the client verifies inclusion + STH signature on
  receipt (`KeyTransparencyVerifier`). [Chapter 13](./13-key-transparency.md)
  and the [Implementation Status](./07-implementation-status.md) KT row were
  rewritten to state what is live and to name the real remaining gap — no
  public monitor endpoint, no in-practice consistency checking, no STH
  gossip/auditor — i.e. the current STH catches a self-contradicting server
  but not one that equivocates consistently across victims (split view).
- **Protocol-code audit (2026-08-26).** Reconciled the public spec with
  `construct-core`, `construct-server`, and the iOS client on the protocol
  surfaces implementers need:
  - WirePayload and CFE byte layouts corrected to little-endian where the
    reference encodes little-endian; CFE CRC corrected to payload-only.
  - Suite 3 (`PQ_RATCHET`) documented as a separate, capability-negotiated
    sparse continuous ML-KEM-768 ratchet, with its WirePayload PQ section
    and message-key HKDF.
  - Double Ratchet KDF labels corrected (`Double-Ratchet-*`), AD v3 length
    corrected to 125 B for UUID sessions (129 B with Suite 3 epoch), and AD
    v2 fallback corrected to the same field layout with a different version
    byte.
  - Prekey signatures corrected from `public_key || epoch` to
    `b"KonstruktX3DH-v1" || [0x00, suite_id] || public_key`; SPK clean
    freshness corrected from 10 days to 30 days with explicit stale-tolerant
    degraded init.
  - Hybrid Ed25519 + ML-DSA-65 signatures updated from planned to
    implemented/capability-gated, including the hybrid identity
    cross-signature and 3373-byte signature format.
  - Sealed sender metadata updated: normal sealed traffic no longer exposes
    real `content_type`; `SealedInner.content_type`, `priority`, and `ttl`
    are deprecated server-visible compatibility fields, with only structural
    exceptions 21 and 24 allowed before decryption.
- **Suite 3 operational parameters and prior-art comparison (2026-08-28).**
  Read out of `construct-core` while answering how the classical and
  post-quantum halves combine end to end.
  - §2.4.1 adds the cadence and retention constants that the chapter
    previously described only as "a configured cadence": 16 **DH-ratchet
    turns** (clamped `[4, 64]`), 4 retained epoch secrets, unanswered
    proposals abandoned by age. The unit matters and was not stated: the
    counter advances inside the DH ratchet step, so a one-sided burst of
    any length makes no PQ progress. A pending field rides on every
    outgoing frame including delivery receipts, so an acknowledging peer
    carries the exchange forward without replying.
  - §2.4.2 adds five normative rules that were implemented but unwritten:
    commit-on-success (a malformed PQ field must not alter session state
    and must not affect its carrier's classical delivery), re-attach until
    implicitly acknowledged, one exchange in flight, `ek_hash`
    disambiguation of re-proposals, and the fact that the epoch secret is
    constant within an epoch.
  - New [Appendix B](./appendix-b-pq-comparison.md) compares the
    construction with Signal PQXDH, Signal's Triple Ratchet / SPQR
    (October 2025), Apple iMessage PQ3, and the MLS post-quantum
    cipher-suite drafts, on five axes: handshake-only versus continuing,
    rekey cadence, how the 1184/1088-byte KEM objects are carried,
    advancing without a reply, and the granularity of the post-quantum
    guarantee.
  - §7.3 records four open issues that comparison surfaced — `PQR-1`
    (no wall-clock rekey floor), `PQR-2` (epoch-granular post-quantum
    forward secrecy against message-granular classical), `PQR-3` (KEM
    objects carried whole and re-attached per message), `PQR-4` (epoch
    retention of 4 against a skipped-key tolerance of 1000).
