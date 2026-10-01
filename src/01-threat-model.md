# Threat Model

This chapter defines who Konstruct claims to protect against, who it
explicitly does not, and the assumptions on which every later chapter
rests. **Read it before reading the rest** — a security property only
means something against a specific adversary class, and most
disagreements about "is X secure" reduce to disagreements about which
adversary the discussion has in mind.

## Adversary classes (in scope)

### Network adversary

Capabilities: full passive recording of traffic between any two
endpoints; full active control of the network path (drop, inject,
modify, reorder, replay); deep-packet inspection and traffic
classification; observation across multiple vantage points (e.g.
recording at both ISP and at a transit AS).

What Konstruct guarantees against this adversary:

- Plaintext confidentiality — recovered traffic decrypts to nothing
  more than ciphertext blobs and routing-shaped metadata.
- Tamper detection — any in-flight modification of a Double Ratchet
  ciphertext is rejected by AEAD.
- Forward secrecy — recording today does not enable decryption later
  if a long-term key is later compromised.
- Quantum-recording resistance — recording today does not enable
  decryption later by a quantum-equipped attacker, **for the content of
  one-to-one messages and of the attachments they carry**. Every
  session is opened with PQXDH v2 (ML-KEM-1024), mandatory since
  construct-core 0.18.0; there is no classical-only session to fall back
  to. Who sent a message (the sealed envelope, and the first message of a
  session sealed whole) and the media of calls (DTLS 1.3 with
  X25519MLKEM768) are covered too. **This does not cover every layer:**
  groups, several server-signed objects and some sealed boxes are still
  classical — see [Post-quantum coverage](#post-quantum-coverage) below. Until
  2026-10-01 this line promised the property "for sessions that used
  Suite 2 (PQXDH)", a suite no session negotiates, and named no
  exceptions.

What Konstruct does **not** guarantee:

- That a sufficiently sophisticated network adversary cannot infer
  *that* communication is happening. The [transport
  layer](./06-transport.md) reduces this surface (VEIL, padding, cover
  traffic) but does not eliminate it.

### Server adversary

Three sub-classes, treated together because the design is the same:
honest-but-curious, malicious, fully compromised. Konstruct's
server is *blind to message content by construction* — the same key
material the client uses to decrypt simply is not on the server.

**Sealed sender is deployed and on by default.** Outgoing user traffic —
messages, delivery receipts, call signalling, and the session-control
handshake — is *sealed*: ordinary sealed sends use the dedicated
`SendSealedMessage` RPC whose request carries only `sealed_sender`
bytes plus an optional attempt id; transitional session-control paths
may still carry `Envelope.sealed_sender`, but the outer sender,
conversation id, and real content type are omitted. In both paths the
client seals a server-issued sender certificate to the recipient's
identity key, so only the recipient can recover who sent a message. A
compromised server therefore **cannot** read `sender_id` from sealed
traffic and cannot directly reconstruct the `sender_id → recipient_id`
edge for a sealed message.

- Client policy (always-on in release builds): `construct-ios`
  `Services/StealthPolicy.swift:42` (`isEnabled`), `:71`
  (`shouldUseSealedSender`).
- Client transport: `construct-ios`
  `Networking/gRPC/Services/MessagingServiceClient.swift:203`-`:225`
  (`sendSealedMessage` uses no outer `Envelope`, sender,
  conversation id, or content type).
- Legacy sealed control transport: `construct-ios`
  `Networking/gRPC/Services/MessagingServiceClient.swift:35`-`:68`,
  `:269`-`:351`; `construct-server`
  `messaging-service/src/grpc.rs:333`-`:360`.
- Sealed-inner construction: `construct-ios`
  `Security/StealthSenderService.swift:400`-`:415` (ordinary traffic
  omits `content_type`; only structural sealed-sender exceptions are
  visible before decrypt).
- Server handling: `construct-server`
  `messaging-service/src/grpc.rs:701`-`:750`
  (`send_sealed_message` deliberately does not extract an authenticated
  user id) and `messaging-service/src/envelope.rs:140`-`:270`
  (`dispatch_sealed_sender` routes from `SealedInner` without a sender).

What the server can still see today (single-trusted-server alpha), even
with sealed sender:

- The **recipient** identifier, delivery tag, token fields, payload size,
  and delivery timestamp of each sealed message. The sender is not in
  the `SendSealedMessage` request or the plaintext `SealedInner`; it is
  inside `sender_cert_ciphertext`.
- The pre-existing **contact graph** — contact relationships are stored to
  route message streams.
- **Ciphertext size after padding** and traffic timing/volume.
- **Connection metadata** at the network layer: the source IP address
  (unavoidable for packet routing), transport handshake characteristics,
  and session durations. The server does **not** store the raw IP — its
  anti-abuse rate-limit keys and logs use a salted one-way hash of the
  address (`construct-utils/src/lib.rs:92` `hash_client_ip`, applied in
  `construct-user-service/src/account.rs:140` and
  `construct-auth-service/src/devices.rs:292`). The honest limit: a salted
  hash of the small IPv4 address space is not perfectly anonymous against a
  party holding the salt — it removes the raw address from storage, it does
  not make the origin undiscoverable.
- The encrypted payload bytes (it must, in order to route them).

Anti-abuse tokens (Privacy Pass) accompany sealed sends. Server-side token
**enforcement** (`MSG_STEALTH_TOKEN_POLICY`) currently runs in `warn` mode,
not `enforce` — see [Implementation Status](./07-implementation-status.md).

### Historical device adversary

Capability: after a session has been used for some period of time,
obtain a snapshot of a participating device's state (key material at
rest, session state, message history).

Konstruct guarantees:

- Past message confidentiality up to the moment of compromise
  (forward secrecy via the Double Ratchet's per-message key derivation
  and key eviction).
- Self-healing of future messages after at most one round-trip via the
  DH ratchet step — provided the attacker is no longer active in the
  network path.

### Spam / Sybil adversary

Capability: automated mass registration; commodity GPU farms;
disposable IP pools.

Konstruct deters this with a memory-hard proof of work at registration
(Argon2id, see [Cryptographic Primitives](./02-cryptographic-primitives.md))
and server-side rate limits. Full prevention of nation-state-resourced
Sybil attacks is **not** a Konstruct goal — that would require
identity verification, which is incompatible with privacy goals
elsewhere in the design.

## Out of scope (explicit non-goals)

Konstruct does **not** defend against:

- A live compromise of an *unlocked* device at the moment of decrypt.
  If the attacker has the running process, no end-to-end protocol can
  help.
- OS-, kernel-, or secure-enclave-level compromise of the host
  platform. Keys are stored using platform key stores (on iOS, the
  Keychain; crypto and Double-Ratchet session state that must survive a
  background/locked push-decrypt is gated
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` —
  `construct-ios` `Security/KeychainManager.swift:21` `cryptoKeyAccessible`);
  if those primitives are broken, so is everything that relies on them.
- Hardware-level side channels (Spectre, power analysis, EM
  emanations). Software-level constant-time primitives (`subtle`
  crate, audited AEAD implementations) are used where they apply; this
  does not extend to physics.
- Coercion of the user. A protocol cannot stop a person from being
  forced to unlock their phone.

## Post-quantum coverage

"Post-quantum" in this specification means: an adversary who records
traffic today and obtains a cryptographically relevant quantum computer
later learns nothing protected by that layer. The table lists every
layer that uses public-key cryptography, and whether it meets that bar
today. Symmetric primitives (ChaCha20-Poly1305, AES-256-GCM,
HKDF-SHA256) are not listed: at 256-bit keys they are not the weak point.

| Layer | Post-quantum? | Mechanism | Source |
|---|---|---|---|
| 1:1 session handshake | **Yes** | PQXDH v2: an ML-KEM-1024 (Kyber-1024) secret in the root key beside X25519 ([04](./04-session-handshake.md)) | `construct-core/src/crypto/pq_x3dh.rs` |
| 1:1 messages after the handshake | **Yes** | Suite 4: sparse continuous ML-KEM-768 (Kyber-768) ratchet, one post-quantum key per message ([02 §2.4](./02-cryptographic-primitives.md)). Gap: only the exchange initiator proposes a new epoch (§7.3) | `construct-core/src/crypto/messaging/double_ratchet/internals.rs` |
| Attachments | **Yes**, through the message | AES-256-GCM, key carried inside the 1:1 message | client code (iOS `MediaManager`, Android `MediaRepository`) |
| Prekey bundle authentication | **Yes** | Ed25519 + ML-DSA-65 (Dilithium-3) hybrid signatures, required before PQXDH | `construct-core/src/orchestration/pq_prekey_plan.rs:217` |
| History transfer between own devices | **Yes** | Channel key from X25519 **and** ML-KEM | `construct-core/src/history/channel.rs:206` |
| Sealed sender: who sent a message, **after first contact** | **Yes** (construct-core 0.26) | Session envelope: keyed from the session's PQXDH v2 root, writer found by a tag ([08](./08-metadata-privacy.md)) | `construct-core/src/crypto/sealed_sender/envelope.rs`, `book.rs` |
| Sealed sender: who sent a session's **first** message | **Yes** (construct-core 0.27) | First-flight box: X25519 plus the handshake's ML-KEM-1024 secret; the certificate and the whole handshake header are inside ([08](./08-metadata-privacy.md)). Android bundle fetches still name the fetcher (`BF-1`) | `construct-core/src/crypto/sealed_sender/first_flight.rs` |
| **Other sealed boxes** | **Partly** | A DECRYPTION_ERROR about an enveloped message goes back along the session envelope (post-quantum). One about a failed first message, and device metadata sealed to sibling devices, are still the X25519 box | `src/orchestration/decryption_error.rs:120`, `src/uniffi_bindings.rs:4508` |
| **Server-signed objects** | **No** (authentication) | Sender certificates and Key Transparency tree heads are Ed25519. A future quantum attacker could forge them; it cannot use that to read recorded traffic. After first contact a peer is held by its pinned KEM identity key, not the certificate ([04](./04-session-handshake.md)) | `src/crypto/sealed_sender/mod.rs:171`, `src/crypto/key_transparency.rs:9` |
| **Device and recovery authentication to the server** | **No** (authentication) | Ed25519 device signatures and the Ed25519 recovery key derived from the seed phrase ([11](./11-account-recovery.md)). A forgery would act on the account at the server; it does not decrypt messages | `src/crypto/keys.rs:451`, `src/crypto/recovery.rs:92` |
| **Calls** | **Yes** (since 2026-10-01) | DTLS 1.3 with X25519MLKEM768 for the SRTP keys ([10](./10-calls.md)). Chosen by the two endpoints: a peer whose build does not offer the group gets X25519 alone, and the app cannot see which was agreed | libwebrtc field trial `WebRTC-EnableDtlsPqc`, construct-ios `WebRTCSession.swift` |
| **Group messaging (MLS)** | **No** | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ([12](./12-group-messaging.md)); no shipping product surface | `src/group/mls_store.rs:39` |
| **Privacy Pass tokens** | **No** (anti-abuse only) | VOPRF over Ristretto255 ([09](./09-privacy-pass.md)). A quantum attacker could mint tokens; blinding still keeps a redeemed token unlinkable to its issuance | `src/crypto/privacy_pass/mod.rs` |
| **Transport TLS** | **Not established** | VEIL and QUIC use rustls with the `ring` provider, which offers no hybrid key exchange. The iOS direct gRPC path uses the system TLS stack, whose hybrid support has not been verified against the server ([06](./06-transport.md)). TLS is not what keeps message content confidential either way | `construct-transport/Cargo.toml:22` |

The rows marked **No** are tracked as `PQC-1`…`PQC-6` in
[Chapter 7 §7.3](./07-implementation-status.md#73-open-security-issues).

## Security goals — formal statement

| Goal | Mechanism (chapter) | Guaranteed against |
|---|---|---|
| Confidentiality | X3DH/PQXDH + Double Ratchet AEAD ([04](./04-session-handshake.md), [05](./05-message-encryption.md)) | Network, server (honest-but-curious or malicious) |
| Integrity & authentication | ChaCha20-Poly1305 AEAD with bound AD ([05](./05-message-encryption.md)) | Network, server |
| Forward secrecy | Per-message key derivation + chain key eviction ([05](./05-message-encryption.md)) | Historical device compromise |
| Post-compromise security | DH ratchet step after one round-trip ([05](./05-message-encryption.md)) | Network compromise of a single session |
| Replay resistance | Two-layer dedup: protocol (Double Ratchet message number) + application (ACK store) ([05](./05-message-encryption.md)) | Network |
| Post-quantum confidentiality of 1:1 content | PQXDH v2 (ML-KEM-1024) and the Suite 4 ratchet (ML-KEM-768) ([04](./04-session-handshake.md), [02](./02-cryptographic-primitives.md)) — not every layer, see [Post-quantum coverage](#post-quantum-coverage) | A future quantum-equipped attacker replaying recorded traffic |
| Identity unforgeability | Ed25519 + ML-DSA-65 hybrid signatures over prekey bundles ([03](./03-identity-key-hierarchy.md)) | Network, server |

## Trust assumptions

- **Trusted today** (would compromise security if breached): the local
  device's OS and key store; the bundled `construct-core` binary; the
  audited Rust cryptography crates listed in
  [Cryptographic Primitives](./02-cryptographic-primitives.md); the
  user's choice not to expose their device to an active attacker.
- **Untrusted today**: the network path; the server (for message
  content); other users (until they are explicitly added as contacts).
- **Trust shrinks over time, by design**: the federation roadmap is
  intended to remove the single-trusted-server assumption; the
  veil-front transport is intended to reduce reliance on the network
  not being adversarial.

The remainder of this specification proceeds from this threat model.
A property described later as "secure" means "secure against the
adversary classes above and no others".
