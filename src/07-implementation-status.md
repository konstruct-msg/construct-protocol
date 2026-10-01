# Implementation Status

This chapter is the honest matrix of what the reference implementation
in `konstruct-msg/construct-core` (and the surrounding repositories)
**actually does today**, distinct from what this specification
*requires* a fully-conforming implementation to do.

It is the chapter readers should consult before relying on Konstruct
for any specific threat model. Every line is grounded in a source-tree
reference so it can be re-verified independently.

## 7.1 Component matrix

| Component | Implementation status | Where it lives |
|---|---|---|
| X3DH + PQXDH v2 handshake (ML-KEM-1024 in the initial root key) | **Implemented and mandatory** since 2026-09-25 (core 0.18); shipped in iOS TestFlight and the Android build. No classical-only path; v1 removed without compatibility | `construct-core/src/crypto/handshake/x3dh.rs:162`-`:185`; `src/crypto/pq_x3dh.rs` (`mlkem1024_*`); refusals `src/orchestration/pq_prekey_plan.rs` |
| Kyber prekey signatures (Ed25519 + hybrid, over `created_at`) | **Implemented**, verified by the initiator's core; a missing or invalid one refuses the session | `construct-core/src/crypto/kyber_prekey_auth.rs` |
| PQ-ratchet downgrade refusal | **Removed** with PQXDH v2 (2026-09-25, core 0.18). Until then, a device that had advertised or used the PQ ratchet was refused (`PQ_DOWNGRADE_REFUSED`) if a later bundle stopped advertising the unsigned `supports_pq_ratchet` capability. The same commit made the PQ ratchet mandatory wherever `post-quantum` is built and deleted both the capability and its downgrade ledger — nothing is left to downgrade | `construct-core/src/crypto/session_api.rs` (`local_supports_pq_ratchet`); removal noted in `src/orchestration/pq_prekey_plan.rs` |
| Responder's proof of the initiator (ML-KEM-1024 identity key) | **Implemented and mandatory** since 2026-09-28 (core 0.22) — the responder pins the initiator's KEM identity key and answers to it; the initiator is `ReceivedProven` once it sends on a chain after that answer. No signature: the first contact stays deniable. First contact is trust-on-first-use | `construct-core/src/orchestration/orchestrator.rs` (`admit_kem_identity`); `double_ratchet/internals.rs` (`answer_initiator_identity`, `mix_identity_secret`) |
| Receiving open from the sender certificate | **Implemented** since 2026-09-27 — no bundle fetch to receive; the certificate's server signature is required | `construct-core/src/orchestration/orchestrator.rs` (`open_receiving`); `src/crypto/sealed_sender/mod.rs:245` |
| Previous states (renew by sending) | **Implemented** since 2026-09-27 — up to 3 previous states per device, 7-day bound; any message with the handshake header opens | `construct-core/src/orchestration/session_lifecycle.rs:31`-`:39` |
| DECRYPTION_ERROR (content type 28) | **Implemented** since 2026-09-28 on core, iOS and Android; replaces END_SESSION | `construct-core/src/orchestration/decryption_error.rs` |
| Sparse continuous PQ ratchet (Suite 4; per-message chains, PQR-2, since core 0.24.0) | **Implemented and mandatory** wherever the `post-quantum` build feature is present (every platform build) since PQXDH v2, 2026-09-25 (core 0.18) — not bundle-negotiated; a first message on any other suite is refused (`PQXDH_REQUIRED`). Suite 3 (epoch-granular) is retired without a compatibility path | `construct-core/src/crypto/suite_id.rs`; `src/crypto/session_api.rs`; `src/orchestration/orchestrator.rs`; wire section `src/wire_payload.rs` |
| Double Ratchet | **Implemented**, including DH ratchet, skipped-key handling, AD v3 (with v2 fallback), and Suite 4 PQ epoch/index tags | `construct-core/src/crypto/messaging/double_ratchet/messaging.rs`; `internals.rs` |
| PKCS#7 length padding (mod 255) | **Implemented**, constant-time unpad | `construct-core/src/traffic_protection/padding.rs:96`-`:126` |
| ACK deduplication store | **Implemented** | `construct-core/src/orchestration/ack_store.rs:83`-`:143` |
| CFE binary envelope at FFI | **Implemented**, used by iOS / macOS / Android bindings | `construct-core/src/cfe/envelope.rs:8`-`:25`, `:48`-`:65` |
| WirePayload binary frame | **Implemented**, little-endian fixed header + Suite 4 PQ-ratchet section (LEB128 key index) | `construct-core/src/wire_payload.rs` |
| MLS group chat (RFC 9420) | **Core present** (OpenMLS, ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), **no shipping product surface**; design documented in [Chapter 12](./12-group-messaging.md), not yet a normative interop spec | `construct-core/src/group/mls_store.rs:1`-`:39` |
| Argon2id proof-of-work | **Implemented** | `construct-core/src/pow.rs` |
| Account recovery — BIP39 (12-word) + SLIP-39 social recovery | **Implemented.** BIP39 restores account access on a new device (recovery Ed25519 keypair, server holds only the public key); SLIP-39 threshold-restores the identity vault. See [Chapter 11](./11-account-recovery.md). | `construct-core/src/crypto/social_recovery.rs`; BIP39/BIP32 derivation in `construct-core` |
| Privacy Pass token issuance | **Implemented** (feature-gated) | `construct-core/src/crypto/privacy_pass/mod.rs:94`-`:165`; server issuance `construct-server/identity-service/src/main.rs:942`-`:1057` |
| Key transparency | **Per-bundle inclusion proofs live; split-view detection not.** The server maintains an append-only Merkle log and returns a Signed Tree Head + inclusion proof inline with every bundle (`key-service/src/kt.rs`, migrations 044/054); the client verifies inclusion + STH signature on receipt (`KeyTransparencyVerifier`). **Missing:** a public monitor endpoint, in-practice consistency checking, and STH gossip/auditing — so the current STH catches a self-contradicting server but not one that equivocates consistently across victims. Design + gap in [Chapter 13](./13-key-transparency.md). | server `key-service/src/kt.rs:172`-`:309`; client `construct-core/src/crypto/key_transparency.rs:273`-`:332`, `construct-ios` `Security/KeyTransparencyVerifier.swift:94`-`:134` |
| ML-DSA-65 hybrid PQ signatures (Ed25519 + ML-DSA-65) | **Implemented and required to open a session**: a missing or invalid hybrid identity, cross-signature or Kyber-prekey hybrid signature refuses it; the hybrid identity is pinned per device. The hybrid key's trust root is still its Ed25519 cross-signature | `construct-core/src/crypto/suites/hybrid.rs:1`-`:51`; server `crates/construct-crypto/src/pqc/hybrid.rs:45`-`:65`; client `construct-ios` `Security/HybridBundleVerifier.swift:34`-`:120` |
| Sealed sender | **Implemented and on by default.** All outgoing user traffic — messages, delivery receipts, call signalling, and session control (since 2026-09-28 the only session-control message is DECRYPTION_ERROR, content type 28) — is sealed. Ordinary sends use the dedicated `SendSealedMessage` path; DECRYPTION_ERROR still uses the authenticated `Envelope.sealed_sender` path, but omit the outer sender, conversation id, and real content type. Identified-downgrade paths (retries, seal-failure, in-scope control channel) are closed and **fail-closed**: stealth-on ⇒ an in-scope application send is sealed or queued, never emitted identified. | server `messaging-service/src/grpc.rs:333`-`:360`, `:701`-`:750`, `messaging-service/src/envelope.rs:140`-`:270`; client policy `construct-ios` `Services/StealthPolicy.swift:42`; sealed RPC `Networking/gRPC/Services/MessagingServiceClient.swift:203`-`:225`; sealed control `Services/Session/SessionCoordinator.swift:1208`-`:1312`, `MessagingServiceClient.swift:269`-`:351` |
| Client IP minimisation | **Implemented** — the server never stores a raw client IP; anti-abuse rate-limit keys and logs use a salted one-way hash (`hash_client_ip`) of the address. Honest limit: a salted hash of the small IPv4 space is not perfectly anonymous against a salt-holder. | `construct-utils/src/lib.rs:92`; applied in `construct-user-service/src/account.rs:140`, `construct-auth-service/src/devices.rs:292` |
| Privacy Pass token enforcement | **Warn mode** in production (`MSG_STEALTH_TOKEN_POLICY=warn`); tokens are issued, attached to sealed sends, and redemption-validated, but a failed/absent token does not block delivery. `enforce` is deferred past 1.0 (needs verifiable-VOPRF client + soak). | `construct-server/messaging-service/src/envelope.rs:188`-`:248`; `construct-core/src/crypto/privacy_pass/mod.rs:94`-`:165` |
| Federation (S2S) | **Implemented** — inbound + outbound sealed delivery, Ed25519-signed, per-origin rate-limited. Multi-node interoperability test outstanding. | `construct-server/messaging-service/src/federation.rs:135`-`:258`, `:291`-`:360` |
| QUIC / HTTP-3 transport | **In production** as the engine-QUIC direct path; HTTP/2 fallback remains mandatory. Release builds use plain QUIC; Salamander-style per-datagram obfuscation is forced off outside DEBUG. | `construct-ios` `Utilities/Constants.swift`, `Networking/gRPC/GRPCChannelManager.swift`; `construct-transport/src/client.rs` |
| Direct P2P delivery | **Not implemented.** All traffic via server. | — |
| Formal verification (Kani / Prusti) | **Not started.** | — |
| External cryptographic audit | **Not performed.** | — |

## 7.2 Platform matrix

| Platform | Build target | Status |
|---|---|---|
| iOS device | `aarch64-apple-ios` | Production-quality code, shipped via TestFlight beta. No public App Store release. |
| iOS simulator | `aarch64-apple-ios-sim` | Builds and tests pass. |
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` | The same Swift code base and the same core as iOS, linked directly through UniFFI (the `construct-engine` single-binary path was retired on 2026-07-28). The desktop GUI is frozen: it builds, but is not distributed. |
| Android | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | Kotlin client on the same core release as iOS (currently 0.21): PQXDH v2, receiving opens from the sender certificate, DECRYPTION_ERROR, sealed sender. Exchanges messages with iOS on the test stand. Debug builds only — no signed release, no store distribution. No Google Play Services dependency by design. No VEIL transport yet. |
| Terminal client (`construct-tui`, Linux / macOS) | native | Paused since 2026-08-25. It predates PQXDH v2 and the event-based session answers of core 0.19–0.21, so it does not interoperate with the current clients. |
| Windows | — | No client. |
| Web (WASM) | — | Planned, not started. |

## 7.3 Open security issues

The table below lists residual risks that remain after the current
code audit. It deliberately excludes items that have shipped since the
older internal TODO list was written.

| Tag | Severity | Description | Target fix |
|---|---|---|---|
| `BS-3` | High | If no X25519 OPK is available at handshake time, the protocol falls back to 3-DH silently. Forward secrecy from the OPK contribution is lost; the user is not notified. The ML-KEM-1024 secret still enters the root key, so the first flight is not classical-only. | Surface a warning to the application layer. |
| `KT-1` | High | Key Transparency returns per-bundle inclusion proofs, but there is no public monitor endpoint, no in-practice consistency checking, and no STH gossip/auditor. A consistently equivocating server can still maintain a split view. | Publish monitor/consistency API, persist and compare STHs, and add gossip/auditor path. |
| `PQR-3` | Low | The ML-KEM-768 encapsulation key (1184 B) and ciphertext (1088 B) are carried whole and re-attached to **every** outgoing frame until implicitly acknowledged, so an unacknowledged exchange costs that much per message for its duration. Signal SPQR spreads both across Reed–Solomon-coded chunks instead, bounding per-message overhead. | Chunk the objects with a systematic erasure code, or bound re-attachment by a retry schedule. |
| `PQR-4` | Low | `PQ_CHAIN_RETENTION = 2` (the current epoch and the one before it) bounds how many epochs' chains are kept; an older epoch's message opens only by a skipped key, bounded like the classical ones (1000 keys, a 2000-message jump, 7-day age — §5.8.1/§2.4.3). What is lost by design (no silent downgrade) is the last message its writer sent on an epoch, arriving after the reader has completed two further exchanges. Whether real reordering ever reaches that depth is **being measured**: construct-core 0.25.0 counts, per process, decrypted messages by epoch lag, the deepest skip, and decrypt failures on an evicted epoch (`orchestration/reorder_stats.rs`, exported as `OrchestratorCore::reorder_stats`); clients write them to their local diagnostics log. | Read the counters from real use; keep 2 if no eviction loss appears, otherwise raise the retention. |
| `PQC-1` | Medium | **Sealed sender is not post-quantum.** The sender certificate — who sent the message — is sealed to the recipient's identity key with X25519 only (`construct-core/src/crypto/sealed_sender/mod.rs:67`); so are device metadata sealed to sibling devices and DECRYPTION_ERROR replies. A recorded sealed message reveals its sender to a future quantum attacker; its content stays protected by the PQ ratchet inside. | A hybrid box: X25519 and ML-KEM to the recipient device. |
| `PQC-2` | Low | Server-signed objects — sender certificates (`sealed_sender/mod.rs:171`) and Key Transparency tree heads (`key_transparency.rs:9`) — are Ed25519 only. A quantum attacker could forge them; forging does not decrypt recorded traffic, and after first contact a peer is held by its pinned KEM identity key. | Hybrid Ed25519 + ML-DSA-65 server signatures. |
| `PQC-3` | Low | Device authentication to the server (`crypto/keys.rs:451`) and the recovery key derived from the seed phrase (`crypto/recovery.rs:92`) are Ed25519 only. A forgery would act on the account at the server (sign in, start recovery); it does not decrypt messages. | Hybrid signatures for device and recovery challenges. |
| `PQC-4` | Medium | **Calls are not post-quantum.** Media is WebRTC DTLS-SRTP with an ECDHE handshake (Chapter 10); a recorded call can be decrypted later. | Derive SRTP keys (or an SFrame key) from the PQ session instead of DTLS alone. |
| `PQC-5` | Low | Group messaging uses `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`group/mls_store.rs:39`). No product surface ships groups yet. | Choose a hybrid MLS ciphersuite before groups ship. |
| `PQC-6` | Low | Transport TLS key exchange is not established as post-quantum: VEIL and QUIC use rustls with the `ring` provider, which offers no hybrid group (`construct-transport/Cargo.toml:22`); the iOS direct gRPC path's system TLS has not been verified against the server. Message content does not depend on it. | Verify what each path negotiates; move rustls to a provider with X25519MLKEM768. |
| `SEC-009` | Low | Session state (CFE records containing `dh_ratchet_private`, the root key and chain keys) is stored in the platform key store without an additional encryption-at-rest layer. If the OS key store is compromised, an attacker reads the session state. | Add wrap-with-master-key at the session-export boundary. |

**Resolved since the previous revision:**

- `SEC-006` — the AD v2 fallback decrypt is gone (construct-core 0.24.2). Every session is PQXDH
  v2, opened since 2026-09-25, and every writer of PQXDH v2 seals with AD v3: the retry could no
  longer open anything and only doubled the work of each failure.
- `DE-2` — the map from a sealed copy's server-assigned id to the sender's own id is persisted
  on both clients (iOS since 2026-09-30, 30-day retention; Android in its database), so a
  DECRYPTION_ERROR that arrives after the writer restarted still resends the named message.

- `PQR-1` — Suite 4 rekeyed only on a count of DH-ratchet turns, so a conversation that never
  changed direction (one side always writing, the other always reading) never rekeyed at all.
  construct-core 0.24.1 (2026-09-30) added a 7-day age floor: the exchange initiator proposes a
  new epoch on its next send once the current one is that old, turns or not — matching the floor
  Apple PQ3 guarantees. **Remaining gap:** only the exchange initiator ever proposes, so a
  conversation in which only the *responder* writes still cannot rekey by either path; closing
  that needs roles that alternate per epoch, a protocol change of its own, not a parameter. See
  [Chapter 2 §2.4.3](./02-cryptographic-primitives.md#243-cadence-and-retention) and
  [Appendix B §B.3](./appendix-b-pq-comparison.md#b3-rekey-cadence).
- `PQR-2` — every message key in a Suite 3 PQ epoch was
  derived from the same stored `pq_epoch_secret`, so the post-quantum half of the ratchet had
  epoch, not message, forward-secrecy granularity. construct-core 0.24.0 (2026-09-30) replaced the
  stored secret with two per-direction chains, stepped per message and never persisted (Suite 4);
  see [Chapter 2 §2.4](./02-cryptographic-primitives.md#24-suite-4--sparse-continuous-pq-ratchet-per-message-chains)
  and [Appendix B §B.6](./appendix-b-pq-comparison.md#b6-granularity-of-the-post-quantum-guarantee).

Items listed as "Out of scope" in [Chapter 1 §1.2](./01-threat-model.md#out-of-scope-explicit-non-goals)
are NOT on this list — they are not bugs, they are explicit
non-goals.

## 7.4 Test coverage

The reference includes:

| Test suite | Scope |
|---|---|
| Unit tests (`cargo test`, in-module) | KDF labels, AD construction, padding, wire-payload round-trips, ratchet invariants; the PQXDH v2 handshake end to end between two cores; Kyber prekey signature checks and every `PqxdhRefusal`; previous-state promotion, retirement and bounds; DECRYPTION_ERROR sealing, domain separation and the writer's current / previous / unknown cases. Session behaviour is tested in the modules that own it (`session_lifecycle.rs`, `orchestrator.rs`, `decryption_error.rs`), not in `tests/`. |
| Integration tests (`tests/`) | Two files: orchestrator state save / restore (`state_management_test.rs`) and the build-version stamp. |
| Cross-platform fixture tests | iOS bridging-header parity, UniFFI binding generation. |
| Property / fuzz tests | WirePayload decoder fuzz target (no panic on arbitrary bytes). |
| Cross-reference vectors | Cryptographic library outputs cross-checked against published test vectors (NIST FIPS 203 for ML-KEM, RFC 8032 for Ed25519). |

What is **not** covered today:

- Full product-level multi-device interoperability coverage across all
  sealed-sender, sender-sync, and Suite 4 cases.
- Multi-node (two-VPS) federation interoperability test — federation is
  implemented with contract-level tests, but the two-server integration test
  is outstanding.
- Formal verification (planned, not done).
- Adversarial / red-team testing by an external party.

## 7.5 Reproducibility

The reference is built from the commit indicated in the version
metadata of the released artefact. To reproduce a build:

```bash
git clone https://github.com/konstruct-msg/construct-core
cd construct-core
# iOS staticlib:
./build_crypto_lib.sh --all     # see construct-ios repo for the wrapper
# Android shared library:
cd ../construct-android
./build_crypto_lib.sh --all
```

The `Cargo.lock` checked into the repository pins every transitive
dependency, so two builds from the same commit will produce binaries
that differ only in compiler-version-dependent ways (debug info,
timestamp markers).

## 7.6 Versioning policy

This specification follows [Semantic Versioning](https://semver.org/)
at the **document** level:

- MAJOR — a wire-incompatible protocol change.
- MINOR — a backwards-compatible normative addition (new field, new
  optional behaviour).
- PATCH — editorial corrections that do not change implementer
  obligations.

The implementation's own versioning is separate; see the
`construct-core` `Cargo.toml` for the crate version.

## 7.7 References

- Open-issue tracker (internal): `construct-core/TODO.md`.
- Disclosure & contact: [Disclosure](./disclosure.md).
- Document changelog: [Changelog](./changelog.md).
