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
| X3DH classical handshake | **Implemented**, shipped in iOS TestFlight build | `construct-core/src/crypto/handshake/x3dh.rs:417`-`:424` |
| PQXDH (ML-KEM-768) extension | **Implemented**, opt-in via Suite 2 flag, shipped | `construct-core/src/crypto/pq_x3dh.rs:12`-`:19`, `src/crypto/messaging/double_ratchet/internals.rs:62`-`:99` |
| Sparse continuous PQ ratchet (Suite 3) | **Implemented**, capability-gated by `supports_pq_ratchet`; negotiated only when both peers advertise support | `construct-core/src/crypto/suite_id.rs:28`-`:33`; negotiation test `src/crypto/client_api.rs:1082`-`:1152`; wire section `src/wire_payload.rs:76`-`:129` |
| Double Ratchet | **Implemented**, including DH ratchet, skipped-key handling, AD v3 (with v2 fallback), and Suite 3 PQ epoch tags | `construct-core/src/crypto/messaging/double_ratchet/messaging.rs:307`-`:332`; `internals.rs:533`-`:554` |
| PKCS#7 length padding (mod 255) | **Implemented**, constant-time unpad | `construct-core/src/traffic_protection/padding.rs:96`-`:126` |
| Session healing queue | **Implemented**, platform-persisted via orchestrator actions | `construct-core/src/orchestration/healing_queue.rs:144`-`:210` |
| ACK deduplication store | **Implemented** | `construct-core/src/orchestration/ack_store.rs:83`-`:143` |
| PQ contribution store (deferred KEM ss) | **Implemented**, CFE-backed and persisted via secure-store actions | `construct-core/src/orchestration/pq_contribution.rs:200`-`:217`, `:360`-`:385` |
| CFE binary envelope at FFI | **Implemented**, used by iOS / macOS / Android bindings | `construct-core/src/cfe/envelope.rs:8`-`:25`, `:48`-`:65` |
| WirePayload binary frame | **Implemented**, little-endian fixed header + Suite 3 PQ section | `construct-core/src/wire_payload.rs:7`-`:17`, `:76`-`:129` |
| MLS group chat (RFC 9420) | **Core present** (OpenMLS, ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), **no shipping product surface**; design documented in [Chapter 12](./12-group-messaging.md), not yet a normative interop spec | `construct-core/src/group/mls_store.rs:1`-`:39` |
| Argon2id proof-of-work | **Implemented** | `construct-core/src/pow.rs` |
| Account recovery — BIP39 (12-word) + SLIP-39 social recovery | **Implemented.** BIP39 restores account access on a new device (recovery Ed25519 keypair, server holds only the public key); SLIP-39 threshold-restores the identity vault. See [Chapter 11](./11-account-recovery.md). | `construct-core/src/crypto/social_recovery.rs`; BIP39/BIP32 derivation in `construct-core` |
| Privacy Pass token issuance | **Implemented** (feature-gated) | `construct-core/src/crypto/privacy_pass/mod.rs:94`-`:165`; server issuance `construct-server/identity-service/src/main.rs:942`-`:1057` |
| Key transparency | **Per-bundle inclusion proofs live; split-view detection not.** The server maintains an append-only Merkle log and returns a Signed Tree Head + inclusion proof inline with every bundle (`key-service/src/kt.rs`, migrations 044/054); the client verifies inclusion + STH signature on receipt (`KeyTransparencyVerifier`). **Missing:** a public monitor endpoint, in-practice consistency checking, and STH gossip/auditing — so the current STH catches a self-contradicting server but not one that equivocates consistently across victims. Design + gap in [Chapter 13](./13-key-transparency.md). | server `key-service/src/kt.rs:172`-`:309`; client `construct-core/src/crypto/key_transparency.rs:273`-`:332`, `construct-ios` `Security/KeyTransparencyVerifier.swift:94`-`:134` |
| ML-DSA-65 hybrid PQ signatures (Ed25519 + ML-DSA-65) | **Implemented**, optional/capability-gated; invalid hybrid identity rejects, missing SPK-level hybrid attestation degrades to classical Ed25519 path | `construct-core/src/crypto/suites/hybrid.rs:1`-`:51`; server `crates/construct-crypto/src/pqc/hybrid.rs:45`-`:65`; client `construct-ios` `Security/HybridBundleVerifier.swift:34`-`:120` |
| Sealed sender | **Implemented and on by default.** All outgoing user traffic — messages, delivery receipts, call signalling, and the session-control handshake (`session_ready` / tie-break ping / `SESSION_RESET_INIT` / `END_SESSION`) — is sealed. Ordinary sends use the dedicated `SendSealedMessage` path; some session-control paths still use legacy authenticated `Envelope.sealed_sender`, but omit the outer sender, conversation id, and real content type. Identified-downgrade paths (retries, seal-failure, in-scope control channel) are closed and **fail-closed**: stealth-on ⇒ an in-scope application send is sealed or queued, never emitted identified. | server `messaging-service/src/grpc.rs:333`-`:360`, `:701`-`:750`, `messaging-service/src/envelope.rs:140`-`:270`; client policy `construct-ios` `Services/StealthPolicy.swift:42`; sealed RPC `Networking/gRPC/Services/MessagingServiceClient.swift:203`-`:225`; sealed control `Services/Session/SessionCoordinator.swift:1208`-`:1312`, `MessagingServiceClient.swift:269`-`:351` |
| Client IP minimisation | **Implemented** — the server never stores a raw client IP; anti-abuse rate-limit keys and logs use a salted one-way hash (`hash_client_ip`) of the address. Honest limit: a salted hash of the small IPv4 space is not perfectly anonymous against a salt-holder. | `construct-utils/src/lib.rs:92`; applied in `construct-user-service/src/account.rs:140`, `construct-auth-service/src/devices.rs:292` |
| Privacy Pass token enforcement | **Warn mode** in production (`MSG_STEALTH_TOKEN_POLICY=warn`); tokens are issued, attached to sealed sends, and redemption-validated, but a failed/absent token does not block delivery. `enforce` is deferred past 1.0 (needs verifiable-VOPRF client + soak). | `construct-server/messaging-service/src/envelope.rs:188`-`:248`; `construct-core/src/crypto/privacy_pass/mod.rs:94`-`:165` |
| Federation (S2S) | **Implemented** — inbound + outbound sealed delivery, Ed25519-signed, per-origin rate-limited. Multi-node interoperability test outstanding. | `construct-server/messaging-service/src/federation.rs:135`-`:258`, `:291`-`:360` |
| QUIC / HTTP-3 transport | **In production** as the engine-QUIC direct path; HTTP/2 fallback remains mandatory. Release builds use plain QUIC; Salamander-style per-datagram obfuscation is forced off outside DEBUG. | `construct-ios` `Utilities/Constants.swift:414`-`:456`, `Networking/gRPC/GRPCChannelManager.swift:474`-`:535`; `construct-engine/src/transport/mod.rs:50`-`:113`, `src/transport/connection.rs:60`-`:107` |
| Direct P2P delivery | **Not implemented.** All traffic via server. | — |
| Formal verification (Kani / Prusti) | **Not started.** | — |
| External cryptographic audit | **Not performed.** | — |

## 7.2 Platform matrix

| Platform | Build target | Status |
|---|---|---|
| iOS device | `aarch64-apple-ios` | Production-quality code, shipped via TestFlight beta. No public App Store release. |
| iOS simulator | `aarch64-apple-ios-sim` | Builds and tests pass. |
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` | Builds and runs; mid-migration from direct `construct-core` to a `construct-engine`-mediated path. |
| Android | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | `construct-core` cross-compiles cleanly; UniFFI bindings regenerated. No Kotlin VEIL surface yet (Phase 0). |
| Desktop (Linux / Windows) | native | CLI tools only; no application client. |
| Web (WASM) | — | Planned, not started. |

## 7.3 Open security issues

The table below lists residual risks that remain after the current
code audit. It deliberately excludes items that have shipped since the
older internal TODO list was written.

| Tag | Severity | Description | Target fix |
|---|---|---|---|
| `BS-3` | High | If no X25519 OPK is available at handshake time, the protocol falls back to 3-DH silently. Forward secrecy from the OPK contribution is lost; the user is not notified. | Surface a warning to the application layer; consider hard-failing in Suite 2 when both OPK and ML-KEM-768 OPK are unavailable. |
| `KT-1` | High | Key Transparency returns per-bundle inclusion proofs, but there is no public monitor endpoint, no in-practice consistency checking, and no STH gossip/auditor. A consistently equivocating server can still maintain a split view. | Publish monitor/consistency API, persist and compare STHs, and add gossip/auditor path. |
| `SEC-006` | Medium | The AD v2 → v3 graceful migration uses a fallback decrypt path. Once no v2 messages can be in flight, the fallback SHOULD be removed. | Remove `AD_VERSION_PREV` fallback after the in-flight window passes. |
| `SEC-009` | Low | Session JSON (containing `dh_ratchet_private`, RK, chain keys) is stored in the platform key store but without an additional encryption-at-rest layer. If the OS key store is compromised, an attacker reads the session state. | Add wrap-with-master-key at the session-export boundary. |

Items listed as "Out of scope" in [Chapter 1 §1.2](./01-threat-model.md#out-of-scope-explicit-non-goals)
are NOT on this list — they are not bugs, they are explicit
non-goals.

## 7.4 Test coverage

The reference includes:

| Test suite | Scope |
|---|---|
| Unit tests (`cargo test`) | Per-module: KDF labels, AD construction, padding edge cases, wire-payload round-trips, ratchet step invariants. |
| Integration tests (`tests/`) | Cross-module: full X3DH handshake + first message exchange; PQ contribution apply; session healing round-trip; CFE envelope corner cases. |
| Cross-platform fixture tests | iOS bridging-header parity, UniFFI binding generation. |
| Property / fuzz tests | WirePayload decoder fuzz target (no panic on arbitrary bytes). |
| Cross-reference vectors | Cryptographic library outputs cross-checked against published test vectors (NIST FIPS 203 for ML-KEM, RFC 8032 for Ed25519). |

What is **not** covered today:

- Full product-level multi-device interoperability coverage across all
  sealed-sender, sender-sync, and Suite 3 cases.
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
