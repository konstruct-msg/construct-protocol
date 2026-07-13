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
| X3DH classical handshake | **Implemented**, shipped in iOS TestFlight build | `construct-core/src/crypto/handshake/x3dh.rs` |
| PQXDH (ML-KEM-768) extension | **Implemented**, opt-in via Suite 2 flag, shipped | `construct-core/src/crypto/pq_x3dh.rs` |
| Double Ratchet | **Implemented**, including DH ratchet, skipped-key handling, AD v3 (with v2 fallback) | `construct-core/src/crypto/messaging/double_ratchet/` |
| PKCS#7 length padding (mod 255) | **Implemented**, constant-time unpad | `construct-core/src/traffic_protection/padding.rs` |
| Session healing queue | **Implemented**, Keychain-backed | `construct-core/src/orchestration/healing_queue.rs` |
| ACK deduplication store | **Implemented** | `construct-core/src/orchestration/ack_store.rs` |
| PQ contribution store (deferred KEM ss) | **Implemented (RAM)**, persistent layer pending | `construct-core/src/orchestration/pq_contribution.rs` |
| CFE binary envelope at FFI | **Implemented**, used by iOS / macOS / Android bindings | `construct-core/src/cfe/` |
| WirePayload binary frame | **Implemented** | `construct-core/src/wire_payload.rs` |
| MLS group chat (RFC 9420) | **Code present**, **not** yet documented at protocol-spec level; expect a future chapter | `construct-core/src/group/` |
| Argon2id proof-of-work | **Implemented** | `construct-core/src/pow.rs` |
| BIP39 / SLIP-39 social recovery | **Implemented** | `construct-core/src/crypto/social_recovery.rs` |
| Privacy Pass token issuance | **Implemented** (feature-gated) | `construct-core/src/crypto/privacy_pass/` |
| Key transparency log verification | **Stub** — server side not yet shipping the log | `construct-core/src/crypto/key_transparency.rs` |
| ML-DSA-65 hybrid PQ signatures (Ed25519 + ML-DSA-65) | **Implemented**, opt-in via `post-quantum` feature flag | `construct-crypto/src/pqc/hybrid.rs`; server wire-up in `construct-server/e2e.rs:318` |
| Sealed sender | **Implemented** — the sealed path leaves no `sender_id` at rest; making sealed the enforced default (dropping the non-sealed fallback) is in progress. | `messaging-service/src/envelope.rs` |
| Federation (S2S) | **Implemented** — inbound + outbound sealed delivery, Ed25519-signed, per-origin rate-limited. Multi-node interoperability test outstanding. | `messaging-service/src/federation.rs` |
| QUIC / HTTP-3 transport | **In production** (plain QUIC); HTTP/2 fallback; per-packet obfuscation demoted to debug-only. | `construct-transport` |
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

The reference tracks these in `TODO.md`. They are listed here so a
reader can decide whether the current build is adequate for a given
threat model.

| Tag | Severity | Description | Target fix |
|---|---|---|---|
| `BS-3` | High | If no X25519 OPK is available at handshake time, the protocol falls back to 3-DH silently. Forward secrecy from the OPK contribution is lost; the user is not notified. | Surface a warning to the application layer; consider hard-failing in Suite 2 when both OPK and Kyber-OPK are unavailable. |
| `BS-6` | High | The deferred PQ shared secret `kem_ss` is held in RAM only between "first message sent" and "PQ contribution applied at RK₁". An app crash in that window silently downgrades the session to classical-only. | Persist `kem_ss` to Keychain (a la `RustPQContributions`'s in-memory store, but with disk backing). |
| `SEC-005` | Medium | `SPK_MAX_AGE_SECS` is 10 days; the SPK rotation policy itself rotates at 7 days. The 3-day overlap window weakens forward secrecy by extending the SPK validity. | Align rotation interval (rotate at 7 days, accept up to 10) and add a stale-SPK alert at the 8-day mark. |
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

- End-to-end multi-device tests (no multi-device support yet).
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
