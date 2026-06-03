# Cryptographic Primitives

> *Verified against `construct-core` HEAD as of v0.1 of this document.*

Konstruct uses two cryptographic suites: a classical suite (Suite 1)
that is always active, and a hybrid post-quantum extension (Suite 2)
that is opt-in.

## Suite 1 — Classical (always active)

| Role | Algorithm | Crate | Reference |
|---|---|---|---|
| Key agreement | X25519 | `x25519-dalek 2.0` | `construct-core/Cargo.toml` |
| Signatures | Ed25519 | `ed25519-dalek 2.0` | `construct-core/Cargo.toml` |
| AEAD | ChaCha20-Poly1305 | `chacha20poly1305 0.10` | `construct-core/Cargo.toml` |
| Key derivation | HKDF-SHA256 | `hkdf 0.12` | `construct-core/Cargo.toml` |
| Password-based KDF | PBKDF2 | `pbkdf2 0.12` | `construct-core/src/crypto/master_key.rs` |
| Anti-spam proof-of-work | Argon2id (v0x13) | `argon2 0.5` | `construct-core/src/pow.rs` |

## Suite 2 — Post-Quantum extension (opt-in)

Suite 2 = everything from Suite 1 + a parallel post-quantum KEM whose
shared secret is mixed into the same handshake.

| Role | Algorithm | Crate | Reference |
|---|---|---|---|
| KEM | ML-KEM-768 (NIST FIPS 203, Kyber-768) | `ml-kem 0.3.0` (feature-gated) | `construct-core/src/crypto/pq_x3dh.rs` |
| Signatures (PQ) | **Not yet implemented.** ML-DSA-65 (NIST FIPS 204, Dilithium-3) is planned but not in code; signatures in Suite 2 use Ed25519 today. | — | Comment in `construct-core/src/crypto/suites/mod.rs` |

The hybrid design property: even if **either** the classical X25519
component **or** the ML-KEM-768 component is broken in isolation, the
combined shared secret retains security from the surviving component.

*Detailed parameter tables, prologue strings, KDF labels, AD format,
and primitive-by-primitive verification notes will be written out in
the next revision.*
