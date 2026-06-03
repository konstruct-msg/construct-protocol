# Cryptographic Primitives

This chapter enumerates every cryptographic primitive that an
interoperable Konstruct implementation MUST use, with concrete
parameters, byte sizes, and crate-level references to the verified
reference implementation. Two cryptographic suites are defined:
Suite 1 (classical, always active) and Suite 2 (Suite 1 plus a
post-quantum KEM, opt-in).

Keywords MUST, MUST NOT, SHOULD, MAY are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2.1 Suite identifiers

Each session is parameterised by a suite identifier. The suite is
fixed at handshake time and MUST NOT change for the lifetime of the
session.

| Identifier | Value (u16, big-endian on wire) | Description |
|---|---|---|
| `SUITE_CLASSIC_V1` | `0x0001` | X25519 + Ed25519 + ChaCha20-Poly1305 + HKDF-SHA256 |
| `SUITE_PQ_HYBRID_V1` | `0x0002` | Suite 1 + ML-KEM-768 hybrid KEM |

The suite identifier appears in the WirePayload header
([Chapter 5 §5.3](./05-message-encryption.md#53-wire-format-wirepayload-header))
and MUST be checked by the receiver before any cryptographic
operation; a mismatched suite MUST cause the message to be rejected.

## 2.2 Suite 1 — Classical (always active)

### 2.2.1 X25519 key agreement

- Curve: Curve25519 per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748).
- Crate: `x25519-dalek 2.0` with the `reusable_secrets` and
  `static_secrets` features.
- Public key size: **32 bytes** (Montgomery form, encoded little-endian).
- Private key size: **32 bytes** (clamped scalar).
- DH operation: `DH(a, B) = scalar_mult(a, B)`. Output: **32 bytes**.
- Implementations MUST clamp scalars per RFC 7748 §5; the `dalek`
  crate does this internally.
- Implementations MUST validate that received public keys are not
  all-zero (which would force the DH output to zero). The reference
  inherits this check from `dalek`.

### 2.2.2 Ed25519 signatures

- Algorithm: Ed25519 per [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
- Crate: `ed25519-dalek 2.0` with the `std` and `rand_core` features.
- Public key size: **32 bytes**.
- Private key (signing key) size: **32 bytes** (seed) or **64 bytes**
  (expanded). The reference uses the 32-byte seed form.
- Signature size: **64 bytes** (`R || S`, each 32 bytes).
- Verification: `Verify(VK, M, sig) → ok | error`. The reference uses
  `VerifyingKey::verify_strict` where strict validation is required.
- An interoperable signer MUST sign the same canonical encoding of the
  signed artefact. Signed artefacts in this specification are:
  - Signed prekey: `Ed25519_Sign(SK_priv, SPK_pub || rotation_epoch_be)`
  - Kyber signed prekey: `Ed25519_Sign(SK_priv, KEM_pub || rotation_epoch_be)`
  - Other artefacts (registration receipts, invites) are out of scope
    for v0.1.

### 2.2.3 ChaCha20-Poly1305 AEAD

- Algorithm: ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
- Crate: `chacha20poly1305 0.10` with the `std` and `getrandom` features.
- Key size: **32 bytes**.
- Nonce size: **12 bytes**. Each AEAD invocation in Konstruct uses a
  freshly random nonce (never a counter-derived nonce); see
  [Chapter 5 §5.5](./05-message-encryption.md#55-encryption-ratchetencrypt).
- Tag size: **16 bytes** (Poly1305).
- Associated Data: variable; the AD construction for Double Ratchet
  messages is specified in [Chapter 5 §5.4](./05-message-encryption.md#54-associated-data-construction-ad).
- The plaintext input to the AEAD MUST be the PKCS#7-padded plaintext
  (§5.7), not the raw application bytes.

### 2.2.4 HKDF-SHA-256

- Algorithm: HKDF per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869),
  instantiated with SHA-256.
- Crate: `hkdf 0.12`.
- Three distinct HKDF invocations appear in the specification, each
  with a normative `info` byte string. Implementations MUST use the
  exact byte strings below.

| Use | `salt` | `IKM` | `info` | `L` |
|---|---|---|---|---|
| X3DH root key (Ch. 4 §4.3) | `[0xFF; 32]` | `DH_combined` | `b"Construct-X3DH-RootKey-v1"` (25 B) | 32 |
| Double Ratchet root step (Ch. 5 §5.2) | `RK` | `dh_out` (32 B) | `b"Construct-DoubleRatchet-RootKey-v1"` (33 B) | 64 |
| PQ contribution at RK₁ (Ch. 4 §4.5) | `RK₁` | `kem_ss` (32 B) | `b"Construct-X3DH-RootKey-v1"` (25 B) | 32 |

The Double Ratchet chain-step uses HMAC-SHA-256 directly rather than
HKDF; see [Chapter 5 §5.2](./05-message-encryption.md#52-kdf-helpers).

### 2.2.5 PBKDF2 (password-based KDF)

- Algorithm: PBKDF2 per [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018),
  HMAC-SHA-256 PRF.
- Crate: `pbkdf2 0.12` with the `simple` feature.
- Iterations (reference default): **100 000**
  (`construct-core/src/config.rs:117`).
- Use site: master-key derivation for at-rest encryption of recovery
  artefacts. PBKDF2 is **not** used in the wire protocol, only in
  application-level key wrapping.

### 2.2.6 Argon2id (anti-spam PoW)

- Algorithm: Argon2id per [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106).
- Crate: `argon2 0.5`.
- Version: `V0x13` (Argon2 v1.3).
- Parameters (reference):
  - Memory cost `m` = 32 768 KiB
  - Iterations `t` = 2
  - Parallelism `p` = 1
- Use site: registration proof-of-work, in `construct-core/src/pow.rs`.
  The server issues a fresh PoW challenge per registration attempt;
  the client returns a nonce whose Argon2id hash satisfies a
  difficulty target.

## 2.3 Suite 2 — Post-quantum extension (opt-in)

Suite 2 inherits all of Suite 1, and adds a hybrid post-quantum KEM
whose shared secret is mixed into the root key after the first DH
ratchet step (the "deferred" application; see
[Chapter 4 §4.5](./04-session-handshake.md#45-pqxdh-suite-2--post-quantum-extension)).

### 2.3.1 ML-KEM-768 (Kyber-768)

- Algorithm: ML-KEM-768 per [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
- Crate: `ml-kem 0.3.0` (feature-gated as `post-quantum`).
- Encapsulation key size: **1184 bytes**.
- Ciphertext size: **1088 bytes**.
- Decapsulation (secret) key size: **2400 bytes** (expanded form, as
  exposed by `ExpandedKeyEncoding` in the `ml-kem` crate). The
  reference exports the expanded form because re-derivation from a
  32-byte seed adds runtime cost; both are equivalent at the protocol
  level.
- Shared secret size: **32 bytes**.
- Operations:
  - `(ek, dk) = MlKem768::Generate()`
  - `(ct, ss) = MlKem768::Encapsulate(ek)`
  - `ss = MlKem768::Decapsulate(dk, ct)`
- Implementations MUST use the FIPS-203 final variant, not the
  earlier `Kyber-768-R3` draft variant. The reference crate
  `ml-kem 0.3.0` implements FIPS 203 final.

### 2.3.2 Hybrid design

The combined session security is determined by:

```
SK_root  = HKDF(F, DH_combined, "Construct-X3DH-RootKey-v1", 32)
RK₁      = (root after first DH ratchet step)
RK₁'     = HKDF(RK₁, kem_ss, "Construct-X3DH-RootKey-v1", 32)
```

Because RK₁' depends on both `DH_combined` (classical) and `kem_ss`
(post-quantum), an adversary MUST break **both** components to recover
plaintext. Breaking only X25519 leaves `kem_ss` as a 32-byte
unknown input to the KDF; breaking only ML-KEM-768 leaves
`DH_combined` similarly. This is the standard hybrid-security argument
and the reason Suite 2 is constructed as KEM **alongside** rather than
**instead of** classical X3DH.

### 2.3.3 Signatures in Suite 2

Suite 2 does **not** define hybrid signatures. All signature
operations (signed prekey, signed Kyber prekey, registration receipts)
use Ed25519 even when the session is operating under Suite 2.

Hybrid PQ signatures using ML-DSA-65 (Dilithium-3, NIST FIPS 204) are
planned but **not yet implemented**; see
[Implementation Status §7.1](./07-implementation-status.md#71-component-matrix).

## 2.4 Randomness

All key generation, ephemeral keypair generation, and AEAD nonces MUST
be sourced from a cryptographically secure RNG. The reference uses
`rand::rngs::OsRng` for classical primitives and a separately-seeded
`getrandom`-backed RNG for the `ml-kem` crate's PQ operations
(`getrandom_pq` feature).

Implementations MUST NOT use deterministic or counter-derived
randomness for any of the values above. A failure of the OS RNG MUST
cause the operation to abort, not to proceed with a weak source.

## 2.5 Key zeroization

All ephemeral and per-message keys MUST be zeroised before their
memory is released:

| Material | Zeroise after |
|---|---|
| `DH_combined`, individual `DH_n` outputs | X3DH root key derivation completes |
| `kem_ss` | PQ contribution applied at RK₁ |
| `MK` (per-message key) | AEAD operation completes (encrypt or decrypt) |
| `dh_out` (DH ratchet output) | Both `KDF_RK` calls in the ratchet step complete |
| Chain key superseded by `KDF_CK` | Immediately on derivation of the successor |

The reference uses `zeroize` / `zeroize::Zeroizing` from the
`zeroize 1.7` crate for these. Long-term keys (`IK_priv`, `SK_priv`)
are kept in platform-protected storage; they are not zeroised at
runtime because they are needed across process lifetimes.

## 2.6 Constants summary

For ease of cross-reference, all normative byte constants used in this
specification:

| Constant | Value | Length |
|---|---|---|
| Prologue | `b"KonstruktX3DH-v1"` | 17 B |
| Salt F (X3DH HKDF) | `[0xFF; 32]` | 32 B |
| Info (X3DH root key) | `b"Construct-X3DH-RootKey-v1"` | 25 B |
| Info (Double Ratchet root step) | `b"Construct-DoubleRatchet-RootKey-v1"` | 33 B |
| Info (PQ contribution) | `b"Construct-X3DH-RootKey-v1"` | 25 B |
| Suite 1 ID | `0x0001` | 2 B (u16 BE) |
| Suite 2 ID | `0x0002` | 2 B (u16 BE) |
| Argon2id version | `V0x13` | — |
| CFE magic | `[0x43, 0x46]` ("CF") | 2 B |
| CFE version | `0x01` | 1 B |

These constants MUST be byte-identical between conforming
implementations. Changing any of them produces an instantly
non-interoperable handshake or AEAD failure.

## 2.7 References

- Reference implementation (single source of truth for parameters
  above): `construct-core/`, particularly `src/crypto/`, `src/pow.rs`,
  and `Cargo.toml`.
- NIST FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
- RFC 7748 (X25519): <https://www.rfc-editor.org/rfc/rfc7748>
- RFC 8032 (Ed25519): <https://www.rfc-editor.org/rfc/rfc8032>
- RFC 8439 (ChaCha20-Poly1305): <https://www.rfc-editor.org/rfc/rfc8439>
- RFC 5869 (HKDF): <https://www.rfc-editor.org/rfc/rfc5869>
- RFC 9106 (Argon2): <https://www.rfc-editor.org/rfc/rfc9106>
