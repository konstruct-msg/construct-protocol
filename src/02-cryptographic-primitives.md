# Cryptographic Primitives

This chapter enumerates every cryptographic primitive that an
interoperable Konstruct implementation MUST use, with concrete
parameters, byte sizes, and crate-level references to the verified
reference implementation. Three core suite identifiers are currently
accepted by `construct-core`: Suite 1 (classical), Suite 2 (PQXDH
hybrid KEM + optional hybrid signatures), and Suite 3 (sparse
continuous ML-KEM-768 ratchet).

Keywords MUST, MUST NOT, SHOULD, MAY are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2.1 Suite identifiers

Each session is parameterised by a suite identifier. The suite is
fixed at handshake time and MUST NOT change for the lifetime of the
session.

| Identifier | Value | Description |
|---|---|---|
| `SUITE_CLASSIC_V1` | `0x0001` | X25519 + Ed25519 + ChaCha20-Poly1305 + HKDF-SHA256 |
| `SUITE_PQ_HYBRID_V1` | `0x0002` | Suite 1 + deferred ML-KEM-768 (Kyber-768) PQXDH contribution + optional hybrid signatures |
| `SUITE_PQ_RATCHET_V1` | `0x0003` | Suite 1 + sparse continuous ML-KEM-768 ratchet mixed at the message-key layer |

The suite identifier appears in the WirePayload header
([Chapter 5 §5.3](./05-message-encryption.md#53-wire-format-wirepayload-header))
and MUST be checked by the receiver before any cryptographic
operation; a mismatched suite MUST cause the message to be rejected.
In the WirePayload header it is encoded as `u16` little-endian
(`construct-core/src/wire_payload.rs:15`, `:106`-`:129`). Signature
prologues use their own explicitly-specified byte order (§2.2.2).
The accepted IDs are defined in `construct-core/src/crypto/suite_id.rs:22`-`:33`.

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
  - X25519 signed prekey: `Ed25519_Sign(SK_priv, b"KonstruktX3DH-v1" || [0x00, 0x01] || SPK_pub)`.
  - ML-KEM-768 signed prekey: `Ed25519_Sign(SK_priv, b"KonstruktX3DH-v1" || [0x00, 0x10] || KEM_pub)`.
  - Hybrid identity binding: `Ed25519_Sign(SK_priv, b"KonstruktHybridId-v1" || hybrid_identity_key)`.

`spk_rotation_epoch` is a freshness/replay field carried beside the
prekey in the bundle; it is not part of the current prekey signature
message. Server verification builds the prekey message in
`construct-server/key-service/src/core.rs:150`-`:179`; the shared
hybrid helper builds the same bytes in
`construct-server/crates/construct-crypto/src/pqc/hybrid.rs:55`-`:65`.

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

ChaCha20-Poly1305 is the AEAD for **Double Ratchet message payloads**. A
second AEAD is used for **media attachments** (photos, video, files, voice
messages): each attachment is encrypted client-side with **AES-256-GCM**
under a fresh per-file 256-bit key, wire format `nonce(12) || ciphertext ||
tag(16)`, before upload. The per-file key never reaches the media server —
it travels end-to-end inside the (ChaCha20-Poly1305-sealed) message, so the
server stores only an opaque encrypted blob. Reference: `construct-ios`
`Services/MediaUploadService.swift:83` (`decryptMediaData`, 32-byte
AES-256-GCM key). AES-256-GCM here rides Apple/hardware-accelerated
`CryptoKit`; the Double Ratchet deliberately stays on ChaCha20-Poly1305.

### 2.2.4 HKDF-SHA-256

- Algorithm: HKDF per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869),
  instantiated with SHA-256.
- Crate: `hkdf 0.12`.
- Several distinct HKDF invocations appear in the specification, each
  with a normative `info` byte string. Implementations MUST use the
  exact byte strings below.

| Use | `salt` | `IKM` | `info` | `L` |
|---|---|---|---|---|
| X3DH root key (Ch. 4 §4.3) | `[0xFF; 32]` | `DH_combined` | `b"Construct-X3DH-RootKey-v1"` (25 B) | 32 |
| Initial Double Ratchet root normalisation | `[0xFE; 32]` | X3DH root key | `b"InitialRootKey"` (14 B) | 32 |
| Double Ratchet root step (Ch. 5 §5.2) | `RK` | `dh_out` (32 B) | `b"Double-Ratchet-Root-Key-Expansion"` (33 B) | 64 |
| Double Ratchet chain step (Ch. 5 §5.2) | `CK` | empty string | `b"Double-Ratchet-Chain-Key-Expansion"` (34 B) | 64 |
| PQ contribution at RK₁ (Ch. 4 §4.5) | `RK₁` | `kem_ss` (32 B) | `b"construct-pqxdh-v1"` (18 B) | 32 |
| Suite 3 PQ message-key mix | `pq_epoch_secret` | Double Ratchet message key | `b"construct-pqr-msg-v1"` (20 B) | 32 |
| Suite 3 EK hash | empty string | ML-KEM-768 encapsulation key | `b"construct-pqr-ekhash-v1"` (23 B) | 8 |

The Double Ratchet root and chain KDFs are implemented in
`construct-core/src/crypto/suites/classic.rs:233`-`:257` and mirrored
by the hybrid provider. The initial root normalisation is in
`construct-core/src/crypto/messaging/double_ratchet/messaging.rs:54`-`:59`.
The PQXDH and Suite 3 HKDF calls are in
`construct-core/src/crypto/messaging/double_ratchet/internals.rs:62`-`:99`
and `:280`-`:438`.

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
SK_root = HKDF(salt = F, IKM = DH_combined,
               info = "Construct-X3DH-RootKey-v1", L = 32)
RK₁     = (root after first DH ratchet step)
RK₁'    = HKDF(salt = RK₁, IKM = kem_ss,
               info = "construct-pqxdh-v1", L = 32)
```

Because RK₁' depends on both `DH_combined` (classical) and `kem_ss`
(post-quantum), an adversary MUST break **both** components to recover
plaintext. Breaking only X25519 leaves `kem_ss` as a 32-byte
unknown input to the KDF; breaking only ML-KEM-768 leaves
`DH_combined` similarly. This is the standard hybrid-security argument
and the reason Suite 2 is constructed as KEM **alongside** rather than
**instead of** classical X3DH.

### 2.3.3 Signatures in Suite 2

Suite 2 keeps Ed25519 signatures as the mandatory classical
authentication path and adds optional, capability-gated hybrid
signatures using **ML-DSA-65 (Dilithium-3)** per NIST FIPS 204.
Hybrid signatures do not replace Ed25519 in the current wire format;
they are an additional attestation over the same prekey sign-message.

The hybrid signature public key format is:

```
hybrid_identity_key = ed25519_pk(32) || mldsa65_pk(1952)       -- 1984 B
hybrid_signature    = ed25519_sig(64) || mldsa65_sig(3309)     -- 3373 B
```

The stored hybrid signing secret is
`ed25519_seed(32) || mldsa65_seed(32) || mldsa65_pk(1952)`
(2016 B). The device binds that independent hybrid identity key to
its existing Ed25519 identity with
`Ed25519("KonstruktHybridId-v1" || hybrid_identity_key)`. Prekey-level
hybrid signatures cover
`"KonstruktX3DH-v1" || [0x00, suite_id] || public_key`, where
`suite_id = 0x01` for the X25519 SPK and `suite_id = 0x10` for the
ML-KEM-768 SPK. Reference sizes and verification behaviour:
`construct-core/src/crypto/suites/hybrid.rs:1`-`:51`,
`construct-server/shared/proto/services/key_service.proto:248`-`:270`,
and `construct-ios` `Security/HybridBundleVerifier.swift:34`-`:120`.

If a bundle lacks hybrid fields, a conforming client MUST continue to
accept the Ed25519-only path. If the hybrid identity cross-signature
is present and invalid, the bundle MUST be rejected. If the hybrid
identity is authentic but a prekey-level hybrid signature is missing
or invalid, the reference client degrades to the classical Ed25519
attestation path instead of hard-failing reachability
(`HybridBundleVerifier.swift:72`-`:109`).

## 2.4 Suite 3 — Sparse continuous PQ ratchet

Suite 3 (`0x0003`) is a ratchet-level extension, not a new protobuf
`CryptoSuite` bundle value. A new session may negotiate Suite 3 only
when the fetched bundle advertises `supports_pq_ratchet`; the iOS
client maps bundle crypto-suite values only to core suite 1 or 2 and
derives suite 3 from that capability
(`construct-ios` `Networking/gRPC/Services/KeyServiceClient.swift:418`-`:430`;
`construct-core/src/crypto/client_api.rs:1082`-`:1152`).

At a configured cadence, the designated Suite 3 initiator attaches an
ML-KEM-768 encapsulation key to outgoing messages. The peer
encapsulates once and re-attaches the ciphertext until the initiator
activates the epoch. Completed PQ epoch secrets are not mixed into
the Double Ratchet root or chain keys; instead, the per-message key is:

```
MK_pq = HKDF(salt = pq_epoch_secret,
             IKM = MK_dr,
             info = "construct-pqr-msg-v1", L = 32)
```

`pq_message_epoch = 0` means no PQ epoch has been mixed yet. Unknown
or evicted non-zero epochs are a hard decrypt error, because silently
skipping the mix would be a downgrade. The implemented state machine
is in `construct-core/src/crypto/messaging/double_ratchet/internals.rs:276`-`:438`.

### 2.4.1 Cadence and retention

| Parameter | Reference value | Source |
|---|---|---|
| Rekey cadence | 16 DH-ratchet turns | `construct-core/src/config.rs:141` |
| Cadence bounds (env override) | clamped to `[4, 64]` | `config.rs:216`-`:218` |
| Retained completed epoch secrets | 4 | `double_ratchet/mod.rs:180` |
| Unanswered proposal abandoned after | `max_skipped_message_age_seconds` | `internals.rs:243`-`:252` |

The counter advances inside the DH ratchet step
(`internals.rs:217`), so the unit is a **DH ratchet turn — a change of
conversational direction — not a message and not elapsed time**. A
one-sided burst of a hundred messages performs no DH step and so makes
no PQ progress; sixteen alternations do. The reference implementation
has no time-based floor.

A pending field is attached by `encrypt` to *every* outgoing frame
(`messaging.rs:385`), which includes control frames such as delivery
receipts. A peer that only sends receipts therefore both advances the
turn counter and carries the exchange forward, without the user
replying.

Retention is a hard bound with a hard consequence. A message naming an
epoch that has already been evicted is a decrypt error, by the same
no-silent-downgrade rule as an unknown epoch. Implementations that
tolerate deeper reordering than the reference MUST raise the retention
count rather than relax the error.

### 2.4.2 Normative rules for the sparse exchange

1. **Commit on success only.** PQ processing of a received frame — EK
   ingestion, ciphertext completion, epoch promotion — MUST run only
   after the carrying message has authenticated and decrypted. A
   malformed or hostile PQ field MUST NOT alter session state, and the
   classical delivery of its carrier MUST be unaffected. By
   construction an EK/CT field always rides on a frame tagged with a
   pre-completion epoch, so decrypting the carrier never depends on the
   material it carries
   (`internals.rs:352`-`:388`).

2. **Re-attach until implicitly acknowledged.** There is no explicit
   acknowledgement frame. The initiator re-attaches its EK to every
   outgoing message until a matching ciphertext arrives; the responder
   re-attaches its ciphertext until a peer message tagged at or above
   the provisional epoch arrives — which proves the initiator
   decapsulated the same secret, because that tag was just used
   successfully to derive the message key. A dropped message therefore
   costs bandwidth, never a stuck exchange
   (`internals.rs:449`-`:466`).

3. **One exchange in flight.** A new proposal MUST NOT be started while
   one is pending; the cadence counter simply retries on the next turn.

4. **`ek_hash` disambiguates re-proposals.** After an unanswered
   proposal is abandoned, the same epoch number may be re-proposed with
   a fresh keypair. The 8-byte `ek_hash` accompanying a ciphertext
   identifies which encapsulation key it completes; a ciphertext whose
   hash does not match the pending keypair MUST be ignored, and the
   local proposal kept.

5. **Epoch secrets are constant within an epoch.** The reference
   derives every message key of an epoch from the same
   `pq_epoch_secret`; the post-quantum component does not ratchet
   between rekeys. Forward secrecy within an epoch is supplied by the
   classical Double Ratchet alone. See
   [Appendix B](./appendix-b-pq-comparison.md) for how this compares
   with other deployed designs.

## 2.5 Randomness

All key generation, ephemeral keypair generation, and AEAD nonces MUST
be sourced from a cryptographically secure RNG. The reference uses
`rand::rngs::OsRng` for classical primitives and a separately-seeded
`getrandom`-backed RNG for the `ml-kem` crate's PQ operations
(`getrandom_pq` feature).

Implementations MUST NOT use deterministic or counter-derived
randomness for any of the values above. A failure of the OS RNG MUST
cause the operation to abort, not to proceed with a weak source.

## 2.6 Key zeroization

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

## 2.7 Constants summary

For ease of cross-reference, all normative byte constants used in this
specification:

| Constant | Value | Length |
|---|---|---|
| X3DH/prekey prologue | `b"KonstruktX3DH-v1"` | 16 B |
| Hybrid identity bind prologue | `b"KonstruktHybridId-v1"` | 20 B |
| Salt F (X3DH HKDF) | `[0xFF; 32]` | 32 B |
| Salt for initial DR root | `[0xFE; 32]` | 32 B |
| Info (X3DH root key) | `b"Construct-X3DH-RootKey-v1"` | 25 B |
| Info (initial DR root) | `b"InitialRootKey"` | 14 B |
| Info (Double Ratchet root step) | `b"Double-Ratchet-Root-Key-Expansion"` | 33 B |
| Info (Double Ratchet chain step) | `b"Double-Ratchet-Chain-Key-Expansion"` | 34 B |
| Info (PQXDH contribution) | `b"construct-pqxdh-v1"` | 18 B |
| Info (Suite 3 message-key mix) | `b"construct-pqr-msg-v1"` | 20 B |
| Info (Suite 3 EK hash) | `b"construct-pqr-ekhash-v1"` | 23 B |
| Suite 1 ID | `0x0001` | 2 B (`u16`; LE in WirePayload, BE inside X3DH prologue) |
| Suite 2 ID | `0x0002` | 2 B (`u16`; LE in WirePayload, BE inside X3DH prologue) |
| Suite 3 ID | `0x0003` | 2 B (`u16`; LE in WirePayload) |
| Suite 3 rekey cadence | 16 ratchet turns (clamped `[4, 64]`) | — |
| Suite 3 retained epoch secrets | 4 | — |
| ML-KEM-768 encapsulation key | 1184 | B |
| ML-KEM-768 ciphertext | 1088 | B |
| ML-KEM-768 shared secret | 32 | B |
| Argon2id version | `V0x13` | — |
| CFE magic | `[0x43, 0x46]` ("CF") | 2 B |
| CFE version | `0x01` | 1 B |

These constants MUST be byte-identical between conforming
implementations. Changing any of them produces an instantly
non-interoperable handshake or AEAD failure.

## 2.8 References

- Reference implementation (single source of truth for parameters
  above): `construct-core/`, particularly `src/crypto/`, `src/pow.rs`,
  and `Cargo.toml`.
- NIST FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 204 (ML-DSA): <https://csrc.nist.gov/pubs/fips/204/final>
- RFC 7748 (X25519): <https://www.rfc-editor.org/rfc/rfc7748>
- RFC 8032 (Ed25519): <https://www.rfc-editor.org/rfc/rfc8032>
- RFC 8439 (ChaCha20-Poly1305): <https://www.rfc-editor.org/rfc/rfc8439>
- RFC 5869 (HKDF): <https://www.rfc-editor.org/rfc/rfc5869>
- RFC 9106 (Argon2): <https://www.rfc-editor.org/rfc/rfc9106>
