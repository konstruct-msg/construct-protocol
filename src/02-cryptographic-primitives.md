# Cryptographic Primitives

This chapter enumerates every cryptographic primitive that an
interoperable Konstruct implementation MUST use, with concrete
parameters, byte sizes, and crate-level references to the verified
reference implementation. Three core suite identifiers are currently
accepted by `construct-core`: Suite 1 (classical ratchet), Suite 2
(hybrid Ed25519 + ML-DSA-65 signatures), and Suite 3 (sparse continuous
ML-KEM-768 ratchet). Independently of the suite, every session opens with
PQXDH v2 — ML-KEM-1024 in the initial root key — and a session is not
created without it (§2.3, Chapter 4).

Keywords MUST, MUST NOT, SHOULD, MAY are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2.1 Suite identifiers

Each session is parameterised by a suite identifier. The suite is
fixed at handshake time and MUST NOT change for the lifetime of the
session.

| Identifier | Value | Description |
|---|---|---|
| `SUITE_CLASSIC_V1` | `0x0001` | X25519 + Ed25519 + ChaCha20-Poly1305 + HKDF-SHA256 |
| `SUITE_PQ_HYBRID_V1` | `0x0002` | Suite 1 + hybrid Ed25519 + ML-DSA-65 signatures |
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
  - ML-KEM-1024 prekey, signed and one-time alike: `Ed25519_Sign(SK_priv, b"KonstruktX3DH-v1" || [0x00, 0x11] || created_at (u64 BE) || KEM_pub)`, and the same message under the hybrid key. The v1 message (`0x10`, a 768-bit key, no time) is retired and MUST NOT verify as v2.
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
| PQXDH root key (Ch. 4 §4.3) | `[0xFF; 32]` | `DH_combined \|\| kem_ss` | `b"Construct-PQXDH-RootKey-v3"` (26 B) `\|\| SHA-256(KEM_pub) \|\| SHA-256(kem_ct) \|\| SHA-256(KIK_A)` | 32 |
| KEM identity seed (Ch. 4 §4.4.4) | empty | ML-DSA-65 seed (32 B) | `b"Construct-KEM-identity-v1"` (25 B) | 64 |
| Identity answer, root (Ch. 4 §4.4.4) | `kik_ss` | `RK` | `b"Construct-KEM-identity-root-v1"` (30 B) | 32 |
| Identity answer, chain (Ch. 4 §4.4.4) | `kik_ss` | `CK` | `b"Construct-KEM-identity-chain-v1"` (31 B) | 32 |
| Classical X3DH root key (builds without `post-quantum` only) | `[0xFF; 32]` | `DH_combined` | `b"Construct-X3DH-RootKey-v1"` (25 B) | 32 |
| Initial Double Ratchet root normalisation | `[0xFE; 32]` | X3DH root key | `b"InitialRootKey"` (14 B) | 32 |
| Double Ratchet root step (Ch. 5 §5.2) | `RK` | `dh_out` (32 B) | `b"Double-Ratchet-Root-Key-Expansion"` (33 B) | 64 |
| Double Ratchet chain step (Ch. 5 §5.2) | `CK` | empty string | `b"Double-Ratchet-Chain-Key-Expansion"` (34 B) | 64 |
| Suite 3 PQ message-key mix | `pq_epoch_secret` | Double Ratchet message key | `b"construct-pqr-msg-v1"` (20 B) | 32 |
| Suite 3 EK hash | empty string | ML-KEM-768 encapsulation key | `b"construct-pqr-ekhash-v1"` (23 B) | 8 |

The Double Ratchet root and chain KDFs are implemented in
`construct-core/src/crypto/suites/classic.rs:233`-`:257` and mirrored
by the hybrid provider. The initial root normalisation is in
`construct-core/src/crypto/messaging/double_ratchet/messaging.rs:54`-`:59`.
The PQXDH v2 root key is `construct-core/src/crypto/handshake/x3dh.rs:162`-`:185`.
The Suite 3 HKDF calls are in
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

## 2.3 Post-quantum key agreement (PQXDH v2, mandatory)

Every session's initial root key includes an ML-KEM-1024 shared secret
([Chapter 4 §4.3](./04-session-handshake.md#43-initiator-path)). This is
not a suite: it applies to Suites 1, 2 and 3 alike, and there is no
classical-only way to open a session with a shipping client.

> **Changed 2026-09-25.** Earlier revisions specified PQXDH v1: an
> ML-KEM-768 secret mixed into the root key *after* the first DH ratchet
> step (`info = "construct-pqxdh-v1"`), which left the first chain of every
> session classical only, and made PQ optional. v1 is removed without a
> compatibility path.

### 2.3.1 ML-KEM-1024 (prekeys and the first message)

- Algorithm: ML-KEM-1024 per [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
- Crate: `ml-kem` (feature `post-quantum`, which every platform build enables).
- Encapsulation key: **1568 bytes**. Ciphertext: **1568 bytes**. Shared secret: **32 bytes**.
- Secret keys are generated and kept by the core as 64-byte seeds
  (`MLKEM_SEED_SIZE`, `construct-core/src/crypto/pq_x3dh.rs:151`-`:155`).
- Implementations MUST use the FIPS 203 final variant.

ML-KEM-768 (1184-byte key, 1088-byte ciphertext) is used only in the
Suite 3 ratchet (§2.4). The split — 1024 for prekeys, 768 in the ratchet —
is the one Signal (PQXDH and SPQR) and Apple PQ3 use.

### 2.3.2 Hybrid design

```
IKM     = DH1 || DH2 || DH3 [|| DH4] || kem_ss
SK_root = HKDF(salt = F, IKM,
               info = "Construct-PQXDH-RootKey-v3" || SHA-256(KEM_pub) || SHA-256(kem_ct)
                      || SHA-256(KIK_A),
               L = 32)
```

Because `SK_root` depends on both the DH outputs (classical) and
`kem_ss` (post-quantum), an adversary must break **both** to recover any
message, including the first. Breaking only X25519 leaves `kem_ss` as a
32-byte unknown input; breaking only ML-KEM leaves the DH outputs. The
Kyber key and ciphertext are bound through `info`, so the construction
does not rely on which binding properties a particular KEM has.

### 2.3.3 Hybrid signatures

Ed25519 stays the classical authentication path, and every Kyber prekey
additionally carries a hybrid signature using **ML-DSA-65 (Dilithium-3)**
per NIST FIPS 204. Hybrid signatures do not replace Ed25519 in the
wire format; they are a second attestation over the same sign-message.

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
`"KonstruktX3DH-v1" || [0x00, 0x01] || SPK_pub` for the X25519 SPK and
`"KonstruktX3DH-v1" || [0x00, 0x11] || created_at || KEM_pub` for every
ML-KEM-1024 prekey. Reference sizes and verification behaviour:
`construct-core/src/crypto/suites/hybrid.rs:1`-`:51`,
`construct-server/shared/proto/services/key_service.proto:248`-`:270`,
and `construct-ios` `Security/HybridBundleVerifier.swift:34`-`:120`.

For opening a session, the hybrid fields are **required**
(`construct-core/src/orchestration/pq_prekey_plan.rs`): a bundle without
the hybrid identity key, with an invalid cross-signature, or with a Kyber
prekey whose Ed25519 or hybrid signature is missing or invalid is refused,
and no session is created. The fingerprint of the hybrid identity key is
pinned per device; a changed one is refused (`HybridIdentityChanged`).
Until 2026-09-24 no receiving side checked Kyber signatures at all, and a
substituted Kyber key would have received the ML-KEM secret of every
session opened to that device while every indicator said "PQ".

The hybrid key's own trust root is still its Ed25519 cross-signature; the
identity and addressing layer is not post-quantum (Chapter 7).

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
| Info (PQXDH root key, prefix) | `b"Construct-PQXDH-RootKey-v3"` | 26 B |
| Info (KEM identity seed) | `b"Construct-KEM-identity-v1"` | 25 B |
| Info (identity answer, root / chain) | `b"Construct-KEM-identity-root-v1"` / `b"Construct-KEM-identity-chain-v1"` | 30 / 31 B |
| Info (classical X3DH root key, non-PQ builds) | `b"Construct-X3DH-RootKey-v1"` | 25 B |
| Kyber prekey sign-message suite byte | `0x11` | 1 B |
| Kyber SPK maximum age (signed `created_at`) | 30 days | — |
| PQXDH v2 flag in wire `suite_id` | `0x0100` | — |
| KEM identity key / identity answer flags in wire `suite_id` | `0x0200` / `0x0400` | — |
| Info (initial DR root) | `b"InitialRootKey"` | 14 B |
| Info (Double Ratchet root step) | `b"Double-Ratchet-Root-Key-Expansion"` | 33 B |
| Info (Double Ratchet chain step) | `b"Double-Ratchet-Chain-Key-Expansion"` | 34 B |
| Info (Suite 3 message-key mix) | `b"construct-pqr-msg-v1"` | 20 B |
| Info (Suite 3 EK hash) | `b"construct-pqr-ekhash-v1"` | 23 B |
| Suite 1 ID | `0x0001` | 2 B (`u16`; LE in WirePayload, BE inside X3DH prologue) |
| Suite 2 ID | `0x0002` | 2 B (`u16`; LE in WirePayload, BE inside X3DH prologue) |
| Suite 3 ID | `0x0003` | 2 B (`u16`; LE in WirePayload) |
| Suite 3 rekey cadence | 16 ratchet turns (clamped `[4, 64]`) | — |
| Suite 3 retained epoch secrets | 4 | — |
| ML-KEM-1024 encapsulation key (prekeys) | 1568 | B |
| ML-KEM-1024 ciphertext (first flight) | 1568 | B |
| ML-KEM-768 encapsulation key (Suite 3 only) | 1184 | B |
| ML-KEM-768 ciphertext (Suite 3 only) | 1088 | B |
| ML-KEM shared secret | 32 | B |
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
