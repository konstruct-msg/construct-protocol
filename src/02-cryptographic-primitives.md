# Cryptographic Primitives

This chapter enumerates every cryptographic primitive that an
interoperable Konstruct implementation MUST use, with concrete
parameters, byte sizes, and crate-level references to the verified
reference implementation. Three core suite identifiers are currently
accepted by `construct-core`: Suite 1 (classical ratchet), Suite 2
(hybrid Ed25519 + ML-DSA-65 signatures), and Suite 4 (sparse continuous
ML-KEM-768 ratchet, one post-quantum key per message). Suite 3, an
earlier PQ-ratchet design that mixed one key per *epoch* instead of per
message, is retired without a compatibility path (§2.4). Independently of the suite, every session opens with
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
| `SUITE_PQ_RATCHET_V1` | `0x0003` | **Retired** (construct-core 0.24.0, PQR-2). Suite 1 + sparse continuous ML-KEM-768 ratchet, one epoch secret mixed into every message key of the epoch. Refused outright at unpack and at session restore; see §2.4. |
| `SUITE_PQ_RATCHET_V2` | `0x0004` | Suite 1 + sparse continuous ML-KEM-768 ratchet, one derived key per message (§2.4) |

The suite identifier appears in the WirePayload header
([Chapter 5 §5.3](./05-message-encryption.md#53-wire-format-wirepayload-header))
and MUST be checked by the receiver before any cryptographic
operation; a mismatched suite MUST cause the message to be rejected.
In the WirePayload header it is encoded as `u16` little-endian
(`construct-core/src/wire_payload.rs`). Signature
prologues use their own explicitly-specified byte order (§2.2.2).
The accepted IDs — currently `1`, `2` and `4` — are defined in
`SuiteID::new` (`construct-core/src/crypto/suite_id.rs`); `3` is named
only so a refusal can say what it refused
(`SuiteID::RETIRED_PQ_RATCHET_V1`).

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
| PQ ratchet epoch chains (§2.4) | empty | ML-KEM-768 shared secret | `b"construct-pqr-chains-v2"` ‖ epoch (`u32` BE) (23 + 4 = 27 B) | 64 |
| PQ ratchet chain step (§2.4) | empty | PQ chain key | `b"construct-pqr-step-v2"` (21 B) | 64 |
| PQ ratchet message-key mix (§2.4) | PQ chain key at `(epoch, index)` | Double Ratchet message key | `b"construct-pqr-msg-v2"` (20 B) | 32 |
| PQ ratchet EK hash | empty string | ML-KEM-768 encapsulation key | `b"construct-pqr-ekhash-v1"` (23 B) | 8 |

The Double Ratchet root and chain KDFs are implemented in
`construct-core/src/crypto/suites/classic.rs` and mirrored
by the hybrid provider. The initial root normalisation is in
`construct-core/src/crypto/messaging/double_ratchet/messaging.rs`.
The PQXDH v2 root key is `construct-core/src/crypto/handshake/x3dh.rs`.
The PQ ratchet HKDF calls (`pq_epoch_chains`, `pq_chain_step`,
`mix_pq_message_key`, `pq_ek_hash`) are in
`construct-core/src/crypto/messaging/double_ratchet/internals.rs`.

> **Changed in construct-core 0.24.0** (PQR-2,
> `decisions/pq-ratchet-per-message-chain.md`). Until then the PQ
> message-key mix used a single `pq_epoch_secret` stored for the
> lifetime of an epoch (`info = b"construct-pqr-msg-v1"`, retired with
> Suite 3), so every message key of an epoch was derived from the same
> salt. The epoch secret is now spent once, into the two chain keys
> above, and never stored (§2.4).

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
Suite 4 ratchet (§2.4). The split — 1024 for prekeys, 768 in the ratchet —
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

## 2.4 Suite 4 — Sparse continuous PQ ratchet, per-message chains

Suite 4 (`0x0004`) is a ratchet-level extension, not a new protobuf
`CryptoSuite` bundle value, and it is not negotiated from the bundle at all: it is mandatory
wherever the `post-quantum` build feature is present (every platform build, §2.3.1). An
initiator with that feature always proposes it
(`session_api::negotiated_initiator_suite`/`local_supports_pq_ratchet`,
`construct-core/src/crypto/session_api.rs`), and a responder built the same way refuses a first
message on any other suite (`PQXDH_REQUIRED`, `construct-core/src/orchestration/orchestrator.rs`).
The iOS client's bundle-to-suite mapping produces only core suite 1 or 2
(`construct-ios` `Networking/gRPC/Services/KeyServiceClient.swift`) — suite 4 is never read out of
a bundle, it is simply what every current build runs.

> **Changed with PQXDH v2** (2026-09-25, construct-core 0.18,
> `decisions/pqxdh-v2-mandatory-pq-cutover.md`). Suite 4 (then Suite 3) used to be negotiated
> per session from an unsigned `supports_pq_ratchet` capability flag the server served beside the
> bundle: a device that had advertised or used it was refused (`PQ_DOWNGRADE_REFUSED`) if a later
> bundle dropped the flag. The same commit that landed PQXDH v2 removed both the flag and its
> downgrade ledger (`prd`) — there was nothing left for either side to negotiate once the suite
> became mandatory. A bundle that still carries the old field is read as before and the field is
> ignored.

> **Changed in construct-core 0.24.0** (PQR-2,
> `decisions/pq-ratchet-per-message-chain.md`). Suite 3 (`0x0003`) was
> this same sparse exchange, but a completed epoch's ML-KEM secret was
> *stored* and mixed unchanged into every message key of the epoch —
> roughly sixteen DH-ratchet turns' worth of messages sharing one PQ
> contribution, with four such secrets retained for late deliveries. A
> stolen session state plus a broken X25519 therefore read every
> message of those epochs, already-read ones included: the classical
> half of the ratchet had per-message forward secrecy, the
> post-quantum half had only per-epoch. Suite 3 is retired without a
> compatibility path, as PQXDH v1 was before it (§2.3): its messages
> are refused at unpack (`RetiredSuite(3)`, Appendix A §A.4) and its
> stored sessions are refused at restore — the next send opens a
> fresh Suite 4 session. What is unchanged by this revision: the
> exchange protocol itself (EK proposal, CT completion, cadence,
> `ek_hash` disambiguation — rules 1–4 below), where in the frame the
> PQ material rides, and the mixing shape (the PQ key as the HKDF
> salt, §2.2.4).

At a configured cadence (§2.4.3), the designated Suite 4 initiator attaches an
ML-KEM-768 encapsulation key to outgoing messages. The peer
encapsulates once and re-attaches the ciphertext until the initiator
activates the epoch — this exchange is unchanged from Suite 3. What changed is what a
completed epoch *yields*.

### 2.4.1 From an epoch secret to two chains

The moment an epoch completes — the initiator on decapsulating the responder's ciphertext, the
responder (provisionally, ahead of promotion) at encapsulation — its ML-KEM-768 shared secret is
spent at once into two directional chain keys and then discarded; it is never written to
persistent state:

```
ck[epoch, i→r] || ck[epoch, r→i]
    = HKDF-SHA-256(salt = empty, IKM = epoch_secret,
                    info = b"construct-pqr-chains-v2" || epoch (u32 BE), L = 64)
    -> (output[0..32], output[32..64])
```

`ck[epoch, i→r]` is the chain the PQ-exchange **initiator** sends on; `ck[epoch, r→i]` is the
chain the **responder** sends on. (The PQ-exchange initiator is always the Double Ratchet
initiator — single-initiator discipline, unchanged from Suite 3.) Each side's own send chain is
its direction; the other is its receive chain. Both start at index 0.

A chain steps forward one key at a time:

```
ck' || k = HKDF-SHA-256(salt = empty, IKM = ck, info = b"construct-pqr-step-v2", L = 64)
    -> (output[0..32], output[32..64])
```

`ck'` replaces the chain key; `k` is the key for the chain's current index, and the index then
increments. A message takes the next key of its sender's chain for the current epoch and names
`(epoch, index)` in its header (§5.3); the receiver advances the matching chain to that index,
keeping every passed-over key as a skipped PQ key (§2.4.3). The per-message key is mixed exactly
as Suite 3 mixed its epoch secret — only the salt's provenance changed:

```
MK_pq = HKDF-SHA-256(salt = k, IKM = MK_dr, info = b"construct-pqr-msg-v2", L = 32)
```

`pq_message_epoch = 0` (with `pq_key_index = 0`) means no PQ epoch has completed yet — `MK_pq =
MK_dr`, unmixed. A non-zero `pq_key_index` naming epoch 0 is a wire error
(`PqKeyIndexWithoutEpoch`, Appendix A §A.4); a `pq_message_epoch` naming a chain that is neither
retained nor provisional is a hard decrypt error, because silently skipping the mix would be a
downgrade. The implemented state machine is `pq_epoch_chains`, `pq_chain_step`, `pq_send_key`,
`pq_receive_key`, `mix_pq_message_key`
(`construct-core/src/crypto/messaging/double_ratchet/internals.rs`); full receiver procedure and
retention bound: [Chapter 5 §5.8](./05-message-encryption.md#58-decryption-ratchetdecrypt) and
[§5.8.3](./05-message-encryption.md#583-pq-ratchet-retention-suite-4).

### 2.4.2 Known-answer vectors

For `secret = 0x42` repeated 32 times, `epoch = 1`, Double Ratchet message key `= 0x07` repeated
32 times (`construct-core/src/crypto/messaging/double_ratchet/tests.rs`,
`test_pqr2_derivations_known_answers`, recomputed independently in Python `hmac` against RFC 5869
when pinned, 2026-09-30):

| Derivation | Value (hex) |
|---|---|
| Initiator's send chain key (`ck[1, i→r]`) | `1580b9a74a9abc6d8cefbaf561c65c64adc8b33849656f1b0051db2d9af8842f` |
| Initiator's receive chain key (`ck[1, r→i]`) | `30730bf58df681adddf740b817d1c5ff17b8517b05e383fbe1dea05ead8ae57b` |
| Send chain, key at index 0 | `c03bff04f55cd6c9b7b1952306a32de0347e12307f0c9265cd88f4111f7e9325` |
| Send chain, key at index 1 | `7fc0bad75c864e2a790dbfbb04e1e102763d88098ba1d8b7e7210c8cafd002d3` |
| Message key mixed from the key at index 0 | `bd28758bb7c74d3d64fee6e4002b4f6e716169c1148aea322b9800a505976966` |

The responder's chains are the initiator's, crossed: the responder's receive chain equals the
initiator's send chain and vice versa. These are the vectors another implementation (or
`construct-tui`, paused, §7.2) checks itself against once published to
`construct-protos/conformance`.

### 2.4.3 Cadence and retention

| Parameter | Reference value | Source |
|---|---|---|
| Rekey cadence | 16 DH-ratchet turns | `construct-core/src/config.rs` |
| Cadence bounds (env override) | clamped to `[4, 64]` | `config.rs` |
| Rekey age floor (`pq_ratchet_max_age_seconds`) | 7 days | `config.rs` |
| Retained epochs' chains | 2 (current + previous) — `PQ_CHAIN_RETENTION` | `double_ratchet/mod.rs` |
| PQ skipped-key bounds | shared with the classical `MKSKIPPED` bounds: 1000 keys, 2000-message jump, 7-day age | [Chapter 5 §5.8.1](./05-message-encryption.md#581-mandatory-dos-guards) |
| Unanswered proposal abandoned after | `max_skipped_message_age_seconds` | `internals.rs` (`abandon_unanswered_pq_exchange`) |

The rekey-cadence counter advances inside the DH ratchet step, so the unit is a **DH ratchet
turn — a change of conversational direction — not a message and not elapsed time**. A one-sided
burst of a hundred messages performs no DH step and so makes no PQ progress by the turn count
alone; sixteen alternations do.

> **Changed in construct-core 0.24.1** (PQR-1, TODO 64.1). Until then the turn count was the only
> trigger, so a conversation that never changes direction — one side always writing, the other
> always reading — never took a DH step and so never rekeyed: the epoch the PQ ratchet started
> with was the epoch it kept forever, the exact state the ratchet exists to leave. The exchange
> initiator now also checks the current epoch's age on every `encrypt` call
> (`maybe_start_pq_exchange_by_age`) and proposes a new one, turns or not, once it has stood for
> `pq_ratchet_max_age_seconds` — 7 days, the floor Apple PQ3 guarantees; the turn-counted path
> checks the same age and fires early too. `pq_epoch_since` (set when an epoch completes, and at
> session creation) is the clock; it is persisted (CFE `CfePqRatchetStateV2.since`), and a
> restored blob with no value for it is read as maximally old, so the next send proposes rather
> than trusting an age it cannot know.
>
> **Still open:** only the exchange initiator ever proposes (single-initiator discipline, §2.4.4
> rule — unchanged). A conversation in which only the *responder* writes still cannot rekey by
> either path, because the side that could propose never sends. Closing that gap needs roles that
> alternate per epoch — a protocol change of its own, not a parameter. See Chapter 7 §7.3.

A pending EK/CT field is attached by `encrypt` to *every* outgoing frame, which includes control
frames such as delivery receipts. A peer that only sends receipts therefore both advances the
turn counter and carries the exchange forward, without the user replying — and, since 0.24.1, is
also what makes the age check itself run (it runs on every `encrypt`, receipts included).

Only the **current** epoch keeps a send chain: starting a newer epoch's send chain erases the
older one outright. The **previous** epoch keeps its receive chain one epoch longer, so a message
sent just before the peer switched epochs still decrypts; beyond `PQ_CHAIN_RETENTION` the whole
epoch is dropped. This is a hard bound with a hard consequence, unchanged in kind from Suite 3: a
message naming an epoch outside the retained set, and not covered by an already-kept skipped PQ
key, is a decrypt error by the same no-silent-downgrade rule as an unknown epoch. It replaces
Suite 3's `PQ_EPOCH_RETENTION = 4` stored secrets, and answers `PQR-4` (Chapter 7 §7.3): the bound
on out-of-order tolerance is now the same skipped-key window the classical half already uses, not
an independently-sized epoch count.

### 2.4.4 Normative rules for the sparse exchange

1. **Commit on success only.** PQ processing of a received frame — EK
   ingestion, ciphertext completion, epoch promotion, chain derivation — MUST run only
   after the carrying message has authenticated and decrypted. A
   malformed or hostile PQ field MUST NOT alter session state, and the
   classical delivery of its carrier MUST be unaffected. By
   construction an EK/CT field always rides on a frame tagged with a
   pre-completion epoch, so decrypting the carrier never depends on the
   material it carries
   (`internals.rs`, `commit_pq_post_decrypt`).

2. **Re-attach until implicitly acknowledged.** There is no explicit
   acknowledgement frame. The initiator re-attaches its EK to every
   outgoing message until a matching ciphertext arrives; the responder
   re-attaches its ciphertext until a peer message tagged at or above
   the provisional epoch arrives — which proves the initiator
   decapsulated the same secret, because that tag was just used
   successfully to derive the message key. A dropped message therefore
   costs bandwidth, never a stuck exchange
   (`internals.rs`, `commit_pq_post_decrypt`).

3. **One exchange in flight.** A new proposal MUST NOT be started while
   one is pending; the cadence counter simply retries on the next turn.

4. **`ek_hash` disambiguates re-proposals.** After an unanswered
   proposal is abandoned, the same epoch number may be re-proposed with
   a fresh keypair. The 8-byte `ek_hash` accompanying a ciphertext
   identifies which encapsulation key it completes; a ciphertext whose
   hash does not match the pending keypair MUST be ignored, and the
   local proposal kept.

5. **Per-message chains, not a per-epoch secret.** The reference derives each message's PQ
   contribution from its sender's epoch chain at the key's own index (§2.4.1); the epoch secret
   itself is spent once and never stored. Forward secrecy at message granularity is now supplied
   by *both* halves of the ratchet — the classical Double Ratchet as before, and the PQ chains
   since this revision. A read message's PQ key is derivable by neither side afterwards: the
   chain that produced it has already moved past that index. See
   [Appendix B §B.6](./appendix-b-pq-comparison.md#b6-granularity-of-the-post-quantum-guarantee)
   for how this compares with other deployed designs — Suite 4 now matches Signal SPQR's
   granularity in kind, though not in mechanism (SPQR ratchets a symmetric chain seeded once per
   handshake; Suite 4 reseeds two chains from a fresh ML-KEM secret every epoch).

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
| Info (PQ ratchet epoch chains) | `b"construct-pqr-chains-v2"` | 23 B |
| Info (PQ ratchet chain step) | `b"construct-pqr-step-v2"` | 21 B |
| Info (PQ ratchet message-key mix) | `b"construct-pqr-msg-v2"` (`v1`, retired with Suite 3) | 20 B |
| Info (PQ ratchet EK hash) | `b"construct-pqr-ekhash-v1"` | 23 B |
| Suite 1 ID | `0x0001` | 2 B (`u16`; LE in WirePayload, BE inside X3DH prologue) |
| Suite 2 ID | `0x0002` | 2 B (`u16`; LE in WirePayload, BE inside X3DH prologue) |
| Suite 3 ID (retired, PQR-2) | `0x0003` | 2 B; refused at unpack (`RetiredSuite`) and at session restore |
| Suite 4 ID | `0x0004` | 2 B (`u16`; LE in WirePayload) |
| PQ ratchet rekey cadence | 16 ratchet turns (clamped `[4, 64]`) | — |
| PQ ratchet retained epochs' chains (`PQ_CHAIN_RETENTION`) | 2 (current + previous) | — |
| PQ key index wire encoding | unsigned LEB128, minimal, 1–5 B | — |
| ML-KEM-1024 encapsulation key (prekeys) | 1568 | B |
| ML-KEM-1024 ciphertext (first flight) | 1568 | B |
| ML-KEM-768 encapsulation key (PQ ratchet only) | 1184 | B |
| ML-KEM-768 ciphertext (PQ ratchet only) | 1088 | B |
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
