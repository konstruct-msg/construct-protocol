# Message Encryption (Double Ratchet)

Once a session is established by the handshake of
[Chapter 4](./04-session-handshake.md), every subsequent message is
encrypted under the **Double Ratchet** algorithm of Perrin and Marlinspike.
This chapter specifies Konstruct's variant: state variables, the symmetric
and DH ratchet steps, the AEAD framing and Associated Data, and the
DoS guards that an interoperable implementation MUST enforce.

Keywords MUST, MUST NOT, SHOULD, MAY are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 5.1 Session state

Each party maintains the following state per session. All values are
zeroised on session destruction; `MK` and intermediate chain-key
material MUST be zeroised immediately after use.

| Symbol | Type | Initialised by | Meaning |
|---|---|---|---|
| RK | `[u8; 32]` | X3DH (Ch. 4 §4.3 Step 4) | Root key, advanced by DH ratchet |
| DHs | X25519 keypair | Ratchet step | Sending DH keypair (rotated each step) |
| DHr | `[u8; 32]` | Remote `dh_pub` from peer header | Last seen remote DH public |
| CKs | `[u8; 32]` | DH ratchet | Sending chain key |
| CKr | `[u8; 32]` | DH ratchet | Receiving chain key |
| Ns | `u32` | 0 | Messages sent in the current sending chain |
| Nr | `u32` | 0 | Messages received in the current receiving chain |
| PN | `u32` | 0 | Number of messages in the previous sending chain |
| MKSKIPPED | `Map<(DHr, n), [u8;32]>` | `{}` | Per-message keys for out-of-order delivery |
| `current_pq_epoch` | `u32` | 0 | Suite 3 only: completed PQ epoch mixed into outgoing message keys |
| `pq_epoch_secrets` | bounded list | `{}` | Suite 3 only: completed ML-KEM-768 epoch secrets retained for out-of-order messages |
| pending PQ exchange / ciphertext | optional | none | Suite 3 only: in-flight sparse PQ ratchet material |
| handshake header | optional | Ch. 4 §4.3 Step 5 | INITIATOR only: `EK_A`, `opk_id`, `kem_ct`, `kyber_otpk_id`, repeated on every outgoing message until the peer's first reply |

The reference implementation packs these into
`SessionState` in `construct-core/src/crypto/messaging/double_ratchet/`.

A device holds, per peer device, **one current state and up to three previous states**
(§5.9). What this chapter calls "the session" is the current state unless stated otherwise.

## 5.2 KDF helpers

Two distinct HKDF-SHA-256 instances are used:

```
KDF_RK(rk, dh_out) -> (rk', ck')
    = HKDF-SHA-256(salt = rk, IKM = dh_out,
                   info = b"Double-Ratchet-Root-Key-Expansion", L = 64)
    -> (output[0..32], output[32..64])

KDF_CK(ck) -> (mk, ck')
    = HKDF-SHA-256(salt = ck, IKM = empty,
                   info = b"Double-Ratchet-Chain-Key-Expansion", L = 64)
    -> (output[0..32], output[32..64])
```

`KDF_RK` mixes a new DH output into the root key and emits a fresh
chain key. `KDF_CK` advances a chain key one step and emits a single
message key. The initial X3DH root key is first normalised for the
Double Ratchet with `HKDF(salt = [0xFE; 32], IKM = x3dh_root,
info = b"InitialRootKey", L = 32)`.

## 5.3 Wire format (WirePayload header)

Every encrypted message on the wire is preceded by a fixed-layout
binary header followed by AEAD-protected ciphertext.

```
WirePayload (header, 52 bytes fixed + variable extension fields) ::=
    message_number      : u32  little-endian         (4 B)
    dh_public_key       : [u8; 32]                   (32 B)
    otpk_id             : u32  little-endian         (4 B)  -- 0 if N/A
    kyber_otpk_id       : u32  little-endian         (4 B)  -- 0 if N/A
    kem_len             : u16  little-endian         (2 B)
    prev_chain_length   : u32  little-endian         (4 B)
    suite_id            : u16  little-endian         (2 B)  -- bit 0x0100 = PQXDH v2 header
    -- followed by kem_ct (kem_len bytes; absent when kem_len = 0)
    -- followed by Suite 3 PQ section when suite_id = 0x0003
    -- followed by AEAD framing (nonce || ciphertext || tag)
```

`HEADER_SIZE = 52` bytes is fixed by the reference (sum of the field
sizes above, `construct-core/src/wire_payload.rs:22`-`:36`). The
variable KEM ciphertext follows the header when `kem_len > 0`: it is the
PQXDH v2 handshake header (Ch. 4 §4.3 Step 5), 1568 bytes of ML-KEM-1024
ciphertext, present on every message of the initiator's first flight and
absent afterwards. A frame that carries it sets bit `0x0100` of `suite_id`
(`PQXDH_V2_FLAG`, `wire_payload.rs:36`); `unpack` strips the bit, so the
suite the AEAD authenticates is the low byte. A KEM ciphertext on a frame
is exactly what makes it able to open a session (§4.4.1). The
pack/unpack routines are `wire_payload::pack` /
`wire_payload::unpack`; deviating from the ordering or endianness
produces non-interoperable frames.

Suite 3 adds a PQ section between `kem_ct` and the AEAD frame:

```
Suite3PqSection ::=
    pq_message_epoch : u32 little-endian
    field_type       : u8     -- 0 none, 1 EK proposal, 2 CT completion

field_type = 1:
    field_epoch      : u32 little-endian
    ek_len           : u16 little-endian
    ek               : bytes  -- ML-KEM-768 public key, normally 1184 B

field_type = 2:
    field_epoch      : u32 little-endian
    ek_hash          : [u8; 8]
    ct_len           : u16 little-endian
    ct               : bytes  -- ML-KEM-768 ciphertext, normally 1088 B
```

`pq_message_epoch` is always present for Suite 3, even when
`field_type = 0`. It is always `0` and no PQ section is encoded for
Suite 1 and Suite 2 frames. Reference layout:
`construct-core/src/wire_payload.rs:76`-`:129` and `:220`-`:264`.

The AEAD output `(nonce || ciphertext || tag)` uses:

| Component | Size |
|---|---|
| Nonce | 12 bytes (ChaCha20-Poly1305) |
| Ciphertext | `padded_plaintext.len()` bytes (1:1 with plaintext after padding) |
| Tag | 16 bytes (Poly1305) |

## 5.4 Associated Data construction (AD)

The AEAD MUST be called with an Associated Data buffer that binds the
ciphertext to its session, parties, ratchet position, and protocol
version. The current format is **AD version 3**, defined as:

```
AD_v3 ::=
    ad_version          : u8 = 3                     (1 B)
    sender_user_id      : utf-8 bytes (36 chars)     (36 B for UUID)
    receiver_user_id    : utf-8 bytes (36 chars)     (36 B for UUID)
    session_id          : [u8; 16]                   (16 B; decoded from 32 lowercase hex chars)
    dh_public_key       : [u8; 32]                   (32 B)
    message_number      : u32 big-endian             (4 B)
    pq_message_epoch    : u32 big-endian             (4 B; Suite 3 only)
```

Total length for canonical 36-character UUIDs: **125 bytes** for
Suite 1/2, **129 bytes** for Suite 3. The session id is derived as
`HKDF(salt = x3dh_root, IKM = b"construct-session-id",
info = b"Construct-SessionID-v2\x00" || min_user_id || 0x00 || max_user_id,
L = 16)` and stored as hex
(`construct-core/src/crypto/messaging/double_ratchet/mod.rs:204`-`:227`).
The reference constructs encryption AD in
`construct-core/src/crypto/messaging/double_ratchet/messaging.rs:307`-`:332`
and decryption AD in `internals.rs:533`-`:554`.

Order is normative. Each direction of a session computes its own AD —
ENCRYPT uses `(local_user_id_sender, contact_id_receiver)`; DECRYPT
uses `(contact_id_sender, local_user_id_receiver)`, with the field
positions swapped so the AD on each side matches:

```
ENCRYPT side (Alice → Bob):
    AD = 0x03 || alice_user_id || bob_user_id || session_id || ...

DECRYPT side (Bob receiving from Alice):
    AD = 0x03 || alice_user_id || bob_user_id || session_id || ...
```

i.e. the "sender_id" position is always populated with the sender's
user-id regardless of which side is computing AD. A mismatch (e.g.
using `device_id` (32-char hex) instead of `user_id` (36-char UUID))
produces an AD length difference and instant AEAD failure.

### 5.4.1 AD migration (v2 → v3)

The previous version `AD_VERSION_PREV = 2` uses the same fields as
v3, including the 16-byte session id; it differs by the leading
version byte. A receiver MUST attempt decryption first with
`AD_VERSION = 3`; if AEAD verification fails, the receiver MUST retry
once with `AD_VERSION = 2` before treating the message as
undecryptable. For Suite 3, both attempts include
`pq_message_epoch` in AD. This fallback path is purely for in-flight
v2 messages during the migration window and SHOULD be removed in a
future protocol revision (`SEC-006`).

## 5.5 Encryption (RatchetEncrypt)

```
RatchetEncrypt(state, plaintext, peer_id):
    1. padded = pkcs7_pad(plaintext, 255)        -- §5.7
    2. (mk_dr, CKs') = KDF_CK(state.CKs)
    3. state.CKs = CKs'
    4. pq_epoch = state.current_pq_epoch if state.suite_id = 3 else 0
    5. mk = mix_pq_message_key(mk_dr, pq_epoch)
    6. message_number = state.Ns
    7. state.Ns += 1
    8. header = {
           message_number  = message_number,
           dh_public_key   = state.DHs.pub,
           prev_chain_length = state.PN,
           suite_id        = state.suite_id,
           kem_len         = 0,                -- non-handshake messages
           otpk_id         = 0,
           kyber_otpk_id   = 0,
       }
    9. ad = build_ad(AD_VERSION_3, state.local_user_id,
                     peer_id, state.session_id,
                     state.DHs.pub, message_number,
                     pq_epoch if state.suite_id = 3)
   10. (nonce, ct, tag) = AEAD-Encrypt(key = mk,
                                       plaintext = padded,
                                       associated_data = ad)
   11. zeroise(mk_dr, mk)
   12. return wire_payload::pack(header, kem_ct = None,
                                 sealed_box = nonce || ct || tag,
                                 pq_message_epoch = pq_epoch,
                                 pq_ratchet_field = pending Suite 3 field, if any)
```

The reference uses `chacha20poly1305 0.10` for AEAD. The `nonce` is a
fresh 12-byte random per message; it is part of the AEAD output and
MUST be transmitted alongside the ciphertext.

For Suite 3, `mix_pq_message_key` returns the Double Ratchet message
key unchanged when `pq_epoch = 0`. For any non-zero epoch it derives
`HKDF(salt = pq_epoch_secret, IKM = mk_dr,
info = b"construct-pqr-msg-v1", L = 32)` and rejects the message if
that epoch secret is unavailable (`construct-core/src/crypto/messaging/double_ratchet/internals.rs:415`-`:440`).

## 5.6 DH ratchet step

A DH ratchet step occurs when an incoming message carries a `dh_public_key`
the receiver has not seen before (i.e. the peer rotated their sending
keypair). The step is:

```
DHRatchetStep(state, peer_dh_pub):
    1. state.PN = state.Ns
    2. state.Ns = 0
    3. state.Nr = 0
    4. state.DHr = peer_dh_pub
    5. dh_out = DH(state.DHs.priv, state.DHr)
    6. (state.RK, state.CKr) = KDF_RK(state.RK, dh_out)
    7. state.DHs = X25519::generate()
    8. dh_out = DH(state.DHs.priv, state.DHr)
    9. (state.RK, state.CKs) = KDF_RK(state.RK, dh_out)
   10. zeroise(dh_out)
```

This performs two `KDF_RK` invocations: one to derive the receiving
chain key (matching the peer's just-completed sending chain) and one
to derive the new sending chain key (after rotating the local DH
keypair). The order is normative; reversing it produces incompatible
chain alignment.

## 5.7 PKCS#7 padding (length-hiding)

Plaintext MUST be padded to a multiple of 255 bytes using PKCS#7
before AEAD-encryption. The padding length byte is itself part of the
plaintext (verified during unpad). This hides the exact application
plaintext length from a network observer, leaving only the bucket
size (multiple of 255).

The reference implements unpad in
`construct-core/src/traffic_protection/padding.rs` using XOR-based
constant-time validation: `diff |= byte ^ expected` aggregated across
the padding region, then checked against zero. A non-constant-time
unpad would leak padding length through timing.

## 5.8 Decryption (RatchetDecrypt)

```
RatchetDecrypt(state, wire_bytes, peer_id):
    1. (header, kem_ct, framing) = wire_payload::unpack(wire_bytes)

    -- §5.8.1 DoS guards (MUST be enforced)
    2. If header.message_number > state.Nr + MAX_MESSAGE_JUMP:
           reject as DoS attempt
    3. skipped = header.message_number - state.Nr
       If skipped > MAX_SKIPPED_MESSAGES:
           reject as DoS attempt

    -- §5.8.2 DH ratchet check
    4. If header.dh_public_key != state.DHr:
           SkipChainKeysUntil(state, header.prev_chain_length)
           DHRatchetStep(state, header.dh_public_key)

    -- §5.8.3 Message key lookup
    5. SkipChainKeysUntil(state, header.message_number)
    6. (mk_dr, CKr') = KDF_CK(state.CKr)
    7. state.CKr = CKr'
    8. state.Nr += 1

    -- §5.8.4 AEAD decrypt with fallback
    9. mk = mix_pq_message_key(mk_dr, header.pq_message_epoch)
   10. ad = build_ad(AD_VERSION_3, peer_id, state.local_user_id,
                     state.session_id, header.dh_public_key,
                     header.message_number,
                     header.pq_message_epoch if state.suite_id = 3)
   11. try:
           padded = AEAD-Decrypt(key = mk, ciphertext = framing,
                                 associated_data = ad)
       except AeadVerifyFailed:
           ad_v2 = build_ad(AD_VERSION_PREV, ...)    -- §5.4.1
           padded = AEAD-Decrypt(..., associated_data = ad_v2)
   12. commit Suite 3 PQ field only after authenticated decrypt succeeds
   13. zeroise(mk_dr, mk)
   14. plaintext = pkcs7_unpad(padded)
   15. return plaintext
```

For Suite 3, a carried EK/CT field is processed only after the carrier
message has authenticated and decrypted successfully. A well-formed but
cryptographically unusable EK/CT field is ignored for PQ state and MUST
NOT roll back already delivered classical plaintext; an invalid wire
encoding is rejected by `wire_payload::unpack`, and an unknown non-zero
`pq_message_epoch` is a decrypt error because it would otherwise skip
the PQ mix.

### 5.8.1 Mandatory DoS guards

| Constant | Default | Source |
|---|---|---|
| `MAX_SKIPPED_MESSAGES` | 1000 | `construct-core/src/config.rs:128` |
| `MAX_MESSAGE_JUMP` | 2000 | `construct-core/src/config.rs:129` |
| `MAX_SKIPPED_MESSAGE_AGE_SECONDS` | 604800 (7 days) | `:130` |

A message that violates any of these MUST be rejected without
performing the AEAD operation. Otherwise an attacker can force the
receiver to derive an arbitrary number of skipped message keys (CPU /
memory DoS) by spoofing a header with a giant `message_number`.

### 5.8.2 Skipped message key cleanup

Skipped message keys (`MKSKIPPED`) MUST be expired:

- By count: oldest first when `len(MKSKIPPED) > MAX_SKIPPED_MESSAGES`.
- By age: any key older than `MAX_SKIPPED_MESSAGE_AGE_SECONDS`.
- By DH ratchet: keys belonging to a chain older than `state.DHr − 2`
  ratchet steps SHOULD be evicted.

## 5.9 Previous states

A session renews by sending: any message carrying the handshake header opens a new state (§4.4.1),
and a device may open one at any time. So that nothing in flight on the old state is lost, the
replaced state is **kept**, not dropped
(`construct-core/src/orchestration/session_lifecycle.rs`).

| Constant | Value | Source |
|---|---|---|
| `MAX_PREVIOUS_STATES` | 3 per peer device, oldest dropped first | `session_lifecycle.rs:31` |
| `PREVIOUS_STATE_TTL_SECONDS` | 604800 (7 days) from the moment it was replaced | `session_lifecycle.rs:39` |

Receiving:

```
Decrypt(record, msg):
    1. try the current state
    2. on failure, try each previous state, newest first
         -- a "message key already used" error from any state is a duplicate: stop, report it
    3. a previous state that decrypts is PROMOTED: it becomes current, and the current one
       becomes the newest previous state — unless it is held back (below)
    4. nothing decrypts:
         carries the handshake header → open a new state from it (§4.4)
         carries none                 → DECRYPTION_ERROR to the writer (§5.10)
```

Every replacement — a receiving open, our own reopen, a promotion — makes the replaced state the
newest previous one. A state leaves the record only by the count or age bound. The bounds are a
compromise: a kept state is chain keys kept, and until it is dropped a compromise of the device
also exposes what is still in flight on it. Signal keeps forty states with no age bound.

A state is **held back** when it was retired because the peer said it cannot read it (§5.10). A
held-back state still decrypts what arrives on it but is never promoted: our next message on it
would fail the same way, so the next send opens a new state instead.

Two devices that open at the same time (§4.5) each end up with both states; the first message
either side reads promotes one, and the other ages out.

## 5.10 DECRYPTION_ERROR

When nothing held decrypts a message and it carries no handshake header, the receiver tells the
writer. There is no END_SESSION, heal or session-reset message: the error names the **state** the
unread message was written on, so the writer can act on exactly that state and a stale error
does nothing.

> **Changed 2026-09-28.** Until then the receiver sent END_SESSION (content type 21), which named
> no state, and both sides rationed it with time windows, cooldowns and retry budgets because a
> redelivered or reordered one could not be told from a live one. Type 21 is retired; a receiver
> acknowledges and ignores it.

### 5.10.1 Payload

Content type 28 (`CONTENT_TYPE_DECRYPTION_ERROR`). Plaintext, fixed length 131 bytes
(`construct-core/src/orchestration/decryption_error.rs`):

```
version      : u8 = 1
hint         : u8           -- 0 none, 1 PrekeyUnavailable; unknown values read as none
ratchet_key  : [u8; 32]     -- the DH ratchet key in the unread message's header
id_len       : u8           -- ≤ 96
message_id   : [u8; id_len] -- the unread message, as the receiver saw it
zero padding to 131 bytes
```

The plaintext is sealed to the writer's X25519 identity key — the key its sender certificate
named — with the sealed-box construction of §8, under the domain salt
`b"ConstructDECRYPTERR-v1"`, distinct from the sender-certificate box so that neither box can be
passed off as the other. The sealed box is 191 bytes whatever the id length. It cannot be
ratchet-encrypted: the ratchet is what failed. It travels as a sealed envelope whose inner
content type is 28, the one type an outer `SealedInner` may name (§8).

An unsealed message carries no certificate, so no error can be addressed for it; none is sent.

### 5.10.2 Writer

On receiving an error, the writer opens it with its identity secret and compares `ratchet_key`
with its own sending keys for that peer device:

| `ratchet_key` is the sending key of… | Writer does |
|---|---|
| the **current** state | retire it (it becomes a held-back previous state, §5.9); the next message opens a new state. With hint `PrekeyUnavailable`, that open uses no one-time prekey. Then resend `message_id` once. |
| a **previous** state | resend `message_id` once; the state was already replaced |
| **none** held | nothing — the error is stale (redelivered, reordered, or about a state long gone) |

A message is resent at most once per error it is named in. The resend is an ordinary message on
the new state, so it carries the handshake header and the receiver opens from it.

### 5.10.3 Receiver

The receiver sends one error per unread message and marks the message processed only once the
error was built, so a redelivery is a duplicate and produces no second error.

An error is sealed only to a writer the server vouches for: the unread message's sender
certificate MUST pass `identity_for_opening` against the server keys held, and its key MUST
derive to the device the message was filed under (`Orchestrator::vouched_writer`,
construct-core 0.20.1). Otherwise no error is sent and the message is not recorded, so the same
message arriving with an honest certificate is still answered. Anyone who knows the recipient's
public identity key can seal an envelope to it; without this check an unsigned certificate
would make the recipient answer a stranger's claim, to a device the stranger named. Until
construct-core 0.20.1 the check was applied only on the failed-open path (`DE-1`).

When a receiving open fails because the named OPK or Kyber prekey is gone (§4.4.3), the
error carries `PrekeyUnavailable`.

What the relay learns: both shipping clients send the error on the authenticated `SendMessage`
path with the payload inside `SealedInner` — the same path END_SESSION used — so the relay learns
that this account sent that account a control envelope, as it did for END_SESSION. It no longer
sees a 1024-byte pad whose size identified the kind; the error box has a fixed 191-byte size.
Moving session control to the unauthenticated `SendSealedMessage` path is part of the open item
on sealed control traffic (Chapter 7).

## 5.11 Security properties (informal)

The Double Ratchet, applied as above, provides:

- **Forward secrecy**: compromise of any state component at time `t`
  does not enable decryption of messages from time `t − 1` or earlier,
  because the chain keys and message keys used then have been zeroised
  and the root key has been re-derived through irreversible KDF and
  DH operations.
- **Post-compromise security**: compromise of all secret state at time
  `t`, followed by *no further active attack*, leaves the attacker
  unable to decrypt messages from time `t + Δ` once a single DH ratchet
  step has completed (typically one round-trip).
- **Replay resistance**: a replayed ciphertext fails the AEAD check
  on the second receive (because `mk` has been zeroised) and also
  fails application-layer ACK dedup.

A formal proof against a specified adversary is **not** part of this
specification. The reference implementation is intended to be amenable
to formal verification (Kani / Prusti); that work is planned but not
done.

## 5.12 References

- Specification: this chapter.
- Reference implementation:
  - `construct-core/src/crypto/messaging/double_ratchet/`
  - `construct-core/src/wire_payload.rs`
  - `construct-core/src/orchestration/session_lifecycle.rs` (previous states)
  - `construct-core/src/orchestration/decryption_error.rs`
  - `construct-core/src/traffic_protection/padding.rs`
- Original design: Perrin & Marlinspike, *The Double Ratchet Algorithm*,
  <https://signal.org/docs/specifications/doubleratchet/>.
