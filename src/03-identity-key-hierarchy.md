# Identity & Key Hierarchy

This chapter specifies, for an interoperable Konstruct implementation,
**what keys exist, how long they live, where they are stored, and what
each one is used for**. The structure mirrors the Signal Protocol's
X3DH / Double Ratchet decomposition into long-term, medium-term, and
ephemeral key material, extended with a parallel set of post-quantum
keys.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this
chapter are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 3.1 Identity model

A Konstruct **identity** is a 36-character UUID issued by the
registration service. It MUST be treated as opaque by the protocol —
all cryptographic operations are bound to keys, not to the identifier.

An identity may have one or more active **devices**. All E2EE key
material is device-scoped: the server stores public keys only, never
private keys, and the key-service protobuf explicitly treats all keys
as device-specific (`construct-server/shared/proto/services/key_service.proto:17`-`:18`).
A device is uniquely identified by a 32-character hex string derived
deterministically from its identity public key (see §3.4).

Implementations MUST NOT mix the two identifier spaces — using a
device-id where a user-id is expected (or vice versa) breaks the
Associated Data (AD) check in the Double Ratchet AEAD and causes
permanent decryption failure. The reference implementation enforces
this through distinct Rust types (`ServerUserId`, `CryptoDeviceId`).

## 3.2 Key inventory

A registered identity holds, at minimum, the following key material.
All keys MUST be generated with cryptographically secure randomness;
the reference uses `rand::rngs::OsRng`.

| Key | Algorithm | Lifetime | Size (pub / priv) | Role |
|---|---|---|---|---|
| Identity key (IK) | X25519 | Permanent | 32 B / 32 B | Long-term key agreement seed |
| Signing key (SK) | Ed25519 | Permanent | 32 B / 32 B | Signs prekey bundles |
| Signed prekey (SPK) | X25519 | Rotate weekly; clean peer acceptance ≤ 30 days | 32 B / 32 B | Medium-term, rotated periodically |
| One-time prekeys (OPK) | X25519 | Single use | 32 B / 32 B | Consumed on first message |
| ML-KEM-1024 signed prekey (KEM-SPK; proto name `kyber_pre_key`) | ML-KEM-1024 | Rotate periodically; refused by peers when its signed `created_at` is > 30 days old | 1568 B / 64 B seed | Post-quantum part of every handshake |
| ML-KEM-1024 one-time prekeys (KEM-OPK; proto name `kyber_one_time_pre_key`) | ML-KEM-1024 | Single use | 1568 B / 64 B seed | Post-quantum, consumed on use |
| Hybrid signature identity key | Ed25519 + ML-DSA-65 | Permanent; required to be opened to | 1984 B / 2016 B | PQ attestation key bound to the device signing key |

The X25519 and Ed25519 sizes are fixed by the underlying curves
(Curve25519, Edwards25519). The ML-KEM-1024 sizes are fixed by NIST
FIPS 203 (public key 1568 bytes, ciphertext 1568 bytes); the core keeps
the secret as the 64-byte seed it was generated from. ML-KEM-768 appears
only in the Suite 4 ratchet, never as a published prekey. The
hybrid signature sizes come from the implemented Ed25519 + ML-DSA-65
format in `construct-core/src/crypto/suites/hybrid.rs:1`-`:51`.

## 3.3 Long-term keys

### Identity key (IK)

The X25519 long-term key. It MUST be generated once at registration
and never rotated for the lifetime of the identity. Rotating it
constitutes destroying the identity.

The private half MUST be stored in the platform's secure key store
under an "after-first-unlock" access class equivalent (iOS:
`kSecAttrAccessibleAfterFirstUnlock`; Android: hardware-backed
Keystore with equivalent flag). The public half is published in the
registration bundle (§3.6) and is what other parties run X25519
against.

### Signing key (SK)

A separate Ed25519 keypair used **only** to sign prekey bundles. It
MUST NOT be reused for any other purpose. Like the IK, it is permanent
and stored in the platform key store. The split between IK (key
agreement) and SK (signatures) follows the Signal convention and lets
each algorithm be replaced independently.

A Konstruct signature, where it appears in this specification, is the
64-byte EdDSA signature over the canonical encoding of the signed
artefact, verified with `ed25519_dalek::VerifyingKey::verify`.

## 3.4 Device identifier

`device_id` is the stable device key identifier used for device
inventory, safety-number UX, Key Transparency leaves, and the
`contact_id` every session is keyed by. It is derived from the device identity public key as:

```
device_id = LOWER_HEX(SHA-256(IK_pub))[0..32]
```

i.e. the lower-case hexadecimal SHA-256 of the 32-byte X25519 identity
public key, truncated to 32 characters (`construct-core/src/device_id.rs:16`-`:45`).
An interoperable implementation MUST produce the same value from the
same `IK_pub`.

`device_id` is **not** the Double Ratchet AEAD sender/receiver
identifier in current AD. AD version 3 uses the sender and receiver
server UUIDs plus the session id (§5.4).

## 3.5 Medium-term keys: signed prekeys

### X25519 signed prekey (SPK)

The SPK is an X25519 keypair generated at registration. The shipping
client rotates its own SPK every 7 days and force-rotates around day 8
(`construct-ios` `Services/Crypto/PreKeyRotationService.swift:29`-`:35`).
The Rust core's clean peer-freshness boundary is
`SPK_MAX_AGE_SECS = 30 * 24 * 3600`
(`construct-core/src/crypto/client_api.rs:61`-`:71`). A bundle older
than this boundary is stale for the clean session-init path; the
reference also exposes an explicit degraded
`init_session_allowing_stale` path that skips only the freshness check
while still verifying signatures (`construct-core/src/crypto/client_api.rs:358`-`:396`).

The SPK carries a `spk_rotation_epoch: u32`. Each rotation increments
this counter monotonically. The current prekey signature does not
include the epoch; clients use the epoch and timestamp as freshness
signals beside the signed key.

When the application rotates the SPK, it MUST upload the new
(public-key, signature, epoch) tuple to the server and SHOULD retain
the previous SPK private half briefly so in-flight first messages that
referenced the old bundle can still decrypt.

The Ed25519 signature over the X25519 SPK is computed over:

```
b"KonstruktX3DH-v1" || [0x00, 0x01] || SPK_pub
```

### ML-KEM-1024 signed prekey (KEM-SPK)

An ML-KEM-1024 encapsulation key, the post-quantum counterpart of the SPK
(Chapter 4 §4.3). Every Kyber prekey — signed and one-time — is signed
over its creation time:

```
b"KonstruktX3DH-v1" || [0x00, 0x11] || created_at (u64 BE, unix seconds) || KEM_pub
```

twice: with the Ed25519 signing key and with the hybrid identity key
(`construct-core/src/crypto/kyber_prekey_auth.rs:44`-`:57`). `created_at`
is under both signatures because the bundle's upload time
(`kyber_spk_uploaded_at`) is the server's own, unsigned claim. An initiator
refuses a KEM-SPK whose signed `created_at` is more than 30 days old, and
unlike the classical SPK there is no stale-tolerant override: for a Kyber
key, skipping the check is the replay attack itself.

The v1 sign-message (suite byte `0x10`, a 768-bit key, no time) is retired;
a v1 signature MUST NOT verify as v2. The protobuf field names still say
`kyber_*`.

The old secrets of a rotated SPK and KEM-SPK are kept for 14 days
(`SPK_RETENTION_AFTER_ROTATION_SECS`, `crypto/keys.rs:18`): the relay
queue holds a message for 7 days, and a handshake to the old key must
still open.

## 3.6 Ephemeral / one-time prekeys

### X25519 one-time prekeys (OPK)

A pool of single-use X25519 keypairs uploaded with the registration
bundle. Each OPK has a `u32` identifier; the X3DH initiator (Alice)
selects one and the server marks it consumed.

If the OPK pool drops below an implementation-defined threshold (the
reference uses 20), the client MUST upload fresh OPKs. Running out of
OPKs falls back to a 3-DH handshake without the OPK component, which
has reduced forward secrecy (the protocol's `BS-3` open issue — see
[Implementation Status](./07-implementation-status.md)).

### ML-KEM-1024 one-time prekeys (KEM-OPK)

A pool of single-use ML-KEM-1024 encapsulation keys, each signed like the
KEM-SPK (with its own `created_at`). The initiator prefers a KEM-OPK;
without one, or if the offered one fails its checks, it encapsulates to
the KEM-SPK and sets `kyber_otpk_id = 0`. Without a KEM-SPK that passes
its checks, no session is created: there is no classical fallback.

## 3.7 Per-session keys (Double Ratchet)

Once X3DH completes (Chapter 4), the session state machine maintains:

| Symbol | Role |
|---|---|
| RK | 32-byte root key, mixed into each DH ratchet step |
| CK_s, CK_r | Sending and receiving chain keys (32 B each) |
| MK_n | Per-message keys (32 B), derived from a chain key, used once, then deleted |
| DHs, DHr | Local sending DH keypair and remote DH public |
| Ns, Nr, PN | Sending counter, receiving counter, previous-chain length |
| `current_pq_epoch`, PQ epoch chains, PQ skipped keys, pending PQ exchange/ciphertext | Suite 4 sparse continuous PQ ratchet state (per-message chains, §2.4), absent or inert in Suite 1/2 |

The Double Ratchet operations on these are specified in
[Chapter 5](./05-message-encryption.md). Suite 4 state is persisted
inside the CFE session-state payload as `CfePqRatchetStateV2` (CFE field
`pqr2`; `construct-core/src/cfe/types.rs`). The earlier `pqr` key
(`CfePqRatchetStateV1`, one stored epoch secret) is retired with
Suite 3 and ignored on an old blob rather than migrated — a suite-3
session is not restored at all (§2.4). Per-message keys MUST
be zeroed immediately after AEAD decrypt; the reference uses
`zeroize::Zeroizing`.

## 3.8 Key storage at rest

The reference implementation stores keys with the following access
classes; an interoperable implementation SHOULD provide an equivalent
guarantee on its platform:

| Key | Access class |
|---|---|
| IK_priv, SK_priv | After-first-unlock, device-only, non-syncable |
| Session JSON (incl. `dh_ratchet_private`, RK, chain keys) | When-unlocked, device-only |
| Refresh / auth tokens | After-first-unlock |
| `device_id` (derived value) | After-first-unlock |

The session blob currently stores `dh_ratchet_private` in cleartext
within the platform-protected blob. Adding an additional
encryption-at-rest layer is open work tracked as `SEC-009` in the
implementation status.

## 3.9 Public key bundle (wire format)

The directory bundle is a protobuf `PreKeyBundle`, not a packed binary
struct. Protobuf owns scalar encoding on the service boundary; the
canonical byte strings that are signed are specified separately in
§3.5 and §2.3.3. The fields a responder publishes are:

```
PreKeyBundle ::=
    registration_id                  : u32
    identity_key                     : bytes      -- X25519 IK public
    signed_pre_key                   : bytes      -- X25519 SPK public
    signed_pre_key_id                : u32
    signed_pre_key_signature         : bytes      -- Ed25519 over SPK sign-message
    one_time_pre_key                 : optional bytes
    one_time_pre_key_id              : optional u32
    crypto_suite                     : CryptoSuite
    generated_at                     : int64
    spk_uploaded_at                  : int64
    spk_rotation_epoch               : u32

    -- PQXDH v2 (mandatory for opening); proto names say `kyber_*`.
    kyber_pre_key                    : optional bytes  -- ML-KEM-1024 KEM-SPK, 1568 B
    kyber_pre_key_id                 : optional u32
    kyber_pre_key_signature          : optional bytes  -- Ed25519 over the 0x11 sign-message
    kyber_one_time_pre_key           : optional bytes  -- ML-KEM-1024 KEM-OPK, 1568 B
    kyber_one_time_pre_key_id        : optional u32
    kyber_spk_uploaded_at            : optional int64
    kyber_spk_rotation_epoch         : optional u32

    -- Server / transparency / PQ signature extensions.
    bundle_signature                 : bytes
    hybrid_identity_key              : optional bytes  -- 1984 B
    hybrid_identity_signature        : optional bytes  -- 64 B Ed25519 cross-signature
    signed_pre_key_hybrid_signature  : optional bytes  -- 3373 B
    kyber_pre_key_hybrid_signature   : optional bytes  -- 3373 B
    supports_pq_ratchet              : bool            -- deprecated since PQXDH v2 (2026-09-25); ignored, field 24 kept only so the number is never reused
    kyber_pre_key_created_at                : optional u64    -- signed, field 25
    kyber_one_time_pre_key_signature        : optional bytes  -- field 26
    kyber_one_time_pre_key_created_at       : optional u64    -- signed, field 27
    kyber_one_time_pre_key_hybrid_signature : optional bytes  -- field 28
```

The hybrid fields are optional in the schema but required by a client
opening a session (Chapter 4 §4.3). `bundle_signature` (the server's
signature over the bundle) is not a basis of trust: the device signatures
are what make the bundle independent of the server, and the server's
signature does not protect against the server.

The current schema is message `PreKeyBundle` in
`construct-server/shared/proto/services/key_service.proto` (fields 25–28
added with PQXDH v2, 2026-09-25).
`supports_pq_ratchet` (field 24) was, before PQXDH v2, a capability flag that let a session
negotiate the PQ ratchet. Since 2026-09-25 the PQ ratchet is mandatory wherever the core's
`post-quantum` feature is built (§2.4) and nothing reads this field: a client MAY still send it
for older servers, but a conforming server and client alike MUST ignore it. It is not removed
from the schema, only deprecated — reusing field 24 for something else would let an old bundle's
stale byte be misread by a new client.

A bundle consumer MUST verify the SPK signature against the published
Ed25519 verifying key before performing any DH against the SPK. A
bundle that fails signature verification MUST be rejected; the
handshake MUST NOT proceed.

## 3.10 Key rotation summary

| Key | Rotation trigger | Cadence |
|---|---|---|
| IK, SK | None (rotating destroys the identity) | Never |
| SPK, KEM-SPK | Periodic + on app launch if stale | Old secrets kept 14 days after rotation; peers refuse a KEM-SPK whose signed age exceeds 30 days |
| OPK, KEM-OPK | Consumed on each handshake | Re-uploaded when pool < threshold |
| RK, CK_s, CK_r | Every Double Ratchet step | Per message / per round-trip |
| MK | Every message | Used once, then deleted |
| Session state as a whole | Any message carrying the handshake header opens a new state; the replaced one is kept as a previous state (Ch. 5 §5.9). A DECRYPTION_ERROR naming the current state retires it (§5.10). | On demand; also a manual, local reset |

These rotation invariants are what give the protocol its forward
secrecy and post-compromise security properties (Chapters 1 and 5).
