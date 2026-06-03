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

An identity is bound to exactly one **device** at a time. (Multi-device
support is a planned feature; until it ships, "identity" and "device"
are 1-to-1.) A device is uniquely identified by a 32-character hex
string derived deterministically from its identity public key (see
§3.4).

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
| Signed prekey (SPK) | X25519 | ≤ 10 days | 32 B / 32 B | Medium-term, rotated periodically |
| One-time prekeys (OPK) | X25519 | Single use | 32 B / 32 B | Consumed on first message |
| Kyber signed prekey (Kyber-SPK) | ML-KEM-768 | ≤ 10 days | 1184 B / 2400 B | Post-quantum medium-term (Suite 2) |
| Kyber one-time prekeys (Kyber-OPK) | ML-KEM-768 | Single use | 1184 B / 2400 B | Post-quantum, consumed on use |

The X25519 and Ed25519 sizes are fixed by the underlying curves
(Curve25519, Edwards25519). The ML-KEM-768 sizes are fixed by NIST
FIPS 203 (public key 1184 bytes, ciphertext 1088 bytes, secret key
2400 bytes in expanded form as exposed by the `ml-kem` crate).

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

Both peers in a Double Ratchet AEAD must agree on the AD construction
(§5.4). The AD includes a stable per-identity tag that survives
session resets. The reference implementation derives this tag as:

```
device_id = LOWER_HEX(SHA-256(IK_pub))[0..32]
```

i.e. the lower-case hexadecimal SHA-256 of the 32-byte X25519 identity
public key, truncated to 32 characters. An interoperable implementation
MUST produce the same value from the same `IK_pub`.

## 3.5 Medium-term keys: signed prekeys

### X25519 signed prekey (SPK)

The SPK is an X25519 keypair generated at registration and rotated at
most every 10 days. The reference enforces this with
`SPK_MAX_AGE_SECS = 10 * 24 * 3600`
(`construct-core/src/crypto/client_api.rs:65`). A bundle whose SPK is
older than this MUST be rejected by a responder.

The SPK carries a `spk_rotation_epoch: u32`. Each rotation increments
this counter monotonically. The epoch is bound into the bundle
signature (§3.6) so that an attacker cannot replay an older valid SPK
into a new bundle.

When the application rotates the SPK, it MUST upload the new
(public-key, signature, epoch) tuple to the server and SHOULD continue
to accept incoming X3DH initiations using the *previous* SPK for a
grace window (default: until the bundle TTL expires) to avoid
dropping in-flight handshakes.

### Kyber signed prekey (Kyber-SPK)

An ML-KEM-768 encapsulation key serving the analogous role for the
post-quantum extension. Lifetime, rotation cadence, and epoch are
identical to the X25519 SPK. A bundle whose Kyber-SPK is older than
`SPK_MAX_AGE_SECS` MUST be rejected when Suite 2 is in use.

The Kyber-SPK signature is computed over the entire
`(Kyber-SPK || rotation_epoch_be_bytes)` payload with the identity's
Ed25519 signing key; PQ signatures (ML-DSA-65) are planned but not
in the reference today, so the *signature* on the Kyber bundle is
classical Ed25519 even in Suite 2.

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

### Kyber one-time prekeys (Kyber-OPK)

A pool of single-use ML-KEM-768 encapsulation keys serving the same
purpose for the post-quantum extension. The server SHOULD maintain
the Kyber-OPK pool with the same threshold logic as classical OPKs.

A Suite 2 initiation in which no Kyber-OPK is available MUST NOT
silently downgrade to Suite 1. The reference enforces this via
`SEC-002` (mandatory Kyber epoch validation in Suite 2 handshakes).

## 3.7 Per-session keys (Double Ratchet)

Once X3DH completes (Chapter 4), the session state machine maintains:

| Symbol | Role |
|---|---|
| RK | 32-byte root key, mixed into each DH ratchet step |
| CK_s, CK_r | Sending and receiving chain keys (32 B each) |
| MK_n | Per-message keys (32 B), derived from a chain key, used once, then deleted |
| DHs, DHr | Local sending DH keypair and remote DH public |
| Ns, Nr, PN | Sending counter, receiving counter, previous-chain length |

The Double Ratchet operations on these are specified in
[Chapter 5](./05-message-encryption.md). Per-message keys MUST be
zeroed immediately after AEAD decrypt; the reference uses
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

The bundle a responder publishes to the directory MUST contain:

```
RegistrationBundle ::=
    suite_id              : u16
    identity_pub          : [u8; 32]              -- X25519
    signing_pub           : [u8; 32]              -- Ed25519
    signed_prekey_pub     : [u8; 32]              -- X25519
    signed_prekey_sig     : [u8; 64]              -- Ed25519(SK_priv,
                                                      SPK_pub || epoch_be)
    spk_rotation_epoch    : u32
    one_time_prekeys      : Vec<(u32, [u8; 32])>  -- (id, pub)

    -- Suite 2 (PQXDH) extension, omitted in Suite 1 bundles:
    kyber_pre_key_pub          : Option<[u8; 1184]>
    kyber_pre_key_sig          : Option<[u8; 64]>     -- Ed25519
    kyber_spk_rotation_epoch   : Option<u32>
    kyber_one_time_prekeys     : Option<Vec<(u32, [u8; 1184])>>
```

All multi-byte integers are big-endian. The exact serialised form
crossing the FFI boundary is a packed binary struct (no JSON), see
[Chapter 6 §6.2](./06-transport.md#62-wire-format-wirepayload).

A responder MUST verify the SPK signature against `signing_pub` before
performing any DH against the SPK. A bundle that fails signature
verification MUST be rejected; the handshake MUST NOT proceed.

## 3.10 Key rotation summary

| Key | Rotation trigger | Cadence |
|---|---|---|
| IK, SK | None (rotating destroys the identity) | Never |
| SPK, Kyber-SPK | Periodic + on app launch if stale | ≤ 10 days |
| OPK, Kyber-OPK | Consumed on each handshake | Re-uploaded when pool < threshold |
| RK, CK_s, CK_r | Every Double Ratchet step | Per message / per round-trip |
| MK | Every message | Used once, then deleted |
| Session as a whole | END_SESSION, healing fallback | On demand |

These rotation invariants are what give the protocol its forward
secrecy and post-compromise security properties (Chapters 1 and 5).
