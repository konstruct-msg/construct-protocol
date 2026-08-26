# Transport Layer

This chapter specifies how Konstruct messages are carried from a
client to the server and (currently) onward to the recipient. It
defines the FFI binary envelope (CFE), the on-wire framing, the gRPC
service surface, and the VEIL anti-censorship transport tier.

Keywords MUST, MUST NOT, SHOULD, MAY are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 6.1 Layering overview

```
                Plaintext (application)
                       │
                       ▼
          ┌─ Konstruct cryptographic core (Rust)
          │     X3DH/PQXDH + Double Ratchet (Ch. 4-5)
          │     padding (PKCS#7 mod 255)
          │     WirePayload pack (§6.2)
          ▼
   AEAD ciphertext frames
          │
          ▼
   CFE binary envelope (§6.3) over UniFFI / JNI / direct C FFI
          │
          ▼
   gRPC bidirectional stream (§6.4) — HTTP/2 over TLS 1.3
          │
          ▼  (optional, when direct TLS is blocked)
   VEIL tier (§6.5) — veil-front  (obfs4 / WebTunnel retired)
          │
          ▼
   TCP / QUIC over the public internet
```

Layers below Konstruct (TLS 1.3, HTTP/2, TCP, QUIC) are standard and
out of scope here.

A QUIC/HTTP-3 direct path is also in production as an alternative to
the HTTP/2 path, selected by the client-side transport router with an
HTTP/2 fallback. The current client calls it **engine-QUIC** and gates
it through `FeatureFlags.engineQuicExperimental`, which defaults on;
release builds use plain QUIC and force Salamander-style datagram
obfuscation off (`construct-ios` `Utilities/Constants.swift:414`-`:456`,
`Networking/gRPC/GRPCChannelManager.swift:474`-`:535`). The H3 path is
implemented in `construct-engine/src/transport/mod.rs:50`-`:113` and
`src/transport/connection.rs:60`-`:107`; it is not yet specified
normatively in this chapter (planned for a future revision).

## 6.2 Wire format (WirePayload)

Every encrypted Konstruct message crosses the wire as a
**WirePayload** — a packed binary frame with the layout defined in
[§5.3](./05-message-encryption.md#53-wire-format-wirepayload-header).
Restated for completeness:

| Field | Type | Size | Description |
|---|---|---|---|
| message_number | u32 LE | 4 B | Double Ratchet sending counter `Ns` |
| dh_public_key | bytes | 32 B | Current sending DH public (`DHs.pub`) |
| otpk_id | u32 LE | 4 B | OPK id consumed by the X3DH initiator; `0` if N/A |
| kyber_otpk_id | u32 LE | 4 B | ML-KEM-768 OPK id consumed; `0` if N/A |
| kem_len | u16 LE | 2 B | Length of the KEM ciphertext that follows; `0` when absent |
| prev_chain_length | u32 LE | 4 B | Previous-chain length `PN` |
| suite_id | u16 LE | 2 B | `0x0001` Suite 1, `0x0002` Suite 2, or `0x0003` Suite 3 |
| kem_ct | bytes | `kem_len` B | ML-KEM-768 ciphertext for PQXDH first messages (1088 B when present) |
| suite3_pq_section | bytes | variable | Present only when `suite_id = 0x0003`; see §5.3 |
| aead_frame | bytes | variable | `nonce(12) || ct(N) || tag(16)` |

Total fixed header size: **52 bytes**
(`construct-core/src/wire_payload.rs:22`-`:36`). All numeric fields
in the fixed WirePayload header and Suite 3 PQ section are
little-endian (`construct-core/src/wire_payload.rs:106`-`:129`,
`:220`-`:264`).

A WirePayload is the unit of work the Double Ratchet produces and
consumes. It MUST NOT carry plaintext routing fields outside of
`suite_id` and the lengths needed to parse the envelope; metadata such
as sender, recipient, timestamps, and conversation ids belongs in the
transport-level wrapper, not in the WirePayload itself.

## 6.3 CFE — Construct Frame Encoding

When a WirePayload (or any other typed protocol message) crosses the
FFI boundary between the Rust core and a platform binding (Swift,
Kotlin), it MUST be wrapped in a **CFE envelope**. CFE eliminates the
JSON parsing attack surface previously present at the FFI line.

### 6.3.1 Envelope layout

```
CFE envelope (16-byte header + payload) ::=
    magic        : [u8; 2]  = [0x43, 0x46]    -- "CF"
    version      : u8       = 0x01
    msg_type     : u8                          -- CfeMessageType enum tag
    flags        : u8                          -- reserved, MUST be 0
    reserved     : [u8; 3]  = [0x00; 3]
    payload_len  : u32 LE                      -- length of the MessagePack body
    crc32        : u32 LE                      -- CRC-32 over payload only
    payload      : [u8; payload_len]           -- MessagePack body
```

Header constants are defined in `construct-core/src/cfe/envelope.rs`:
`CFE_MAGIC = [0x43, 0x46]`, `CFE_VERSION = 0x01`,
`CFE_HEADER_LEN = 16`, `SUPPORTED_FLAGS_MASK = 0x00`, and
`MAX_PAYLOAD_LEN = 256 * 1024` (`:8`-`:25`). The encoder writes the
header in the order above and serialises the payload with
`rmp_serde::to_vec_named` (`:48`-`:65`).

### 6.3.2 Required validations

A receiver of a CFE envelope MUST:

1. Verify the magic bytes match exactly. Mismatch → reject.
2. Verify the version is supported (currently only `0x01`).
3. Verify the `msg_type` byte maps to a known `CfeMessageType`.
4. Verify `flags == 0`; flag constants exist in code, but v1 supports
   no flags (`SUPPORTED_FLAGS_MASK = 0x00`).
5. Verify the three reserved bytes are zero.
6. Decode `payload_len` as little-endian and reject values above the
   implementation cap (reference: 256 KiB).
7. Verify the buffer contains exactly enough bytes for the declared
   payload.
8. Verify `crc32` matches recomputed CRC-32 over the payload bytes
   only (`construct-core/src/cfe/envelope.rs:135`-`:147`).
9. Decode the payload as MessagePack only if all checks above pass.

These checks are what make CFE strictly safer than the JSON
predecessor: a malformed envelope is rejected before any
deserialisation is attempted, and the bounded `payload_len` prevents
unbounded allocation.

### 6.3.3 Message types

The `msg_type` byte selects the MessagePack schema for the payload.
The reference defines 14 incoming and 28 outgoing message types
covering events such as `IncomingMessage`, `SessionStateChanged`,
`Action::SendEncryptedMessage`, etc. The enum is normative; new
variants MUST be added with a new value, never by repurposing an
existing one.

## 6.4 gRPC service surface

Konstruct uses gRPC over HTTP/2 over TLS 1.3 as the primary transport.
The protobuf service definitions live in the
`konstruct-msg/construct-protos` package (separate repository); the
ones relevant to a client implementer are:

| Service | RPC | Direction |
|---|---|---|
| AuthService | `GetPowChallenge`, `RegisterDevice`, `AuthenticateDevice`, `RefreshToken` | unary, **no JWT required** |
| UserService | `CheckUsernameAvailability` | unary, no JWT required |
| UserService | (other) | unary, JWT required |
| DeviceService | `*` | unary, no JWT required |
| MessagingService | `MessageStream` | bidirectional stream, JWT required |
| MessagingService | `SendSealedMessage` | unary sealed send, deliberately no JWT required |
| SignalingService | `Signal` | bidirectional stream, JWT required |
| KeyService | prekey upload / fetch | unary, JWT required |

JWT-required RPCs MUST carry an `authorization: Bearer <token>` header
and an `x-user-id` header. The reference adds them in an
`AuthInterceptor`; an interoperable client implementation MUST do the
same.

`MessageStream` carries WirePayload frames (§6.2) as bytes in the
request/response stream. The server treats the byte field as opaque
and routes by metadata fields outside the WirePayload.

`SendSealedMessage` carries a `SealedSenderEnvelope` and deliberately
does not extract an authenticated user id; anti-abuse is enforced by
per-IP rate limiting, Privacy Pass token redemption, and delivery-tag
replay checks (`construct-server/messaging-service/src/grpc.rs:701`-`:750`,
`messaging-service/src/envelope.rs:139`-`:270`). This is the transport
entry point that removes the sender identity from the server-visible
request for sealed sender ([Chapter 8](./08-metadata-privacy.md)).

For key fetches, new clients MUST set
`consume_one_time_prekey` explicitly. Legacy absence is interpreted as
"consume" for wire compatibility, while non-session lookups should set
it to false to avoid draining OPK pools
(`construct-server/shared/proto/services/key_service.proto:80`-`:103`).

## 6.5 VEIL — anti-censorship transport tier

When the direct gRPC-over-TLS path is blocked, throttled, or
fingerprinted by an adversarial network, the client MAY route through
VEIL instead. VEIL is a *pluggable transport tier* with several
backend strategies:

| Backend | Status | Wire shape on the network |
|---|---|---|
| **veil-front** | **Production** | TLS 1.3 to an honest cover application; the relay routes valid AUTH frames to the tunnel and everything else to the cover app via a constant-shape gate. The primary (and only production) obfuscation backend on mobile. |
| **obfs4** / **WebTunnel** | **Retired** | Superseded by veil-front and cut by active DPI in the target region. Adapters remain in-tree but are not registered on mobile builds; the standalone relay repository is archived. |

The VEIL coordinator (in `construct-veil/src/veil/coordinator.rs`)
runs a *happy-eyeballs probe race* over the configured backends and
keeps per-backend persistent quality scores in a small SQLite store.
The winner is dispatched as the data plane; losers are cancelled.

### 6.5.1 Pluggable transport selection

A client MUST honour:

- An explicit user preference (`VeilMode = .off | .auto | .on`).
- A network-fingerprint hash that namespaces per-backend score
  caches (so that scores from network A do not pollute scores on
  network B).
- A per-backend `MethodId` (`obfs4 = 0`, `webTunnel = 1`,
  `masque = 2`, `veilFront = 3`). Method ids are normative on the
  Rust C FFI of `construct-veil`.

### 6.5.2 Constant-shape gate (veil-front)

For the veil-front backend, the relay MUST satisfy:

- Failed authentication MUST be routed to the cover application using
  the cover's own response timing and shape. There MUST NOT be a
  separate "tunnel rejected" code path with distinguishable timing.
- Frame-level length bucketing MUST be applied to the tunnel direction
  so that record-length distributions are bounded.
- `veil_front_ticket_b64` MUST be supplied by the client; an empty
  ticket field MUST cause the veil-front method to be excluded from
  the probe race rather than silently downgraded.

The constant-shape requirement is the *load-bearing* property of
veil-front; if a future deployment violates it, the wire becomes
distinguishable from the cover application and the construction's
purpose is defeated.

### 6.5.3 Connection ladder and graceful degradation

In `VeilMode = .auto` (the default) the client is **direct-first**: it
attempts the plain gRPC/QUIC path first and escalates to VEIL only on a
real connection failure. It MUST NOT pre-activate a relay purely because
of coarse geography — a censored network that is momentarily reachable
directly should use the direct path, and a relay is engaged only when the
direct attempt actually fails.

The result is a ladder that degrades with the hostility of the network:

| Network tier | Path used |
|---|---|
| Free / uncensored | Direct gRPC/QUIC; HTTP/2 fallback. |
| DPI blacklist (throttle / fingerprint direct TLS) | Escalate to veil-front (honest-front TLS to a cover application). |
| National **allowlist** (only permitted destinations reachable) | Not crossable by obfuscation alone — this is an explicit non-goal of the transport tier. |
| Blackout (no connectivity) | Out of scope for the server-routed transport; an offline-mesh foundation is a separate design track. |

This is deliberately honest: obfuscation buys reachability against
*classification*, not against an adversary who drops everything except an
allowlist. See [Architecture Overview](./architecture-overview.md) for the
tiered model. VEIL also is **not** a metadata-hiding layer on its own — it
helps a connection blend in, but a network observer who already sees the
connection can still infer timing and volume; sealed sender
([Chapter 8](./08-metadata-privacy.md)) and padding ([§5.7](./05-message-encryption.md))
are the metadata mechanisms, not VEIL.

## 6.6 Transport guarantees and non-guarantees

### What the transport layer guarantees

| Property | Mechanism |
|---|---|
| Tamper detection on the FFI line | CFE CRC-32 + magic bytes |
| Bounded FFI input size | CFE `payload_len` cap |
| Server cannot read message content | Cryptographic core (Ch. 5), not the transport |
| Length privacy from a network observer | PKCS#7 padding (§5.7) + VEIL length bucketing |
| Censorship resistance | VEIL backends (§6.5) |
| Memory safety at the FFI boundary | CFE owned `Vec<u8>` (no raw pointers) + bounded length |

### What the transport layer does **not** guarantee

| Exposure | Mitigation status |
|---|---|
| IP visibility to the relay operator | Inherent — a relay terminates your connection and sees its source address. Server-side, only a salted hash is retained ([Ch. 8 §8.6](./08-metadata-privacy.md#86-connection-layer-metadata-ip-minimisation)); to keep the address off the path, route through VEIL, a VPN, or Tor. |
| Server sees per-connection metadata (timestamps, session durations) | Inherent to a client–server design; raw client IPs are **not** persisted (salted hash only). |
| Active DPI in a hostile region | **veil-front** (honest-front TLS) is the production answer; the retired obfs4/WebTunnel backends were cut by active DPI. Even veil-front does not cross a national **allowlist** (where only explicitly permitted destinations are reachable) — see [Architecture Overview](./architecture-overview.md). |
| Sender identity to the server | Removed on all user traffic — sealed sender is **on by default** ([Ch. 8](./08-metadata-privacy.md)); the identified path is fail-closed, not a silent downgrade. |

## 6.7 Configuration constants summary

| Constant | Value | Source |
|---|---|---|
| CFE magic | `[0x43, 0x46]` | `cfe/envelope.rs:8` |
| CFE version | `0x01` | `cfe/envelope.rs:9` |
| CFE header length | 16 bytes | `cfe/envelope.rs:10` |
| CFE supported flags | `0x00` mask; all flags rejected | `cfe/envelope.rs:17`, `:110`-`:112` |
| CFE max payload | 256 KiB | `cfe/envelope.rs:19`-`:25`, `:119`-`:124` |
| WirePayload header length | 52 bytes (fixed) | `wire_payload.rs:22`-`:36` |
| Padding modulus | 255 | `traffic_protection/padding.rs` |
| VEIL probe timeout | implementation-defined (reference: a few seconds per backend) | `construct-veil/src/veil/coordinator.rs` |

## 6.8 References

- WirePayload: `construct-core/src/wire_payload.rs`
- CFE envelope: `construct-core/src/cfe/envelope.rs`, `cfe/types.rs`
- gRPC service definitions: `konstruct-msg/construct-protos`
- VEIL coordinator and FFI: `konstruct-msg/construct-veil`
