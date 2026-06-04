# Appendix A — Error Registry

This appendix is the canonical registry of every error that a
conforming Konstruct client can observe, organised by the layer that
produces it. Each entry cites the exact variant in `construct-core`
(or, where noted, the sibling `construct-veil` crate) and records the
condition that raises it.

Keywords MUST, MUST NOT, SHOULD, MAY are per
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## A.1 Layered error model

Errors in Konstruct travel up a stack of progressively narrower
surfaces. An error condition that originates deep inside the
cryptographic core is converted at each layer boundary into a variant
appropriate for the consumer at that layer:

```
   application (iOS / macOS / Android UI)
                  ▲
                  │   uniffi_bindings::CryptoError      (FFI surface, §A.2)
   ────────────── ┼ ───────────────────────────────────────────────
                  │   cfe::CfeError                     (envelope,  §A.3)
                  │   wire_payload::WirePayloadError    (framing,   §A.4)
                  │   traffic_protection::PaddingError  (padding,   §A.5)
                  │
                  │   error::CryptoError                (internal,  §A.6)
                  │   utils::ConstructError             (top-level, §A.7)
                  │   group::mls_error::MlsError        (groups,    §A.8)
                  ▲
   Rust core
```

The dividing line at "FFI surface" is normatively significant: only
the variants in §A.2 cross the UniFFI / JNI boundary by name. All
deeper error types are mapped into `SessionInitializationFailed`,
`EncryptionFailed`, or `DecryptionFailed` with a human-readable
`message` field. Application code MUST NOT attempt to parse those
message strings — they are diagnostic only.

The transport tier ([Chapter 6 §6.5](./06-transport.md#65-veil--anti-censorship-transport-tier))
has its own error surface in the separate `construct-veil` crate; it
is included as §A.9 for completeness but is informational rather than
normative for the core protocol.

Wire-level errors (server → client) flow as standard
[gRPC status codes](https://grpc.io/docs/guides/status-codes/) and are
covered in §A.10.

### A.1.1 Stability policy

| Surface | Stability |
|---|---|
| §A.2 FFI surface | Stable. Variants MUST NOT be reordered or repurposed. New variants are MINOR additions. |
| §A.3 CFE envelope | Stable. The wire format is fixed; new validation errors are MINOR additions. |
| §A.4 WirePayload | Stable. Header layout is normative. |
| §A.5 Padding | Stable. |
| §A.6–A.8 Internal | Unstable. Variant names and counts MAY change between releases. Catch the FFI surface (§A.2) instead. |
| §A.9 VEIL | Unstable. Tracked in the `construct-veil` crate. |
| §A.10 gRPC | Inherited from gRPC; semantics MUST follow the gRPC spec. |

## A.2 FFI surface — `CryptoError`

The application-facing error type exposed across UniFFI / JNI.
Defined in `construct-core/src/uniffi_bindings.rs:30`.

| Tag | Variant | Raised when | Recovery |
|---|---|---|---|
| `FFI-INIT` | `InitializationFailed` | The core failed to initialise (e.g. RNG unavailable, keychain locked). | Surface to user; retry after unlock or restart. |
| `FFI-SESSION-NOT-FOUND` | `SessionNotFound` | An operation referenced a session id that no session exists for in local state. | Trigger a fresh `init_session` for the peer. |
| `FFI-SESSION-INIT` | `SessionInitializationFailed { message }` | X3DH / PQXDH handshake construction failed. Wraps a deeper `error::CryptoError`. | Surface and retry after fetching a fresh prekey bundle. |
| `FFI-ENCRYPT` | `EncryptionFailed { message }` | `RatchetEncrypt` failed. Most commonly: session state corruption or AEAD allocation failure. | Surface; do not silently fall back. |
| `FFI-DECRYPT` | `DecryptionFailed { message }` | `RatchetDecrypt` failed. Most commonly: bad AD, replayed message, skipped-key cache exhausted, or tampered ciphertext. | Apply healing flow (`init_receiving_session` retry) if `msg_num == 0`; otherwise END_SESSION. |
| `FFI-INVALID-KEY` | `InvalidKeyData` | A key field had the wrong length or failed point validation. | Reject the message / bundle. |
| `FFI-INVALID-CT` | `InvalidCiphertext` | A KEM ciphertext or AEAD frame failed structural validation. | Reject the message. |
| `FFI-SERIALIZE` | `SerializationFailed` | A MessagePack encode failed for an outbound CFE payload. | Surface as internal error. |
| `FFI-MSGPACK-DESERIALIZE` | `MessagePackDeserializationFailed` | A MessagePack decode failed on an incoming CFE payload. | Reject the envelope. |
| `FFI-SPK-STALE` | `PeerSpkStale { age_secs }` | The peer's Signed Pre-Key exceeds `SPK_MAX_AGE_SECS` (10 days). | Wait for the peer to open their app and rotate, or surface to user. Do NOT proceed with X3DH against a stale SPK. |

`FFI-SPK-STALE` is the only variant with structured data that
applications MUST react to: it conveys the `age_secs` so that UI can
report "peer hasn't been online for N days" without re-deriving the
threshold.

## A.3 CFE envelope errors — `CfeError`

Raised when parsing a CFE envelope at the FFI boundary. Defined in
`construct-core/src/cfe/error.rs`. Every entry below is a *parse-time*
or *integrity* failure and MUST cause the envelope to be rejected
before its payload is deserialised.

| Tag | Variant | Condition |
|---|---|---|
| `CFE-TOO-SHORT` | `TooShort { min, got }` | Buffer is shorter than the 16-byte header. |
| `CFE-INVALID-MAGIC` | `InvalidMagic` | First two bytes are not `[0x43, 0x46]`. |
| `CFE-LEGACY-JSON` | `LegacyJson` | Buffer begins with `{` or `[` — caller is on a pre-CFE path. |
| `CFE-UNSUP-VERSION` | `UnsupportedVersion(u8)` | Version byte is not `0x01`. |
| `CFE-UNKNOWN-TYPE` | `UnknownType(u8)` | `msg_type` byte does not correspond to any known `CfeMessageType` variant. |
| `CFE-CRC-MISMATCH` | `ChecksumMismatch { stored, computed }` | CRC-32 over `(header[crc=0] || payload)` does not match the stored value. |
| `CFE-PAYLOAD-TOO-LARGE` | `PayloadTooLarge { max, got }` | `payload_len` exceeds the implementation cap (reference: 256 KiB). |
| `CFE-TRUNCATED` | `TruncatedPayload { expected, got }` | Buffer ends before `payload_len` bytes can be read. |
| `CFE-RESERVED-NONZERO` | `InvalidReservedBytes` | The three reserved bytes are not `[0x00, 0x00, 0x00]`. |
| `CFE-UNSUP-FLAGS` | `UnsupportedFlags(u8)` | `flags` byte is non-zero (no flags defined in v1). |
| `CFE-TYPE-MISMATCH` | `TypeMismatch { expected, got }` | Decoder was invoked for a specific type but the envelope carries a different one. |
| `CFE-INVALID-FORMAT` | `InvalidFormat` | Catch-all structural error (used by helpers that detect format violations beyond the schema). |
| `CFE-SERIALIZE` | `SerializeFailed(String)` | MessagePack encoder rejected the payload (e.g. unsupported type). |
| `CFE-DESERIALIZE` | `DeserializeFailed(String)` | MessagePack decoder rejected the payload. |
| `CFE-LEGACY-JSON-PARSE` | `LegacyJsonParseFailed(String)` | A pre-CFE JSON payload could not be parsed even on the migration path. |
| `CFE-B64-DECODE` | `Base64DecodeFailed(String)` | A base64-encoded field inside a payload failed to decode. Should NOT occur in current binary payloads. |
| `CFE-HEX-DECODE` | `HexDecodeFailed(String)` | A hex-encoded field failed to decode. |
| `CFE-INVALID-FIELD` | `InvalidField(String)` | A semantic field-level validation failed inside an otherwise well-formed payload. |
| `CFE-KDF-FAILED` | `KeyDerivationFailed(String)` | A KDF step inside a CFE-wrapped operation failed. |

`CFE-CRC-MISMATCH`, `CFE-PAYLOAD-TOO-LARGE`, and `CFE-TRUNCATED` are
the load-bearing integrity errors: they MUST cause an immediate
rejection without any attempt to deserialise the payload.

## A.4 WirePayload framing — `WirePayloadError`

Raised by the WirePayload pack/unpack routines
([Chapter 6 §6.2](./06-transport.md#62-wire-format-wirepayload)).
Defined in `construct-core/src/wire_payload.rs:172`.

| Tag | Variant | Condition |
|---|---|---|
| `WP-INVALID-DH` | `InvalidDhPublicKey(usize)` | The DH public key field is not exactly 32 bytes (X25519 Montgomery point). |
| `WP-KEM-TOO-LARGE` | `KemTooLarge(usize)` | KEM ciphertext exceeds `u16::MAX` bytes (only Suite 2; reference value is 1088). |
| `WP-TOO-SHORT` | `TooShort(usize)` | Buffer is shorter than the 52-byte fixed header. |

A WirePayload that fails to parse MUST be dropped without affecting
session state. The receiver MUST NOT advance its Double Ratchet on a
malformed frame.

## A.5 Padding errors — `PaddingError`

Raised by the PKCS#7-style padding helpers
([Chapter 5 §5.7](./05-message-encryption.md#57-pkcs7-padding-length-hiding)).
Defined in `construct-core/src/traffic_protection/padding.rs:21`.

| Tag | Variant | Condition |
|---|---|---|
| `PAD-TOO-LARGE` | `MessageTooLarge(actual, max)` | Plaintext exceeds `MAX_MESSAGE_SIZE` (reference: 65 536 bytes). |
| `PAD-INVALID` | `InvalidPadding` | Last byte of the unpadded buffer indicates a length that exceeds the buffer or fails the constant-time unpad check. |
| `PAD-EMPTY` | `EmptyMessage` | Caller attempted to unpad a zero-byte buffer. |

`PAD-INVALID` MUST be returned in constant time relative to the
plaintext length, to avoid leaking padding information via a timing
side channel.

## A.6 Internal `CryptoError`

Defined in `construct-core/src/error.rs`. These variants are not
exposed across the FFI surface; they are converted to one of the §A.2
variants at the boundary (`From<error::CryptoError> for
uniffi_bindings::CryptoError`).

| Variant | Approximate condition |
|---|---|
| `KeyGenerationError(String)` | RNG failure, dalek keypair generation rejected. |
| `SigningError(String)` | Ed25519 sign failed (typically wraps `ed25519_dalek::SignatureError`). |
| `SignatureVerificationError(String)` | Ed25519 verification failed. Includes the SPK signature check. |
| `KemEncapsulationError(String)` | ML-KEM-768 `Encapsulate` failed. |
| `KemDecapsulationError(String)` | ML-KEM-768 `Decapsulate` failed (malformed ciphertext or wrong key). |
| `AeadEncryptionError(String)` | ChaCha20-Poly1305 seal failed (typically allocation). |
| `AeadDecryptionError(String)` | ChaCha20-Poly1305 open failed — tag mismatch, wrong AD, wrong key. |
| `KeyDerivationError(String)` | HKDF / HMAC-SHA-256 step failed (rare; usually IKM-length validation). |
| `NonceGenerationError(String)` | RNG returned an error during AEAD nonce sampling. |
| `InvalidInputError(String)` | Generic input-shape rejection. |
| `SerializationError(String)` | Internal serialization failure (typically MessagePack). |
| `DeserializationError(String)` | Internal deserialization failure. |
| `InvalidKeyData` | Point-on-curve or length check failed (mapped to `FFI-INVALID-KEY`). |
| `InvalidCiphertext` | Structural ciphertext check failed (mapped to `FFI-INVALID-CT`). |
| `Other(String)` | Catch-all. |

## A.7 Top-level `ConstructError`

Defined in `construct-core/src/utils/error.rs`. This is the `Result<T>`
type returned by most public functions in the core; it composes
`CryptoError` via `#[from]`.

| Variant | Approximate condition |
|---|---|
| `Crypto(CryptoError)` | Any §A.6 variant, propagated. |
| `StorageError(String)` | Local persistence (Keychain / SecureStorage / SQLite) failed. |
| `NetworkError(String)` | Transport-layer call failed before reaching the protocol layer. |
| `SerializationError(String)` | Top-level serialisation failure (distinct from `CryptoError::SerializationError` which is per-crypto-step). |
| `ValidationError(String)` | Domain-level input validation failed (e.g. malformed user id). |
| `SessionError(String)` | Session state inconsistency (e.g. trying to encrypt before init). |
| `NotFound(String)` | A keyed lookup failed (user, session, pre-key id). |
| `InvalidInput(String)` | Caller passed an argument that fails an invariant. |
| `InternalError(String)` | Should-be-unreachable branch hit; treat as a bug. |
| `NotImplemented` | A feature stub was called. MUST be surfaced as `unimplemented` at the FFI surface, not silently swallowed. |
| `Unauthenticated(String)` | The local state indicates the device is not authenticated (no `device_id`, no auth token). |

## A.8 MLS group errors — `MlsError`

Defined in `construct-core/src/group/mls_error.rs`. MLS itself is
documented at protocol-spec level in a future revision (see
[Implementation Status §7.1](./07-implementation-status.md#71-component-matrix));
the errors are listed here so that current implementers know what to
expect from the `construct-core/src/group/` API surface.

| Tag | Variant | Condition |
|---|---|---|
| `MLS-CRYPTO` | `CryptoError(String)` | Underlying crypto operation failed inside a group-protocol step. |
| `MLS-EPOCH-MISMATCH` | `EpochMismatch` | Local epoch is behind the server; caller MUST `FetchCommits` and reapply before retrying. |
| `MLS-NOT-MEMBER` | `NotAMember` | Caller is not a member of the addressed group. |
| `MLS-SERIALIZE` | `SerializationError(String)` | Group state could not be (de)serialised. |
| `MLS-WELCOME` | `WelcomeError(String)` | A Welcome message was invalid, expired, or addressed wrong keys. |
| `MLS-COMMIT` | `CommitError(String)` | A commit could not be applied (stale epoch, invalid signature, etc.). |
| `MLS-CRYPT` | `EncryptionError(String)` | Application-message encrypt or decrypt failed inside the group. |

## A.9 VEIL transport errors (informational)

These errors are produced by the `construct-veil` crate, NOT the
protocol core. They are not part of the normative protocol surface
and MAY change between releases of `construct-veil`. They are
documented here as a navigation aid for implementers wiring the
anti-censorship tier.

### A.9.1 Coordinator — `CoordinatorError`

(`construct-veil/src/veil/coordinator.rs`)

| Variant | Condition |
|---|---|
| `Io(std::io::Error)` | Underlying socket / I/O failure. |
| `Scoring(String)` | Persistent score store reported an error. |
| `Stopped` | Session was cancelled by the caller before a backend won. |
| `AllProbesFailed` | Every configured backend failed its probe. |

### A.9.2 Obfuscator — `ObfuscatorError`

(`construct-veil/src/veil/obfuscator.rs`)

| Variant | Condition |
|---|---|
| `Io` | I/O error during obfuscated handshake or stream. |
| `ConnectionRefused` | TCP connect was refused by the relay. |
| `Tls(String)` | TLS handshake or peer verification failed. |
| `Handshake(String)` | obfs4 or WebSocket upgrade failed at the application layer. |
| `Timeout` | Probe exceeded its time budget. |
| `Cancelled` | Probe was cancelled by the coordinator. |
| `FingerprintBlocked` | TLS alert 40 / handshake_failure — DPI has classified the method. |
| `WebTunnelDecoyResponse` | Non-101 on WebSocket upgrade — transparent proxy interception. |

### A.9.3 Probe failure classification — `ProbeFailureReason`

(`construct-veil/src/veil/fsm/types.rs`) — used by the scoring layer
to bucket probe outcomes:

`FingerprintBlocked` · `WebTunnelDecoyResponse` · `TlsCertProblem` ·
`ConnectionFailed` · `Timeout` · `Unknown`.

The sibling enum `TransportFailureKind` covers steady-state transport
degradation (after a probe has already won) and shares the same
spelling for the network-observable categories.

### A.9.4 Scoring — `ScoringError`

(`construct-veil/src/veil/scoring.rs`)

| Variant | Condition |
|---|---|
| `DbError(String)` | SQLite persistence error in the per-backend score store. |

## A.10 gRPC status codes (informational)

Server-to-client errors in the MessagingService / AuthService etc. use
standard [gRPC status codes](https://grpc.io/docs/guides/status-codes/).
The conventions below are normative for a conforming Konstruct
deployment:

| gRPC status | Numeric | Konstruct semantics |
|---|---|---|
| `OK` | 0 | Request succeeded. |
| `UNAUTHENTICATED` | 16 | JWT missing, invalid, or expired. Client MUST clear the in-memory auth state, fall back to `RefreshToken`, and if that fails treat the device as logged out. |
| `PERMISSION_DENIED` | 7 | The authenticated identity is not allowed to perform this operation (e.g. wrong device id). Treated equivalently to `UNAUTHENTICATED` for device-key disposal. |
| `INVALID_ARGUMENT` | 3 | Request was structurally invalid (e.g. malformed user id). MUST NOT delete local device keys. |
| `NOT_FOUND` | 5 | Addressed resource (user, pre-key, message) does not exist. |
| `ALREADY_EXISTS` | 6 | Idempotent create attempted on a resource that already exists (e.g. duplicate registration). |
| `RESOURCE_EXHAUSTED` | 8 | PoW failed, rate limit hit, or pre-key pool empty. Client MUST back off; SHOULD surface a user-visible cooldown. |
| `FAILED_PRECONDITION` | 9 | Operation requires earlier state (e.g. encrypt before session init). |
| `ABORTED` | 10 | Concurrent modification (rare; used for prekey-bundle race resolution). |
| `UNAVAILABLE` | 14 | Server is starting up, restarting, or routed through a failing relay. Client SHOULD retry with backoff. |
| `INTERNAL` | 13 | Server-side bug. MUST NOT be auto-retried more than once. |
| `DEADLINE_EXCEEDED` | 4 | Request took longer than the per-RPC deadline. SHOULD be retried with a fresh deadline. |

### A.10.1 Auth disposal rules (CRITICAL)

The client MUST distinguish "transport failure" from "server says you
are not authenticated":

- On `UNAUTHENTICATED` (16) or `PERMISSION_DENIED` (7) — and only on
  those codes — the client MUST delete its device keys and trigger
  re-registration.
- On *any* other gRPC error (`UNAVAILABLE`, `DEADLINE_EXCEEDED`,
  `INTERNAL`, etc.) the client MUST NOT touch device keys. These are
  transient failures.

The reference iOS interceptor implements this distinction in
`AuthInterceptor.swift`; client implementations on other platforms
MUST replicate it. Deleting device keys on a transient failure
silently logs the user out and forces them through re-registration —
this has been a recurring bug in early development; the rule above
exists to prevent regressions.

## A.11 Diagnostics & logging guidance

When surfacing any error from this registry to the user or to logs:

1. **At the FFI surface (§A.2)**, the variant tag is the stable
   contract. Show or log it verbatim. Do not parse the `message`
   field for control flow.
2. **Below the FFI surface (§A.6–A.8)**, the variant names are
   advisory only. Logs MAY include them for debugging but the
   application code SHOULD treat the §A.2 variant it eventually
   receives as the source of truth.
3. **Wire integrity errors (§A.3 `CFE-CRC-MISMATCH`, §A.4 `WP-*`)**
   SHOULD be counted as security-relevant log events. A sustained
   stream of these from a single peer indicates either a misbehaving
   client or an active attacker injecting bytes.
4. **`FFI-SPK-STALE`** is a user-facing condition, not an internal
   error. UIs SHOULD render it as "this person hasn't opened
   Konstruct in N days" rather than as a generic failure dialog.

## A.12 References

- FFI surface: `construct-core/src/uniffi_bindings.rs`
- CFE envelope: `construct-core/src/cfe/error.rs`
- WirePayload framing: `construct-core/src/wire_payload.rs`
- Padding: `construct-core/src/traffic_protection/padding.rs`
- Internal crypto: `construct-core/src/error.rs`
- Top-level `Result`: `construct-core/src/utils/error.rs`
- MLS: `construct-core/src/group/mls_error.rs`
- VEIL coordinator: `construct-veil/src/veil/coordinator.rs`
- VEIL obfuscator: `construct-veil/src/veil/obfuscator.rs`
- VEIL probe FSM: `construct-veil/src/veil/fsm/types.rs`
- VEIL scoring: `construct-veil/src/veil/scoring.rs`
- gRPC status codes: <https://grpc.io/docs/guides/status-codes/>
