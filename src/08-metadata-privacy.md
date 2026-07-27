# Metadata Privacy & Sealed Sender

End-to-end encryption hides *what* is said. This chapter specifies how
Konstruct also reduces *who says it to whom* that a server can observe —
and, just as importantly, states honestly what it does **not** hide. It
builds on the [Threat Model](./01-threat-model.md) (server adversary) and
the [Message Encryption](./05-message-encryption.md) chapter.

## 8.1 Goal and non-goals

**Goal.** For all ordinary user traffic, remove the sender's identity from
what any server stores or must read to route a message. A server should be
able to deliver a message to its recipient without learning who sent it.

**Non-goals.** This is metadata *minimisation*, not network-layer
*unlinkability*. Konstruct does **not** run a mixnet and does not claim to
defeat an adversary who can watch both legs of a connection and correlate
by timing and volume. See [Architecture Overview](./architecture-overview.md)
for that boundary. The honest residual-metadata list is in §8.7 below.

## 8.2 The sealed envelope

A sealed message replaces the normal `Envelope` `sender` field with a
`SealedSenderEnvelope`. The wire structures are defined normatively in
`shared/proto/core/envelope.proto` (message `SealedSenderEnvelope`,
`envelope.proto:359`; `SealedInner`, `envelope.proto:380`).

```
SealedSenderEnvelope {          // visible to the home/entry server
  recipient_server : string     // federation destination domain (S2S routing)
  sealed_inner     : bytes      // opaque — the home server MUST NOT parse it
  forwarding_token : bytes      // HMAC-SHA256(server_secret, sealed_inner || timestamp)
  timestamp        : int64      // freshness; reject if > 5 min old
}

SealedInner {                   // read by the destination server
  recipient_user_id     : string   // needed to route to the recipient
  delivery_tag          : bytes    // random 32 B; server dedups for 24h
  sender_cert_ciphertext: bytes    // SenderCertificate sealed to recipient IK — server MUST NOT decrypt
  encrypted_payload     : bytes    // the Double Ratchet ciphertext (Chapter 5)
  content_type          : ContentType
  priority              : MessagePriority
  ttl                   : uint32
  token_nonce           : bytes    // Privacy Pass (optional, §8.5)
  token_bytes           : bytes
}
```

What each party sees:

- **Home / entry server**: `recipient_server` plus an opaque `sealed_inner`
  blob and its `forwarding_token`. It routes by destination domain and
  forwards the blob without parsing it.
- **Destination server**: parses `SealedInner`. It learns the
  **recipient**, the `content_type` (message kind — needed to compose the
  push notification and set priority), the `delivery_tag` (for replay
  suppression), and the opaque `encrypted_payload`. It does **not** learn
  the **sender**: the sender identity lives only inside
  `sender_cert_ciphertext`, which is encrypted to the recipient's identity
  key, and which the server "MUST NOT attempt to decrypt"
  (`envelope.proto:390`).

On the single-server deployment shipping today the home and destination
roles are the same process, so it sees the `SealedInner` fields above — but
still never the sender.

On the client, the outer-envelope masking is applied in `construct-ios`
`Networking/gRPC/Services/MessagingServiceClient.swift` (`buildEnvelope`):
when a `SealedInner` is present it sets `sealed_sender` and omits `sender`,
`conversation_id`, and the real `content_type` from the outer `Envelope`.
Server-side reconstruction and the sender-hiding path are in
`messaging-service/src/envelope.rs:38` (`if envelope.is_sealed_sender { … }`).

## 8.3 Sender certificate and recipient verification

The recipient learns and *verifies* the sender from the `SenderCertificate`
(`envelope.proto:425`) inside `sender_cert_ciphertext`:

```
SenderCertificate {
  sender_user_id      : string
  sender_domain       : string   // home server, for public-key lookup
  sender_identity_key : bytes    // X25519 (32 B) — must match the session
  sender_device_id    : string
  issued_at           : int64
  expires_at          : int64    // typically issued_at + 24h
  server_signature    : bytes    // Ed25519 by the sender's home server
}
```

The certificate is issued and signed by the sender's home server
(identity-service) with the same Ed25519 key published at
`.well-known/konstruct`. The signature covers the direct big-endian
concatenation `sender_user_id || sender_domain || sender_identity_key ||
sender_device_id || issued_at || expires_at` — one canonical format, pinned
in stealth-sealed-sender v2 Phase 3 (server
`identity-service::build_sender_cert_sign_payload`; client `construct-ios`
`Security/StealthSenderService.swift` `buildCertPayload`).

The recipient attests the sender through one of two levers, strongest
first (`SenderVouchBasis` in `StealthSenderService.swift`):

1. **KT lever** (`.kt`): the certificate's `sender_identity_key` matches the
   recipient's locally stored, key-transparency-verified `knownIdentityKey`
   for that contact. No dependency on any fetched server key.
2. **Signature lever** (`.signature`): the certificate's Ed25519 signature
   validates against the sender's home-server public key (fetched or
   pinned). Used on first contact, before a local KT key exists.

**Delivery is not gated on attestation.** If neither lever vouches (missing
or stale bundle key, expired cert), the message is still delivered and
logged as `UNVOUCHED` with a reason — the Double Ratchet is the real
authenticator, and an unvouched attestation triggers a bundle-key refresh
so the next message re-vouches (`MessageRouter.routeIncomingMessage`,
`construct-ios`). This is a deliberate availability-over-strictness choice:
a key rotation must not silently drop mail.

## 8.4 Always-on scope, and the fail-closed invariant

Sealed sending is **on by default** in release builds — there is no user
toggle to turn it off (`construct-ios` `Services/StealthPolicy.swift:42`
`isEnabled`, `:71` `shouldUseSealedSender`). DEBUG builds keep a developer
override for exercising the legacy identified path.

**Invariant (fail-closed): while stealth is on, every message send is
sealed or queued — it is never emitted identified.** Identified sends are
legal only when `shouldUseSealedSender()` is false. When sealing is
temporarily impossible (recipient identity key not yet known, sender
certificate unfetchable), the send does not fall back to an identified
envelope; it throws `StealthDowngradeBlocked` and the message is held for a
later retry (`StealthSendRecovery.swift`, `ChunkedMessageDelivery.swift`).
This closes a server-influence deanonymisation vector: a server that could
force identified sends by failing sealed ones could deanonymise on demand.

Traffic **in scope** (sealed):

- User messages (text, media, voice, files, replies) and edits.
- End-to-end delivery receipts — otherwise sender↔recipient timing
  correlation leaks even when bodies are sealed.
- Call signalling (SDP / ICE — see [Transport](./06-transport.md)).
- The **session-control handshake**: `session_ready`, the tie-break ping,
  `SESSION_RESET_INIT`, and `END_SESSION`. With all user traffic sealed,
  these directed control messages were the primary remaining cleartext
  `sender → recipient` signal, so they are sealed too (client
  `Services/Session/SessionCoordinator.swift` `sendSessionControlCore`,
  `MessagingServiceClient.swift` `sendEndSession`).

Traffic **deliberately excluded** (identified, by decision — the leak is
low-value or the frequency/cost is high):

- End-to-end heartbeats (`content_type = 13`).
- Multi-device internal sync (a user talking to their own devices).

## 8.5 Anti-abuse: Privacy Pass tokens

Removing the sender identity also removes the server's usual per-sender
abuse lever. Konstruct restores one with **Privacy Pass** anonymous tokens:
a sealed send MAY carry `token_nonce` + `token_bytes` (`envelope.proto:409`),
a blind-signed single-use credential the sender spends from a local wallet.
The token is itself sealed to the destination server's X25519 key so relay
operators cannot read the spent token. The full construction — the VOPRF,
issuance/redemption, and the verifiable-issuance DLEQ proof — is specified
in [Chapter 9](./09-privacy-pass.md).

**Deployment status.** Token enforcement is governed by
`MSG_STEALTH_TOKEN_POLICY`, currently **`warn`** in production: tokens are
issued, attached, and redemption-validated, but an absent or failed token
does **not** block delivery — anti-abuse is degraded, anonymity is intact.
`enforce` is **deferred past 1.0** (see [Implementation
Status](./07-implementation-status.md)). Issuance is rate-limited with an
age-tiered per-account cap.

**Verifiable issuance (planned/partial).** So that a malicious issuer
cannot tag individual users via a per-user signing key, the issuer proves in
zero knowledge that every token was signed with the *same* published key
(batched Chaum–Pedersen DLEQ). The server half is implemented
(`construct-crypto/src/privacy_pass.rs`) and the client pins the issuer key
and verifies the proof; treat end-to-end verifiable-VOPRF as **in progress**
until enforcement relies on it. Until then, sender-unlinkability against a
*malicious* (as opposed to honest-but-curious) server is not claimed.

## 8.6 Connection-layer metadata: IP minimisation

Sealed sender hides application-layer identity; the **network** layer still
exposes the connection's source IP address, which is unavoidable for packet
routing. Konstruct minimises what is *retained*: the server never stores a
raw client IP. Anti-abuse rate-limit keys and logs use a salted one-way
hash of the address (`construct-utils/src/lib.rs:92` `hash_client_ip`,
applied in `construct-user-service/src/account.rs:140` and
`construct-auth-service/src/devices.rs:292`). Per-address anti-abuse
granularity is preserved (same address → same tag); the raw address is not
written to databases, rate-limit state, or logs, and no raw IP-to-account
mapping is kept.

Honest limit: a salted hash of the small IPv4 address space is *not*
perfectly anonymous against a party holding the salt — it removes the raw
address from storage, it does not make the network origin undiscoverable.
To keep the address off the path entirely, route through VEIL
([Transport](./06-transport.md)), a VPN, or Tor; the terminating endpoint
still sees the apparent source address of the connection it accepts.

## 8.7 Residual metadata — what a server still sees

Even with sealed sender always on, a compromised destination server can
still observe the following. This is the honest counterpart to §8.1.

| Metadata | Visible? | Note |
|---|---|---|
| Message **content** | No | End-to-end encrypted; key material is not on the server. |
| **Sender** identity (per message) | No (sealed) | Only inside the recipient-encrypted certificate. |
| **Recipient** identity + timing | **Yes** | Required to deliver; `SealedInner.recipient_user_id`. |
| Message **kind** (`content_type`) | **Yes** | Needed for notification text / priority. |
| Ciphertext **size after padding**, volume | **Yes** | Padding buckets blunt but do not erase this. |
| **Contact graph** | **Yes** | Contact relationships are stored to route streams. |
| Connection **IP** (live) | **Yes** | At connection time; only a salted hash is retained (§8.6). |
| `sender_id → recipient_id` edge | Not from one sealed message | May still be inferable from timing/volume correlation — the network-adversary non-goal. |

## 8.8 References

- Wire structures: `shared/proto/core/envelope.proto`
  (`SealedSenderEnvelope`, `SealedInner`, `SenderCertificate`).
- Server: `messaging-service/src/envelope.rs`;
  `construct-core/src/crypto/privacy_pass/`;
  `construct-utils/src/lib.rs` (`hash_client_ip`).
- Client (`construct-ios`): `Services/StealthPolicy.swift`,
  `Security/StealthSenderService.swift`,
  `Networking/gRPC/Services/MessagingServiceClient.swift`,
  `Services/Session/SessionCoordinator.swift`,
  `Security/StealthSendRecovery.swift`.
- Design rationale (internal): construct-docs `decisions/` —
  `stealth-sealed-sender-v2-always-on`, `sealed-sender-anti-abuse-economics`,
  `sealed-sender-session-control-channel`, `stealth-heartbeat-exclusion`,
  `server-influence-minimization`, `stealth-phase-c-verifiable-voprf`.
