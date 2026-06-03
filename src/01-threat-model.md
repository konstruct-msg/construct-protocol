# Threat Model

This chapter defines who Konstruct claims to protect against, who it
explicitly does not, and the assumptions on which every later chapter
rests. **Read it before reading the rest** — a security property only
means something against a specific adversary class, and most
disagreements about "is X secure" reduce to disagreements about which
adversary the discussion has in mind.

## Adversary classes (in scope)

### Network adversary

Capabilities: full passive recording of traffic between any two
endpoints; full active control of the network path (drop, inject,
modify, reorder, replay); deep-packet inspection and traffic
classification; observation across multiple vantage points (e.g.
recording at both ISP and at a transit AS).

What Konstruct guarantees against this adversary:

- Plaintext confidentiality — recovered traffic decrypts to nothing
  more than ciphertext blobs and routing-shaped metadata.
- Tamper detection — any in-flight modification of a Double Ratchet
  ciphertext is rejected by AEAD.
- Forward secrecy — recording today does not enable decryption later
  if a long-term key is later compromised.
- Quantum-recording resistance — recording today does not enable
  decryption later by a quantum-equipped attacker, **for sessions that
  used Suite 2 (PQXDH)**. Suite 1-only sessions are vulnerable in this
  scenario.

What Konstruct does **not** guarantee:

- That a sufficiently sophisticated network adversary cannot infer
  *that* communication is happening. The [transport
  layer](./06-transport.md) reduces this surface (VEIL, padding, cover
  traffic) but does not eliminate it.

### Server adversary

Three sub-classes, treated together because the design is the same:
honest-but-curious, malicious, fully compromised. Konstruct's
server is *blind to message content by construction* — the same key
material the client uses to decrypt simply is not on the server.

What the server can see today (single-trusted-server alpha):

- Which user identifiers exchange messages, with what timestamps.
- Connection metadata (IPs, TLS handshake fingerprint, session
  durations).
- The encrypted payload bytes (it must, in order to route them).

Sender-side metadata minimisation ("sealed sender") is on the roadmap
but **not yet deployed** — until it is, a compromised server can
correlate `sender_id` → `recipient_id` even though it cannot read what
they said.

### Historical device adversary

Capability: after a session has been used for some period of time,
obtain a snapshot of a participating device's state (key material at
rest, session state, message history).

Konstruct guarantees:

- Past message confidentiality up to the moment of compromise
  (forward secrecy via the Double Ratchet's per-message key derivation
  and key eviction).
- Self-healing of future messages after at most one round-trip via the
  DH ratchet step — provided the attacker is no longer active in the
  network path.

### Spam / Sybil adversary

Capability: automated mass registration; commodity GPU farms;
disposable IP pools.

Konstruct deters this with a memory-hard proof of work at registration
(Argon2id, see [Cryptographic Primitives](./02-cryptographic-primitives.md))
and server-side rate limits. Full prevention of nation-state-resourced
Sybil attacks is **not** a Konstruct goal — that would require
identity verification, which is incompatible with privacy goals
elsewhere in the design.

## Out of scope (explicit non-goals)

Konstruct does **not** defend against:

- A live compromise of an *unlocked* device at the moment of decrypt.
  If the attacker has the running process, no end-to-end protocol can
  help.
- OS-, kernel-, or secure-enclave-level compromise of the host
  platform. Keys are stored using platform key stores (iOS Keychain
  with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, etc.); if those
  primitives are broken, so is everything that relies on them.
- Hardware-level side channels (Spectre, power analysis, EM
  emanations). Software-level constant-time primitives (`subtle`
  crate, audited AEAD implementations) are used where they apply; this
  does not extend to physics.
- Coercion of the user. A protocol cannot stop a person from being
  forced to unlock their phone.

## Security goals — formal statement

| Goal | Mechanism (chapter) | Guaranteed against |
|---|---|---|
| Confidentiality | X3DH/PQXDH + Double Ratchet AEAD ([04](./04-session-handshake.md), [05](./05-message-encryption.md)) | Network, server (honest-but-curious or malicious) |
| Integrity & authentication | ChaCha20-Poly1305 AEAD with bound AD ([05](./05-message-encryption.md)) | Network, server |
| Forward secrecy | Per-message key derivation + chain key eviction ([05](./05-message-encryption.md)) | Historical device compromise |
| Post-compromise security | DH ratchet step after one round-trip ([05](./05-message-encryption.md)) | Network compromise of a single session |
| Replay resistance | Two-layer dedup: protocol (Double Ratchet message number) + application (ACK store) ([05](./05-message-encryption.md)) | Network |
| Post-quantum confidentiality | Hybrid PQXDH KEM ([04](./04-session-handshake.md)) | A future quantum-equipped attacker replaying recorded traffic |
| Identity unforgeability | Ed25519 signatures over prekey bundles ([03](./03-identity-key-hierarchy.md)) | Network, server |

## Trust assumptions

- **Trusted today** (would compromise security if breached): the local
  device's OS and key store; the bundled `construct-core` binary; the
  audited Rust cryptography crates listed in
  [Cryptographic Primitives](./02-cryptographic-primitives.md); the
  user's choice not to expose their device to an active attacker.
- **Untrusted today**: the network path; the server (for message
  content); other users (until they are explicitly added as contacts).
- **Trust shrinks over time, by design**: the federation roadmap is
  intended to remove the single-trusted-server assumption; the
  veil-front transport is intended to reduce reliance on the network
  not being adversarial.

The remainder of this specification proceeds from this threat model.
A property described later as "secure" means "secure against the
adversary classes above and no others".
