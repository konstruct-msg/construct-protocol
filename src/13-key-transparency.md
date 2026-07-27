# Key Transparency

> **Status: client verification implemented, not yet live end-to-end.** The
> RFC 6962 proof-verification primitives exist and are tested in
> `construct-core/src/crypto/key_transparency.rs`, but the **server does not
> yet publish the transparency log** (Signed Tree Heads + proofs), so the
> end-to-end guarantee below is **designed and client-ready, not in
> production**. This chapter records the design and the exact
> implementation boundary.

## 13.1 The problem it solves

End-to-end encryption authenticates messages to *a key*, but a client still
has to trust that the identity key it fetched for a contact is really that
contact's key. A malicious or compromised directory server could hand out a
key it controls (a key-substitution / MITM attack). Fingerprint comparison
("safety numbers") defends against this but depends on users manually
comparing out of band.

**Key Transparency (KT)** makes the directory *accountable* instead: every
identity key the server ever vouches for is committed to a public,
append-only log, and clients cryptographically verify that the key they were
given is in that log and that the log has never been rewritten. A server
that equivocates — showing one key to the victim and another to everyone
else — is caught, because it cannot produce consistent proofs against a
single published log.

## 13.2 Construction (RFC 6962)

Konstruct's log follows **[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)
§2** (the Certificate Transparency Merkle tree), reused for identity keys:

- **Leaf.** Each device registration appends a leaf hashing the pair
  `(device_id, identity_public_key)` — `kt_hash_leaf(device_id,
  identity_key_b64)`.
- **Tree head.** The **Merkle Tree Hash** (`merkle_tree_hash` /
  `kt_compute_root`) reduces all leaves to a single root. The server
  publishes a **Signed Tree Head (STH) = Ed25519(tree_size ‖ root_hash)**.
- **Inclusion proof** (RFC 6962 §2.1.3, `kt_verify_inclusion`): proves a
  specific `(device_id, identity_key)` leaf is present at a given index in a
  tree of a given size and root.
- **Consistency proof** (`kt_verify_consistency`): proves that a newer tree
  is an *append-only extension* of an older one — the log grew, and no
  earlier entry was altered or removed.

## 13.3 What a client verifies

When live, a conforming client MUST, for a contact's identity key:

1. **Inclusion** — verify the received identity key is a leaf in the log
   under the current STH. A key that is not in the log is not trusted as
   KT-verified.
2. **Consistency** — verify each new STH is consistent with the last STH the
   client saw, so the server cannot silently rewrite history or fork the log
   between checks.

Only a key that passes both is marked **KT-verified**. This is the strongest
of the sender-attestation levers used by sealed sender (the `.kt` lever,
[Chapter 8 §8.3](./08-metadata-privacy.md#83-sender-certificate-and-recipient-verification)):
a sealed sender whose certificate key matches a locally stored KT-verified
key is vouched with no dependency on any freshly fetched server key.

## 13.4 Implementation boundary

| Piece | Status |
|---|---|
| RFC 6962 Merkle tree hash, inclusion + consistency verification | **Implemented** (`key_transparency.rs`, unit-tested). |
| Client STH signature check (Ed25519) | **Implemented** primitive. |
| Server-published append-only log + STH endpoint | **Not yet deployed.** |
| Gossip / auditor cross-checking of STHs | **Not designed here** — a full KT deployment also needs out-of-band STH gossip to detect a server that forks the log per-client; that is future work. |

**Honest limit.** Until the server publishes the log and clients gossip
STHs, KT provides no live guarantee — key trust today rests on
trust-on-first-use pinning plus the certificate-signature lever
([Chapter 8](./08-metadata-privacy.md)). KT is the mechanism that upgrades
that from "trust the server the first time" to "the server cannot lie about
a key without being caught"; the cryptographic verifier is ready, the
deployment is the remaining work. See [Implementation
Status](./07-implementation-status.md).

## 13.5 References

- `construct-core/src/crypto/key_transparency.rs` — `kt_hash_leaf`,
  `kt_compute_root`, `kt_verify_inclusion`, `kt_verify_consistency`,
  `merkle_tree_hash`.
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) — Certificate
  Transparency Merkle tree (the reused construction).
- Sender-attestation use of KT-verified keys:
  [Chapter 8 §8.3](./08-metadata-privacy.md#83-sender-certificate-and-recipient-verification).
