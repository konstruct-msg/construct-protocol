# Key Transparency

> **Status: per-bundle inclusion proofs are live; split-view detection is
> not.** The server **does** maintain an append-only Merkle log and returns a
> Signed Tree Head (STH) plus an inclusion proof inline with every pre-key
> bundle, and the client **does** verify both on receipt. What is missing is
> the *transparency* layer that makes KT meaningful against a **malicious**
> (not merely honest-but-curious) server: a publicly monitorable log endpoint,
> consistency checking over time, and STH gossip / third-party auditing. Until
> those exist, the STH is a self-signed commitment that catches a server which
> contradicts *itself to you* — not one that equivocates *consistently across
> victims*. This chapter records what is deployed, and the exact remaining
> boundary.

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

- **Leaf.** Each device registration appends a leaf hashing
  `(device_id, identity_public_key)` — `kt_hash_leaf(device_id,
  identity_key_b64)`. A **key rotation appends a new leaf** rather than
  mutating the old one (`db_ensure_leaf`), so the log records the full
  history. The hybrid PQ identity key gets its **own leaf kind** (domain byte
  `0x02` vs `0x00` for the X25519 identity leaf, `key_transparency.rs:246`-`:248`) in the **same tree**, so
  both keys share one STH.
- **Tree head.** The **Merkle Tree Hash** (`merkle_tree_hash` /
  `kt_compute_root`) reduces all leaves to a single root. The server signs a
  **Signed Tree Head (STH) = Ed25519("ConstructKT-v1" ‖ BE64(tree_size) ‖
  root_hash)** with its bundle-signing key (`tree_head_signable`,
  `construct-core/src/crypto/key_transparency.rs:260`). Since construct-core
  0.32.0 a head may also be signed by a delegated hybrid key, over
  `"konstruct/v1/kt-head" ‖ kid ‖ BE64(tree_size) ‖ root_hash`
  (`KtSignedTreeHead`; [Chapter 3 §3.11](./03-identity-key-hierarchy.md#311-server-signing-keys-rooted-offline)).
- **Inclusion proof** (RFC 6962 §2.1.3, `kt_verify_inclusion`): proves a
  specific `(device_id, identity_key)` leaf is present at a given index in a
  tree of a given size and root.
- **Consistency proof** (`kt_verify_consistency`): proves that a newer tree
  is an *append-only extension* of an older one — the log grew, and no
  earlier entry was altered or removed.

## 13.3 What is live today

The cryptographic machinery is **deployed and exercised on every bundle
fetch**, not merely designed:

1. **Server appends + proves inline.** On each pre-key-bundle request the
   server ensures the device's leaf exists (idempotent; a changed key appends
   a rotation leaf), builds the inclusion proof against the whole tree, and
   signs the STH — `build_kt_proof` / `build_hybrid_kt_proof`
   (`key-service/src/kt.rs`). The append-only table is DB-enforced: migration
   044 documents that `UPDATE`/`DELETE` are never granted on `kt_leaves`. The
   proof rides in the bundle response as `KtInclusionProof`.
2. **Client verifies inclusion + STH signature, in the core.** Since
   construct-core 0.32.0 (2026-10-03) the core judges a bundle's proofs
   (`key_transparency::verify_proof`,
   `construct-core/src/crypto/key_transparency.rs:305`-`:384`; UDL
   `verify_kt_proofs`): it recomputes the leaf from the leaf domain
   (`0x00` X25519 identity, `0x02` hybrid identity), the device id and the
   key, checks the inclusion proof against the proof's root, and then
   judges the head the proof is relative to. With a root pinned, a
   delegated head decides alone and MUST name the proof's tree size and
   root; otherwise the Ed25519 head signature decides against the keys the
   platform handed to the core. The verdict is `Verified`, `Unavailable`
   (no key to check with — not evidence of anything), `MalformedProof`,
   `InclusionProofInvalid` or `SignatureInvalid`. **No root is pinned
   yet**, so today the head is checked by Ed25519 against the server's
   published key, as before. Until 2026-10-03 this check was written in
   each client (iOS `KeyTransparencyVerifier`, now removed); the iOS client
   calls the core from `KeyServiceClient`. A failed verdict is recorded on
   the contact and logged; it does not reject the bundle.

A KT-verified key is the strongest certificate-based sender-attestation
lever used by sealed sender (the `.kt` lever, [Chapter 8
§8.3](./08-metadata-privacy.md#83-sender-certificate-and-recipient-verification)):
a sealed sender whose certificate key matches a locally KT-verified key is
vouched without depending on any freshly fetched server key.

## 13.4 What is missing — the split-view gap

Everything below the crypto is the part that makes KT meaningful against a
server that is *actively malicious* rather than honest-but-curious. None of it
is deployed:

| Gap | Consequence today |
|---|---|
| **No public monitor endpoint.** The STH is only ever handed to the requesting client inline with a bundle. There is no `GetLatestTreeHead` / `GetConsistencyProof` RPC (`key_service.proto` has only reserved comments for `GetKeyHistory` / `ReportKeyMismatch`). | Nobody — not the client, not a third party — can fetch the *latest* STH or a consistency proof independently of a bundle request. |
| **Consistency not checked in practice.** The client has the `kt_verify_consistency` primitive but **never calls it**: there is no stored "last seen STH" and no endpoint to fetch `(old_root, new_root, proof)`. | The append-only property is not actually verified over time; the client trusts each STH in isolation. |
| **No STH gossip / split-view detection.** The STH is signed by the *same* key that serves bundles (until a root is pinned and heads are signed by a delegated key — and even then the delegated key is the server's). Without clients (or a witness) cross-checking STHs, a server can sign tree **A** for the victim and tree **B** for everyone else — **both verify locally**. | This is precisely the equivocation KT is supposed to catch, and it is currently uncaught. |
| **No independent auditor / monitor.** No party mirrors the log to confirm it is genuinely append-only and that a given user's key line has not silently forked. | The log's honesty rests on the operator. |

**Why it is not done yet.** These are infrastructure and trust-distribution
problems, not missing crypto. Split-view detection needs *someone to gossip
with* — either multiple independent nodes/witnesses or a client-to-client
gossip channel; federation is only newly implemented and single-node in
practice, so there is no second party to cross-check against. A monitorable
log endpoint plus an auditor is a separate service (storage, a gossip
protocol, or a CT-style witness). For 1.0 the immediate MITM story is covered
by trust-on-first-use pinning, safety-number comparison, and the
certificate-signature lever ([Chapter 8](./08-metadata-privacy.md)).

**Honest limit.** Today's STH is a signed, non-repudiable commitment from the
server *to you*. It catches a server that **contradicts itself to you**, and
gives you a durable signed record — but not a server that **equivocates
consistently across victims**. Closing that requires the monitor endpoint,
in-practice consistency checking, and gossip/auditing above. See
[Implementation Status](./07-implementation-status.md).

## 13.5 References

- `key-service/src/kt.rs` (server) — `build_kt_proof`,
  `build_hybrid_kt_proof`, `db_ensure_leaf`, `generate_inclusion_proof`,
  `tree_head_signable`; `shared/migrations/044_key_transparency.sql`
  (append-only log), `054_kt_hybrid_leaf.sql` (hybrid leaf kind).
- `construct-core/src/crypto/key_transparency.rs` — `kt_hash_leaf`,
  `kt_compute_root`, `kt_verify_inclusion`, `kt_verify_consistency`,
  `merkle_tree_hash` (shared client/server algorithm); `verify_proof`, the
  client's judgement of a bundle's proofs and head.
- `construct-core/src/crypto/server_trust.rs` — delegated head keys
  (Chapter 3 §3.11).
- `construct-ios` `Networking/gRPC/Services/KeyServiceClient.swift` — calls
  `verify_kt_proofs` on every bundle fetch.
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) — Certificate
  Transparency Merkle tree (the reused construction).
- Sender-attestation use of KT-verified keys:
  [Chapter 8 §8.3](./08-metadata-privacy.md#83-sender-certificate-and-recipient-verification).
