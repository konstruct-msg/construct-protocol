# Group Messaging (MLS)

> **Status: designed, core implemented, not a shipped feature.** The
> cryptographic group engine exists in `construct-core/src/group/` (built on
> [OpenMLS](https://openmls.tech/)), but there is no group-chat product
> surface in the shipping clients, and this chapter is **not** yet a
> normative interoperability specification. It documents the design and the
> current implementation boundary so the direction is on record; treat every
> statement as "designed / partial", not "in production". The 1:1 protocol
> (Chapters 4–5) is unaffected.

## 12.1 Why MLS rather than pairwise fan-out

The 1:1 protocol ([Chapter 5](./05-message-encryption.md)) gives two-party
forward secrecy and post-compromise security via the Double Ratchet.
Extending that to groups by encrypting separately to each member (pairwise
fan-out) costs `O(n)` per message and has no group-level post-compromise
security. Konstruct's group design instead uses **MLS — the Messaging Layer
Security protocol, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)** —
which maintains a shared group secret through a logarithmic-cost ratchet
tree, so adding/removing a member and healing after a compromise are
`O(log n)` operations.

## 12.2 Ciphersuite and library

- MLS ciphersuite:
  **`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`**
  (`construct-core/src/group/mod.rs`) — DHKEM-X25519 for the ratchet-tree
  HPKE, AES-128-GCM as the group AEAD, SHA-256 as the hash, Ed25519 for
  signatures. This is a standard RFC 9420 ciphersuite; interoperability is
  a design goal.
- Implementation: the **OpenMLS** Rust library with the
  `OpenMlsRustCrypto` provider, wrapped by `construct-core`'s
  `group` module. Konstruct does not re-implement the MLS state machine.

Post-quantum note: this ciphersuite is classical (X25519/Ed25519). A hybrid
PQ MLS ciphersuite is future work and is **not** part of the current design.

## 12.3 Group state model

MLS advances a group through **epochs**. Membership changes and key updates
are carried as **Proposals** that are applied by a **Commit**; a new member
is bootstrapped with a **Welcome** message. The core surfaces exactly these
concepts (`construct-core/src/group/mls_error.rs`: `EpochMismatch`,
`WelcomeError`, `CommitError`):

- **KeyPackage** — a member publishes a signed key package (an X25519 HPKE
  init key + Ed25519 credential) that others use to add it.
- **Welcome** — joining material for a newly added member; processed via
  `join_from_welcome`.
- **Commit** — applies a batch of proposals and advances the epoch; a client
  whose local epoch is behind MUST pull pending commits before sending
  (`EpochMismatch` → "pull pending commits first").

The server orders and fans out these handshake messages but, as in the 1:1
case, cannot derive the group secret — it never holds the members' HPKE
private keys.

## 12.4 Device store and persistence

OpenMLS persists all group state (ratchet-tree material, pending key
packages, epoch secrets) through its `StorageProvider`. Konstruct uses
**one long-lived provider per device** — `MlsStore`
(`construct-core/src/group/mls_store.rs`) — rather than a throwaway provider
per group, because a `Welcome` references key-package material that must
already be in the same store that later loads the group by id. The whole
store is exported for host-app persistence as a versioned CFE blob
(`CfeMlsStoreV1`, `msg_type = 0x44`; CFE envelope per
[§6.3](./06-transport.md#63-cfe--construct-frame-encoding)).

## 12.5 Implementation boundary

| Piece | Status |
|---|---|
| MLS engine (OpenMLS wrapper, ciphersuite, device store) | **Implemented** in `construct-core/src/group/`. |
| Group create / add / remove / commit / welcome plumbing | **Present** at the core API level. |
| Server group service (ordering, fan-out, key-package directory) | Partial / not covered here. |
| Client group-chat product surface (UI, notifications, membership UX) | **Not shipped.** |
| Normative interop spec (wire messages, directory RPCs) | **Not written** — this chapter is descriptive only. |
| Hybrid PQ group ciphersuite | Future work. |

Until the interop spec and the shipping surface exist, a second
implementation cannot target Konstruct groups from this document alone. That
work is tracked as a future revision; see [Implementation
Status](./07-implementation-status.md).
