# Appendix B — Post-Quantum Designs in Other Deployed Messengers

This appendix situates Konstruct's post-quantum construction against the
other post-quantum messaging designs that are publicly documented and
deployed at scale. It exists because the design decisions in
[Chapter 2 §2.4](./02-cryptographic-primitives.md#24-suite-4--sparse-continuous-pq-ratchet-per-message-chains)
and [Chapter 4 §4.3](./04-session-handshake.md#43-initiator-path)
are not novel in kind, and a reader should be able to see which parts
are conventional and which are ours.

Claims about other systems are sourced from their published
specifications and are dated; claims about Konstruct cite the reference
implementation, as required by the editorial rule.

## B.1 The shared shape

Every deployed design in this space, Konstruct included, follows the
same two-part pattern:

1. A post-quantum KEM is run **alongside** a classical Diffie–Hellman, never instead of it, and
   the two secrets are combined through a KDF so that an adversary must
   break both.
2. The classical Double Ratchet is left intact, and post-quantum
   material is layered on top of it rather than replacing its DH
   ratchet.

The differences are in *when* fresh KEM material is introduced after
the handshake, and *how* the large KEM objects are carried.

The parameter split is shared too: Signal PQXDH, Apple PQ3 and Konstruct
(since PQXDH v2, 2026-09-25) use the 1024 parameter set for the prekeys
and the initial key, and the continuing ratchets — Apple's rekey, Signal
SPQR, Konstruct Suite 4 — use ML-KEM-768. Konstruct's earlier PQXDH v1
used ML-KEM-768 and mixed its secret in only after the first DH ratchet
step, so the first chain of every session was classical; v2 puts the
secret in the initial root key.

## B.2 Handshake-only versus continuing

| System | PQ at handshake | PQ after handshake |
|---|---|---|
| Signal PQXDH (2023) | yes | no |
| Apple iMessage PQ3 (2024) | yes | yes — periodic rekey |
| Signal Triple Ratchet / SPQR (Oct 2025) | yes | yes — continuous chunked ratchet |
| Konstruct Suites 1 and 2 | yes — PQXDH v2, mandatory (§4.3) | no |
| Konstruct Suite 4 | yes | yes — sparse periodic rekey (§2.4) |

Signal's PQXDH was the first at-scale deployment and deliberately
covered only the initial handshake, which means it provided no
post-quantum post-compromise security: a session that ran for months
rested on a single KEM contribution made at its start. Apple's PQ3 and
Signal's later SPQR both exist to close that gap, and Konstruct's Suite
4 addresses the same gap by the same reasoning.

Konstruct without Suite 4 therefore sits at the PQXDH level. The
continuing property requires Suite 4, which is negotiated separately
(§2.4).

## B.3 Rekey cadence

| System | Cadence |
|---|---|
| Apple PQ3 | approximately every 50 messages, **and at least once every 7 days** |
| Signal SPQR | continuous — a new exchange proceeds as fast as message flow allows |
| Konstruct Suite 4 | every 16 DH-ratchet turns, **and at least once every 7 days** (construct-core 0.24.1) |

The three units are not comparable directly. Konstruct counts DH
ratchet turns — changes of conversational direction — while additionally bounding the epoch's
wall-clock age; Apple counts messages and also guarantees a floor in wall-clock time; Signal is
bounded only by how fast chunks can be carried.

> **Changed in construct-core 0.24.1** (PQR-1, TODO 64.1). Until then Konstruct was the only one
> of the three with no time-based floor: a one-sided conversation took no DH turn and so never
> rekeyed, however long it ran. The exchange initiator now also proposes a new epoch on its next
> send once the current one has stood for `pq_ratchet_max_age_seconds` (7 days) — the same floor
> Apple PQ3 guarantees — independent of the turn count. The gap this does not close: only the
> initiator ever proposes, so a conversation in which only the *responder* writes still cannot
> rekey by either path (§2.4.3, Chapter 7 §7.3).

## B.4 Carrying the KEM objects

In the continuing ratchets, ML-KEM-768 encapsulation keys are 1184
bytes and ciphertexts 1088 bytes, against 32 bytes for an X25519 public
key. (Konstruct's handshake ciphertext is ML-KEM-1024, 1568 bytes, and
rides only on the initiator's first flight.) Each system resolves
this differently:

- **Apple PQ3** sends the key whole and accepts the cost, reporting
  that the PQ ratchet adds more than 2 KB to a message. The published
  rationale for rekeying only periodically is precisely that sending it
  with every message caused visible delivery delays on poor
  connectivity.
- **Signal SPQR** splits both objects into chunks protected by
  Reed–Solomon systematic erasure codes, spread across message headers:
  roughly 36 and 30 chunks for the two bulk phases, so that any
  sufficient subset reconstructs the object regardless of loss or
  reordering. The published design also splits the encapsulation key
  into a 64-byte seed-plus-hash phase and a bulk phase so the two
  directions can transmit in parallel.
- **Konstruct Suite 4** sends each object whole in the frame's PQ
  section ([Chapter 5 §5.3](./05-message-encryption.md#53-wire-format-wirepayload-header)),
  and re-attaches it to every outgoing message until implicitly
  acknowledged (§2.4.4 rule 2). Loss is therefore recovered by
  repetition rather than by redundancy, at a cost of 1184 or 1088 bytes
  per outgoing message for the duration of an unacknowledged exchange.

## B.5 Advancing without a reply

A rekey that needs a message in the opposite direction stalls in a
one-sided conversation. Apple PQ3 addresses this explicitly by letting
encrypted delivery receipts carry the ratchet forward, so a device that
is merely online completes the exchange without the user replying.

Konstruct obtains the same property without a dedicated mechanism.
Delivery receipts are ordinary session frames — they are encrypted
through the same ratchet as any message (content type 14 inside the
frame) — so they advance the DH ratchet turn counter on receipt and
carry any pending PQ field on send (§2.4.3). A device that is online
and acknowledging therefore keeps the exchange moving whether or not
its user replies.

## B.6 Granularity of the post-quantum guarantee

> **Changed 2026-09-30** (construct-core 0.24.0, PQR-2). Until then this section described a real
> asymmetry: Konstruct's Suite 3 derived every message key of an epoch from one stored
> `pq_epoch_secret`, so the post-quantum contribution was constant within an epoch while the
> classical half already ratcheted per message. That gap is closed. What follows is the current
> state, kept honest about what changed and when rather than rewritten as if it had always been
> true.

Signal's SPQR carries its own symmetric chain inside the post-quantum
component, so the post-quantum contribution ratchets between rekeys and
the post-quantum half of forward secrecy has the same per-message
granularity as the classical half.

Konstruct's Suite 4 now does the same in kind, by a different mechanism. A completed epoch's
ML-KEM-768 secret is spent once, into two directional chain keys (§2.4.1), and is never itself
stored; each message takes the next key of its sender's chain, and a receiver's PQ key for a read
message is derivable by neither side afterwards — the chain that produced it has already stepped
past that index (§2.4.4 rule 5). Forward secrecy at message granularity is now supplied by *both*
halves of the ratchet, where before it was the classical Double Ratchet alone.

A completed epoch, in turn, now arrives at least every 16 DH-ratchet turns or every 7 days —
whichever comes first, since `PQR-1` was resolved in construct-core 0.24.1 (§2.4.3) — rather than
only on a turn count a one-sided conversation might never reach. The practical reading: an
adversary who steals a session state now recovers no post-quantum contribution to a message
already read, regardless of epoch, whether or not they can also break X25519. What they can still
recover is the *future* of the current epoch's chains and any not-yet-consumed skipped key within
`PQ_CHAIN_RETENTION` (§2.4.3) — the same residual an equivalent compromise leaves against the
classical chain.

## B.7 Authenticating the peer

Both deployed designs authenticate the peer classically: PQXDH's
identity keys are X25519 / XEdDSA and its specification states that
authentication rests on the discrete-log problem; PQ3 signs with ECDSA
P-256. The stated reasoning is the same in both — breaking
authentication needs a quantum computer at the time of the attack, while
confidentiality has to survive one built later.

Konstruct authenticates post-quantum in both directions after the first
contact, by two different means. The initiator encapsulates to a Kyber
prekey signed by the responder's pinned hybrid (Ed25519 + ML-DSA-65) key,
so only the responder can read. The responder encapsulates to the
initiator's pinned ML-KEM-1024 identity key and mixes the secret into its
first reply, so only the initiator can continue
([Chapter 4 §4.4.4](./04-session-handshake.md#444-the-initiator-proves-its-kem-identity-key)).
The second direction uses a KEM rather than a signature on purpose: a
signature over the handshake would be a transferable proof that one
device opened a conversation with another. Both pins are trust-on-first-use,
and the initiator's first-flight messages are authenticated classically
until the responder's answer is read.

## B.8 Group messaging

Konstruct's group path is MLS ([Chapter 12](./12-group-messaging.md)).
Post-quantum MLS cipher suites combining ML-KEM with traditional
elliptic-curve KEMs are specified in an IETF draft
(`draft-ietf-mls-pq-ciphersuites`) and are not adopted here; the
group path is classical today.

Matrix, for comparison, uses Olm/Megolm and has no deployed
post-quantum layer; its published direction is migration to MLS, which
would inherit MLS's post-quantum cipher suites when those are adopted.

## B.9 Formal analysis

Signal's SPQR implementation is machine-checked with Hax and F* for
panic-freedom and field-arithmetic correctness, with ProVerif models of
the protocol properties; the underlying construction was published at
Eurocrypt 2025 and USENIX Security 2025. Apple's PQ3 received an
independent mechanised analysis published at USENIX Security 2025.

Konstruct's construction has received no formal analysis. This is
stated as a fact about the current state of the work, not as a
deficiency claim about the construction.

## B.10 Sources

- [Signal — Signal Protocol and Post-Quantum Ratchets](https://signal.org/blog/spqr/) (2 October 2025)
- [signalapp/SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet)
- [Signal — The PQXDH Key Agreement Protocol](https://signal.org/docs/specifications/pqxdh/)
- [Apple Security Research — iMessage with PQ3](https://security.apple.com/blog/imessage-pq3/) (2024)
- [A Formal Analysis of Apple's iMessage PQ3 Protocol](https://www.usenix.org/conference/usenixsecurity25/presentation/linker), USENIX Security 2025
- [ML-KEM and Hybrid Cipher Suites for MLS](https://www.ietf.org/archive/id/draft-mahy-mls-pq-00.html), IETF draft
- [Olm & Megolm — Matrix Specification](https://spec.matrix.org/unstable/olm-megolm/)
