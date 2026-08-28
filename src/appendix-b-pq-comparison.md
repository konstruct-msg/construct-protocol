# Appendix B — Post-Quantum Designs in Other Deployed Messengers

This appendix situates Konstruct's post-quantum construction against the
other post-quantum messaging designs that are publicly documented and
deployed at scale. It exists because the design decisions in
[Chapter 2 §2.4](./02-cryptographic-primitives.md#24-suite-3--sparse-continuous-pq-ratchet)
and [Chapter 4 §4.5](./04-session-handshake.md#45-pqxdh-suite-2--post-quantum-extension)
are not novel in kind, and a reader should be able to see which parts
are conventional and which are ours.

Claims about other systems are sourced from their published
specifications and are dated; claims about Konstruct cite the reference
implementation, as required by the editorial rule.

## B.1 The shared shape

Every deployed design in this space, Konstruct included, follows the
same two-part pattern:

1. A post-quantum KEM (ML-KEM-768 in all four systems below) is run
   **alongside** a classical Diffie–Hellman, never instead of it, and
   the two secrets are combined through a KDF so that an adversary must
   break both.
2. The classical Double Ratchet is left intact, and post-quantum
   material is layered on top of it rather than replacing its DH
   ratchet.

The differences are in *when* fresh KEM material is introduced after
the handshake, and *how* the large KEM objects are carried.

## B.2 Handshake-only versus continuing

| System | PQ at handshake | PQ after handshake |
|---|---|---|
| Signal PQXDH (2023) | yes | no |
| Apple iMessage PQ3 (2024) | yes | yes — periodic rekey |
| Signal Triple Ratchet / SPQR (Oct 2025) | yes | yes — continuous chunked ratchet |
| Konstruct Suite 2 | yes (§4.5) | no |
| Konstruct Suite 3 | yes | yes — sparse periodic rekey (§2.4) |

Signal's PQXDH was the first at-scale deployment and deliberately
covered only the initial handshake, which means it provided no
post-quantum post-compromise security: a session that ran for months
rested on a single KEM contribution made at its start. Apple's PQ3 and
Signal's later SPQR both exist to close that gap, and Konstruct's Suite
3 addresses the same gap by the same reasoning.

Konstruct Suite 2 alone therefore sits at the PQXDH level. The
continuing property requires Suite 3, which is negotiated separately
(§2.4).

## B.3 Rekey cadence

| System | Cadence |
|---|---|
| Apple PQ3 | approximately every 50 messages, **and at least once every 7 days** |
| Signal SPQR | continuous — a new exchange proceeds as fast as message flow allows |
| Konstruct Suite 3 | every 16 DH-ratchet turns; no time-based floor |

The three units are not comparable directly. Konstruct counts DH
ratchet turns — changes of conversational direction — so a one-sided
burst of any length makes no progress, while an alternating exchange
rekeys after sixteen turns. Apple counts messages and additionally
guarantees a floor in wall-clock time; Signal is bounded only by how
fast chunks can be carried.

Konstruct is the only one of the three with no time-based floor. A
conversation that alternates a few times a month rekeys at that rate,
and one that never alternates does not rekey at all.

## B.4 Carrying the KEM objects

ML-KEM-768 encapsulation keys are 1184 bytes and ciphertexts 1088
bytes, against 32 bytes for an X25519 public key. Each system resolves
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
- **Konstruct Suite 3** sends each object whole in the frame's PQ
  section ([Chapter 5 §5.3](./05-message-encryption.md#53-wire-format-wirepayload-header)),
  and re-attaches it to every outgoing message until implicitly
  acknowledged (§2.4.2 rule 2). Loss is therefore recovered by
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
carry any pending PQ field on send (§2.4.1). A device that is online
and acknowledging therefore keeps the exchange moving whether or not
its user replies.

## B.6 Granularity of the post-quantum guarantee

This is the sharpest difference and worth stating precisely.

Signal's SPQR carries its own symmetric chain inside the post-quantum
component, so the post-quantum contribution ratchets between rekeys and
the post-quantum half of forward secrecy has the same per-message
granularity as the classical half.

Konstruct's Suite 3 derives every message key of an epoch from the same
`pq_epoch_secret` (§2.4.2 rule 5). Within an epoch the post-quantum
contribution is a constant. Forward secrecy at message granularity is
supplied by the classical Double Ratchet, which is unmodified and
continues to provide it; what is coarser is specifically the
post-quantum component, whose granularity is the epoch rather than the
message.

The practical reading: an adversary who obtains one epoch secret — and
who can also break X25519 — recovers the messages of that epoch.
Against an adversary who can break neither, or only one of the two, the
guarantee is unchanged.

## B.7 Group messaging

Konstruct's group path is MLS ([Chapter 12](./12-group-messaging.md)).
Post-quantum MLS cipher suites combining ML-KEM with traditional
elliptic-curve KEMs are specified in an IETF draft
(`draft-ietf-mls-pq-ciphersuites`) and are not adopted here; the
group path is classical today.

Matrix, for comparison, uses Olm/Megolm and has no deployed
post-quantum layer; its published direction is migration to MLS, which
would inherit MLS's post-quantum cipher suites when those are adopted.

## B.8 Formal analysis

Signal's SPQR implementation is machine-checked with Hax and F* for
panic-freedom and field-arithmetic correctness, with ProVerif models of
the protocol properties; the underlying construction was published at
Eurocrypt 2025 and USENIX Security 2025. Apple's PQ3 received an
independent mechanised analysis published at USENIX Security 2025.

Konstruct's construction has received no formal analysis. This is
stated as a fact about the current state of the work, not as a
deficiency claim about the construction.

## B.9 Sources

- [Signal — Signal Protocol and Post-Quantum Ratchets](https://signal.org/blog/spqr/) (2 October 2025)
- [signalapp/SparsePostQuantumRatchet](https://github.com/signalapp/SparsePostQuantumRatchet)
- [Apple Security Research — iMessage with PQ3](https://security.apple.com/blog/imessage-pq3/) (2024)
- [A Formal Analysis of Apple's iMessage PQ3 Protocol](https://www.usenix.org/conference/usenixsecurity25/presentation/linker), USENIX Security 2025
- [ML-KEM and Hybrid Cipher Suites for MLS](https://www.ietf.org/archive/id/draft-mahy-mls-pq-00.html), IETF draft
- [Olm & Megolm — Matrix Specification](https://spec.matrix.org/unstable/olm-megolm/)
