# Message Encryption (Double Ratchet)

> *Stub — to be written in v0.1.*

This chapter will document:

- The Double Ratchet state machine: sending chain, receiving chain,
  DH ratchet step, and the conditions under which a new ratchet step
  is performed.
- Skipped-message-key management: storage limits, eviction strategy,
  and how the cleanup heuristic interacts with replay protection.
- AD (associated data) construction and the v2 → v3 migration —
  including which fields are bound to the AEAD and why each is
  necessary for resistance to specific attack classes.
- Self-healing: how a session that has gotten out of sync recovers
  without END_SESSION, the conditions under which healing is attempted
  vs giving up to a full re-handshake, and the rate limits that
  prevent healing-as-DoS.

Until this chapter lands, the Double Ratchet implementation lives at
`construct-core/src/crypto/messaging/double_ratchet/`.
