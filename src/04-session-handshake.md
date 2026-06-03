# Session Handshake (X3DH + PQXDH)

> *Stub — to be written in v0.1.*

This chapter will document:

- The X3DH handshake variant used by Konstruct, including the prologue
  string, KDF labels, AD construction, and the difference between the
  initiator and responder paths.
- The PQXDH extension: how the ML-KEM-768 shared secret is mixed in,
  why it is applied deferred at the post-first-ratchet root key (RK1)
  rather than at the initial root derivation, and what the responder
  has to persist to make the deferred contribution survive an app
  restart.
- The bundle freshness rule (SPK timestamp + rotation epoch) and the
  responder-side validation introduced after the v1.0 audit.
- A worked example with concrete byte counts for every wire field.

Until this chapter lands, the X3DH and PQXDH implementations live in
`construct-core/src/crypto/handshake/x3dh.rs` and
`construct-core/src/crypto/pq_x3dh.rs` respectively.
