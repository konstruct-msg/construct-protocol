# Transport Layer

> *Stub — to be written in v0.1.*

This chapter will document:

- The on-wire framing (WirePayload + CFE binary envelope) and the
  invariants that make the FFI boundary memory-safe by construction.
- gRPC transport: bidirectional message stream, heartbeat cadence,
  reconnect behaviour.
- QUIC secondary transport (ConstructEngine) and the conditions under
  which it is preferred over gRPC over HTTP/2.
- VEIL anti-censorship layer: obfs4 pluggable transport, WebTunnel,
  the constant-shape gate, and the in-progress veil-front honest-front
  approach.
- The decision policy that chooses between transports at runtime
  (happy-eyeballs probe race, persistent scoring).

Until this chapter lands, the transport implementations live in the
`construct-veil`, `construct-engine`, and `construct-core/src/cfe/`
modules of the respective repositories.
