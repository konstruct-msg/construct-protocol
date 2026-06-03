# Identity & Key Hierarchy

> *Stub — to be written in v0.1.*

This chapter will document:

- The five long-term and medium-term key types each Konstruct identity holds
  (identity key, signing key, signed prekey, one-time prekeys, PQ KEM
  prekeys), their crypto suite mapping, lifetimes, and rotation schedule.
- The derivation chain from these long-term keys to per-session root keys,
  per-chain keys, and per-message keys.
- How session IDs are derived deterministically by both sides and used as
  associated data in the Double Ratchet AEAD.
- Where each key type lives at rest (platform keychain, encrypted blob,
  or plain Rust memory) and what attacker has to compromise to extract it.
