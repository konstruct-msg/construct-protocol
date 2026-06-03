# Threat Model

> *This chapter is a stub — to be written in v0.1.*

Konstruct is designed against the following adversary classes. Anything
not listed here is **out of scope**: we do not claim defence against it.

- **Network adversary** — passive recording, active MitM, DPI / traffic
  classification.
- **Server adversary** — honest-but-curious, malicious, fully
  compromised.
- **Historical device adversary** — post-facto compromise of a key
  after a session ran.
- **Spam / Sybil adversary** — automated mass registration.

Explicitly **out of scope**: live compromise of an unlocked device at
decrypt time; compromise of the OS / kernel / secure enclave;
hardware-level side channels (Spectre, power analysis); nation-state
Sybil attacks with sufficient resources to perform identity
verification at population scale.

*Detailed adversary capabilities, security goals (confidentiality,
forward secrecy, post-compromise security, replay resistance, etc.),
trust assumptions, and concrete attack scenarios will be written out
in the next revision.*
