# Introduction

> **Document status:** v0.1.2 — early draft.
> **Implementation reference:** `construct-core` v0.9.x (see [Implementation Status](./07-implementation-status.md)).
> **Document license:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) ·
> **Reference implementation:** MIT.

This document is the public technical specification of the **Konstruct
messenger protocol** — what it does, how it does it, and where it
provably falls short today.

It is written against the open-source reference implementation. Every
algorithmic claim in this document is verifiable by reading the cited
source file in the `konstruct-msg/construct-core` repository. If
something in the text does not match the code, the code wins and the
text is a bug — please [open a security advisory](./disclosure.md).

> **Looking for a single-page read?**
> [→ View the whole specification as one page](./print.html) (concatenated,
> searchable with Ctrl+F).

## What Konstruct is

A messenger protocol built on the Signal Protocol design — X3DH
handshake + Double Ratchet for ongoing messaging — extended with:

- A hybrid post-quantum KEM (**ML-KEM-768**, NIST FIPS 203) layered
  alongside the classical X25519 key exchange.
- A pluggable transport layer (**VEIL**) designed to keep the messenger
  reachable when the network operator is hostile.
- A binary FFI envelope (**CFE**) so the Rust crypto core can be shared
  unchanged across iOS, macOS, Android, and desktop clients without
  exposing a JSON parsing attack surface.

## What this document is not

- **Not a security audit.** No third-party cryptographic audit has been
  performed at the time of writing. The text identifies known open
  issues but does not certify the absence of others.
- **Not a marketing site.** Public-facing positioning lives at
  [konstruct.cc](https://konstruct.cc). This document is for
  implementers, auditors, and readers who want the protocol at the
  level of cryptographic detail needed to reason about it or build a
  compatible client.
- **Not a full protocol RFC.** Wire format reference, error code
  registry, and the federation / group-chat protocols are out of scope
  for v0.1 and will land in later versions.

## Conventions

This specification uses [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
keywords (MUST, MUST NOT, SHOULD, MAY) where it makes a normative
requirement on an implementation. Descriptive prose uses ordinary
English.

Code references take the form `path/to/file.rs:LINE` and point at the
public reference implementation
([construct-core](https://github.com/konstruct-msg/construct-core)).

## Honest current status

| Area | Status |
|---|---|
| Cryptographic core (X3DH, Double Ratchet, hybrid PQ KEM) | Implemented and used in production by the iOS TestFlight build. |
| iOS / macOS client | Production-quality code, distributed via [TestFlight beta](https://testflight.apple.com/join/NH3WssFh). No public App Store release yet. |
| Android client | Phase 0 — Rust core builds, Kotlin wrapper not yet written. |
| Federation (server-to-server) | **Implemented** — inbound + outbound sealed delivery, Ed25519-signed. Multi-node interoperability test outstanding. |
| Sealed sender | **Implemented and on by default** — all outgoing user traffic (messages, receipts, call signalling, session-control handshake) is sealed and leaves no `sender_id` at rest; identified-downgrade paths are fail-closed. Privacy Pass token *enforcement* runs in `warn` mode (not `enforce`). |
| MLS group chat | Implemented in `construct-core` but not yet documented at protocol-spec level. To be added in a future revision. |
| QUIC / HTTP-3 transport | **In production** — plain QUIC (`construct-transport`), always-on with an HTTP/2 fallback. |
| VEIL veil-front (honest-front transport) | **In production** — the primary obfuscation transport for censored networks. |
| VEIL obfs4 / WebTunnel (legacy) | **Retired** — cut by active DPI in the target region; superseded by veil-front, standalone relay archived. |
| External security audit | Planned. Not yet performed. |

## Document layout

| Chapter | Audience |
|---|---|
| [Threat Model](./01-threat-model.md) | Who Konstruct protects against, who it doesn't. Read first. |
| [Cryptographic Primitives](./02-cryptographic-primitives.md) | Exact algorithm choices, key sizes, library versions. |
| [Identity & Key Hierarchy](./03-identity-key-hierarchy.md) | Long-term, medium-term, and per-session keys. |
| [Session Handshake](./04-session-handshake.md) | X3DH and the post-quantum extension PQXDH. |
| [Message Encryption](./05-message-encryption.md) | Double Ratchet, AEAD framing, associated data. |
| [Transport Layer](./06-transport.md) | gRPC over TLS, VEIL anti-censorship, CFE binary envelope. |
| [Implementation Status](./07-implementation-status.md) | What works, what's open, what's planned. |
