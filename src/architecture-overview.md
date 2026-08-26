# Architecture Overview

> **Orientation chapter.** This is the map of the whole system: how the
> cryptographic core ([Message Encryption](./05-message-encryption.md)) and
> the [Transport Layer](./06-transport.md) fit together, and how Konstruct
> stays reachable as a network operator turns hostile. It is *descriptive
> architecture* — normative (RFC 2119) requirements live in the per-component
> chapters it points to. For the authoritative per-component build state, see
> [Implementation Status](./07-implementation-status.md).

Konstruct is a layered system with **one invariant at the bottom and a ladder
of reachability strategies above it**. The invariant: end-to-end encryption is
always on and never depends on any server (see [Threat Model](./01-threat-model.md)
and [Message Encryption](./05-message-encryption.md)). Everything above the
crypto core exists to answer a single question — *can this message reach its
recipient?* — as the network becomes more adversarial, degrading gracefully
from a fast direct connection down to a device-to-device mesh that needs no
network at all.

## Design position

Four goals pull against one another. Konstruct takes a deliberate position
rather than pretending to maximise all four at once:

| Goal | Position |
|---|---|
| **Security (E2EE)** | A *floor*, not a tradeoff. Content confidentiality/integrity is always on and independent of any server. |
| **Censorship-resistance** | The *primary driver*. The hardest tier is a national **allowlist** (only an explicit set of destinations is reachable), which pure obfuscation cannot cross. |
| **Usability** | Kept high. Entry selection, relay choice, and re-homing are designed to require no user configuration. |
| **Anonymity** | Metadata *minimisation* (sealed sender), **not** network-layer unlinkability. Konstruct deliberately does **not** run a mixnet. |

The anonymity position is load-bearing enough to state precisely. Konstruct
provides **pseudonymity with no real-world anchor**, not unlinkability against
a global observer:

| Provided | Not provided (deliberately out of scope) |
|---|---|
| Identity is a **public key** — registration is passwordless, with no phone number, email, or mandatory username. There is no personal datum to link an account to a real person, even under full server seizure. | **Network-layer unlinkability** — who-talks-to-whom against an adversary who can watch both legs of a relay or correlate timing. That is a mixnet's job; a single relay hop hides the user's IP, not the linkage. |
| Sealed sender removes sender identity from the delivery path for sealed traffic. | It does not erase pre-existing server-side contact records or hide the recipient from the delivery node. |

A mixnet (Sphinx packets, per-hop cover traffic) would add network-layer
unlinkability at a large cost to usability and — being enumerable — to
censorship-resistance itself. For Konstruct's users that tradeoff is not worth
it; the sealed-sender ceiling is the accepted metadata boundary.

## The layered model

Above the always-on cryptographic floor, the system is five layers plus an
offline foundation. Each is a distinct concern with its own implementation;
they are composed, not merged.

```
   always-on floor ─── E2EE (Double Ratchet · sealed sender)  ·  identity = public key (no PII)
   ══════════════════════════════════════════════════════════════════════════════════════
   ▲ outward path
   │  Transport        move bytes + obfuscation   (QUIC/H3 · veil-front HTTPS · H2 fallback)
   │  EntryDirectory   find a reachable, un-burned entry point
   │  RouteLayer       a single proxy hop that hides the user's IP from the server
   │  Overlay          location-independent addressing & discovery (route_id, DHT)
   │  Delivery         federation, store-and-forward, trust posture
   ▼
   Mesh floor          device-to-device with no network at all   (foundation)
```

| Layer | Role | Where it lives | Status |
|---|---|---|---|
| **Transport** | Carry bytes; obfuscate them where a censor inspects. Two stacks — engine-QUIC/H3 for speed everywhere, veil-front HTTPS for censored networks — selected by one client-side router. | `construct-engine`, `construct-veil`, iOS `TransportRouter` | Both stacks implemented; plain QUIC and veil-front in production use. |
| **EntryDirectory** | Discover a live entry point the censor has not blocked, and rotate off blocked ones without user action. | client + backend (design) | Designed; not yet implemented. |
| **RouteLayer** | One proxy hop hiding the user IP from the home server (IP-hiding, not unlinkability). | veil-front relay | The single-hop model is the accepted design; deeper anonymity (mixnet) is explicitly out of scope. |
| **Overlay** | Address an account by a location-independent identifier so it stays reachable after it moves. | `construct-core`, backend | Identity key + `route_id` present; dual-addressing and DHT discovery planned. |
| **Delivery** | Server-to-server sealed delivery between independent deployments; a seizure-safe relay posture; two domestic nodes forming a self-contained island. | `construct-core` (federation), relay profiles | Federation implemented; multi-node interoperability test outstanding. |
| **Mesh floor** | Keep 1:1 messaging alive with no internet and no server, over local radio. | design (see below) | Analysis only; a proof-of-concept spike is the next step. |

`route_id` is the SHA-256 of the account's identity public key. Because it is
derived from the key and carries no location, an account can move between
servers (or onto a domestic island, or onto the mesh) and remain addressable —
this is what makes zero-configuration re-homing and the offline mesh share one
identity model.

## Graceful degradation by network tier

The layers active at any moment depend on how hostile the network is. The same
system reconfigures itself down the ladder:

| Layer | Free (no censor) | Moderate–hard DPI (blacklist) | Allowlist island (whitelist) | Blackout (no network) |
|---|---|---|---|---|
| **Transport** | plain QUIC, direct | veil-front, obfuscated HTTPS | obfuscation optional, in-zone | mesh links (WiFi-Direct / BLE) |
| **EntryDirectory** | — | discover a foreign entry | discover a *domestic* entry | — |
| **RouteLayer** | — | one hop, hide IP | — | — |
| **Overlay** | `route_id` | `route_id` | in-zone (island) DHT | mesh announce, no server |
| **Delivery** | home server | foreign, federated | domestic island, no foreign egress | store-carry-forward, delay-tolerant |

Two properties of this table matter. First, **obfuscation answers "can they
tell what this is?", not "can this arrive at all?"** — under an allowlist the
censor drops a packet by destination before inspecting it, so the answer there
is not a better disguise but an in-zone deployment that never needs to cross the
border (in-country federation, a domestic-only overlay). Second, **veil-front
has no transport fallback beneath it**; if its relay is blocked, reachability
depends on the EntryDirectory layer having diverse entries, and ultimately on
the mesh floor. The layers are coupled: finishing the transport is not the same
as finishing censorship-resistance.

## The offline mesh floor (design)

The lowest rung keeps two people messaging with no infrastructure at all — a
total blackout or a fully sealed island. It is a **parallel offline mini-stack**
that supplies its own addressing, routing, and store-carry-forward, and it
carries **opaque Konstruct end-to-end payloads** — it does not replace the
message crypto.

The design direction adopts **Reticulum** (a cryptographic networking stack
that routes over any medium) as the overlay, for two reasons: its
destination addressing is a hash of a public key, which maps directly onto
Konstruct's `route_id`; and it is medium-agnostic, so "which radio" becomes a
pluggable interface rather than a new routing engine.

| Interface | Range | Bandwidth | Platform reach | Role |
|---|---|---|---|---|
| WiFi-Direct / Wi-Fi Aware (Android); Multipeer/AWDL (iOS) | ~50–100 m | high | same-platform only (the two do not interoperate) | preferred high-bandwidth link |
| **BLE** | ~10 m | low | iOS + Android | the cross-platform floor |
| LoRa | kilometres | very low (duty-cycle limited) | companion radio hardware | long-range, later |

Message security remains Konstruct's end-to-end layer; a mesh relay learns no
more than an online sealed-sender relay does. This rung is **analysis-stage**:
the gating questions are the Rust implementation path and cross-platform local
interoperability, to be resolved by a laptop-first spike before any mobile work.

## What the architecture does and does not provide

Consistent with [Transport §6.6](./06-transport.md), stated for the whole system:

**Provided:** content confidentiality and integrity (E2EE, always on); no link
between an account and a real-world person; sealed sender removing sender
identity from sealed delivery requests; the user's IP hidden from the home
server; the home server's IP hidden from the censor; and continued operation as
the network degrades — including, by design, with no network.

**Not provided:** unlinkability of who-talks-to-whom against an adversary who
observes both ends or correlates timing; recipient identity at the delivering
node; connection metadata (times, sizes, IPs a relay itself sees). A single
relay hop is IP-hiding, not anonymity, and Konstruct does not claim otherwise.

## Where the detail lives

| For | Read |
|---|---|
| Who the system protects against | [Threat Model](./01-threat-model.md) |
| The cryptographic floor these layers carry | [Message Encryption](./05-message-encryption.md) |
| Normative transport, CFE, and VEIL requirements | [Transport Layer](./06-transport.md) |
| The authoritative, per-component build state | [Implementation Status](./07-implementation-status.md) |
