# Voice and Video Calls

Konstruct carries 1:1 real-time calls over WebRTC. This chapter specifies
how call **setup** is protected by the same end-to-end cryptography as
chat, and how the call **media** is encrypted between the two devices — and
states honestly what the connectivity layer still exposes.

Status: **audio 1:1 is implemented**; video is wired through the
call-entry UI but the media layer is not yet enabled
(`construct-ios` `Services/Calls/CallsFeature.swift:14`,
`isVideoEnabled = false`). Group calls / SFU are out of scope
([Chapter 7](./07-implementation-status.md)).

## 10.1 Two planes: signalling and media

A WebRTC call has two data planes:

- the **signalling** plane — the SDP offer/answer that negotiates codecs
  and keys, and the ICE candidates that discover a network path;
- the **media** plane — the actual encrypted audio/video (SRTP).

Konstruct's property is that the signalling plane rides the existing
end-to-end-encrypted message path, and because the media keys are agreed
*inside* that signalling, the media plane is end-to-end encrypted between
the two devices too.

## 10.2 Signalling over the E2EE path

SDP offers/answers and ICE candidates are not sent to the server in the
clear. They are encrypted with the peer's Double Ratchet session
([Chapter 5](./05-message-encryption.md)) as call-signal messages
and are **sealed** like any other in-scope user traffic
([Chapter 8](./08-metadata-privacy.md)) — so the server can read neither
the SDP (which carries the DTLS fingerprints and ICE ufrag/pwd) nor the
sender identity. On the ordinary message path, the real call content type
(`12`) rides inside the encrypted KNST frame; `SealedInner.content_type`
and the outer envelope remain `UNSPECIFIED`
(`construct-ios` `Services/Calls/CallManager.swift:1295`-`:1300`).
The client-side framing that carries the suite id and PQ ratchet fields
for a call signal is `CallSignalCrypto` (`Services/Calls/CallSignalCrypto.swift:87`-`:104`);
orchestration is in `Services/Calls/CallManager.swift`.

Two delivery routes exist, both E2EE:

- the **message path** — the first offer is typically delivered E2EE ahead
  of the answer (a backgrounded callee is woken by a PushKit VoIP token
  that carries no call content);
- a low-latency **signal stream** (`SignalingService.Signal`, opened via
  `SignalingServiceClient`) for real-time exchange once both peers are
  live. The server relays these frames without being able to decrypt them.

**ICE candidate batching.** ICE candidates are flushed in size-bounded
batches to stay under the signalling rate limit and, critically, under the
padded-frame size cap — Suite-3 PQ blobs per candidate can otherwise
overflow a single frame and drop the whole batch, so the client splits a
large flush into chunks (`CallManager.swift`,
`Shared_Proto_Signaling_V1_IceCandidate`).

TURN credentials for relayed connectivity are fetched per call
(`SignalingServiceClient.getTurnCredentials`).

## 10.3 Media encryption

Call media uses WebRTC's standard **DTLS-SRTP**. The DTLS handshake that
establishes the SRTP keys authenticates itself with certificate
fingerprints — and those fingerprints are exchanged **inside the SDP**,
which travelled over the E2EE signalling channel above. An active
network attacker therefore cannot substitute its own DTLS fingerprints
(that would require forging an E2EE-authenticated SDP), so for a 1:1 call
the media is **end-to-end encrypted between the two devices**. No
application-layer media re-encryption (e.g. SFrame) is required for the
two-party case; SFrame would only be needed for a future group/SFU
topology where a server forwards media.

Neither the Konstruct server nor a TURN relay used for NAT traversal can
decrypt the media: a TURN relay forwards only opaque SRTP.

## 10.4 What the connectivity layer still exposes

Honest counterpart to §10.1 — even with signalling sealed and media
DTLS-SRTP-encrypted:

| Exposure | Note |
|---|---|
| That a call is being set up, and its timing | The signal exchange and TURN-credential fetch are observable as events (sealed, but present). |
| Participants' **network addresses** | ICE exchanges candidate IP:port pairs so the devices can find a path; a TURN relay sees both peers' addresses. This is connection metadata, not call content. |
| Media **timing / volume** | Inherent to real-time media; not hidden. |
| Call **content** (audio/video) | Not exposed — DTLS-SRTP, keyed via E2EE signalling. |

Because ICE reveals network addresses to establish direct connectivity, a
privacy-maximising user who wants to hide their address from the peer or a
relay should force TURN-relayed connectivity (so only the relay's address
is shared with the peer) or route through a network-layer anonymiser; this
is a connectivity/anonymity trade-off, not a content-confidentiality one.

## 10.5 References

- Client (`construct-ios`): `Services/Calls/CallManager.swift`,
  `Services/Calls/CallSignalCrypto.swift`,
  `Services/Calls/WebRTCSession.swift`,
  `Services/Calls/CallsFeature.swift`;
  `Networking/gRPC/Services/SignalingServiceClient.swift`.
- Protos: `konstruct-msg/construct-protos` `signaling` package
  (`IceCandidate`, `Signal`).
- Sealing of call signals: [Chapter 8](./08-metadata-privacy.md); message
  encryption: [Chapter 5](./05-message-encryption.md).
- Design detail (construct-docs): `client/specs/CALLS_CLIENT_SPEC.md`.
