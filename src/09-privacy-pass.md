# Anti-Abuse: Privacy Pass Tokens

Sealed sender ([Chapter 8](./08-metadata-privacy.md)) removes the sender's
identity from what a server can read. That also removes the server's usual
per-sender abuse lever: it can no longer rate-limit "this account is
flooding" because it does not know which account sent a sealed message.
Konstruct restores an abuse lever **without** re-introducing an identity —
anonymous, single-use **Privacy Pass** tokens. This chapter specifies the
verifiable Oblivious Pseudo-Random Function (VOPRF) they are built on, the
issuance and redemption flows, and — the security-critical part — the
zero-knowledge proof that stops a *malicious* issuer from turning the tokens
themselves into a de-anonymising tag.

## 9.1 Design requirement

A token must satisfy two properties at once:

- **Unlinkable**: the server that *redeems* a token cannot connect it to the
  issuance event that minted it, nor to the account that requested it.
- **Unforgeable & one-time**: only the server's secret issuer key can mint a
  valid token, and each token spends exactly once.

A blind VOPRF gives both: the client blinds its token material before
issuance, so the issuer signs something it cannot read; the client then
unblinds to a value only it holds; redemption re-derives and checks that
value. Double-spend is caught by a server-side seen-set.

## 9.2 The VOPRF construction

- Group: **Ristretto255**; `G = RISTRETTO_BASEPOINT_POINT`. Points are
  32-byte canonical compressed encodings; scalars are 32-byte canonical
  little-endian.
- Hash-to-group: `H(x) = RistrettoPoint::from_hash(SHA-512(x))`.
- Issuer secret: a scalar `k`; its public commitment is `K = k·G` (§9.5).

Let `nonce` be 32 random bytes chosen by the client, and `r` a random
blinding scalar.

```
Client blind:     T = H(nonce);   B = r·T                    → send B
Server evaluate:  Z = k·B                                    → return Z (+ DLEQ proof, §9.5)
Client unblind:   N = r⁻¹·Z = k·T
Token:            token = HKDF-SHA512( compress(N) ‖ nonce, info="ConstructPP-v1" )[0..32]
```

The client stores `(token, nonce)` in a local wallet and later presents the
pair when spending. At redemption the server recomputes the same value from
`nonce` and its own `k`:

```
verify:  N' = k·H(nonce);   token' = HKDF-SHA512( compress(N') ‖ nonce, "ConstructPP-v1" );
         accept iff constant_time_eq(token, token')
```

Reference: redemption `verify_token`
(`construct-crypto/src/privacy_pass.rs:174`); token derivation
`derive_token` (`:158`); the `k` is `from_bytes_mod_order`-reduced
identically on both sides (`:174` comment) — a mismatch there issues fine
but fails every redemption.

## 9.3 Issuance and issuance caps

Tokens are minted by identity-service `issue_tokens`
(`identity-service/src/main.rs:907`). The request carries the blinded
points `Bᵢ`; the response returns the evaluations `Zᵢ = k·Bᵢ`, the issuer
commitment `K` (`server_pubkey`, proto field 2), the batched DLEQ proof
(field 3), and `issuer_key_version` (field 4). Because the points are
blinded, the issuer cannot read the token material it signs.

Anti-abuse at issuance is an **age-tiered per-account hourly cap**
(`effective_issuance_cap`, `identity-service/src/main.rs:65`, applied
`:952`): a young account (below `TOKEN_ISSUANCE_MATURITY_HOURS`, default
24 h) is capped at `TOKEN_ISSUANCE_YOUNG_MAX_PER_HOUR` (default 30); a
matured account at `TOKEN_ISSUANCE_MAX_PER_HOUR` (default 120). An
account-age lookup failure fails safe to the young cap. The client wallet
tops up reactively toward the cap as it spends and bootstraps an initial
batch at registration.

## 9.4 Redemption, double-spend, and policy

A sealed send MAY carry the spent token in `SealedInner.token_nonce` /
`SealedInner.token_bytes` ([Chapter 8 §8.2](./08-metadata-privacy.md)). The
token bytes are themselves sealed to the destination server's X25519 key
(`open_sealed_token_bytes`, `construct-crypto/src/privacy_pass.rs:107`;
client seals with the key delivered over the authenticated
`GetSenderCertificateResponse`), so a relay operator cannot read the spent
token in transit.

The server redeems via `redeem_token_checked`
(`messaging-service/src/envelope.rs:208`), which runs `verify_token` and a
single-use check (a Redis seen-set keyed by the token, `SET NX`). Outcomes
map to a typed `TokenRejected` error (`envelope.rs:18`) with a
`FAILED_PRECONDITION "privacy_pass:{label}"` status (labels:
`missing_token` / `invalid_token` / `double_spent` / `decrypt_failed` / …).

Enforcement is governed by `MSG_STEALTH_TOKEN_POLICY`
(`envelope.rs:192`), a three-way switch:

| Policy | Behaviour |
|---|---|
| `off` | tokens ignored. |
| `warn` | **current production** — tokens verified and the result logged, but a bad/absent token does **not** block delivery. Anti-abuse degraded, anonymity intact. |
| `enforce` | a bad/absent token fails the send with the typed error. **Deferred past 1.0** (§9.6). |

The client's response to an `enforce` rejection is **never** to fall back to
an identified send — it force-replenishes the wallet, rebuilds the sealed
envelope with a fresh token, and retries the sealed path once
(`StealthSendRecovery.swift`; the [Chapter 8 §8.4](./08-metadata-privacy.md#84-always-on-scope-and-the-fail-closed-invariant)
fail-closed invariant). A server that could force identified sends by
rejecting tokens could otherwise deanonymise on demand.

## 9.5 Verifiable issuance — batched DLEQ

Blinding hides the token from an *honest-but-curious* issuer. It does **not**
by itself stop a *malicious* issuer from a **key-tagging** attack: a
compromised server could evaluate a targeted user under a unique per-user
secret `kᵤ` while still publishing `K = k·G`, silently marking that user's
tokens so they de-anonymise the sealed sender at redemption.

The defence is a **batched Chaum–Pedersen DLEQ proof** returned with each
issuance: a non-interactive zero-knowledge proof that *every* `Zᵢ` was
evaluated with the *same* scalar `k` whose commitment `K = k·G` is published.
A per-user `kᵤ` produces a proof that **fails**, so the client rejects the
tokens instead of unknowingly carrying a tag.

The commitment is published at `/.well-known/construct-server` as
`token_issuer_public` (= `K`) and `token_issuer_key_version`. The client
**pins** `K` per version and verifies each response's proof against the
*pinned* `K` — it must **not** trust the `server_pubkey` echoed in the
response as the commitment, which would defeat the purpose.

The transcript is a **client-parity contract** — iOS and Android reimplement
verification byte-for-byte; any change is a flag-day break (bump the domain
string). Full spec: construct-docs `cryptocore/privacy-pass-dleq-v1.md`;
reference `construct-crypto/src/privacy_pass.rs` (`DLEQ_DOMAIN:195`,
`issuer_public_key:221`, `generate_dleq_proof:274`, `verify_dleq_proof:313`).

- `DOMAIN = "ConstructPP-DLEQ-v1"` (ASCII, 19 bytes). Context tags: `0x00`
  seed, `0x01` coefficient, `0x02` nonce, `0x03` challenge.
- Hash-to-scalar: SHA-512 wide reduction over the concatenated byte-strings.

For a batch `(Bᵢ, Zᵢ)`, `i = 0..n`, in request order:

```
Composites (prover and verifier, identical):
  seed = SHA512( DOMAIN ‖ 0x00 ‖ K ‖ (B_0‖Z_0) ‖ … ‖ (B_{n-1}‖Z_{n-1}) )
  d_i  = SHA512→scalar( DOMAIN ‖ 0x01 ‖ seed ‖ u32_be(i) ‖ B_i ‖ Z_i )
  M    = Σ_i d_i·B_i ,   Zc = Σ_i d_i·Z_i

Prove (server; needs k):
  t  = SHA512→scalar( DOMAIN ‖ 0x02 ‖ k ‖ M ‖ Zc )     // deterministic nonce
  c  = SHA512→scalar( DOMAIN ‖ 0x03 ‖ K ‖ M ‖ Zc ‖ t·G ‖ t·M )
  s  = t + c·k ;   proof = c ‖ s                        // 64 bytes

Verify (client / auditor):
  A1' = s·G − c·K ,   A2' = s·M − c·Zc
  c'  = SHA512→scalar( DOMAIN ‖ 0x03 ‖ K ‖ M ‖ Zc ‖ A1' ‖ A2' )
  accept iff c' == c   (constant-time)
```

The deterministic nonce `t = H(DOMAIN ‖ 0x02 ‖ k ‖ M ‖ Zc)` binds the secret
`k` and the statement `(M, Zc)` (which never repeats across distinct
batches), so no RNG is used and there is no nonce-reuse-leaks-`k` failure
mode. A known-answer test vector pins the whole transcript
(`privacy_pass::tests::dleq_kat_vector`; proof prefix
`a5fc4353…`).

## 9.6 Status and honest limits

| Piece | Status |
|---|---|
| VOPRF issuance + redemption (`verify_token`) | **Implemented**, in production. |
| Age-tiered issuance cap | **Implemented** (`identity-service/src/main.rs:65`). |
| Token enforcement (`MSG_STEALTH_TOKEN_POLICY`) | **`warn`** in production; `enforce` **deferred past 1.0**. |
| DLEQ proof — server issuance | **Implemented** (`construct-crypto/src/privacy_pass.rs`). |
| DLEQ verification — client (iOS pinned `K` v1) | **Implemented** and device-confirmed. |
| Well-known publication of `token_issuer_public` | Operational step to fully activate client pinning across versions. |

**Claim boundary.** Until token *enforcement* is on `enforce` **and** every
client hard-verifies the DLEQ against a pinned commitment, Konstruct claims
sender-unlinkability against an **honest-but-curious** server, not against a
**malicious/compromised** one. The DLEQ machinery is what upgrades that
claim; it is shipped on the server and verified on iOS, but the end-to-end
guarantee is only load-bearing once `enforce` relies on it. Marketing and
threat-model text must not over-claim past this line — see
[Threat Model](./01-threat-model.md).

## 9.7 References

- `construct-crypto/src/privacy_pass.rs` — VOPRF (`verify_token:174`,
  `derive_token:158`, `open_sealed_token_bytes:107`) and DLEQ
  (`DLEQ_DOMAIN:195`, `issuer_public_key:221`, `generate_dleq_proof:274`,
  `verify_dleq_proof:313`).
- `identity-service/src/main.rs` — issuance (`issue_tokens:907`) and caps
  (`effective_issuance_cap:65`).
- `messaging-service/src/envelope.rs` — redemption + policy
  (`redeem_token_checked:208`, `TokenRejected:18`, policy switch `:192`).
- Client (`construct-ios`): `BlindTokenService`, `StealthSendRecovery.swift`.
- Contract / rationale (construct-docs): `cryptocore/privacy-pass-dleq-v1.md`;
  `decisions/stealth-phase-c-verifiable-voprf`,
  `sealed-sender-anti-abuse-economics`.
