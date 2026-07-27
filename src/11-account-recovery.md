# Account Recovery

Konstruct has no password and no email, so the usual "reset via email"
path does not exist. Recovery is key-based and comes in two independent
mechanisms with different goals: a **12-word BIP39 phrase** that restores
*account access* on a new device, and **SLIP-39 social recovery** that
threshold-restores the identity *vault* itself. Both are implemented in the
shared Rust core so every client behaves identically.

Throughout: the recovery secrets never leave the device to the server in
the clear. The server can only ever hold a recovery *public* key — there is
no plaintext key escrow.

## 11.1 BIP39 seed-phrase account recovery

### 11.1.1 Derivation

A recovery phrase is **12 BIP39 words = 128 bits** of entropy. 12 (not 24)
is deliberate: 128 bits already matches the Ed25519 security level that the
derived key targets, so 24 words would add UX cost for no cryptographic
gain (`client/specs/ACCOUNT_RECOVERY_CLIENT_SPEC.md`).

```
seed_phrase (12 BIP39 words)
   → mnemonic_to_seed()      -- PBKDF2, 2048 rounds, no passphrase → 64-byte seed
   → BIP32 derive m/44'/0'/0'/0/0
   → Ed25519 (recovery_private_key, recovery_public_key)   -- 32 B each
```

The core exposes `generate_mnemonic`, `validate_mnemonic`,
`mnemonic_to_seed`, `derive_recovery_keypair`, and
`sign_recovery_challenge` / `verify_recovery_signature`
(construct-core BIP39/BIP32 + `ed25519-dalek`).

### 11.1.2 Setup and recovery flows

Recovery is **optional** and set up separately from registration
(recommended UX: prompt after first registration):

1. **Setup** — the client derives the recovery keypair, signs
   `"CONSTRUCT_RECOVERY_SETUP:{userId}:{timestamp}"` with the recovery
   private key, and calls `SetRecoveryKey` with the recovery **public** key
   plus the signature. The server stores only the public key.
2. **Recover** (new device) — the user enters the 12 words (checksum
   validated locally first); the client re-derives the recovery keypair,
   signs a fresh challenge, generates **new** device identity keys, and
   calls `RecoverAccount`. The server verifies the signature against the
   stored recovery public key and re-associates the account
   (`userId`) with the new device.

### 11.1.3 What it restores — and what it does not

- **Restores**: access to the same account identifier (`userId`) on a new
  device, provided the user holds the 12 words.
- **Does not restore**: the previous device's Double Ratchet sessions or
  local message history. The new device registers fresh identity keys, so
  contacts observe an identity-key change and sessions re-establish (their
  clients surface this as expected). Recovery is *account re-access*, not a
  cryptographic clone of the lost device.
- **Trust note**: possession of the 12 words is sufficient to re-take the
  account. The phrase MUST be stored as carefully as any root credential;
  §11.2 exists precisely to remove the single-phrase single point of
  failure for users who want that.

## 11.2 SLIP-39 social recovery (vault)

Social recovery targets a different goal: threshold recovery of an identity
**vault key** across several trustees or locations, so that no single share
— and no single lost phrase — can either recover *or* deny recovery of the
identity. Implemented in `construct-core/src/crypto/social_recovery.rs`.

### 11.2.1 Construction

1. A 32-byte `vault_key` protects the identity/backup bundle.
2. `vault_key` is split with **Shamir Secret Sharing over GF(2⁸)** into
   `share_count` shares requiring a `threshold` to reconstruct; both are in
   `2..=10` with `threshold ≤ share_count` (`split_secret`).
3. Each share (a 1-based index + 32 bytes + checksum) is encoded as a
   **28-word SLIP-39 mnemonic** over a 1024-word wordlist (10 bits/word).
4. Recovery: the user supplies **≥ threshold** mnemonics; the core
   validates each share checksum and reconstructs `vault_key` by Lagrange
   interpolation (`combine_shares`), then decrypts the bundle.

Because it is `t`-of-`n`, losing up to `n − t` shares still recovers, and
gaining fewer than `t` shares reveals nothing about `vault_key`.

## 11.3 Privacy and trust properties

| Property | BIP39 (11.1) | SLIP-39 (11.2) |
|---|---|---|
| Secret leaves device to server? | No — server stores only the recovery **public** key. | No — shares are held by the user/trustees; the vault ciphertext, if backed up, is opaque. |
| Single point of failure | Yes — one 12-word phrase. | No — `t`-of-`n` threshold. |
| Restores | Account access (new device keys) | Identity vault (the key material itself) |
| Server can recover the account alone? | No — needs the recovery private key it never holds. | No — needs `≥ t` shares it never holds. |

Honest limits: neither mechanism can help a user who loses *all* recovery
material — there is no server-side backdoor by design. The BIP39 phrase is
a bearer credential (whoever holds it can re-take the account), which is why
social recovery is offered for users who prefer distributed trust over a
single phrase.

## 11.4 References

- `construct-core/src/crypto/social_recovery.rs` — SLIP-39 Shamir split /
  combine, 28-word encoding.
- construct-core BIP39/BIP32 recovery-keypair derivation
  (`generate_mnemonic`, `mnemonic_to_seed`, `derive_recovery_keypair`,
  `sign_recovery_challenge`).
- `client/specs/ACCOUNT_RECOVERY_CLIENT_SPEC.md` — flows, RPC surface
  (`SetRecoveryKey`, `RecoverAccount`), derivation-path rationale.
