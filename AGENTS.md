# AGENTS.md — construct-protocol

Editorial guidance for coding agents (Claude, Copilot, Codex, etc.) and
human contributors working in this repository.

## What this repo is

The **canonical public specification** of the Konstruct messenger
protocol, published via mdBook → GitHub Pages.

## The one editorial rule

**Every algorithmic claim in this document MUST be verifiable against
the reference implementation in [construct-core](https://github.com/konstruct-msg/construct-core).**

If something is in the document but not in the code, the document is
wrong and should be patched. If something is in the code but not in
the document, the document is incomplete. The code wins.

Concretely:

- **Crypto algorithm names**: use the NIST FIPS name (`ML-KEM-768`,
  `ML-DSA-65`) with the informal name in parentheses (`Kyber-768`,
  `Dilithium-3`). Never use informal names alone — they are
  ambiguous about variant (e.g. Kyber-512 / Kyber-768 / Kyber-1024).
  Specifically: **the deployed KEM is ML-KEM-768, not Kyber-1024 or
  any other variant.**
- **Implementation status claims**: must cite the source file and line.
- **Things not yet in code**: must be explicitly marked as "designed"
  / "planned" / "not yet implemented". Never present them in present
  tense. If federation is Phase 3 of the roadmap, don't say "federated
  identity" without qualification.
- **Self-graded security scores**: do not use. The notion of a
  "security score" out of 10 has no industry standard. Use a checklist
  of concrete open issues instead.

## What this repo is not

- Marketing copy (lives at `~/Code/construct-landing/`,
  konstruct.cc).
- Internal architecture decisions (live in `~/Code/construct-docs/`).
- Aspirational roadmap content (lives in construct-docs or the
  landing site's roadmap section, not here).

## Cross-references

- **Crypto suites ground truth**: see `[[reference-crypto-suites]]` in
  the agent's auto-memory — verified algorithm list from the actual
  code, treat as authoritative.
- **Public repo names**: see `[[reference-public-repos]]`. In
  particular: the iOS repo is `construct-ios`, not `construct-messenger`.
- **Brand**: `Konstruct` in Latin script (English / international),
  `Конструкт` in Cyrillic (Russian); see `[[feedback-brand-naming]]`.

## Build & deploy

```bash
mdbook serve --open    # local preview at http://localhost:3000
mdbook build           # outputs to ./book/
```

Published via `.github/workflows/deploy.yml` on every push to `main`.
GitHub Pages site root: <https://konstruct-msg.github.io/construct-protocol/>.

## Where to save reasoning

When making a non-trivial editorial decision (e.g. how to phrase a
contested claim, what to include / omit, how to resolve a contradiction
between two source docs), write a session note in
`~/Code/construct-docs/wiki/sessions/YYYY-MM-DD-<topic>.md` using the
standard sections (`Context`, `What Changed`, `Why`, `Intended
Outcome`, `Decisions`, `Open Questions`).

The shared construct-docs vault is the canonical place for cross-repo
reasoning; this repo holds only the published artefacts.
