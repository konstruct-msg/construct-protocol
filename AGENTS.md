# AGENTS.md — construct-protocol

The canonical public specification of the Konstruct messenger protocol, published as an mdBook to
GitHub Pages. It is editorial: the reference implementation is
[construct-core](https://github.com/konstruct-msg/construct-core), and **the code wins**.

## Read first

| File | Why |
|---|---|
| `~/Code/construct-docs/decisions/rules-from-the-first-year.md` | why the rules exist; checklist before designing groups, rooms, any new protocol feature |
| `src/07-implementation-status.md` · `src/changelog.md` | what is implemented; the history of claims |
| `src/01-threat-model.md` … `src/13-key-transparency.md` | the chapters; `src/SUMMARY.md` is the index |
| `construct-core/src/crypto/pq_x3dh.rs` | verify any PQ or algorithm claim here before writing it |
| `~/Code/construct-docs` | internal decisions and reasoning; its own `AGENTS.md` is authoritative |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md`. Change it there first.

## Rules

1. **Prior art first.** A chapter on a mechanism says how Signal / MLS (RFC 9420) / Matrix solve it and why we deviate.
2. **The core decides.** The spec describes what `construct-core` does; if the document and the code disagree, patch the document.
3. **A message names the state it means.** Describe every control message by the epoch, key or number it carries; a timer or window in the text signals a missing address.
4. **Reproduce, then fix.** A claim found wrong is checked against the code or a test run before the text is changed.
5. **One meaning, one carrier.** One term, one meaning, one chapter that defines it; new `content_type` values match `construct-protos/conformance/knst_content_types.json`.
6. **Bytes stay bytes.** Specify fields as bytes; base64 only at named text boundaries.
7. **Measure, then build.** Performance and censorship claims cite the measurement.
8. **The effect is the proof.** An implementation-status claim cites source file and line.
9. **A test that cannot fail is worse than none.** A claim "tested" names the test that fails if the claim is false.
10. **Depth before breadth.** Do not specify a surface (groups, rooms) as present before it works on the stand.
11. **Temporary has an end and a check.** "Planned" text carries what will replace it; see the status rule below.
12. **Branch and PR, always.**

## Invariants of this repo

- **Every algorithmic claim is verifiable against construct-core.** In the document but not in the code: the document is wrong. In the code but not in the document: incomplete.
- **Crypto names use the NIST FIPS name with the informal one in parentheses** (`ML-KEM-768` (Kyber-768), `ML-DSA-65` (Dilithium-3)); never the informal name alone (variant ambiguity). Since PQXDH v2 (2026-09-25): prekeys and the handshake use **ML-KEM-1024**; ML-KEM-768 appears only in the Suite 4 ratchet (Suite 3 until core 0.24.0). Name the parameter set and the role; an unqualified "ML-KEM" is ambiguous.
- **"Post-quantum" names a layer, never the product.** 1:1 message content is post-quantum; several surrounding layers are not (Chapter 1, "Post-quantum coverage"). A new layer is added to that table in the same change that describes it.
- **Implementation-status claims cite the source file and line.**
- **Not yet in code** is marked "designed" / "planned" / "not yet implemented", never in present tense (federation is Phase 3: no "federated identity" without qualification).
- **No self-graded security scores;** use a checklist of concrete open issues.
- **Not here:** marketing copy (`~/Code/construct-landing/`, konstruct.cc), internal decisions (`construct-docs`), aspirational roadmap.
- **Names:** the iOS repo is `construct-ios`, not `construct-messenger`; brand is `Konstruct` in Latin (Cyrillic `Конструкт` only in Russian text).
- **Cross-references** (agent memory): `[[reference-crypto-suites]]` is the verified algorithm list; `[[reference-public-repos]]` has the public repo names; `[[feedback-brand-naming]]` the brand rule.
- **Build:** `mdbook serve --open` (preview at http://localhost:3000), `mdbook build` (output `./book/`). `.github/workflows/deploy.yml` publishes on every push to `main` to <https://konstruct-msg.github.io/construct-protocol/>.
- **Reasoning goes to the vault:** a non-trivial editorial decision gets a note in `~/Code/construct-docs/wiki/sessions/YYYY-MM-DD-<topic>.md` (Context, What Changed, Why, Intended Outcome, Decisions, Open Questions). This repo holds only published artefacts.

## Git and process

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from an up-to-date `main`, PR into it; `main` publishes. Agents push and open the PR only when asked.
- A commit made on `main` by mistake and not pushed moves with `git branch <topic> && git reset --keep origin/main && git switch <topic>`. Pushed history is never rewritten.
- Check the branch and `git status` before every commit; never `checkout -- .`, `reset --hard` or `stash` in a shared tree.
