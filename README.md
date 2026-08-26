# construct-protocol

Public technical specification of the **Konstruct** messenger protocol.

This repository is the **canonical home** of the Konstruct whitepaper /
protocol specification. Marketing copy and aspirational claims live at
[konstruct.cc](https://konstruct.cc); this repo contains only content
that is verifiable against the open-source reference implementation in
[construct-core](https://github.com/konstruct-msg/construct-core).

## Read the specification

The rendered specification is published via GitHub Pages:

**→ <https://konstruct-msg.github.io/construct-protocol/>**

For a single-page read, use the [print view](https://konstruct-msg.github.io/construct-protocol/print.html)
— it concatenates the entire specification onto one URL with full
Ctrl+F search.

## Build locally

```bash
cargo install mdbook              # one-off
mdbook serve --open               # http://localhost:3000, live reload
mdbook build                      # outputs to ./book/
```

The published site is regenerated automatically on every push to `main`
by `.github/workflows/deploy.yml`.

## Repository layout

```
.
├── book.toml              mdBook configuration
├── src/
│   ├── SUMMARY.md         table of contents
│   ├── introduction.md
│   ├── architecture-overview.md
│   ├── 01-threat-model.md
│   ├── 02-cryptographic-primitives.md
│   ├── 03-identity-key-hierarchy.md
│   ├── 04-session-handshake.md
│   ├── 05-message-encryption.md
│   ├── 06-transport.md
│   ├── 07-implementation-status.md
│   ├── 08-metadata-privacy.md
│   ├── 09-privacy-pass.md
│   ├── 10-calls.md
│   ├── 11-account-recovery.md
│   ├── 12-group-messaging.md
│   ├── 13-key-transparency.md
│   ├── appendix-a-errors.md
│   ├── disclosure.md
│   └── changelog.md
├── .github/workflows/deploy.yml   GitHub Actions → Pages
├── LICENSE                          CC BY 4.0 (document text)
├── SECURITY.md                      → GitHub Security Advisories
└── AGENTS.md                        editorial rules for contributors
```

## Versioning

The specification follows [Semantic Versioning](https://semver.org/) at
the document level (see [`src/changelog.md`](src/changelog.md)). MAJOR
indicates a wire-incompatible protocol change; MINOR adds a new normative
section or a backwards-compatible protocol field; PATCH is editorial
corrections that don't change implementer obligations.

## License

- **Document text** (this README, the specification, the changelog,
  the disclosure page): [CC BY 4.0](LICENSE).
- **Code snippets** quoted from the reference implementation retain
  their original [MIT license](https://github.com/konstruct-msg/construct-core/blob/main/LICENSE).

## Trademark

**Konstruct™** / **Конструкт™** and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does **not** grant trademark rights — see [TRADEMARK.md](TRADEMARK.md).
Forks that distribute a modified version must rebrand.
