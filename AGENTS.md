# AGENTS.md

## Project-Local Skill

Use the project-local
[YamlSigil Rust spec update skill](.agents/skills/yaml-sigil-rs-spec-update/SKILL.md)
when reviewing YamlSigil specification changes, importing local spec
artifacts, or reconciling this Rust implementation after spec updates.

## Agent Documentation Standards

Project-local skills exist under `.agents/skills/` and should remain
discoverable by agents working in this repository. Maintain those skills
according to the
[Agent Skills specification](https://agentskills.io/specification), and
maintain this file according to the
[AGENTS.md standard](https://agents.md/). Keep both portable across compatible
agent clients, without assumptions about user-specific paths or session state.

## Scope

This repository implements **YamlSigil v1alpha1** for Rust consumers. It is
self-contained for normal clone, build, test, and publish workflows.

Local implementation inputs:

- `crates/yaml-sigil-core/spec/proto/yaml_sigil/v1alpha1/yaml_sigil.proto`
  for protobuf wire codegen.
- `crates/yaml-sigil-core/spec/schema/YamlSigilSignature.v1alpha1.schema.json`
  for the optional JSON Schema validation helper.
- `crates/yaml-sigil-conformance/fixtures/` for conformance tests.
- `THIRD_PARTY_NOTICES.md` and
  `crates/yaml-sigil-conformance/THIRD_PARTY_NOTICES.md` for notices that
  accompany imported conformance material.

There is no `source-spec` submodule. When the separate `yaml-sigil-spec`
repository changes, review it outside this checkout and import only the local
artifacts and code changes this implementation needs. Use
`cargo xtask update-spec` for the local proto/schema/fixture/notice import and
`.agents/skills/yaml-sigil-rs-spec-update/SKILL.md` for the review workflow.

The public extension-trait contract lives in the separately published
`yaml-sigil-traits` crate. Do not edit, generate, or publish traits from this
repository.

## Documentation Style Guide

These rules apply to Markdown files in this Rust implementation workspace,
including README files, `docs/`, conformance notes, and release guidance.
Use GitHub Flavored Markdown as the source dialect unless a file documents a
narrower renderer requirement.

Write like you are explaining the implementation to a colleague. Be direct,
specific, and concise. Be accurate about whether behavior belongs to this
workspace, `yaml-sigil-traits`, or the external YamlSigil specification.

The Markdown dialect target is GitHub Flavored Markdown (GFM), as rendered by
GitHub repository views. Rely on GitHub's generated document outline for
navigation. Avoid renderer-specific inline attributes such as `{width=50%}`
in new content unless the file explicitly targets a separate renderer.

### Voice And Tone

- Use active voice. Write "`yaml-sigil-core` parses YAML signature documents
  with `noyalib`." not "YAML signature documents are parsed with `noyalib`."
- Use second person, `you`, when addressing the reader.
- Use present tense. Write "The command returns an error." not "The command
  will return an error."
- State facts. Do not hedge with "simply," "just," "easily," or "of course."

### Things To Avoid

These patterns make technical documentation harder to read. Remove them during
review.

| Pattern | Problem | Fix |
|---------|---------|-----|
| Unnecessary bold | "This is a **critical** conformance step" on routine instructions. | Reserve bold for UI labels, parameter names, and genuine warnings. |
| Repeated em dashes | "The fixture import -- which runs through `cargo xtask update-spec` -- refreshes local artifacts." | Use commas or split the sentence. Use em dashes sparingly. |
| Superlatives | "`yaml-sigil-rs` provides a powerful, robust, seamless signature experience." | Say which crate or API performs the work. |
| Hedge words | "Simply run `cargo xtask hygiene`." | Write "Run `cargo xtask hygiene`." |
| Emoji in prose | "Run tests before publish." with an emoji prefix. | Do not use emoji in documentation prose. |
| Rhetorical questions | "Want to validate fixtures?" | State the purpose directly. |

### Formatting Rules

- Never add line breaks inside an *italic* or **bold** span. If you must wrap
  the text, start the formatting again on the next line.
- Never add line breaks inside `[markdown](links)`.
- End every sentence with a period.
- Use `code` formatting for CLI commands, file paths, flags, parameter names,
  crate names, feature names, and literal values.
- Use `shell` code blocks for copyable CLI examples. Do not prefix commands
  with `$`.

  ```shell
  cargo xtask hygiene
  ```

- Use `text` code blocks for transcripts, log output, and examples that should
  not be copied verbatim.
- Use tables for structured comparisons. Keep tables simple and avoid nested
  formatting.
- Use GitHub Flavored Markdown alert notices for non-normative notes and
  implementation asides when the content benefits from a visible notice label.
  Supported labels are `> [!NOTE]`, `> [!TIP]`, `> [!IMPORTANT]`,
  `> [!WARNING]`, and `> [!CAUTION]`. Use plain Markdown blockquotes (`>`) for
  lower-emphasis asides. Do not use bold callouts or documentation-framework
  components this repository does not use.
- Use itemized bullet lists when the instructions clearly benefit from them.
- Do not number section titles. Write "Update conformance fixtures" not
  "Step 3: Update conformance fixtures."
- Do not use colons in titles. Write "Update conformance fixtures" not
  "Conformance: Update fixtures."
- Use colons only to introduce a list. Do not use colons as general-purpose
  punctuation between clauses.

### Repository-Specific Documentation Rules

- Keep conformance documentation specific. Name the fixture path, expected
  outcome, and divergence reason in `docs/conformance-validation.md`.
- When documenting spec imports, name the local artifact changed and avoid
  implying this repository owns the upstream specification.
- When documenting public APIs, distinguish re-exported `yaml-sigil-traits`
  contracts from implementation details in this workspace.

## Commands

Run from the repository root:

```shell
cargo xtask hygiene
cargo xtask update-spec
cargo xtask update-spec --ref origin/dev/example-branch
cargo xtask sync-workspace-versions
cargo xtask coverage
cargo xtask coverage --open
cargo xtask coverage-open
cargo xtask perfreport
cargo xtask rust-perf-html
cargo xtask perf-open
```

Manual equivalents for the core quality loop:

```shell
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
```

## Cargo Features

The workspace uses `resolver = "3"` and Rust edition 2024.

| Area | Features | Notes |
|------|----------|-------|
| Protobuf codegen | n/a | Generated with `buffa` from the local `yaml_sigil.proto`. |
| YAML parser | n/a | YAML signature documents are parsed with `noyalib`. |
| JSON Schema helper | `json-schema-validate` | Exposes validation against the local signature-document schema. |

## Conformance

`crates/yaml-sigil-conformance` drives local fixture artifacts through the
public trait surfaces and core byte helpers. It is publish-disabled and exists
for this workspace and sibling implementation checks.

Any conformance-related change must update `docs/conformance-validation.md` in
the same commit. This includes fixture imports, fixture remapping, expected
outcome changes, ignored tests, public API surfaced because of a fixture, and
deliberate divergences.

When a fixture would require going far outside the natural patterns of the Rust
crates in use, prefer recording a divergence in
`docs/conformance-validation.md` over inventing a workaround.

## Async

Sync and async trait pairs are defined in `yaml-sigil-traits` and re-exported
from the API crates. Async traits use native AFIT/RPITIT with explicit `+ Send`
returned futures and `Send + Sync` trait bounds. Do not add `async-trait`
unless a real consumer requires an object-safe shim and the tradeoff is
documented.

## Crypto And Secrets

- Never log private keys, seed material, tokens, or raw signatures on trusted
  fact surfaces.
- `SigningKey` debug output in `yaml-sigil-signing` is redacted by design.

## Permanent Out Of Scope

Do not add gRPC servers, clients, gateways, transport adapters, generated
service stubs, or runtime bindings for the signing, verification, or
transcription service IDL. This repository owns the Rust library
implementation and the protobuf wire envelope helpers, not deployable RPC
services.

Consumers that need RPC transport wire it in their own deployment.

## Change Separation

Keep proto/schema imports, conformance fixture changes, crypto behavior
changes, CI edits, and unrelated formatting in separate commits or clearly
separated commit sections when possible.
