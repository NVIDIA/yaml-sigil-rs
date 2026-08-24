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

## Commit messages

Use Conventional Commits for every commit. Format the subject as
`<type>(<optional scope>): <description>`, keep it under 72 characters, and
choose the smallest accurate type. Follow the sign-off requirements in
`CONTRIBUTING.md`.

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
- `crates/yaml-sigil-core/THIRD_PARTY_NOTICES.md` and
  `crates/yaml-sigil-verification/THIRD_PARTY_NOTICES.md` for independently
  packaged copied specification, constant, and reference-vector material.

There is no `source-spec` submodule. When the separate `yaml-sigil-spec`
repository changes, review it outside this checkout and import only the local
artifacts and code changes this implementation needs. Use
`cargo xtask update-spec` for the local proto/schema/fixture/notice import and
`.agents/skills/yaml-sigil-rs-spec-update/SKILL.md` for the review workflow.

The public extension-trait contract lives in the separately published
`yaml-sigil-traits` crate. Do not edit, generate, or publish traits from this
repository.

## Third-party material and attribution

`THIRD_PARTY_NOTICES.md` is the canonical attribution and redistribution
record for imported standards text, test vectors, parameters, tables, and
other third-party material in this workspace. The matching notice beside
`crates/yaml-sigil-conformance` accompanies the imported fixtures. Import both
files from `yaml-sigil-spec` with `cargo xtask update-spec`; do not let the
copies diverge.

Crate-local `THIRD_PARTY_NOTICES.md` files cover third-party material packaged
by independently distributed crates. Reconcile those notices with the
canonical imported notice whenever the corresponding source material or terms
change.

When adding or changing third-party material:

- Update the authoritative notice in `yaml-sigil-spec` first, then use the
  documented import workflow. Record the exact source, version, section,
  copyright holder, applicable copying conditions, warranty disclaimer, and
  patent or other intellectual-property caveat.
- Read the source's own copyright notice and terms. For an RFC, check its
  publication stream and the BCP 78 or IETF Trust terms in effect on its
  publication date. Do not assume that RFC test data, tables, ABNF, or code
  blocks are IETF Code Components or covered by a BSD license.
- Ensure every file or other independently distributed material that mentions
  or references either SEC source identifies it by its full title:
  *Standards for Efficient Cryptography 1 (SEC 1)* or
  *Standards for Efficient Cryptography 2 (SEC 2)*. Use the full title on the
  first source reference in each file; the `SEC 1` and `SEC 2` short forms may
  follow within that file.
- Add a short provenance comment next to copied or derived constants,
  algorithms, encodings, validation rules, or test values. State when
  identified third-party material is not covered by a file's Apache-2.0
  declaration.
- Do not alter semantic fixture bytes to add attribution. For binary files,
  signed artifacts, parser inputs, or other exact-byte fixtures, put the
  provenance in the nearest `README.md`, a safe sidecar, and the authoritative
  generator source.
- Keep the `.gitattributes` rule for
  `crates/yaml-sigil-conformance/fixtures/**` marked `-text`; these are
  exact-byte inputs and must not undergo checkout line-ending conversion.
- Preserve applicable non-endorsement language. Do not present this workspace
  as an official publication of, or as affiliated with or endorsed by, a
  cited author, publisher, or standards organization.
- Verify every package containing identified third-party material includes
  the applicable crate-local notice. Keep notice files in explicit Cargo
  `include` lists when a package uses one.

Keep these instructions durable and repository-focused. Do not record private
correspondence, reviewer identities, or approval history in repository
documentation. Attribution-only imports may leave fixture bytes and runtime
behavior unchanged, but they still require an entry in
`docs/conformance-validation.md`.

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
| Hedge words | "Simply run `cargo xtask ci`." | Write "Run `cargo xtask ci`." |
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
  cargo xtask ci
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

- Write repository READMEs for human readers. Keep agent workflows and durable
  repository instructions in `AGENTS.md`.
- Use absolute links in READMEs packaged with published crates so the links work
  on crates.io and docs.rs.
- Prefer inline-code `yaml-sigil` in prose. Use “YAML Sigil” when code styling
  reads awkwardly.
- Reserve `YamlSigil` and `YamlSigil.v1alpha1` for code or exact identifiers.
- Usually omit the protocol version. When the version is necessary, write the
  lowercase inline-code form `v1alpha1`.
- Link other crates with inline-code names and absolute crates.io URLs.
- Explain behavior in ordinary language before introducing specification
  terminology.
- Keep conformance documentation specific. Name the fixture path, expected
  outcome, and divergence reason in `docs/conformance-validation.md`.
- When documenting spec imports, name the local artifact changed and avoid
  implying this repository owns the upstream specification.
- When documenting public APIs, distinguish re-exported `yaml-sigil-traits`
  contracts from implementation details in this workspace.

## Commands

Run from the repository root:

```shell
cargo xtask ci
cargo xtask package-content
cargo xtask update-spec
cargo xtask update-spec --ref origin/dev/example-branch
cargo xtask sync-workspace-versions
cargo xtask coverage
cargo xtask coverage --open
cargo xtask coverage-open
cargo xtask profile
cargo xtask profile --iterations 250
cargo xtask profile --open
cargo xtask profile-open
```

`cargo xtask ci` runs the complete provider-neutral non-release validation
sequence locally. Its exact commands are:

```shell
rumdl check .
buf build crates/yaml-sigil-core
buf lint crates/yaml-sigil-core
buf format crates/yaml-sigil-core --diff --exit-code
cargo fmt --all --check
cargo fmt --manifest-path xtask/Cargo.toml --all --check
cargo xtask release-version check
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-core
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-transcription
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-signing
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-verification
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --locked --manifest-path xtask/Cargo.toml
cargo-machete --with-metadata
cargo audit
cargo audit --file xtask/Cargo.lock
```

To apply the validator from the current checkout to another repository
checkout, pass its root explicitly:

```shell
cargo xtask ci --candidate-root PATH
```

The command still builds and runs the xtask from the current checkout; only
the repository content being validated comes from `PATH`.

The static package-content stage runs
`cargo package --list --allow-dirty --exclude-lockfile --package <crate>` for
each of the four publishable crates and compares Cargo's modeled paths with the
committed exact inventory under `xtask/package-contents/`. `--allow-dirty`
permits source-tree inspection without changing tracked files.
`--exclude-lockfile` prevents Cargo from resolving unpublished local
dependencies while paths are listed; the validator adds Cargo's generated
package-local `Cargo.lock` path to the observed set before comparing it. The
stage does not assemble a `.crate` archive or publish anything. Run
`cargo xtask package-content` when you need only this check. Full package
validation with `cargo package` remains release-sequenced.

Publish only `yaml-sigil-core`, `yaml-sigil-transcription`,
`yaml-sigil-signing`, and `yaml-sigil-verification` as crates.io `.crate`
source packages. Keep the workspace default, conformance, test-key, and xtask
packages unpublished. Do not distribute compiled native executables,
executable WebAssembly, installers, containers, retained CI or build outputs,
GitHub Release assets, or separately generated source archives. Local and
ephemeral compilation remains permitted for validation.

The xtask resolves its Buf executable through the same pinned `buf-tools`
version used by `yaml-sigil-core` at build time. A system `buf` or `protoc`
installation is not required. Keep the `buf-tools` pins in the root workspace
and `xtask/Cargo.toml`, the `bufbuild/buf-action` `version` input, and this
command documentation aligned when updating Buf.

Install `rumdl`, `cargo-audit`, and `cargo-machete` with Cargo before running
the wrapper:

```shell
cargo install rumdl
cargo install cargo-audit
cargo install --locked cargo-machete --version 0.9.2
```

Keep the cargo-machete version aligned with hosted CI. The
`--with-metadata` check resolves normal, development, and build dependency
names across all features, but remains an unused-dependency heuristic; retain
the all-target, all-feature Clippy and test checks as the compilation proof.

Hosted CI declares these checks as independent steps. Keep its command coverage,
`xtask/src/ci.rs`, and the exact-command documentation above aligned when
changing the validation sequence. Do not make the xtask read, parse, or test
provider-specific workflow files. Validate provider configuration with its
native tooling.

Validate shell scripts under `.github/scripts` with Shuck before landing
changes. Install it from the `shuck-cli` crate and run it from the repository
root:

```shell
cargo install shuck-cli
shuck check .github/scripts
```

ShellCheck is an acceptable fallback:

```shell
shellcheck .github/scripts/check-pull-request-commits.sh
```

Hosted CI runs its pinned ShellCheck Action for these provider-specific scripts.
Keep this validation outside `cargo xtask ci`.

Hosted CI runs the provider-neutral Rust and Cargo portion of this sequence on
NVIDIA's `linux-amd64-cpu8` runner and GitHub's moving `macos-latest` and
`windows-latest` labels. Every matrix leg checks formatting, synchronized
release versions, package contents, Clippy, tests, unused dependencies, and
both dependency audits against that platform's resolved dependency graph.
Linux commit-policy, Markdown, Protobuf, provider-workflow, and aggregation
jobs run on `linux-amd64-cpu4`. The local command does not launch other
operating systems.

Treat every GitHub Action `uses:` pin update as a potential validation-behavior
change, even when the workflow inputs remain unchanged. While evaluating a
candidate update, compare the Action at the current and candidate immutable
SHAs, including its commands, inputs and defaults, runtime, and transitive
`uses:` dependencies. Determine whether those changes affect the local
`cargo xtask ci` equivalent or this exact-command documentation. When an Action
update changes relevant behavior, reify it in hosted CI and, when applicable,
the xtask command plan and this file in the same change. Document any
intentional hosted-versus-local difference without making the xtask depend on
the hosted provider's configuration.

The root workspace does not commit `Cargo.lock`, so its Cargo checks must work
from a clean checkout without `--locked`. Keep fixture imports, version
synchronization, coverage, and profiling commands separate from CI unless the
workflow explicitly needs them.

### Coverage and profiling

Install the Cargo tools used for local reports:

```shell
cargo install cargo-llvm-cov
cargo install --locked samply
```

The coverage and profiling xtasks check for their required tool before doing
other work and print the corresponding installation command above when it is
absent. Keep these commands aligned with the constants and synchronization
test in `xtask/src/main.rs`.

`cargo xtask coverage` tests the workspace with all features and writes an HTML
coverage report to `target/llvm-cov-html/html/index.html`. It does not open a
browser unless `--open` is supplied. `cargo xtask coverage-open` opens an
existing report without rebuilding it.

`cargo xtask profile` builds the focused E2E test with release-equivalent
optimization and debug symbols, records it with Samply, and writes Firefox
Profiler data to `target/profile/profile.json`. The test is very short, so the
task runs it 100 times by default; use `--iterations` to tune the sample. The
default is non-interactive. Use `--open` after recording or run
`cargo xtask profile-open` later to launch the interactive browser UI. Samply
does not produce a standalone HTML file. On Linux, the host's perf-event policy
must permit unprivileged profiling; follow local system policy if Samply reports
that `perf_event_paranoid` is too restrictive.

Agents should begin performance work with focused source inspection, tests,
benchmarks, or timings that answer the question with less data. Run
`cargo xtask profile` when investigating a concrete CPU-performance issue, and
leave it non-interactive unless a human asks to open the browser UI. Report the
saved profile path so a human can inspect it with `cargo xtask profile-open`.

## Cargo Features

The workspace uses `resolver = "3"` and Rust edition 2024.

| Area | Features | Notes |
|------|----------|-------|
| Protobuf codegen | n/a | Generated with `buffa` from the local `yaml_sigil.proto`, using Buf from `buf-tools`. |
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
