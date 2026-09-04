# AGENTS.md

## Project-Local Skill

Use the project-local
[YamlSigil Rust spec update skill](.agents/skills/yaml-sigil-rs-spec-update/SKILL.md)
when reviewing YamlSigil specification changes, importing local spec
artifacts, or reconciling this Rust implementation after spec updates.

Follow [`xtask/AGENTS.md`](xtask/AGENTS.md) when changing the developer task
crate or its release-command boundaries.

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
cargo xtask release prepare --version MAJOR.MINOR.PATCH[-PRERELEASE]
cargo xtask release check --version MAJOR.MINOR.PATCH[-PRERELEASE]
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
cargo xtask sync-workspace-versions --check
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

Copied-ref CI first runs protected commit/release-path policy plus fixed-path
actionlint, ShellCheck, rumdl, cargo-machete, and `cargo-audit` against the
committed `xtask/Cargo.lock`. The root lockfile is intentionally absent, so the
full workspace audit inside the final `cargo xtask ci` phase is candidate
execution, not trusted pre-execution policy evidence. Candidate tools, Cargo
state, targets, temporary files, and materialized source stay under fresh
runner-temporary paths; no policy or privileged step follows candidate Rust.

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
installation is not required. Follow the coordinated upgrade workflow below
when changing any Buf-related version or installation control.

## Coordinated Buf upgrades

Publishing a new `buf-tools` release does not automatically update any
YamlSigil repository. Use coordinated pull requests to update every applicable
pin and verification surface. Do not infer its crate version from the upstream
Buf CLI version.

The controls have distinct roles:

- `buf-tools` is the Rust build dependency used by this workspace and its
  xtask. Its version may contain a suffix such as `-hotfix.N`; do not derive it
  mechanically from the Buf CLI version. Update the exact pins in `Cargo.toml`
  and `xtask/Cargo.toml`, then regenerate the committed `xtask/Cargo.lock`.
  The root workspace intentionally does not commit `Cargo.lock`, so do not add
  it merely for a Buf upgrade. CI obtains the executable only through this
  exact crate dependency; do not add a second provider-specific installer.
- `buf.lock` locks BSR or module dependencies, not the installed Buf CLI
  version. Do not update it solely because the CLI or `buf-tools` changed.

Coordinate these repository-specific surfaces:

- In `yaml-sigil-rs`, update `Cargo.toml`, `xtask/Cargo.toml`,
  `xtask/Cargo.lock`, the provider-neutral Buf checks in `xtask/src/ci.rs`, and
  their exact command documentation. Candidate CI obtains Buf through the same
  pinned `buf-tools` dependency.
- In `yaml-sigil-spec`, update its ordinary and protected
  `bufbuild/buf-action` configuration, protected runner pin, and policy tests.
  It has no product `buf-tools` dependency unless its current source proves
  otherwise.
- In `yaml-sigil-traits`, update only applicable current validation surfaces.
  It otherwise has no independent Buf product dependency unless its current
  source proves otherwise.

For each future coordinated upgrade:

- Review the selected Buf and `buf-tools` releases and confirm their published
  mapping.
- Make one coordinated change that updates every applicable pin and
  verification surface.
- Regenerate only Cargo lockfiles already committed by the affected
  repository.
- Verify that no unplanned protobuf-generated output changed.
- Run the local Cargo and protected-policy suites, ShellCheck or Shuck,
  actionlint, and Markdown checks.
- Require successful ordinary and App-owned protected CI at the exact reviewed
  heads.
- Confirm that CI used the pinned `buf-tools` executable and retained no
  artifacts.

Install `rumdl`, exact `cargo-audit` `0.22.2`, and exact `cargo-machete`
`0.9.2` with Cargo before running the wrapper:

```shell
rustup toolchain install 1.98.0 --component clippy,rustfmt
cargo +1.98.0 install rumdl
cargo +1.98.0 install --locked cargo-audit --version 0.22.2
cargo +1.98.0 install --locked cargo-machete --version 0.9.2
```

Keep the cargo-audit and cargo-machete versions aligned with hosted CI, and
require `cargo-audit --version` to report exactly `cargo-audit 0.22.2`. The
`--with-metadata` check resolves normal, development, and build dependency
names across all features, but remains an unused-dependency heuristic; retain
the all-target, all-feature Clippy and test checks as the compilation proof.

Hosted CI declares these checks as independent steps. Keep its command coverage,
`xtask/src/ci.rs`, and the exact-command documentation above aligned when
changing the validation sequence. Do not make the xtask read, parse, or test
provider-specific workflow files. Validate provider configuration with its
native tooling.

The only permitted provider-specific xtask namespace is
`cargo xtask github`. Keep it limited to typed, repository-owned GitHub
operations that consolidate release automation. It must not become an
arbitrary `gh api` passthrough or a replacement for actionlint. It must never
parse, embed, snapshot, or validate workflow YAML, triggers, job names,
permissions, secrets, expressions, Action pins, or historical workflow files.
Accept tokens only through environment variables; never log them, serialize
them into fixtures, or pass them as command-line arguments.

Within GitHub Actions, bind repository selection to GitHub's default
`GITHUB_ACTIONS` and `GITHUB_REPOSITORY` variables and require an exact match
with a compiled repository-policy table and the local package family. Do not
use the mutable `CI` variable or configurable environment values as a trust
switch. Local mutation commands must take an explicit repository and bind it
to that same table and checkout.

`cargo xtask ci` and every non-`github` command must remain provider-neutral
and credential-free. The checkout-free protected-PR reporter remains Python so
protected default-branch policy can run without compiling candidate Rust. Keep
`.github/scripts/check-pull-request-commits.sh` identical across the YamlSigil
repositories. Small host-setup helpers may remain shell when moving them would
add complexity without consolidating policy.

The surviving provider helpers have deliberately narrow roles:

- `report_required_ci.py` and its focused fixture tests bind one terminal
  copied-ref run and the exact verified signer, raw author/committer, and
  author DCO identities before the scoped App creates `Required CI`.
- `bind-candidate-pr.py` anonymously binds the open pull request, current main,
  copied ref, exact basic verification inventory, and optional canonical
  release branch before source materialization.
- `materialize-candidate.sh` and its tests perform anonymous exact-head
  materialization while rejecting filters, ancestor Cargo configuration, and
  candidate-selected submodule behavior.
- `install-actionlint.sh` stages the checksum-verified Linux actionlint binary
  before candidate materialization, so no Action runs after candidate source
  exists.
- `check-trusted-tool-pins.sh` admits only the exact reviewed Rust baselines
  and rejects any workflow `tool:` scalar that names a floating or unexpected
  cargo-audit version without modeling workflow topology.
- `check-pull-request-commits.sh` enforces the shared exact-range, linear
  history, and DCO policy across all three YamlSigil repositories.
- `check-release-pull-request.sh` adds the canonical branch, single-commit, and
  release-file boundary for explicit version changes.
- `attach-release-source.sh` binds an already-qualified source only to local
  main refs immediately before the protected release-plz publication call; it
  never updates a remote.
- `rebind-release-policy.sh` anonymously confirms the post-approval policy
  checkout is still exact live `main` and the source remains on its lineage
  immediately before the publisher or finalizer receives release authority.
- `remove-preinstalled-aws-tap.sh` performs one bounded macOS host cleanup
  before Rust setup.

Release qualification, same-source recovery, and deterministic release-object
finalization belong in the narrow `cargo xtask github release` commands, not in
additional Python or shell helpers. Local version preparation and content
validation remain provider-neutral under `cargo xtask release`. The exact
release-plz dry run is a separate maintainer-operated acceptance step because
release-plz requires read-only forge association context.

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

Hosted CI pins its authoritative stable baseline to Rust `1.98.0` and runs an
independent Rust `1.95.0` lane on NVIDIA's `linux-amd64-cpu8` runner.
GitHub-hosted macOS and Windows jobs are advisory. Explicitly admitted copied
refs run the same provider-neutral source checks without secrets, OIDC,
protected environments, cache saves, or retained artifacts. Only
`Candidate CI (Linux)` feeds the checkout-free App reporter;
advisory conclusions never affect `Required CI`.

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
