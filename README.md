# yaml-sigil-rs

[![GitHub license](https://img.shields.io/github/license/NVIDIA/yaml-sigil-rs)](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/LICENSE)
[![CI](https://github.com/NVIDIA/yaml-sigil-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/NVIDIA/yaml-sigil-rs/actions/workflows/ci.yml)

`yaml-sigil-rs` provides Rust implementation crates for
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr). It depends on
[`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits) for the
public extension-trait contract. This workspace implements signing,
verification, transcription, protobuf wire helpers, YAML signature-document
parsing, and local conformance checks.

The repo vendors the implementation inputs it needs: the protobuf schema, the
signature-document JSON Schema, the curated conformance fixtures, and the
third-party notices that accompany those fixtures. The normative specification
lives in [`yaml-sigil-spec`](https://github.com/NVIDIA/yaml-sigil-spec), not
this repository.

NVIDIA-authored material is licensed under the
[Apache License 2.0](./LICENSE). Third-party test data, standards-derived
material, and their redistribution requirements are documented in
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

The `yaml-sigil-verification` source package also includes its scoped notice
for RFC 8032-derived constants, canonical-encoding rules, and a test-vector
value. The other published implementation crates do not package material
covered by that notice.

Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before proposing a change.

## Crates

The workspace publishes four crates. Most applications start with
`yaml-sigil-signing` when producing signed documents and
`yaml-sigil-verification` when accepting them. The core and transcription
crates provide the shared document handling used by those higher-level APIs.

### [`yaml-sigil-core`](./crates/yaml-sigil-core/README.md)

[![yaml-sigil-core on crates.io](https://img.shields.io/crates/v/yaml-sigil-core.svg?label=yaml-sigil-core)](https://crates.io/crates/yaml-sigil-core)

This crate contains the document machinery shared by the other crates. It
recognizes document boundaries, applies payload rules, reads and writes YAML
signature documents, handles the protobuf wire format, and maps signature
algorithms. It generates protobuf helpers with
[`buffa`](https://crates.io/crates/buffa) and parses YAML with
[`noyalib`](https://crates.io/crates/noyalib). Its optional
`json-schema-validate` feature validates signature documents against the local
schema.

The other released crates build on this layer. Signing uses it to apply the
document rules and encode signature information. Transcription uses it to take
artifacts apart and handle protobuf envelopes. Verification uses it to read
signature information and reject malformed artifacts before checking a
signature. Most applications therefore use `yaml-sigil-core` indirectly.

### [`yaml-sigil-transcription`](./crates/yaml-sigil-transcription/README.md)

[![yaml-sigil-transcription on crates.io](https://img.shields.io/crates/v/yaml-sigil-transcription.svg?label=yaml-sigil-transcription)](https://crates.io/crates/yaml-sigil-transcription)

This crate puts the pieces of a signed artifact together or takes them apart.
`compose` combines a document and its encoded signature information into a
YAML or protobuf artifact. `decompose` separates the artifact into those pieces
again. These operations are structural. They do not create or verify a
signature.

In a signing flow, `yaml-sigil-signing` uses transcription to assemble a YAML
artifact after creating its signature. During verification,
`yaml-sigil-verification` uses transcription to take a YAML or protobuf
artifact apart so it can read the signature information and check the
signature.

### [`yaml-sigil-signing`](./crates/yaml-sigil-signing/README.md)

[![yaml-sigil-signing on crates.io](https://img.shields.io/crates/v/yaml-sigil-signing.svg?label=yaml-sigil-signing)](https://crates.io/crates/yaml-sigil-signing)

Applications use this crate to turn a YAML or protobuf document into a signed
artifact. It prepares the document, creates the signature information with the
chosen signing key and algorithm, and packages the document and signature for
storage or transport.

Signing relies on `yaml-sigil-core` to apply the document rules and encode the
signature information. For YAML, it asks `yaml-sigil-transcription` to combine
the document and signature. For protobuf, it uses the core wire-format support.
The resulting artifact can be stored or transported for a recipient to process
with `yaml-sigil-verification`.

### [`yaml-sigil-verification`](./crates/yaml-sigil-verification/README.md)

[![yaml-sigil-verification on crates.io](https://img.shields.io/crates/v/yaml-sigil-verification.svg?label=yaml-sigil-verification)](https://crates.io/crates/yaml-sigil-verification)

Applications use this crate to check a signed artifact received from another
party. The application identifies the artifact as YAML or protobuf and
supplies the public keys it trusts. Verification then uses
`yaml-sigil-transcription` to take the artifact apart, uses `yaml-sigil-core`
to read it and enforce the document rules, and checks the signature.
`pre_verify` exposes the structural stage when you need to inspect an artifact
without performing cryptography.

Treat only the document bytes returned by `VerifierState::Verified` as
authenticated. The caller remains responsible for choosing the artifact form
and deciding which public keys are trusted.

### Signing and verification flow

1. A producer uses `yaml-sigil-signing` to sign a document.
2. Signing uses core document support and, for YAML, transcription to package
   the document and its signature as one artifact.
3. A recipient gives that artifact and its trusted public keys to
   `yaml-sigil-verification`.
4. Verification takes the artifact apart, checks that it follows the document
   rules, and reports whether its signature is valid for the document.

### Workspace-only support crates

- `yaml-sigil-conformance` exercises the implementation against the vendored
  fixture suite.
- `yaml-sigil-test-keys` provides deterministic key material for workspace
  tests. It is not a production key-management API.

### Choosing a document form

Callers select artifact forms through the public form enums. Bind each artifact
source, route, or storage class to one form before processing its bytes. Do not
sniff the bytes to select a form or retry the other form after structural or
verification failure. `v1alpha1` defines no magic bytes, media type, or required
file extension.

YAML decompose and verify operations require complete artifacts because
boundary selection uses the last constrained marker.

## Build

The development toolchain follows Rust `stable` through
`rust-toolchain.toml`. The minimum supported Rust version (MSRV) is Rust
`1.95.0`, as declared in the root `Cargo.toml`. Protobuf code generation uses
the Buf version pinned by the `buf-tools` build dependency; a system `buf` or
`protoc` installation is not required. The first uncached build downloads and
verifies the corresponding official Buf release asset.

The root workspace publishes library crates and does not commit `Cargo.lock`.
Cargo may generate an ignored local lockfile while building or testing. The
standalone `xtask` helper keeps its own lockfile.

The complete developer validation commands appear at the end of this README.

Run the focused E2E fixture check with:

```shell
cargo test -p yaml-sigil-conformance --test e2e_buildtime_keys
```

## Coverage and profiling

Install the report tools with Cargo:

```shell
cargo install cargo-llvm-cov
cargo install --locked samply
```

The coverage and profiling xtasks check for their required tool before doing
other work and print the corresponding installation command above when it is
absent. Keep these commands aligned with the constants and synchronization
test in `xtask/src/main.rs`.

Generate the workspace coverage report and optionally open its HTML index:

```shell
cargo xtask coverage
cargo xtask coverage --open
cargo xtask coverage-open
```

Record the focused E2E test with release-equivalent optimization and retained
debug symbols:

```shell
cargo xtask profile
cargo xtask profile --open
cargo xtask profile-open
```

The non-interactive default repeats the short E2E test 100 times and writes
Firefox Profiler data to `target/profile/profile.json`. Use
`--iterations <COUNT>` when a different sample size is useful. `--open` and
`profile-open` launch Samply's interactive browser UI; Samply does not generate
a standalone profiling HTML file. On Linux, the host's perf-event policy must
permit unprivileged profiling.

## Specification and conformance

The import task refreshes only the local artifacts this workspace owns.

```shell
cargo xtask update-spec
cargo xtask update-spec --ref origin/dev/example-branch
```

Update `docs/conformance-validation.md` in the same change when you change
fixtures, fixture plumbing, expected outcomes, exposed behavior, or deliberate
divergences.

## Release preparation

Release preparation publishes only `yaml-sigil-core`,
`yaml-sigil-transcription`, `yaml-sigil-signing`, and
`yaml-sigil-verification` to crates.io. The workspace default, conformance,
test-key, and xtask packages remain unpublished.

When preparing a workspace version change, align internal dependency versions
with:

```shell
cargo xtask sync-workspace-versions
```

## Developer validation

Run the complete CI sequence or its focused package-content check from the
workspace root. The per-crate list commands show the README, `LICENSE`, and
other files Cargo would place in each source package.

```shell
cargo xtask ci
cargo xtask package-content
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-core
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-transcription
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-signing
cargo package --list --allow-dirty --exclude-lockfile --package yaml-sigil-verification
```

These checks do not upload anything. The package-content checks only list and
compare modeled source-package paths; full package assembly and publication
remain release-preparation operations.
