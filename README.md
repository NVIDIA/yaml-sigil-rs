# yaml-sigil-rs

`yaml-sigil-rs` provides Rust implementation crates for YamlSigil v1alpha1. It
depends on
[`yaml-sigil-traits`](https://github.com/NVIDIA-dev/yaml-sigil-traits) for the
public extension-trait contract; this workspace implements signing,
verification, transcription, protobuf wire helpers, YAML signature-document
parsing, and local conformance checks.

The repo vendors the implementation inputs it needs: the protobuf schema, the
signature-document JSON Schema, the curated conformance fixtures, and the
third-party notices that accompany those fixtures. The normative specification
lives in
[`yaml-sigil-spec`](https://github.com/NVIDIA-dev/yaml-sigil-spec), not this
repository.

NVIDIA-authored material is licensed under the
[Apache License 2.0](./LICENSE). Third-party test data, standards-derived
material, and their redistribution requirements are documented in
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

Read [AGENTS.md](AGENTS.md) for the contributor workflow, conformance policy,
and documentation style guide.

## Crates

- `crates/yaml-sigil-core`: decomposition, payload invariants, YAML
  signature-document parsing, JSON Schema validation, and protobuf wire
  helpers.
- `crates/yaml-sigil-transcription`: compose and decompose operations plus the
  default `Transcriber` implementations.
- `crates/yaml-sigil-verification`: verify and pre-verify operations plus the
  default `Verifier` implementations.
- `crates/yaml-sigil-signing`: signing operations plus the default `Signer`
  implementations.
- `crates/yaml-sigil-conformance`: workspace-only fixture harness.
- `crates/yaml-sigil-test-keys`: workspace-only test key material.

`yaml-sigil-core` generates protobuf helpers with `buffa` and parses YAML
signature documents with `noyalib`. The optional `json-schema-validate` feature
adds validation against the local signature-document schema.

Callers select artifact forms through the public form enums. `v1alpha1` defines
no magic bytes, media type, or required file extension.

YAML decompose and verify operations require complete artifacts because
boundary selection uses the last constrained marker.

### Published Crate Compliance Documents

Every published library crate includes its crate README, the Apache 2.0
`LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` with the Developer Certificate
of Origin sign-off policy. The crate-local security and contribution paths are
symlinks to the workspace-root documents; Cargo flattens them into ordinary
files when it assembles a `.crate` archive.

`yaml-sigil-verification` additionally includes its scoped
`THIRD_PARTY_NOTICES.md` for the RFC 8032-derived constants,
canonical-encoding rules, and test-vector value packaged in that crate. The
other published implementation crates do not package material covered by that
notice.

Before release, use `cargo package --list -p <crate>` to confirm the applicable
documents are present in each archive.

## Build

`rust-toolchain.toml` pins Rust. `protoc` must be on `PATH`.

The root workspace publishes library crates and does not commit `Cargo.lock`.
Cargo may generate an ignored local lockfile while building or testing. The
standalone `xtask` helper keeps its own lockfile.

```shell
cargo xtask hygiene
cargo test --workspace --all-features
```

Run the focused E2E fixture check with:

```shell
cargo test -p yaml-sigil-conformance --test e2e_buildtime_keys
```

## Spec And Conformance

Read [AGENTS.md](AGENTS.md) before importing upstream spec changes. The import
task refreshes only the local artifacts this workspace owns.

```shell
cargo xtask update-spec
cargo xtask update-spec --ref origin/dev/example-branch
```

Update `docs/conformance-validation.md` in the same change when you change
fixtures, fixture plumbing, expected outcomes, exposed behavior, or deliberate
divergences.

## Validation

Run hygiene, core tests, and E2E tests locally before release-oriented changes.

Publishing is disabled in this prelaunch cleanup branch. Re-enable and validate
crates.io metadata in a later release-preparation change.

```shell
cargo xtask sync-workspace-versions
```
