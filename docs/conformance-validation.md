# Conformance validation

This document records how `yaml-sigil-rs` uses its local conformance fixture
tree:

```text
crates/yaml-sigil-conformance/fixtures/
```

The fixture tree is a curated import of the spec conformance artifacts used by
this Rust implementation. It intentionally omits upstream rebuild generators
and vendor data. Spec changes are reviewed separately, then fixture artifacts
are imported here only when this implementation needs them.

Every conformance-related change must update this document in the same commit.
That includes fixture imports, fixture removals, fixture-to-API remapping,
expected outcome changes, ignored tests, API additions discovered through a
fixture, and deliberate divergences.

## Suite Layout

`crates/yaml-sigil-conformance` exposes one sync suite per fixture directory
and async siblings where the exercised trait surface has async APIs. Downstream
implementations can call the same `run_*_suite` helpers to compare behavior.

| Fixture directory | Sync suite | Async suite | Surface exercised |
|-------------------|------------|-------------|-------------------|
| `yaml-decomposition/` | `run_yaml_decomposition_suite` | `run_yaml_decomposition_suite_async` | `(Async)Transcriber::decompose` on YAML form |
| `protobuf-conformance/` | `run_protobuf_outer_suite` | `run_protobuf_outer_suite_async` | `(Async)Transcriber::decompose` on protobuf form |
| `schema-alignment/` | `run_schema_alignment_suite` | `run_schema_alignment_suite_async` | `(Async)Verifier::pre_verify` and `verify` |
| `key-id/` | `run_keyid_suite` | `run_keyid_suite_async` | `(Async)Verifier::pre_verify` and `verify` |
| `base64/` | `run_base64_suite` | n/a | Core base64 helper behavior |
| `alg-ed25519/` | `run_ed25519_suite` | `run_ed25519_suite_async` | `(Async)Verifier::verify`, key resolution, signing |
| `alg-ecdsa/` | `run_ecdsa_suite` | `run_ecdsa_suite_async` | `(Async)Verifier::verify`, key resolution, signing |
| `yaml-signature-conformance/` | `run_yaml_signature_suite` | `run_yaml_signature_suite_async` | `(Async)Verifier::verify` over YAML signature documents |

Primary entry points:

- `crates/yaml-sigil-conformance/tests/conformance_default.rs`
- `crates/yaml-sigil-conformance/tests/conformance_default_smoke.rs`
- `crates/yaml-sigil-conformance/tests/conformance_default_smoke_async.rs`
- `crates/yaml-sigil-conformance/tests/e2e_buildtime_keys.rs`
- `crates/yaml-sigil-conformance/tests/yaml_metadata_conformance.rs`

The conformance tests exercise this workspace's implementation crates.

## Expected Behavior Summary

The current fixture set covers:

- YAML decomposition marker handling, unsigned artifacts, malformed carrier
  ranges, marker selection, UTF-8 preconditions, and BOM rejection.
- Protobuf outer-envelope duplicate/unknown-field handling under
  `OuterConformance` modes.
- YAML/protobuf algorithm mapping and malformed algorithm identifiers.
- `keyid` presence, emptiness, UTF-8 byte bounds, and lookup-hint handling.
- URL-safe no-padding base64 behavior, including invalid alphabet, padding,
  whitespace, length, and trailing-bit cases.
- Ed25519 happy paths, noncanonical encodings, small-order configured keys,
  stable re-signing, and algorithm-parameter rejection.
- ECDSA P-256/SHA-256 happy paths, ACVP-derived vectors, high-S/low-S
  acceptance, invalid component ranges, wrong-size signatures, bad keys, and
  nonce-instability fixtures.
- YAML signature-document duplicate-key and unknown-key behavior under the
  implementation's advertised profile.

When a fixture exercises behavior that the Rust implementation cannot or
should not represent naturally, record the divergence here rather than adding
an unnatural workaround.

## Import Review Notes

- 2026-07-09: Imported `yaml-sigil-spec` `origin/main` at
  `189ee8a747749c3b65e9f68fe9bdbda6d70e9c39`. The import adds the complete
  third-party notices at the workspace root and beside the conformance crate,
  including the complete CC BY 4.0 legal code and RFC 8032 copyright-context
  link, and updates fixture provenance wording. Fixture bytes, fixture names,
  suite mappings, and expected outcomes are unchanged.
- 2026-06-16: Imported `yaml-sigil-spec` `origin/main` at
  `aafcc3b432f5b7397e756d2033224bf3d0853c1b`. The imported conformance
  fixture changes are README wording updates only; fixture bytes, fixture
  names, suite mappings, and expected outcomes are unchanged. The imported
  protobuf schema change is comment-only and does not change wire identity or
  generated Rust behavior.
- 2026-06-22: Added coverage-only unit tests for conformance fixture helpers,
  the base64 profile table, YAML signature profile branching, and Tier A schema
  rejection cases. Fixture bytes, fixture names, suite mappings, and expected
  outcomes are unchanged.
- 2026-06-23: Imported `yaml-sigil-spec` `origin/chore/ddurst/prelaunch` at
  `f33c1bc3452b24137dfecac67267c8898a02a02c`. The imported fixture changes add
  `yaml-decomposition/invalid-utf8-no-marker.yaml`,
  `yaml-decomposition/invalid-utf8-before-marker.yaml`,
  `yaml-decomposition/bom-signed.yaml`, and
  `yaml-decomposition/bom-no-marker.yaml`. The YAML decomposition suite now
  asserts `MalformedAttemptedSigned` at transcription and `StructuralFailure`
  at pre-verify for those fixtures.

## Known Behaviors

- `Verifier` advertises `AdvertisedConformanceProfile::Permissive`. Stock
  protobuf decoders use last-wins behavior for duplicate inner fields, so
  advertising a stricter unified inner profile would be misleading.
- YAML duplicate mapping keys are rejected during signature-document parsing.
- After decomposition isolates the YAML signature-document slice, additional
  YAML documents in that slice are not rejected solely because the slice is a
  multi-document stream. This does not constrain multi-document signed payloads.
- YAML merge keys are treated as ordinary mapping keys for signature-document
  parsing.
- YAML anchors, aliases, and custom tags are rejected during
  signature-document parsing.
- Unknown YAML signature-document fields are rejected during
  signature-document parsing.
- Empty signature octets can pass through transcription/decomposition and are
  rejected at verification.
- Protobuf-form payload bytes are arbitrary octets; YAML-form payload bytes
  remain constrained by the YAML envelope rules.

## Updating Fixtures

When importing fixtures from a spec checkout:

1. Copy only the fixture directories that `yaml-sigil-conformance` uses.
2. Do not copy `rebuild-rs/`, ACVP vendor corpora, or generator-only files.
3. Update suite code and this document together if fixture names, categories,
   or expected outcomes change.
4. Run `cargo test -p yaml-sigil-conformance --all-features`.
5. Run `cargo test --workspace --all-features` before release or when fixture
   behavior, protobuf decoding, or YAML parsing changes.
