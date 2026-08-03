# Archived YAML Parser Notes

This note preserves observations from parser-comparison work that has since
been removed. It also records the current YAML backend so the archived findings
have implementation context. It is not a user-facing support matrix.

## Current Implementation

`yaml-sigil-core` uses `noyalib` `0.0.13` for
`YamlSigilSignature.v1alpha1` YAML signature documents. The root `Cargo.toml`
declares the workspace dependency, and `crates/yaml-sigil-core` inherits it with
`noyalib = { workspace = true }`.

The workspace does not expose YAML parser or protobuf codegen selection
features. `yaml-sigil-core` generates protobuf wire helpers with `buffa`.

`parse_signature_document` decodes UTF-8 before YAML parsing and calls
`noyalib::load_all_with_config` and `noyalib::from_str_with_config` with these
parser policies:

- Duplicate mapping keys return an error.
- Merge keys are treated as ordinary keys.
- Anchors are denied.
- Custom tags are denied.
- Serde `deny_unknown_fields` rejects unknown top-level signature-document
  fields.

The parser applies these signature-document-specific resource limits:

| Resource | Limit |
|----------|-------|
| Input bytes | 16 KiB |
| Nesting depth | 16 |
| Alias expansions | 0 |
| Keys in one mapping | 8 |
| Elements in one sequence | 16 |
| Parser events | 128 |
| Constructed nodes | 64 |
| Cumulative scalar bytes | 8 KiB |
| Documents | 1 |
| Merge-key entries | 8 |

These parser budgets apply independently of any deployment-level artifact size
limit. The parser does not register application-defined tag constructors.

The dependency enables only `std` and disables default features. The optional
`noyalib` features do not improve this parser:

- `lossless-u64` does not apply because every signature-document field is a
  string. Unquoted numeric scalars must fail string deserialization, including
  values at and above the `u64` boundary.
- `fast-int` and `fast-float` do not affect serialization. The canonical
  emitter writes fixed schema and algorithm values directly and validates
  signature text against the base64url profile. The parser already uses its
  safe SIMD and SWAR hot paths without the `simd` compatibility feature.
- `strict-deserialise` duplicates the unknown-field protection on
  `SignatureDocument` and does not replace the configured entry point needed
  for duplicate-key, merge-key, anchor, and tag policy.
- `schema` and `validate-schema` do not replace the hand-maintained normative
  JSON Schema or the cached validator exposed by the optional
  `json-schema-validate` feature.
- Recovery, include expansion, compatibility shims, asynchronous I/O, parallel
  multi-document parsing, and third-party validation integrations do not fit
  this small, synchronous, fail-closed parser.

`serialize_signature_document` validates the fixed `schema` and `alg` values
and the base64url `signature` value before it emits the four known fields in
canonical order. It quotes `keyid` when present. Ordinary signatures remain
plain scalars. Empty or YAML-ambiguous base64url values use double-quoted
scalar form so parsing preserves the string value. Signing and transcoding
paths compose the resulting signature-document YAML through
`yaml-sigil-transcription`.

The optional `json-schema-validate` feature validates parsed
`SignatureDocument` values against the local signature-document schema. It does
not select a different YAML parser.

`noyalib` fits this implementation because it provides Serde support and parser
policy hooks in one dependency. The current configuration maps directly to this
workspace's conformance requirements for duplicate keys, unknown fields,
anchors, tags, and merge-key handling.

## Historical Findings

These observations are a historical conformance snapshot. Confirm that the
current dependency set and spec expectations still match before using them for
implementation decisions.

- The removed comparison covered `serde_yaml`, `yaml_serde`, `serde_yaml_bw`,
  `serde_yaml_neo`, and `serde-saphyr` for small, mapping-shaped
  `YamlSigilSignature.v1alpha1` documents.
- `serde-saphyr` was not retained. Its separate Serde-facing wrapper over
  Saphyr read as a little fork-like for this implementation, while `noyalib`
  provides Serde support and duplicate-key policy in one dependency.
- `serde_yml` and its `libyml` dependency were not adopted because they failed
  `cargo audit` at the time of evaluation.
- Duplicate `alg` and `signature` keys were rejected in the removed comparison;
  duplicate keys are still rejected during signature-document parsing.
- Unknown top-level YAML signature-document fields are rejected during
  signature-document parsing.
- The removed comparison tests did not uncover differences for the Tier A
  signature-document examples used at that time.

## Operational Guidance

- Apply deployment-level outer artifact and payload limits before invoking this
  workspace. The parser enforces its own signature-carrier budgets.
- Prefer structural decomposition with `yaml-sigil-core::decompose_artifact`
  before YAML parsing so the parser only sees the signature-document slice.
- Re-run `cargo audit` after any YAML dependency bump.
