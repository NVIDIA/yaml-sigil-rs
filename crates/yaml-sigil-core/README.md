# yaml-sigil-core

`yaml-sigil-core` contains the shared byte-level pieces for the YamlSigil
v1alpha1 Rust implementation.

Use this crate when you need decomposition, payload invariants, signature
document parsing, protobuf wire helpers, or schema validation. Most callers
should start with `yaml-sigil-signing`, `yaml-sigil-verification`, or
`yaml-sigil-transcription` unless they need these lower-level helpers directly.

## What It Provides

- YAML artifact decomposition and payload validation.
- YAML signature-document parsing and serialization with `noyalib`.
- Protobuf `SignedYamlArtifact` helpers generated with `buffa`.
- Algorithm mapping for the YamlSigil v1alpha1 wire and YAML names.
- Optional JSON Schema validation with the `json-schema-validate` feature.

The public extension-trait contract lives in `yaml-sigil-traits`. This crate
provides implementation support for the published API crates in this workspace.
