# yaml-sigil-core

`yaml-sigil-core` provides parsing, encoding, and shared document support for
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr).

Use this crate when you need decomposition, payload invariants, signature
document parsing, protobuf wire helpers, or schema validation. Most callers
should start with
[`yaml-sigil-signing`](https://crates.io/crates/yaml-sigil-signing),
[`yaml-sigil-verification`](https://crates.io/crates/yaml-sigil-verification),
or
[`yaml-sigil-transcription`](https://crates.io/crates/yaml-sigil-transcription)
unless they need these lower-level helpers directly.

## What It Provides

- YAML artifact decomposition and payload validation.
- YAML signature-document parsing and serialization with
  [`noyalib`](https://crates.io/crates/noyalib).
- Protobuf `SignedYamlArtifact` helpers generated with
  [`buffa`](https://crates.io/crates/buffa).
- Algorithm mapping for the `yaml-sigil` wire and YAML names.
- Optional JSON Schema validation with the `json-schema-validate` feature.

The public extension-trait contract lives in
[`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits). This crate
provides implementation support for the published API crates in this
workspace.

Code generation obtains a pinned, verified Buf executable from the
[`buf-tools`](https://crates.io/crates/buf-tools) build dependency and feeds its
descriptor set to [`buffa-build`](https://crates.io/crates/buffa-build).
Neither a system `buf` nor a system `protoc` installation is required.

## The Signature Document

The YAML form uses the fixed `YamlSigilSignature.v1alpha1` schema discriminator.
Its optional `keyid` is nonempty when present, contains no carriage return or
line feed, and is at most 1,024 UTF-8 octets. Its `signature` is an RFC 4648
section 5 URL-safe base64 value without padding. The protobuf form identifies
the schema through its message type and carries the signature as raw octets.

The YAML and protobuf algorithm identifiers map as follows:

| Wire value | YAML identifier | Protobuf identifier |
|-----------:|-----------------|---------------------|
| 1 | `ED25519_PUREEDDSA_RAW_RS64_CANONICAL` | `ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL` |
| 2 | `ECDSA_SECP256R1_SHA256_RAW_RS64` | `ALGORITHM_ECDSA_SECP256R1_SHA256_RAW_RS64` |

Protobuf wire value `0`, `ALGORITHM_UNSPECIFIED`, is invalid. Read the
`yaml-sigil` specification for the complete
[signature-document semantics](https://github.com/NVIDIA/yaml-sigil-spec/blob/07d76b3624265af9632568abcb4bac5143af5a8e/README.md#the-signature-document)
and
[base64 requirements](https://github.com/NVIDIA/yaml-sigil-spec/blob/07d76b3624265af9632568abcb4bac5143af5a8e/base64-requirements.md).

## Third-party material

The crate source archive includes
[`THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/crates/yaml-sigil-core/THIRD_PARTY_NOTICES.md),
which records the current scope, attribution, source terms, disclaimers,
intellectual-property caveats, and non-endorsement language for identified
third-party material.
