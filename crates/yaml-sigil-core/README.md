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
- Backend-neutral YAML signature-document parsing and canonical serialization.
- Stable owned and borrowed protobuf `SignedYamlArtifact` helpers backed by
  private [`buffa`](https://crates.io/crates/buffa) generated code.
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

## YAML and Serde boundary

`SignatureDocument` and its Serde implementations form the stable public
data-model boundary. Concrete YAML dependencies remain implementation details.
This crate currently uses [`noyalib`](https://crates.io/crates/noyalib), but a
consumer does not need the same `noyalib` release. Consumers can use another
Serde-compatible format or library when it represents the documented field
contract. This architectural boundary does not imply that independent YAML
backends accept or emit the same YAML.

Use `parse_signature_document` as the authoritative entry point for untrusted
YAML signature carriers. Direct Serde deserialization constructs the data model
without applying YamlSigil's YAML byte limit, parser resource budgets, document
count, or duplicate-key, merge-key, anchor, and tag policies.

Serde compatibility covers semantic values. It does not promise identical YAML
acceptance, resource policy, comments, scalar style, field order, or bytes
across backends. Use `serialize_signature_document` for canonical YAML output.
Retain the original carrier bytes when forwarding must preserve presentation or
byte identity. Treat the text inside `CoreError::SignatureYaml` as an unstable
human diagnostic, not a machine-readable interface.

The exact-pinned downstream fixture characterizes interoperability between
`noyalib` releases `0.0.35` and `0.0.36`. This same-library, cross-version test
does not establish cross-backend YAML portability or a permanent support
guarantee for either release.

## Protobuf facade

The public `pb` module exposes opaque owned messages and zero-copy borrowed
views. Only `yaml-sigil-core` depends on Buffa directly. Consumers using a
different protobuf implementation or Buffa release exchange encoded bytes
with the facade instead of sharing generated Rust types.

```rust
use yaml_sigil_core::{
    AlgorithmId,
    pb::{SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature},
};

let signature =
    YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
let artifact =
    SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));

let mut wire = Vec::with_capacity(artifact.encoded_len().unwrap());
artifact.encode_into(&mut wire).unwrap();

let decoded = SignedYamlArtifactRef::decode(&wire).unwrap();
assert_eq!(decoded.payload(), b"message\n");
```

Borrowed payload, `keyid`, and signature accessors point into the input. Use
`to_owned` when data must outlive that input. Owned decode and re-encode retain
unknown fields and raw unknown algorithm numbers. Call
`discard_unknown_fields` to remove retained unknown data explicitly.

`DecodeError` and `EncodeError` expose non-exhaustive category enums through
`kind`. Their fields remain private, and their `Debug` and `Display` output
does not retain or print payload, signature, carrier, or unknown-field bytes.
Include a wildcard arm when matching an error category.

Code that previously constructed generated structs with public fields should
use `SignedYamlArtifact::new`, `YamlSigilSignature::new`, and their mutation
methods. Replace Buffa `Message` trait calls with the facade's `decode`,
`encoded_len`, `encode_to_vec`, and `encode_into` methods. All encode methods
are fallible. Use `AlgorithmId` for recognized values and
`algorithm_wire_value` when forwarding an unknown protobuf enum number.

## Resource boundaries

YamlSigil `v1alpha1` defines no maximum complete artifact size. The facade
does not add a deployment-specific byte limit. Applications accepting
potentially untrusted input should apply their selected whole-artifact bound
before YAML or protobuf processing. A deployment can choose a lower value, a
higher value, or no additional limit.

`4 MiB` is an example and the intended default for future opt-in bounded APIs.
It is not a YamlSigil or gRPC protocol requirement, and this crate does not
enforce it today. The existing 16,384-octet YAML signature-carrier constraint
is separate from complete artifact size. Protobuf format limits, parser
safeguards, address-space limits, allocator limits, and deployment controls
still apply when no additional whole-artifact limit is selected.

Whole-artifact limits do not affect conformance results. Rejecting an artifact
under a local resource policy does not make it malformed or non-conforming.

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
[signature-document semantics](https://github.com/NVIDIA/yaml-sigil-spec/blob/bcfa1e05a61fc27c6fd814a3910e7a24a560f038/README.md#the-signature-document)
and
[base64 requirements](https://github.com/NVIDIA/yaml-sigil-spec/blob/bcfa1e05a61fc27c6fd814a3910e7a24a560f038/base64-requirements.md).

## Third-party material

The crate source archive includes
[`THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/crates/yaml-sigil-core/THIRD_PARTY_NOTICES.md),
which records the current scope, attribution, source terms, disclaimers,
intellectual-property caveats, and non-endorsement language for identified
third-party material.
