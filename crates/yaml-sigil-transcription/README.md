# yaml-sigil-transcription

`yaml-sigil-transcription` composes
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr) artifacts from
document and signature components. It also decomposes artifacts into those
components. Both operations support YAML and protobuf forms.

In the API, the document bytes are the `payload` and the encoded signature
component is the `signature_carrier`. `compose` joins them into an artifact,
while `decompose` recovers the payload and signature-carrier bytes. These
operations change document structure only. They do not verify a signature or
authenticate the payload. Use
[`yaml-sigil-verification`](https://crates.io/crates/yaml-sigil-verification)
for signature verification.

YAML composition requires payload bytes that form a valid UTF-8 stream without
a BOM and with a final line terminator when non-empty. Protobuf composition
treats payload bytes as opaque and preserves every accepted byte unchanged.

## Select the contract

Use `yaml_sigil_transcription::v1alpha1` for explicit specification selection.
The unqualified paths remain the `v1alpha1` default and name the same traits,
requests, results, and implementations. Values work through either path
without conversion. The specification identifier is independent of the
crate's SemVer.

## API Surface

- `compose` and `decompose` perform the byte operations.
- `ComposeRequest::resource_limits` and `DecomposeRequest::resource_limits`
  select complete-artifact policy on those same operations.
- `decompose` borrows payload and carrier slices from the original artifact;
  `compose` produces an owned artifact.
- `EncodeError` and `EncodeErrorKind` re-export the common protobuf format
  error used by resource-aware protobuf composition.
- `DefaultTranscriber` and `DefaultAsyncTranscriber` delegate to the free
  functions.
- `Transcriber`, `AsyncTranscriber`, request types, response types, and
  capability types are re-exported from
  [`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits).

This crate does not provide RPC transport. Consumers that need a service
boundary should wire the trait API into their own deployment.

## Resource boundaries

`compose` validates request shape, computes exact output size with checked
arithmetic, and applies `request.resource_limits` before component scans and
complete-output allocation. `ComposeError` distinguishes invocation, resource,
encoding, and content failures in one result. `decompose` checks the original
input before form, conformance, or artifact processing and returns
`DecomposeError` on invocation or resource failure.

`ArtifactResourceLimits::default()` selects `DEFAULT_MAX_ARTIFACT_BYTES`.
Use `unbounded()` explicitly when no whole-artifact ceiling is required.
Default sync and async trait implementations honor the same request policy.

YamlSigil `v1alpha1` defines no maximum complete artifact size. These limits
are operational hardening and do not affect conformance results. The existing
16,384-octet YAML signature-carrier constraint remains separate and applies
where signature metadata is parsed.

## Features

Defaults enable `std`, `yaml`, and `protobuf`. Each format enables `alloc`
without requiring `std`. With defaults disabled, portable resource types
remain available; full operations require `alloc` and an enabled format.
The [portable API guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/no-std.md)
describes migration and isolated validation.
