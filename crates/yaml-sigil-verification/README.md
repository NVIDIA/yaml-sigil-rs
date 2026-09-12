# yaml-sigil-verification

`yaml-sigil-verification` verifies
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr) documents and
their signatures in YAML and protobuf forms.

Use this crate to check document structure, verify Ed25519 or ECDSA P-256
SHA-256 signatures, and retrieve payload bytes only after successful
verification. The public results classify each attempt into the `yaml-sigil`
verifier states.

## API Surface

- `verify`, `verify_yaml`, and `verify_proto` run verification.
- Their `_with_resource_limits` variants apply an explicit complete-input
  policy before verification work.
- `pre_verify`, `pre_verify_yaml`, and `pre_verify_proto` run structural checks
  without crypto.
- Their `_with_resource_limits` variants and
  `can_pre_verify_with_resource_limits` check the original encoded input.
- `verify_from_pre_verify` and its form-specific helpers reuse successful
  pre-verification results.
- `DefaultVerifier` and `DefaultAsyncVerifier` delegate to the free functions.
- `Verifier`, `AsyncVerifier`, result types, and capability types are
  re-exported from
  [`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits).
- `PublicKeys` accepts verifying keys from
  [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) and
  [`p256`](https://crates.io/crates/p256).
- `resolve_ed25519_verifying_key` and `resolve_p256_verifying_key` turn raw
  public-key bytes into those key types.

`PublicKeys` contains caller-supplied verification keys indexed by algorithm.
The artifact's unsigned `keyid` remains a deployment-specific lookup hint.
The shared traits leave key parsing to each implementation. This crate applies
its Ed25519 key-admissibility checks both when it resolves raw key bytes and
when a caller supplies an already constructed typed key.

`resolve_p256_verifying_key` accepts only the 65-byte uncompressed
`0x04 || X || Y` encoding from
*Standards for Efficient Cryptography 1 (SEC 1)*.

Bind each artifact source, route, or storage class to one `ArtifactForm` before
calling the verifier. Do not infer the form from artifact bytes or retry the
other form after structural or verification failure.

Only payload bytes returned by `VerifierState::Verified` are authenticated. A
signature document inside those bytes remains payload content.

## Resource boundaries

Resource-aware verification, pre-verification, and the boolean summary check
the original complete input before form options, parsing, copying, or
cryptography. Their outer `ArtifactResourceResult` reports resource admission;
the inner result or verifier state preserves the existing contract.

Bounded pre-verification enforces complete-input size once while the original
encoded artifact is available. Continue with the existing
`verify_from_pre_verify` functions. They receive in-memory components and do
not reconstruct or recheck an encoded artifact.

YamlSigil `v1alpha1` defines no maximum complete artifact size. A local
resource-policy rejection remains separate from invocation errors, malformed
artifacts, failed cryptographic verification, and conformance results. A
deployment can choose a lower limit, a higher limit, or no additional limit;
`DEFAULT_MAX_ARTIFACT_BYTES` defines the explicit default. Existing
verification entry points and default trait implementations remain unbounded
by this policy. Adopt a bounded operation at the affected trust boundary or
enforce an equivalent earlier raw-input bound. Protobuf format limits, parser
safeguards, address-space limits, allocator limits, and deployment controls
still apply.

## YAML Signature-Document Behavior

The verifier advertises `AdvertisedConformanceProfile::Permissive`. Its YAML
decoder rejects duplicate known mapping keys under every profile and returns
`MalformedAttemptedSigned`; it does not select an effective value from
duplicate occurrences. The decoder also rejects unknown top-level fields,
which is stricter than the `Permissive` requirement.

Before parsing an unauthenticated YAML signature carrier, the verifier applies
these implementation-specific hard bounds:

| Parser dimension | Bound |
|------------------|------:|
| Markerless carrier bytes | 16,384 |
| Nesting depth | 16 |
| Alias expansions | 0 |
| Mapping keys | 8 |
| Sequence length | 16 |
| Parser events | 128 |
| Constructed nodes | 64 |
| Cumulative scalar bytes | 8,192 |
| Documents | 1 |
| Merge keys | 8 |

The parser rejects anchors, aliases, custom tags, and duplicate keys. These
values describe this Rust implementation; they are not portable `yaml-sigil`
limits except for the 16,384-octet markerless carrier limit. That carrier
constraint is independent of complete artifact size.

The verifier exposes parser observations when callers request them. It does not
provide RPC transport.

## Third-party material

NVIDIA-authored crate material is licensed under Apache-2.0. RFC 8032-derived
point-encoding and verification rules and a section 7.1 test-vector value in
`src/crypto.rs` retain their source attribution and terms. The P-256 resolver
follows point-encoding behavior from *Standards for Efficient Cryptography 1
(SEC 1)*. The applicable notices and source terms are retained in
[`THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/crates/yaml-sigil-verification/THIRD_PARTY_NOTICES.md).
