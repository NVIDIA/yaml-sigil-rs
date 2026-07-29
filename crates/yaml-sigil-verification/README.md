# yaml-sigil-verification

`yaml-sigil-verification` implements YamlSigil v1alpha1 verification for YAML
and protobuf artifact forms.

Use this crate when you need to classify artifacts into the YamlSigil verifier
states, run structural pre-verification, or verify Ed25519 and ECDSA P-256
SHA-256 signatures.

## API Surface

- `verify`, `verify_yaml`, and `verify_proto` run verification.
- `pre_verify`, `pre_verify_yaml`, and `pre_verify_proto` run structural checks
  without crypto.
- `verify_from_pre_verify` and its form-specific helpers reuse successful
  pre-verification results.
- `DefaultVerifier` and `DefaultAsyncVerifier` delegate to the free functions.
- `Verifier`, `AsyncVerifier`, request types, result types, key helpers, and
  capability types are re-exported from `yaml-sigil-traits`.

`PublicKeys` is the caller-authorized key set, indexed by algorithm. The
artifact's unsigned `keyid` does not expand that set.

Only payload bytes returned by `VerifierState::Verified` are authenticated. A
signature document inside those bytes remains payload content.

## YAML Signature-Document Behavior

The verifier advertises `AdvertisedConformanceProfile::Permissive`. Its YAML
decoder rejects duplicate known mapping keys and returns
`MalformedAttemptedSigned`; it does not select an effective value from duplicate
occurrences. The decoder also rejects unknown top-level fields, anchors,
aliases, and custom tags.

Before parsing an unauthenticated YAML signature carrier, the verifier applies
signature-document-specific byte, nesting-depth, parser-event, constructed-node,
scalar-byte, document-count, mapping-key, sequence-length, alias-expansion, and
merge-key budgets. It does not register application-defined tag constructors.

The verifier exposes parser observations when callers request them. It does not
provide RPC transport.

## Third-party material

NVIDIA-authored crate material is licensed under Apache-2.0. RFC 8032-derived
constants, canonical-encoding rules, and a section 7.1 test-vector value in
`src/crypto.rs` retain their source attribution and terms in
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
