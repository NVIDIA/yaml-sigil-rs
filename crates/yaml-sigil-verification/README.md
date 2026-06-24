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

The verifier exposes parser observations when callers request them. It does not
provide RPC transport.
