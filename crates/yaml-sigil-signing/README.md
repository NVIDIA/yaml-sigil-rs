# yaml-sigil-signing

`yaml-sigil-signing` implements YamlSigil v1alpha1 signing for YAML and
protobuf artifact forms.

Use this crate when you need to sign payload bytes and emit a YamlSigil
artifact. The crate supports Ed25519 and ECDSA P-256 SHA-256 signatures, and it
can emit either YAML or protobuf wire output.

## API Surface

- `sign` is the unified in-process signing entry point.
- `sign_yaml` and `sign_proto` provide form-specific convenience wrappers.
- `DefaultSigner` and `DefaultAsyncSigner` delegate to the free functions.
- `Signer`, `AsyncSigner`, request types, outcome types, capability types, and
  `SigningKey` are re-exported from `yaml-sigil-traits`.

`SigningKey` debug output is redacted by design. Do not log private keys, seed
material, tokens, or raw signatures on trusted fact surfaces.
