# yaml-sigil-signing

`yaml-sigil-signing` creates signed YAML and protobuf documents for
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr).

Use this crate to sign payload bytes with Ed25519 or ECDSA P-256 SHA-256 and
emit a `yaml-sigil` artifact. Choose YAML or protobuf output explicitly for
each signing request.

## API Surface

- `sign` is the unified in-process signing entry point.
- `sign_yaml` and `sign_proto` provide form-specific convenience wrappers.
- `DefaultSigner` and `DefaultAsyncSigner` delegate to the free functions.
- `Signer`, `AsyncSigner`, request types, outcome types, capability types, and
  `SigningKey` are re-exported from
  [`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits).

`SigningKey` debug output is redacted by design. Do not log private keys, seed
material, tokens, or raw signatures on trusted fact surfaces.
