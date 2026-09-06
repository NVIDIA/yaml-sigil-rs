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
- `Signer`, `AsyncSigner`, outcome types, and capability types are re-exported
  from
  [`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits).
- `SigningKey` accepts signing keys from
  [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) and
  [`p256`](https://crates.io/crates/p256). `SignRequest` uses those same key
  types with the request shape defined by `yaml-sigil-traits`.

The shared traits allow implementations to choose different key types. This
crate's free functions and default signers use the RustCrypto types above.

`SigningKey` debug output is redacted by design. Do not log private keys, seed
material, tokens, or raw signatures on trusted fact surfaces.

## Resource boundaries

Signing adds no deployment-specific maximum complete artifact size for YAML
or protobuf output. It allocates in proportion to the payload and encoded
signature data. Apply any local payload policy before signing and any output
policy to the returned artifact. Checking only the returned bytes does not
bound work or allocation already performed.

The transcoding functions also accept a complete source artifact and
construct a complete destination artifact without a configurable
whole-artifact limit. Applications accepting potentially untrusted input
should bound it before either transcoding direction.

YamlSigil `v1alpha1` defines no maximum complete artifact size. A local limit
is operational hardening, not conformance, and a caller may choose a lower
value, a higher value, or no additional limit. The 16,384-octet YAML
signature-carrier constraint remains separate.
