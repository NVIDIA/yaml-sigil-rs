# yaml-sigil-signing

`yaml-sigil-signing` creates signed YAML and protobuf documents for
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr).

Use this crate to sign payload bytes with Ed25519 or ECDSA P-256 SHA-256 and
emit a `yaml-sigil` artifact. Choose YAML or protobuf output explicitly for
each signing request.

## API Surface

- `sign` is the unified in-process signing entry point.
- `sign_yaml` and `sign_proto` provide form-specific convenience wrappers.
- `sign_with_resource_limits`, `sign_yaml_with_resource_limits`, and
  `sign_proto_with_resource_limits` enforce an explicit complete-output policy.
- `EncodeError` and `EncodeErrorKind` re-export the common protobuf format
  error used by resource-aware protobuf output.
- `sign_with_provider` accepts a qualified provider key, while
  `sign_with_unqualified_provider` makes the deliberate bypass explicit.
- `ProviderSigningKeyBuilder` binds a synchronous `signature` 2.2 signer to
  canonical public-key bytes and offers `build` and `build_unqualified`.
- `DefaultSigner` and `DefaultAsyncSigner` delegate to the free functions.
- `Signer`, `AsyncSigner`, outcome types, and capability types are re-exported
  from
  [`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits).
- `SigningKey` accepts signing keys from
  [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) and
  [`p256`](https://crates.io/crates/p256). `SignRequest` uses those same key
  types with the request shape defined by `yaml-sigil-traits`.

The shared traits allow implementations to choose different key types. `sign`,
its form-specific wrappers, and the default signers use the RustCrypto types
above. The provider entry points accept your adapter's bound keys.

`SigningKey` debug output is redacted by design. Do not log private keys, seed
material, tokens, or raw signatures on trusted fact surfaces.

## Local provider signing

Implement `signature::Signer<[u8; 64]> + Sync` for a type you own that holds or
borrows your provider's initialized key handle. Add a direct dependency on
[`signature`](https://crates.io/crates/signature) 2.2. Your `try_sign` method
performs the provider operation and returns the fixed-width signature or
`signature::Error`, which becomes `SignError::KeyOperationFailure`.

Follow the
[compiling adapter example](https://docs.rs/yaml-sigil-signing/latest/yaml_sigil_signing/provider/index.html#implement-a-signing-adapter)
to implement the trait, bind its public key, construct `ProviderSignRequest`,
and call `sign_with_provider`. The provider types are available at the crate
root and in its public `provider` module. The bound key is an opaque input to
the artifact operation. Implementing the separate
`yaml_sigil_traits::signing::Signer` contract means supplying the complete
signing operation, including artifact processing.

Use `ProviderSigningKeyBuilder::ed25519` with a 32-octet canonical compressed
public key or `ProviderSigningKeyBuilder::ecdsa_p256_sha256` with a 65-octet
uncompressed public key from *Standards for Efficient Cryptography 1 (SEC 1)*.
The builder receives only a synchronous `signature::Signer<[u8; 64]>` adapter
and the corresponding public key. It does not request or expose private-key
bytes.

`build` is the preferred path. It validates the public key and self-verifies
every signature produced for a real request before returning an artifact. It
does not ask the signer to process a hidden qualification message.
`build_unqualified` skips cryptographic output verification, but still
validates the public key and requires structurally valid signature octets. Use
the explicitly named unqualified signing functions with that key type.

YamlSigil checks the algorithm's public-key admissibility and, on the qualified
path, proves that each returned signature matches the bound public key and
real payload. The provider remains responsible for private-key generation
quality, entropy, storage, access policy, and other properties hidden behind
its opaque handle.

The provider receives the final message bytes. YAML signing applies any
authorized final-line-feed normalization first. Protobuf payload bytes remain
unchanged. The boundary does not accept a prehash. A P-256 adapter applies
SHA-256 exactly once and returns raw 64-octet big-endian `r || s`; DER is not a
provider output format. Ed25519 returns canonical 64-octet `R || S`.

Provider support or successful output self-verification does not establish or
imply FIPS validation. Such a claim depends on the complete provider build,
configuration, platform, operational boundary, and deployment.

Provider signing currently has no resource-aware entry point. Apply any
application-specific payload bound before signing. Rejecting an oversized
returned artifact does not bound work or allocation already performed.

## Resource boundaries

The resource-aware signing functions validate the bounded request shape first.
For protobuf output, they calculate the exact prospective wire length from
component lengths before scanning caller buffers or performing cryptography.
The outer result reports resource rejection, a middle result preserves the
protobuf format error, and the existing signing return remains the inner
value. YAML-only signing does not add the protobuf format layer.
For YAML output, they first test a conclusive lower bound that includes any
projected final line feed and the minimum carrier encoding. After signing and
carrier serialization, they check the exact output size before allocating the
complete artifact. Passing the lower-bound check never replaces that final
exact check.

The resource-aware transcoding functions check the original source before
parsing and check the complete destination independently before allocation.
The source and destination lengths are not added together. Errors identify the
form whose boundary failed. YAML-to-protobuf transcoding preserves protobuf
format errors between the outer resource result and the existing transcoding
result.

`ArtifactResourceLimits::default()` selects `DEFAULT_MAX_ARTIFACT_BYTES`, and
you can lower, raise, or disable that ceiling. Existing signing and transcoding
functions remain unbounded by this policy. Adoption at the affected trust
boundary, or an equivalent earlier raw-input bound, is required to protect an
existing caller. The policy is operational hardening, not YamlSigil `v1alpha1`
conformance. The 16,384-octet YAML signature-carrier constraint remains
separate.

## Third-party material

NVIDIA-authored crate material is licensed under Apache-2.0. RFC 8032-derived
point-encoding, scalar, challenge, and verification rules in
`src/provider_crypto.rs` retain their source attribution and terms. The P-256
provider boundary follows point-encoding behavior from
*Standards for Efficient Cryptography 1 (SEC 1)*. The applicable notices and
source terms are retained in
[`THIRD_PARTY_NOTICES.md`](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/crates/yaml-sigil-signing/THIRD_PARTY_NOTICES.md).
