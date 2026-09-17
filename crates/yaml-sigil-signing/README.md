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
- `ProviderSigningKeyBuilder` binds a synchronous `signature` 3.0 signer to
  canonical public-key bytes and offers `build` and `build_unqualified`.
- `AsyncProviderSigner` and `AsyncProviderSigningKeyBuilder` support awaitable
  operations. `ProviderAsyncSigner` and `UnqualifiedProviderAsyncSigner`
  implement `AsyncSigner` with the corresponding bound keys.
- Sync and async provider signing offer `_and_resource_limits` functions.
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
[`signature`](https://crates.io/crates/signature) 3.0. Your `try_sign` method
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

For complete `clap` commands using fresh Ed25519 or P-256 keys, see the
[`ring` and `aws-lc-rs` examples](https://github.com/NVIDIA/yaml-sigil-rs/tree/main/examples).
Both sign and verify YAML artifacts and execute round-trip tests in CI.
They demonstrate synchronous operations. The
[`async-provider` example](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/examples/async_provider.rs)
demonstrates awaitable operations through a simulated service. The
[provider guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/crypto-providers.md)
compares qualified, unqualified, and direct trait implementations and records
what the implementation checks and tests for each choice.

Use `ProviderSigningKeyBuilder::ed25519` with a 32-octet canonical compressed
public key or `ProviderSigningKeyBuilder::ecdsa_p256_sha256` with a 65-octet
uncompressed public key from *Standards for Efficient Cryptography 1 (SEC 1)*.
The builder receives only a synchronous `signature::Signer<[u8; 64]>` adapter
and the corresponding public key. It does not request or expose private-key
bytes.

The shared signer must implement `Sync`. Both qualified and unqualified bound
keys implement `Send + Sync`, so you can share them across worker threads.
Adapters with mutable state synchronize that state internally.

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

Use `sign_with_provider_and_resource_limits` or
`sign_with_unqualified_provider_and_resource_limits` for bounded provider
signing. The async counterparts are
`sign_with_async_provider_and_resource_limits` and
`sign_with_unqualified_async_provider_and_resource_limits`. They reuse the
preflight and exact output checks below. Ordinary provider entry points and
the async trait facades remain unbounded by that optional policy.

Async provider operations do not require a synchronous adapter or a library
runtime. Clients can be borrowed without a `'static` requirement. Local
payload preparation and qualified output self-verification remain synchronous;
the provider's signing operation can suspend. The adapter or caller owns
blocking-pool placement, timeouts, retries, and remote cancellation semantics.

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
