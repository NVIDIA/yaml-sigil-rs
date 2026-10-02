# yaml-sigil-signing

`yaml-sigil-signing` creates signed YAML and protobuf documents for
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr).

Use this crate to sign payload bytes with Ed25519 or ECDSA P-256 SHA-256 and
emit a `yaml-sigil` artifact. Choose YAML or protobuf output explicitly for
each signing request.

## Select the contract

Use `yaml_sigil_signing::v1alpha1` for explicit specification selection,
including provider modules and resource-aware operations. The unqualified
paths remain the `v1alpha1` default and name the same traits, key bindings,
requests, and implementations. Values work through either path without
conversion. The specification identifier is independent of the crate's SemVer.

## API Surface

- `sign` signs either artifact form in process.
- `SignRequest::output_form` selects the enabled artifact format, and
  `SignRequest::resource_limits` selects its complete-output policy.
- `sign_with_rng` accepts a fallible caller-supplied CSPRNG for P-256.
- `EncodeError` and `EncodeErrorKind` re-export the common protobuf format
  error used by resource-aware protobuf output.
- `sign_with_provider` accepts a qualified public-key binding and a callback, while
  `sign_with_unqualified_provider` makes the deliberate bypass explicit.
- `ProviderSigningKeyBuilder` validates canonical public-key bytes and offers
  `build` and `build_unqualified`. It does not store a signer.
- `sign_with_p256_digest_provider` passes the final payload's SHA-256 digest to
  a P-256 callback and independently verifies its output.
- `signature_signing_callback` forwards existing `signature` 3.0 adapters.
- `AsyncProviderSigner` and `AsyncProviderSigningKeyBuilder` support awaitable
  operations. `ProviderAsyncSigner` and `UnqualifiedProviderAsyncSigner`
  implement `AsyncSigner` with the corresponding bound keys.
- Sync and async provider signing honor the request resource policy.
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
above. Synchronous provider calls use public-key bindings and a separate
callback for each operation. Async provider calls use keys bound to their
adapters.

`SigningKey` redacts private material from debug output. Keep private keys,
seed material, tokens, and raw signatures out of logs and trusted verification
records.

## Local provider signing

`p256_der_signature_to_raw` converts a provider's DER signature into the
required 64-octet raw form. `p256_public_key_to_uncompressed` validates and
converts compressed or uncompressed public points into the required 65-octet
form. Both helpers return `P256EncodingError` on invalid input and preserve
valid signature scalar values, including high-S. They are re-exported from
[`yaml-sigil-core`](https://crates.io/crates/yaml-sigil-core); see its
[encoding contracts and compiling examples](https://docs.rs/yaml-sigil-core/latest/yaml_sigil_core/p256_encoding/index.html).
Convert public keys before binding and DER signatures before a callback
returns. The builder still rejects compressed keys, and callbacks still return
raw signatures.

Validate your provider's public key with `ProviderSigningKeyBuilder`, construct
`ProviderSignRequest`, and pass a callback to each `sign_with_provider` call.
The callback has the shape `FnOnce(&[u8]) -> Result<[u8; 64], SignError>` and
may borrow mutable state without `Send` or `Sync`. It runs synchronously on
your calling thread and may block. Map an SDK failure to
`SignError::KeyOperationFailure`; callback errors remain in `SignOutcome::Signer`.

The [compiling examples](https://docs.rs/yaml-sigil-signing/latest/yaml_sigil_signing/provider/index.html)
cover mutable local state, borrowed handle reuse, and concurrent signing.
Existing `signature::Signer<[u8; 64]>` adapters can use
`signature_signing_callback(&adapter)`, which maps `signature::Error` to
`SignError::KeyOperationFailure`. The provider types are available at the crate
root and in `provider`. Implementing the separate
`yaml_sigil_traits::signing::Signer` contract means supplying the complete
signing operation, including artifact processing.

For complete `clap` commands using fresh Ed25519 or P-256 keys, see the
[`ring` and `aws-lc-rs` examples](https://github.com/NVIDIA/yaml-sigil-rs/tree/main/examples).
Both sign and verify YAML artifacts and execute round-trip tests in CI.
They demonstrate synchronous operations. The
[`async-provider` example](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/examples/async_provider.rs)
demonstrates awaitable operations through a simulated service. The
[provider guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/crypto-providers.md)
describes the checks and tests for each integration choice. It covers qualified
and explicitly unqualified adapters as well as direct trait implementations.

Use `ProviderSigningKeyBuilder::ed25519` with a 32-octet canonical compressed
public key or `ProviderSigningKeyBuilder::ecdsa_p256_sha256` with a 65-octet
uncompressed public key from *Standards for Efficient Cryptography 1 (SEC 1)*.
The builder receives only public bytes. It does not request private-key bytes
or hold a provider handle. Requests borrow these bindings. Both qualified and
unqualified keys and requests are `Send + Sync`. Each callback retains the
thread restrictions of its captures. Shared providers can use one binding from
multiple threads; local callbacks can borrow the same mutable session on
successive calls.

`build` selects the qualified path. It validates the public key, and each
operation self-verifies the returned signature before emitting an artifact.
Requests rejected before signing make zero callback calls; admitted signing
operations make one. The library adds no probe signature or retry.
`build_unqualified` skips cryptographic output verification, but still
validates the public key and requires structurally valid signature octets. Use
the explicitly named unqualified signing functions with that key type.

YamlSigil checks the algorithm's public-key admissibility and, on the qualified
path, proves that each returned signature matches the bound public key and
real payload. The provider remains responsible for private-key generation
quality, entropy, storage, access policy, and other properties hidden behind
its opaque handle.

Message callbacks receive final payload bytes after authorized YAML
final-newline handling. Protobuf bytes remain unchanged. A P-256 message
callback applies SHA-256 once. Ed25519 returns canonical 64-octet `R || S`;
P-256 returns 64-octet big-endian `r || s`, never DER.

For a device that signs a digest, use `sign_with_p256_digest_provider` with
`FnOnce(&[u8; 32]) -> Result<[u8; 64], SignError>`. The library computes SHA-256
over the prepared payload once for that callback. Sign those digest bytes
without hashing again. Supply the complete payload in the request so the
library can verify and emit it. The digest path requires a qualified P-256
binding and rejects Ed25519 before calling. Both P-256 callback choices own
the profile's CSPRNG nonce sampling; output verification cannot establish how
the nonce was generated. See the
[compiling digest example](https://docs.rs/yaml-sigil-signing/latest/yaml_sigil_signing/fn.sign_with_p256_digest_provider.html).

Provider support or successful output self-verification does not establish or
imply FIPS validation. Such a claim depends on the complete provider build,
configuration, platform, operational boundary, and deployment.

Set `request.resource_limits` for bounded native, callback, digest, and async
provider signing. All primary operations use the preflight and final checks
under [Resource boundaries](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/crates/yaml-sigil-signing/README.md#resource-boundaries).

Async provider operations do not require a synchronous adapter or a library
runtime. Clients can be borrowed without a `'static` requirement. Local
payload preparation and qualified output self-verification remain synchronous;
the provider's signing operation can suspend. The adapter or caller owns
blocking-pool placement and timeout policy. It also controls retries and remote
cancellation semantics.

## Resource boundaries

Primary signing validates invocation shape and enforces the request policy.
Protobuf output has exact projected sizing before content processing or
cryptography. YAML first tests a conclusive lower bound, then checks the exact
serialized output before complete-artifact allocation. Escaping can make a
late rejection necessary. `SignError` distinguishes invocation, resource,
encoding, and signing failures in a flat result.

Transcoding takes `&ArtifactResourceLimits` on its primary functions, checks
the original source before parsing, and admits the destination independently.
Source and destination sizes are not added together. `TranscodeError`
distinguishes resource, encoding, and conversion failures.

`ArtifactResourceLimits::default()` selects `DEFAULT_MAX_ARTIFACT_BYTES`;
`unbounded()` disables the optional ceiling. This policy does not change
YamlSigil `v1alpha1` conformance or its independent 16,384-octet YAML carrier
constraint.

## Features and entropy

Defaults enable `std`, `yaml`, `protobuf`, and `system-rng`. Disable defaults
and select either format for `no_std + alloc`. Without `system-rng`, `sign`
supports native Ed25519; use `sign_with_rng` for native P-256 or a provider
operation for provider-held keys. `signer_capabilities()` describes native
`sign`, while `signer_capabilities_with_rng()` describes supplied entropy.
Entropy failure aborts without deterministic fallback. P-256 retains uniform
CSPRNG nonce sampling; the library does not replace it with RFC 6979.

The [portable API guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/no-std.md)
describes feature selection and migration.
