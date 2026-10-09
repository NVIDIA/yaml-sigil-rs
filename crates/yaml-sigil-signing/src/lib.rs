// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign YamlSigil `v1alpha1` artifacts with native keys or local providers.
//!
//! Select `v1alpha1` explicitly; default paths name the same definitions.
//! `SignRequest` selects output form and complete-output resource policy.
//! `sign` and provider operations return a flat `SignOutcome`, distinguishing
//! invocation, resource, encoding, and signing failures through `SignError`.
//! Output bytes are owned. Unchanged input payloads are borrowed during signing.
//!
//! Defaults enable `std`, `yaml`, `protobuf`, and `system-rng`. Either format
//! works with `no_std + alloc`. With `system-rng` disabled, native `sign`
//! supports Ed25519; `sign_with_rng` takes a fallible caller CSPRNG for P-256.
//! P-256 samples uniform nonzero nonces and aborts on entropy failure without
//! RFC 6979 fallback. Providers own their nonce generation.
//!
//! Request limits apply to native, callback, digest, and async trait paths.
//! YAML checks a preflight lower bound and its final exact serialized size;
//! protobuf checks exact projected size before signing. These operational
//! policies are independent of `v1alpha1` conformance and carrier constraints.
//!
//! Provider builders bind canonical public-key bytes. Qualified signing
//! independently verifies each real output; explicitly unqualified APIs retain
//! key and signature-structure checks. Async callers select their own executor.
//! Transcoding between both enabled forms lives in the `transcription` module.
//! See the [portable API guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/no-std.md).

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

#[cfg(feature = "alloc")]
mod operations;
pub mod v1alpha1;
#[cfg(feature = "alloc")]
pub use operations::{
    AsyncProviderSignRequest, AsyncProviderSigner, AsyncProviderSigningKey,
    AsyncProviderSigningKeyBuilder, AsyncProviderSigningKeys, AsyncSigner, DefaultAsyncSigner,
    DefaultSigner, EncodeError, EncodeErrorKind, OutputForm, P256EncodingError,
    ProviderAsyncSigner, ProviderSignRequest, ProviderSigningKey, ProviderSigningKeyBuilder,
    ProviderSigningKeyError, ProviderSigningKeyErrorKind, ProviderSigningKeys, SignError,
    SignInvocationError, SignOutcome, SignRequest, SignSuccess, Signer, SignerCapabilities,
    SigningKey, UnqualifiedAsyncProviderSignRequest, UnqualifiedAsyncProviderSigningKey,
    UnqualifiedAsyncProviderSigningKeys, UnqualifiedProviderAsyncSigner,
    UnqualifiedProviderSignRequest, UnqualifiedProviderSigningKey, UnqualifiedProviderSigningKeys,
    async_provider, p256_der_signature_to_raw, p256_public_key_to_uncompressed, provider, sign,
    sign_with_async_provider, sign_with_p256_digest_provider, sign_with_provider, sign_with_rng,
    sign_with_unqualified_async_provider, sign_with_unqualified_provider,
    signature_signing_callback, signer_capabilities, signer_capabilities_with_rng,
};
pub use yaml_sigil_traits::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};

#[cfg(all(feature = "yaml", feature = "protobuf"))]
pub use operations::{
    TranscodeError, proto_wire_to_signed_yaml_stream, signed_yaml_stream_to_proto_wire,
};

#[cfg(all(feature = "yaml", feature = "protobuf"))]
pub use operations::transcription;
