// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API, identical to the default exports.

pub use crate::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
#[cfg(feature = "alloc")]
pub use crate::{
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

#[cfg(all(feature = "yaml", feature = "protobuf"))]
pub use crate::{
    TranscodeError, proto_wire_to_signed_yaml_stream, signed_yaml_stream_to_proto_wire,
    transcription,
};
