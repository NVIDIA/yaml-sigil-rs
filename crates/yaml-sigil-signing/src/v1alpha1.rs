// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API.
//!
//! These re-exports name the same definitions as the crate's unqualified
//! `v1alpha1` default. Values and trait implementations work through either
//! path without conversion. The specification identifier is independent of
//! the crate's package version.

pub use crate::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, AsyncProviderSignRequest, AsyncProviderSigner, AsyncProviderSigningKey,
    AsyncProviderSigningKeyBuilder, AsyncProviderSigningKeys, AsyncSigner,
    DEFAULT_MAX_ARTIFACT_BYTES, DefaultAsyncSigner, DefaultSigner, EncodeError, EncodeErrorKind,
    OutputForm, P256EncodingError, ProviderAsyncSigner, ProviderSignRequest, ProviderSigningKey,
    ProviderSigningKeyBuilder, ProviderSigningKeyError, ProviderSigningKeyErrorKind,
    ProviderSigningKeys, SignError, SignInvocationError, SignOutcome, SignProtoParams, SignRequest,
    SignSuccess, SignYamlParams, Signer, SignerCapabilities, SigningKey, TranscodeError,
    UnqualifiedAsyncProviderSignRequest, UnqualifiedAsyncProviderSigningKey,
    UnqualifiedAsyncProviderSigningKeys, UnqualifiedProviderAsyncSigner,
    UnqualifiedProviderSignRequest, UnqualifiedProviderSigningKey, UnqualifiedProviderSigningKeys,
    async_provider, p256_der_signature_to_raw, p256_public_key_to_uncompressed,
    proto_wire_to_signed_yaml_stream, proto_wire_to_signed_yaml_stream_with_resource_limits,
    provider, sign, sign_proto, sign_proto_with_resource_limits, sign_with_async_provider,
    sign_with_async_provider_and_resource_limits, sign_with_p256_digest_provider,
    sign_with_p256_digest_provider_and_resource_limits, sign_with_provider,
    sign_with_provider_and_resource_limits, sign_with_resource_limits,
    sign_with_unqualified_async_provider, sign_with_unqualified_async_provider_and_resource_limits,
    sign_with_unqualified_provider, sign_with_unqualified_provider_and_resource_limits, sign_yaml,
    sign_yaml_with_resource_limits, signature_signing_callback, signed_yaml_stream_to_proto_wire,
    signed_yaml_stream_to_proto_wire_with_resource_limits, signer_capabilities, transcription,
};
