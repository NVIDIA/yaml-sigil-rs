// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API.
//!
//! These re-exports name the same definitions as the crate's unqualified
//! `v1alpha1` default. Values and trait implementations work through either
//! path without conversion. The specification identifier is independent of
//! the crate's package version.

pub use crate::{
    AdvertisedConformanceProfile, ArtifactForm, ArtifactResourceError, ArtifactResourceErrorKind,
    ArtifactResourceForm, ArtifactResourceLimits, ArtifactResourceResult, AsyncProviderPublicKeys,
    AsyncProviderVerifier, AsyncProviderVerifierFactory, AsyncProviderVerifyingKey,
    AsyncVerificationProviderBuilder, AsyncVerifier, DEFAULT_MAX_ARTIFACT_BYTES,
    DefaultAsyncVerifier, DefaultVerifier, InvocationError, P256EncodingError, PreVerifyOutcome,
    PreVerifyResponse, ProviderAsyncVerifier, ProviderKeyBindingError, ProviderKeyBindingErrorKind,
    ProviderPublicKeys, ProviderQualificationError, ProviderQualificationErrorKind,
    ProviderQualificationStatus, ProviderVerificationOutcome, ProviderVerifier,
    ProviderVerifierFactory, ProviderVerifyingKey, PublicKeys, QualifiedAsyncVerificationProvider,
    QualifiedVerificationProvider, UnqualifiedAsyncProviderPublicKeys,
    UnqualifiedAsyncProviderVerifyingKey, UnqualifiedAsyncVerificationProvider,
    UnqualifiedProviderAsyncVerifier, UnqualifiedProviderPublicKeys,
    UnqualifiedProviderVerifyingKey, UnqualifiedVerificationProvider, UnverifiedSignature,
    VerificationProviderBuilder, Verifier, VerifierCapabilities, VerifierOptions, VerifierState,
    VerifyResult, async_provider, can_pre_verify, can_pre_verify_with_resource_limits,
    p256_der_signature_to_raw, p256_public_key_to_uncompressed, pre_verify, pre_verify_proto,
    pre_verify_proto_with_resource_limits, pre_verify_with_resource_limits, pre_verify_yaml,
    pre_verify_yaml_with_resource_limits, provider, resolve_ed25519_verifying_key,
    resolve_p256_verifying_key, verifier_capabilities, verify, verify_from_pre_verify,
    verify_from_pre_verify_proto, verify_from_pre_verify_with_async_provider,
    verify_from_pre_verify_with_provider, verify_from_pre_verify_with_unqualified_async_provider,
    verify_from_pre_verify_with_unqualified_provider, verify_from_pre_verify_yaml, verify_proto,
    verify_proto_with_resource_limits, verify_with_async_provider,
    verify_with_async_provider_and_metadata, verify_with_metadata,
    verify_with_metadata_and_resource_limits, verify_with_provider,
    verify_with_provider_and_metadata, verify_with_resource_limits,
    verify_with_unqualified_async_provider, verify_with_unqualified_async_provider_and_metadata,
    verify_with_unqualified_provider, verify_with_unqualified_provider_and_metadata, verify_yaml,
    verify_yaml_with_resource_limits,
};
