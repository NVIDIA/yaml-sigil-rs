// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API, identical to the default exports.

#[cfg(feature = "alloc")]
pub use crate::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncProviderPublicKeys, AsyncProviderVerifier,
    AsyncProviderVerifierFactory, AsyncProviderVerifyingKey, AsyncVerificationProviderBuilder,
    AsyncVerifier, DefaultAsyncVerifier, DefaultVerifier, InvocationError, P256EncodingError,
    PreVerifyOptions, PreVerifyOutcome, PreVerifyResponse, ProviderAsyncVerifier,
    ProviderKeyBindingError, ProviderKeyBindingErrorKind, ProviderPublicKeys,
    ProviderQualificationError, ProviderQualificationErrorKind, ProviderQualificationStatus,
    ProviderVerificationOutcome, ProviderVerifier, ProviderVerifierFactory, ProviderVerifyingKey,
    PublicKeys, QualifiedAsyncVerificationProvider, QualifiedVerificationProvider,
    UnqualifiedAsyncProviderPublicKeys, UnqualifiedAsyncProviderVerifyingKey,
    UnqualifiedAsyncVerificationProvider, UnqualifiedProviderAsyncVerifier,
    UnqualifiedProviderPublicKeys, UnqualifiedProviderVerifyingKey,
    UnqualifiedVerificationProvider, UnverifiedSignature, VerificationProviderBuilder, Verifier,
    VerifierCapabilities, VerifierOptions, VerifierState, VerifyError, VerifyResult,
    async_provider, can_pre_verify, p256_der_signature_to_raw, p256_public_key_to_uncompressed,
    pre_verify, provider, resolve_ed25519_verifying_key, resolve_p256_verifying_key,
    verifier_capabilities, verify, verify_from_pre_verify,
    verify_from_pre_verify_with_async_provider, verify_from_pre_verify_with_provider,
    verify_from_pre_verify_with_unqualified_async_provider,
    verify_from_pre_verify_with_unqualified_provider, verify_with_async_provider,
    verify_with_provider, verify_with_unqualified_async_provider, verify_with_unqualified_provider,
};
pub use crate::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
