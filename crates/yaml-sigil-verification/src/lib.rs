// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verify YamlSigil `v1alpha1` artifacts with native keys or local providers.
//!
//! Select `v1alpha1` explicitly; default paths name the same definitions.
//! `verify` returns `VerifyResult`, with the conformance outcome in `state`
//! and optionally requested parser observations. `VerifyError` separates
//! invocation and resource failures from verifier states.
//!
//! Defaults enable `std`, `yaml`, and `protobuf`. Either format works with
//! `no_std + alloc`; disabled forms fail before cryptographic work. Core
//! portable resource types remain available without `alloc`.
//!
//! `VerifierOptions` and `PreVerifyOptions` carry complete-input policy and
//! observation selection. Defaults are unbounded. `pre_verify` and
//! `can_pre_verify` are fallible. Pre-responses retain `source_artifact`, so
//! verification handoffs apply their own policy to the original encoded bytes.
//! Verified payloads borrow only the original artifact, independently of
//! temporary keys, options, and pre-responses. YAML metadata retains its
//! separate 16,384-octet carrier constraint and parser budgets.
//!
//! Qualified providers are tested per exact adapter instance and algorithm.
//! Provider failures remain distinct from mismatches and are not retried
//! through RustCrypto. Async providers choose their own execution policy.
//! See the [provider guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/crypto-providers.md)
//! and [portable API guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/no-std.md).

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
pub use yaml_sigil_traits::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
