// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Awaitable provider binding, qualification, and verification.
//!
//! Implement [`AsyncProviderVerifierFactory`] and [`AsyncProviderVerifier`]
//! without a synchronous shim. Qualification uses the synchronous provider
//! module's fixed public inputs and result interpretation. It tests one exact
//! configured instance, independently for each algorithm. A fixed number of
//! calls does not impose a wall-clock deadline on a remote provider.
//! The adapter remains trusted code. These fixed checks catch compatibility
//! and binding mistakes; they do not defend against deliberate suite evasion.
//!
//! An async factory's returned handle may borrow its client, but cannot borrow
//! the temporary public-key input after binding completes. Concrete key
//! wrappers use a private boxed handle and box one future per verification.
//! Factory binding and the public extension traits use native returned futures.
//!
//! Parsing and structural checks run locally before the awaited operation.
//! Apply [`crate::ArtifactResourceLimits::check_input_size`] to the original
//! artifact, or use bounded pre-verification, before artifact-dependent remote
//! work. Timeouts, retries, blocking-pool placement, and remote cancellation
//! belong to the adapter or caller. No library runtime is required.

use std::{fmt, future::Future, marker::PhantomData, pin::Pin};

use yaml_sigil_core::AlgorithmId;
use yaml_sigil_traits::verification::PublicKeys as GenericPublicKeys;

use crate::provider::{
    ED25519_MIXED_A_MESSAGE, ED25519_MIXED_A_PUBLIC_KEY, ED25519_MIXED_A_SIGNATURE,
    ED25519_MIXED_R_MESSAGE, ED25519_MIXED_R_PUBLIC_KEY, ED25519_MIXED_R_SIGNATURE,
    P256_ALTERNATE_PUBLIC_KEY, P256_ALTERNATE_SIGNATURE, P256_QUALIFICATION_HIGH_SIGNATURE,
    P256_QUALIFICATION_LOW_SIGNATURE, P256_QUALIFICATION_PUBLIC_KEY, RFC8032_TEST_1_PUBLIC_KEY,
    RFC8032_TEST_1_SIGNATURE, binding_error, expect_provider_result, qualification_status,
    validate_public_key,
};
use crate::{
    ArtifactForm, AsyncVerifier, InvocationError, PreVerifyOutcome, PreVerifyResponse,
    ProviderKeyBindingError, ProviderKeyBindingErrorKind, ProviderQualificationErrorKind,
    ProviderQualificationStatus, ProviderVerificationOutcome, VerifierCapabilities,
    VerifierOptions, VerifierState, VerifyResult,
};

/// A key-bound verification operation that may suspend.
///
/// Verify the exact message and fixed 64-octet signature. P-256 applies
/// SHA-256 once and accepts both high-S and low-S representations. Preserve
/// the distinction between signature mismatch and operation/key-access failure.
/// `Send` does not establish that an SDK avoids blocking an executor thread.
pub trait AsyncProviderVerifier: Send + Sync {
    /// Await verification using this handle's immutable public-key binding.
    fn verify_provider<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a [u8; 64],
    ) -> impl Future<Output = ProviderVerificationOutcome> + Send + 'a;
}

/// Bind public keys to opaque handles owned by one configured async provider.
pub trait AsyncProviderVerifierFactory: Send + Sync {
    /// The handle may borrow the factory or its client; it need not be `'static`.
    type Verifier<'factory>: AsyncProviderVerifier + 'factory
    where
        Self: 'factory;

    /// Bind exactly the supplied canonical public key and algorithm.
    ///
    /// The future can borrow `canonical_public_key` until completion. The
    /// returned verifier cannot retain that borrow or substitute a configured
    /// default key. Existing handles must remain bound when another is created.
    /// Keep per-handle key state or a stable key identifier; locking a shared
    /// "current key" does not prevent another bind from retargeting old handles.
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> impl Future<Output = Result<Self::Verifier<'factory>, signature::Error>> + Send;
}

type VerificationFuture<'a> =
    Pin<Box<dyn Future<Output = ProviderVerificationOutcome> + Send + 'a>>;

trait ErasedVerifier: Send + Sync {
    fn verify<'a>(&'a self, message: &'a [u8], signature: &'a [u8; 64]) -> VerificationFuture<'a>;
}

impl<V: AsyncProviderVerifier> ErasedVerifier for V {
    fn verify<'a>(&'a self, message: &'a [u8], signature: &'a [u8; 64]) -> VerificationFuture<'a> {
        Box::pin(self.verify_provider(message, signature))
    }
}

/// Select qualified or explicitly unqualified verification for an exact instance.
pub struct AsyncVerificationProviderBuilder<P> {
    provider: P,
}

impl<P> AsyncVerificationProviderBuilder<P> {
    /// Own the initialized adapter configuration.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: AsyncProviderVerifierFactory> AsyncVerificationProviderBuilder<P> {
    /// Await the bounded public-only suite independently for both algorithms.
    ///
    /// No qualified state escapes a dropped or unfinished future. An
    /// operational failure remains distinct from a demonstrated incompatibility.
    /// A service unable to bind the test keys cannot qualify through this suite;
    /// use the explicitly unqualified choice when appropriate for your integration.
    pub async fn qualify(self) -> QualifiedAsyncVerificationProvider<P> {
        let ed25519 =
            qualification_status(AlgorithmId::Ed25519, qualify_ed25519(&self.provider).await);
        let ecdsa_p256_sha256 = qualification_status(
            AlgorithmId::EcdsaP256Sha256,
            qualify_p256(&self.provider).await,
        );
        QualifiedAsyncVerificationProvider {
            provider: self.provider,
            ed25519,
            ecdsa_p256_sha256,
        }
    }

    /// Skip qualification, retaining key and signature-structure validation.
    pub fn build_unqualified(self) -> UnqualifiedAsyncVerificationProvider<P> {
        UnqualifiedAsyncVerificationProvider {
            provider: self.provider,
        }
    }
}

/// Async provider whose qualification evidence belongs to this exact instance.
pub struct QualifiedAsyncVerificationProvider<P> {
    provider: P,
    ed25519: ProviderQualificationStatus,
    ecdsa_p256_sha256: ProviderQualificationStatus,
}

impl<P: AsyncProviderVerifierFactory> QualifiedAsyncVerificationProvider<P> {
    /// Inspect qualification independently of artifact-processing capabilities.
    pub fn status(&self, algorithm: AlgorithmId) -> &ProviderQualificationStatus {
        match algorithm {
            AlgorithmId::Ed25519 => &self.ed25519,
            AlgorithmId::EcdsaP256Sha256 => &self.ecdsa_p256_sha256,
        }
    }

    /// Await binding of an admissible key through a qualified Ed25519 slot.
    pub async fn bind_ed25519(
        &self,
        public_key: &[u8],
    ) -> Result<AsyncProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        self.bind(AlgorithmId::Ed25519, public_key).await
    }

    /// Await binding of an admissible key through a qualified P-256 slot.
    pub async fn bind_ecdsa_p256_sha256(
        &self,
        public_key: &[u8],
    ) -> Result<AsyncProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        self.bind(AlgorithmId::EcdsaP256Sha256, public_key).await
    }

    async fn bind(
        &self,
        algorithm: AlgorithmId,
        public_key: &[u8],
    ) -> Result<AsyncProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        validate_public_key(algorithm, public_key)?;
        if !self.status(algorithm).is_qualified() {
            return Err(binding_error(
                algorithm,
                ProviderKeyBindingErrorKind::AlgorithmNotQualified,
            ));
        }
        Ok(AsyncProviderVerifyingKey {
            inner: bind_key(&self.provider, algorithm, public_key).await?,
        })
    }
}

/// Async provider that explicitly skips fixed-vector qualification.
pub struct UnqualifiedAsyncVerificationProvider<P> {
    provider: P,
}

impl<P: AsyncProviderVerifierFactory> UnqualifiedAsyncVerificationProvider<P> {
    /// Await binding of an admissible Ed25519 public key without qualification.
    pub async fn bind_ed25519(
        &self,
        public_key: &[u8],
    ) -> Result<UnqualifiedAsyncProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        Ok(UnqualifiedAsyncProviderVerifyingKey {
            inner: bind_key(&self.provider, AlgorithmId::Ed25519, public_key).await?,
        })
    }

    /// Await binding of an admissible P-256 public key without qualification.
    pub async fn bind_ecdsa_p256_sha256(
        &self,
        public_key: &[u8],
    ) -> Result<UnqualifiedAsyncProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        Ok(UnqualifiedAsyncProviderVerifyingKey {
            inner: bind_key(&self.provider, AlgorithmId::EcdsaP256Sha256, public_key).await?,
        })
    }
}

macro_rules! redacted_provider {
    ($name:ident) => {
        impl<P> fmt::Debug for $name<P> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}
redacted_provider!(AsyncVerificationProviderBuilder);
redacted_provider!(QualifiedAsyncVerificationProvider);
redacted_provider!(UnqualifiedAsyncVerificationProvider);

struct BoundVerifier<'a> {
    algorithm: AlgorithmId,
    canonical_public_key: Vec<u8>,
    verifier: Box<dyn ErasedVerifier + 'a>,
}

// Erase the GAT handle before retaining it across another await. Keeping the
// projection in a generic qualification future can impose an implied 'static
// requirement during Send checking, excluding borrowed clients.
async fn bind_verifier<'factory, P: AsyncProviderVerifierFactory>(
    provider: &'factory P,
    algorithm: AlgorithmId,
    public_key: &[u8],
) -> Result<Box<dyn ErasedVerifier + 'factory>, signature::Error> {
    Ok(Box::new(provider.bind(algorithm, public_key).await?))
}

async fn bind_key<'factory, P: AsyncProviderVerifierFactory>(
    provider: &'factory P,
    algorithm: AlgorithmId,
    public_key: &[u8],
) -> Result<BoundVerifier<'factory>, ProviderKeyBindingError> {
    validate_public_key(algorithm, public_key)?;
    let verifier = bind_verifier(provider, algorithm, public_key)
        .await
        .map_err(|_| {
            binding_error(
                algorithm,
                ProviderKeyBindingErrorKind::ProviderBindingFailed,
            )
        })?;
    Ok(BoundVerifier {
        algorithm,
        canonical_public_key: public_key.to_vec(),
        verifier,
    })
}

/// Public key bound through one qualified async provider slot.
pub struct AsyncProviderVerifyingKey<'a> {
    inner: BoundVerifier<'a>,
}
/// Public key bound through the explicitly unqualified async provider path.
pub struct UnqualifiedAsyncProviderVerifyingKey<'a> {
    inner: BoundVerifier<'a>,
}

trait BoundKey: crate::Ed25519KeyValidation + crate::P256KeyValidation + Sync {
    fn inner(&self) -> &BoundVerifier<'_>;
}

macro_rules! bound_key {
    ($name:ident) => {
        impl BoundKey for $name<'_> {
            fn inner(&self) -> &BoundVerifier<'_> {
                &self.inner
            }
        }
        impl crate::Ed25519KeyValidation for $name<'_> {
            fn is_admissible(&self) -> bool {
                self.inner.algorithm == AlgorithmId::Ed25519
                    && crate::crypto::provider_public_key_is_admissible(
                        AlgorithmId::Ed25519,
                        &self.inner.canonical_public_key,
                    )
            }
        }
        impl crate::P256KeyValidation for $name<'_> {
            fn is_admissible(&self) -> bool {
                self.inner.algorithm == AlgorithmId::EcdsaP256Sha256
                    && crate::crypto::provider_public_key_is_admissible(
                        AlgorithmId::EcdsaP256Sha256,
                        &self.inner.canonical_public_key,
                    )
            }
        }
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("algorithm", &self.inner.algorithm)
                    .finish_non_exhaustive()
            }
        }
    };
}
bound_key!(AsyncProviderVerifyingKey);
bound_key!(UnqualifiedAsyncProviderVerifyingKey);

/// Algorithm-indexed qualified async provider verification keys.
pub type AsyncProviderPublicKeys<'a> =
    GenericPublicKeys<'a, AsyncProviderVerifyingKey<'a>, AsyncProviderVerifyingKey<'a>>;
/// Algorithm-indexed explicitly unqualified async provider verification keys.
pub type UnqualifiedAsyncProviderPublicKeys<'a> = GenericPublicKeys<
    'a,
    UnqualifiedAsyncProviderVerifyingKey<'a>,
    UnqualifiedAsyncProviderVerifyingKey<'a>,
>;

async fn verify_from_pre<K: BoundKey>(
    pre: &PreVerifyResponse,
    keys: &GenericPublicKeys<'_, K, K>,
    options: &VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    if !options.algorithm_parameters.is_empty() {
        return Err(InvocationError::InvalidAlgorithmParameters);
    }
    if pre.outcome != PreVerifyOutcome::Ok {
        return Err(InvocationError::InvalidPreVerifyResult);
    }
    let payload = pre
        .unverified_payload_bytes
        .as_ref()
        .ok_or(InvocationError::InvalidPreVerifyResult)?;
    let signature = pre
        .unverified_signature
        .as_ref()
        .ok_or(InvocationError::InvalidPreVerifyResult)?;
    let wire_algorithm = match signature.algorithm {
        AlgorithmId::Ed25519 => 1,
        AlgorithmId::EcdsaP256Sha256 => 2,
    };
    let (key, octets) = match crate::prepare_signature_verification(
        wire_algorithm,
        &signature.signature_octets,
        keys,
        options,
    )? {
        crate::PreparedVerification::Complete(state) => return Ok(state),
        crate::PreparedVerification::Ed25519(key, octets)
        | crate::PreparedVerification::P256(key, octets) => (key.inner(), octets),
    };
    let outcome = key.verifier.verify(payload, octets).await;
    crate::verification_state_from_outcome(
        crate::provider_outcome(outcome),
        payload,
        signature.algorithm,
    )
}

async fn verify_metadata<K: BoundKey>(
    input: &[u8],
    form: ArtifactForm,
    keys: &GenericPublicKeys<'_, K, K>,
    options: VerifierOptions,
    include_parser_observations: bool,
) -> Result<VerifyResult, InvocationError> {
    if !crate::verifier_capabilities()
        .supported_forms
        .contains(&form)
    {
        return Err(InvocationError::InvalidOrUnsupportedForm);
    }
    if !options.algorithm_parameters.is_empty() {
        return Err(InvocationError::InvalidAlgorithmParameters);
    }
    let pre = crate::pre_verify(input, form, false, include_parser_observations);
    let state = match pre.outcome {
        PreVerifyOutcome::Ok => verify_from_pre(&pre, keys, &options).await?,
        PreVerifyOutcome::Unsigned => VerifierState::Unsigned,
        PreVerifyOutcome::StructuralFailure | PreVerifyOutcome::MetadataParseFailure => {
            VerifierState::MalformedAttemptedSigned
        }
    };
    Ok(VerifyResult {
        state,
        parser_observations: if include_parser_observations {
            pre.parser_observations
        } else {
            Vec::new()
        },
    })
}

/// Await verification through a qualified provider. Its verdict is authoritative.
pub async fn verify_with_async_provider(
    input: &[u8],
    form: ArtifactForm,
    keys: &AsyncProviderPublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify_metadata(input, form, keys, options, false)
        .await
        .map(|result| result.state)
}
/// Await qualified verification with optional parser observations.
pub async fn verify_with_async_provider_and_metadata(
    input: &[u8],
    form: ArtifactForm,
    keys: &AsyncProviderPublicKeys<'_>,
    options: VerifierOptions,
    include_parser_observations: bool,
) -> Result<VerifyResult, InvocationError> {
    verify_metadata(input, form, keys, options, include_parser_observations).await
}
/// Await only qualified cryptographic verification of a pre-verification response.
pub async fn verify_from_pre_verify_with_async_provider(
    pre: &PreVerifyResponse,
    keys: &AsyncProviderPublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify_from_pre(pre, keys, &options).await
}
/// Await verification through an explicitly unqualified provider.
pub async fn verify_with_unqualified_async_provider(
    input: &[u8],
    form: ArtifactForm,
    keys: &UnqualifiedAsyncProviderPublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify_metadata(input, form, keys, options, false)
        .await
        .map(|result| result.state)
}
/// Await unqualified verification with optional parser observations.
pub async fn verify_with_unqualified_async_provider_and_metadata(
    input: &[u8],
    form: ArtifactForm,
    keys: &UnqualifiedAsyncProviderPublicKeys<'_>,
    options: VerifierOptions,
    include_parser_observations: bool,
) -> Result<VerifyResult, InvocationError> {
    verify_metadata(input, form, keys, options, include_parser_observations).await
}
/// Await unqualified cryptographic verification after pre-verification.
pub async fn verify_from_pre_verify_with_unqualified_async_provider(
    pre: &PreVerifyResponse,
    keys: &UnqualifiedAsyncProviderPublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify_from_pre(pre, keys, &options).await
}

/// Stateless [`AsyncVerifier`] facade accepting qualified async provider keys.
///
/// Capabilities describe artifact processing, not a factory's qualification.
/// Use its `status` method for slot evidence. Apply input limits before these
/// trait operations, which retain the existing unbounded resource contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProviderAsyncVerifier<'key>(PhantomData<&'key ()>);
/// Stateless [`AsyncVerifier`] facade accepting explicitly unqualified async keys.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnqualifiedProviderAsyncVerifier<'key>(PhantomData<&'key ()>);

macro_rules! verifier_facade {
    ($facade:ident, $key:ident) => {
        impl<'key> AsyncVerifier for $facade<'key> {
            type Ed25519VerifyingKey = $key<'key>;
            type P256VerifyingKey = $key<'key>;
            fn capabilities(&self) -> VerifierCapabilities {
                crate::verifier_capabilities()
            }
            async fn pre_verify(
                &self,
                input: &[u8],
                form: ArtifactForm,
                allow_unsigned: bool,
                observations: bool,
            ) -> PreVerifyResponse {
                crate::pre_verify(input, form, allow_unsigned, observations)
            }
            async fn verify(
                &self,
                input: &[u8],
                form: ArtifactForm,
                keys: &GenericPublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
                options: VerifierOptions,
            ) -> Result<VerifierState, InvocationError> {
                verify_metadata(input, form, keys, options, false)
                    .await
                    .map(|result| result.state)
            }
            async fn verify_with_metadata(
                &self,
                input: &[u8],
                form: ArtifactForm,
                keys: &GenericPublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
                options: VerifierOptions,
                observations: bool,
            ) -> Result<VerifyResult, InvocationError> {
                verify_metadata(input, form, keys, options, observations).await
            }
            async fn verify_from_pre_verify(
                &self,
                pre: &PreVerifyResponse,
                keys: &GenericPublicKeys<'_, Self::Ed25519VerifyingKey, Self::P256VerifyingKey>,
                options: VerifierOptions,
            ) -> Result<VerifierState, InvocationError> {
                verify_from_pre(pre, keys, &options).await
            }
        }
    };
}
verifier_facade!(ProviderAsyncVerifier, AsyncProviderVerifyingKey);
verifier_facade!(
    UnqualifiedProviderAsyncVerifier,
    UnqualifiedAsyncProviderVerifyingKey
);

// Reuse the attributed vectors in provider.rs; no additional signing requests
// or third-party vector material are introduced for the async suite.
async fn qualify_ed25519<P: AsyncProviderVerifierFactory>(
    provider: &P,
) -> Result<(), ProviderQualificationErrorKind> {
    let standard = bind_verifier(provider, AlgorithmId::Ed25519, &RFC8032_TEST_1_PUBLIC_KEY)
        .await
        .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
    expect_provider_result(
        standard.verify(b"", &RFC8032_TEST_1_SIGNATURE).await,
        ProviderVerificationOutcome::Verified,
    )?;
    expect_provider_result(
        standard
            .verify(b"not empty", &RFC8032_TEST_1_SIGNATURE)
            .await,
        ProviderVerificationOutcome::SignatureMismatch,
    )?;
    for (key, message, signature) in [
        (
            &ED25519_MIXED_R_PUBLIC_KEY,
            ED25519_MIXED_R_MESSAGE,
            &ED25519_MIXED_R_SIGNATURE,
        ),
        (
            &ED25519_MIXED_A_PUBLIC_KEY,
            ED25519_MIXED_A_MESSAGE,
            &ED25519_MIXED_A_SIGNATURE,
        ),
    ] {
        let verifier = bind_verifier(provider, AlgorithmId::Ed25519, key)
            .await
            .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
        expect_provider_result(
            verifier.verify(message, signature).await,
            ProviderVerificationOutcome::Verified,
        )?;
        // Preserve the synchronous suite's live-handle and cross-key checks.
        // Awaiting another bind or verification must not change either key.
        expect_provider_result(
            standard.verify(b"", &RFC8032_TEST_1_SIGNATURE).await,
            ProviderVerificationOutcome::Verified,
        )?;
        expect_provider_result(
            verifier.verify(b"", &RFC8032_TEST_1_SIGNATURE).await,
            ProviderVerificationOutcome::SignatureMismatch,
        )?;
        expect_provider_result(
            standard.verify(message, signature).await,
            ProviderVerificationOutcome::SignatureMismatch,
        )?;
        expect_provider_result(
            verifier.verify(message, signature).await,
            ProviderVerificationOutcome::Verified,
        )?;
    }
    Ok(())
}

async fn qualify_p256<P: AsyncProviderVerifierFactory>(
    provider: &P,
) -> Result<(), ProviderQualificationErrorKind> {
    const MESSAGE: &[u8] = b"YamlSigil P-256 SHA-256 qualification";
    let verifier = bind_verifier(
        provider,
        AlgorithmId::EcdsaP256Sha256,
        &P256_QUALIFICATION_PUBLIC_KEY,
    )
    .await
    .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
    expect_provider_result(
        verifier
            .verify(MESSAGE, &P256_QUALIFICATION_LOW_SIGNATURE)
            .await,
        ProviderVerificationOutcome::Verified,
    )?;
    expect_provider_result(
        verifier
            .verify(MESSAGE, &P256_QUALIFICATION_HIGH_SIGNATURE)
            .await,
        ProviderVerificationOutcome::Verified,
    )?;
    expect_provider_result(
        verifier
            .verify(b"different", &P256_QUALIFICATION_LOW_SIGNATURE)
            .await,
        ProviderVerificationOutcome::SignatureMismatch,
    )?;
    let alternate = bind_verifier(
        provider,
        AlgorithmId::EcdsaP256Sha256,
        &P256_ALTERNATE_PUBLIC_KEY,
    )
    .await
    .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
    expect_provider_result(
        alternate.verify(MESSAGE, &P256_ALTERNATE_SIGNATURE).await,
        ProviderVerificationOutcome::Verified,
    )?;
    for signature in [
        &P256_QUALIFICATION_LOW_SIGNATURE,
        &P256_QUALIFICATION_HIGH_SIGNATURE,
    ] {
        expect_provider_result(
            verifier.verify(MESSAGE, signature).await,
            ProviderVerificationOutcome::Verified,
        )?;
        expect_provider_result(
            alternate.verify(MESSAGE, signature).await,
            ProviderVerificationOutcome::SignatureMismatch,
        )?;
    }
    expect_provider_result(
        verifier.verify(MESSAGE, &P256_ALTERNATE_SIGNATURE).await,
        ProviderVerificationOutcome::SignatureMismatch,
    )?;
    expect_provider_result(
        alternate
            .verify(b"different", &P256_ALTERNATE_SIGNATURE)
            .await,
        ProviderVerificationOutcome::SignatureMismatch,
    )?;
    expect_provider_result(
        alternate.verify(MESSAGE, &P256_ALTERNATE_SIGNATURE).await,
        ProviderVerificationOutcome::Verified,
    )?;
    Ok(())
}
