// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Awaitable provider signing without a library-selected executor.
//!
//! Implement [`AsyncProviderSigner`] for an initialized key handle, then bind
//! its public key with [`AsyncProviderSigningKeyBuilder`]. Fetching a remote
//! key or its public bytes belongs to your adapter's initialization. Building
//! this wrapper performs local validation and never signs a challenge.
//!
//! Qualified signing checks each real output using the same validation as
//! synchronous provider signing. The explicitly unqualified path retains key
//! admissibility and signature-structure checks. Both paths pass final message
//! bytes unchanged, with SHA-256 applied exactly once by a P-256 adapter.
//!
//! The public operation trait uses native returned futures. A private bridge
//! boxes one future per signing call to keep the public bound-key types
//! concrete. No runtime, blocking-pool policy, timeout, or retry is imposed.
//! Dropping a pending future does not promise to cancel an operation already
//! submitted to a service. Local parsing and output checks remain synchronous.

use alloc::{boxed::Box, vec::Vec};
use core::{fmt, future::Future, marker::PhantomData, pin::Pin};

use yaml_sigil_traits::AlgorithmId;
use yaml_sigil_traits::signing::{
    SignRequest as GenericSignRequest, SigningKey as GenericSigningKey,
};

use super::provider_crypto::{
    ProviderPublicKey, provider_signature_is_structurally_valid, resolve_provider_public_key,
    verify_provider_signature,
};
use crate::provider::bounded_public_key_copy;
use crate::{
    ArtifactResourceLimits, ArtifactResourceResult, AsyncSigner, EncodeError,
    ProviderSigningKeyError, SignError, SignInvocationError, SignOutcome, SignerCapabilities,
};

/// An initialized provider key whose signing operation can suspend.
///
/// Implementations receive message bytes, not a digest, and return exactly
/// 64 signature octets. P-256 adapters apply SHA-256 once and return big-endian
/// `r || s`, never DER. Ed25519 adapters return canonical `R || S`.
/// Operation or key-access errors become [`SignError::KeyOperationFailure`].
/// A `Send` future is not a guarantee that its implementation avoids blocking.
pub trait AsyncProviderSigner: Send + Sync {
    /// Sign the exact supplied message with the initialized key.
    fn try_sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> impl Future<Output = Result<[u8; 64], signature::Error>> + Send + 'a;
}

type SigningFuture<'a> =
    Pin<Box<dyn Future<Output = Result<[u8; 64], signature::Error>> + Send + 'a>>;

trait ErasedSigner: Send + Sync {
    fn try_sign<'a>(&'a self, message: &'a [u8]) -> SigningFuture<'a>;
}

impl<S: AsyncProviderSigner> ErasedSigner for S {
    fn try_sign<'a>(&'a self, message: &'a [u8]) -> SigningFuture<'a> {
        Box::pin(AsyncProviderSigner::try_sign(self, message))
    }
}

/// Bind an async signing handle to canonical public-key bytes.
///
/// The borrowed adapter need not be `'static`. Public-key input is copied only
/// when it has the selected algorithm's exact length. Private keys stay inside
/// the adapter.
pub struct AsyncProviderSigningKeyBuilder<'a> {
    signer: &'a dyn ErasedSigner,
    algorithm: AlgorithmId,
    public_key_bytes: Vec<u8>,
}

impl<'a> AsyncProviderSigningKeyBuilder<'a> {
    /// Bind an Ed25519 handle to its 32 canonical compressed public-key octets.
    pub fn ed25519<S: AsyncProviderSigner>(signer: &'a S, public_key: &[u8]) -> Self {
        Self::new(signer, AlgorithmId::Ed25519, public_key)
    }

    /// Bind a P-256 handle to its 65-octet uncompressed public key from
    /// *Standards for Efficient Cryptography 1 (SEC 1)*.
    pub fn ecdsa_p256_sha256<S: AsyncProviderSigner>(signer: &'a S, public_key: &[u8]) -> Self {
        Self::new(signer, AlgorithmId::EcdsaP256Sha256, public_key)
    }

    fn new<S: AsyncProviderSigner>(
        signer: &'a S,
        algorithm: AlgorithmId,
        public_key: &[u8],
    ) -> Self {
        Self {
            signer,
            algorithm,
            public_key_bytes: bounded_public_key_copy(algorithm, public_key),
        }
    }

    /// Validate the public key and require self-verification of every output.
    pub fn build(self) -> Result<AsyncProviderSigningKey<'a>, ProviderSigningKeyError> {
        Ok(AsyncProviderSigningKey {
            inner: self.resolve()?,
        })
    }

    /// Validate the public key while explicitly skipping output self-verification.
    pub fn build_unqualified(
        self,
    ) -> Result<UnqualifiedAsyncProviderSigningKey<'a>, ProviderSigningKeyError> {
        Ok(UnqualifiedAsyncProviderSigningKey {
            inner: self.resolve()?,
        })
    }

    fn resolve(self) -> Result<BoundSigner<'a>, ProviderSigningKeyError> {
        let public_key = resolve_provider_public_key(self.algorithm, &self.public_key_bytes)
            .ok_or_else(|| ProviderSigningKeyError::invalid_public_key(self.algorithm))?;
        Ok(BoundSigner {
            signer: self.signer,
            public_key,
        })
    }
}

impl fmt::Debug for AsyncProviderSigningKeyBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncProviderSigningKeyBuilder")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

struct BoundSigner<'a> {
    signer: &'a dyn ErasedSigner,
    public_key: ProviderPublicKey,
}

/// Async provider key whose real signatures are self-verified before framing.
pub struct AsyncProviderSigningKey<'a> {
    inner: BoundSigner<'a>,
}

/// Async provider key that explicitly skips cryptographic output checking.
pub struct UnqualifiedAsyncProviderSigningKey<'a> {
    inner: BoundSigner<'a>,
}

trait BoundKey: Sync {
    const SELF_VERIFY: bool;
    fn inner(&self) -> &BoundSigner<'_>;
}

macro_rules! bound_key {
    ($key:ident, $qualified:literal) => {
        impl BoundKey for $key<'_> {
            const SELF_VERIFY: bool = $qualified;
            fn inner(&self) -> &BoundSigner<'_> {
                &self.inner
            }
        }
        impl fmt::Debug for $key<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($key))
                    .field("algorithm", &self.inner.public_key.algorithm())
                    .finish_non_exhaustive()
            }
        }
    };
}
bound_key!(AsyncProviderSigningKey, true);
bound_key!(UnqualifiedAsyncProviderSigningKey, false);

/// Algorithm-indexed qualified async provider keys.
pub type AsyncProviderSigningKeys<'a> =
    GenericSigningKey<'a, AsyncProviderSigningKey<'a>, AsyncProviderSigningKey<'a>>;
/// Signing request using qualified async provider keys.
pub type AsyncProviderSignRequest<'a> =
    GenericSignRequest<'a, AsyncProviderSigningKey<'a>, AsyncProviderSigningKey<'a>>;
/// Algorithm-indexed unqualified async provider keys.
pub type UnqualifiedAsyncProviderSigningKeys<'a> = GenericSigningKey<
    'a,
    UnqualifiedAsyncProviderSigningKey<'a>,
    UnqualifiedAsyncProviderSigningKey<'a>,
>;
/// Signing request using explicitly unqualified async provider keys.
pub type UnqualifiedAsyncProviderSignRequest<'a> = GenericSignRequest<
    'a,
    UnqualifiedAsyncProviderSigningKey<'a>,
    UnqualifiedAsyncProviderSigningKey<'a>,
>;

async fn sign_inner<K: BoundKey>(
    req: &GenericSignRequest<'_, K, K>,
    limits: Option<&ArtifactResourceLimits>,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    let validation = if limits.is_some() {
        super::validate_invocation_shape(req)
    } else {
        super::validate_invocation(req)
    };
    if let Err(error) = validation {
        return Ok(Ok(Err(yaml_sigil_traits::signing::SignError::Invocation(
            error,
        ))));
    }
    let key = match req.key {
        GenericSigningKey::Ed25519(key) | GenericSigningKey::EcdsaP256Sha256(key) => key.inner(),
    };
    if key.public_key.algorithm() != req.algorithm {
        return Ok(Ok(Err(yaml_sigil_traits::signing::SignError::Invocation(
            SignInvocationError::InvalidOrUnsupportedAlgorithm,
        ))));
    }
    if let Some(limits) = limits {
        if let Err(error) = super::preflight_signing_output(req, limits)? {
            return Ok(Err(error));
        }
        if let Err(error) = super::validate_keyid_content(req) {
            return Ok(Ok(Err(yaml_sigil_traits::signing::SignError::Invocation(
                error,
            ))));
        }
    }
    let prepared = match super::prepare_signing_payload(req) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(Ok(Err(error))),
    };
    let signature = match key.signer.try_sign(&prepared.payload).await {
        Ok(signature) => signature,
        Err(_) => return Ok(Ok(Err(SignError::KeyOperationFailure))),
    };
    if !provider_signature_is_structurally_valid(req.algorithm, &signature)
        || (K::SELF_VERIFY
            && !verify_provider_signature(&key.public_key, &prepared.payload, &signature))
    {
        return Ok(Ok(Err(SignError::KeyOperationFailure)));
    }
    Ok(Ok(super::finish_signing(
        req, prepared, &signature, limits,
    )?))
}

/// Await qualified signing and return the framed artifact after output checks.
#[cfg_attr(feature = "std", tracing::instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form)))]
pub async fn sign_with_async_provider(req: &AsyncProviderSignRequest<'_>) -> SignOutcome {
    super::validate_primary_invocation(req)?;
    sign_inner(req, Some(&req.resource_limits)).await??
}

/// Await signing while explicitly skipping output self-verification.
#[cfg_attr(feature = "std", tracing::instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form)))]
pub async fn sign_with_unqualified_async_provider(
    req: &UnqualifiedAsyncProviderSignRequest<'_>,
) -> SignOutcome {
    super::validate_primary_invocation(req)?;
    sign_inner(req, Some(&req.resource_limits)).await??
}

/// Stateless [`AsyncSigner`] implementation accepting qualified async keys.
///
/// The lifetime permits keys borrowing an initialized client. These trait
/// operations honor the request resource policy. Capabilities describe the
/// enabled formats and provider-supported algorithms.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProviderAsyncSigner<'key>(PhantomData<&'key ()>);

/// Stateless [`AsyncSigner`] implementation accepting unqualified async keys.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnqualifiedProviderAsyncSigner<'key>(PhantomData<&'key ()>);

macro_rules! signer_facade {
    ($facade:ident, $key:ident, $sign:ident) => {
        impl<'key> AsyncSigner for $facade<'key> {
            type Ed25519SigningKey = $key<'key>;
            type P256SigningKey = $key<'key>;
            fn capabilities(&self) -> SignerCapabilities {
                crate::signer_capabilities_with_rng()
            }
            async fn sign(
                &self,
                req: &GenericSignRequest<'_, Self::Ed25519SigningKey, Self::P256SigningKey>,
            ) -> SignOutcome {
                $sign(req).await
            }
        }
    };
}
signer_facade!(
    ProviderAsyncSigner,
    AsyncProviderSigningKey,
    sign_with_async_provider
);
signer_facade!(
    UnqualifiedProviderAsyncSigner,
    UnqualifiedAsyncProviderSigningKey,
    sign_with_unqualified_async_provider
);
