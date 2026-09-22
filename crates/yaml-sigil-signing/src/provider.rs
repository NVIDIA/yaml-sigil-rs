// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Public-key bindings for synchronous signing callbacks.
//!
//! Bind the selected algorithm and canonical public key before signing, then
//! supply a callback to each operation. The binding stores no provider handle.
//! Bindings and requests remain [`Send`] and [`Sync`]; callbacks may borrow
//! mutable, thread-confined state without either bound. A callback runs
//! synchronously on the calling thread and may block it. YamlSigil adds no
//! executor, signing probe, or retry.
//!
//! [`crate::sign_with_provider`] passes the final payload bytes, after any
//! authorized YAML final-newline handling. Protobuf payloads stay unchanged.
//! Ed25519 output is canonical RFC 8032 `R || S`. P-256 output is big-endian
//! `r || s`, and a message callback applies SHA-256 exactly once. The separate
//! [`crate::sign_with_p256_digest_provider`] operation computes that hash and
//! passes `&[u8; 32]`; its callback must sign the digest without hashing again.
//! P-256 callbacks remain responsible for the profile's CSPRNG nonce sampling.
//!
//! [`ProviderSigningKeyBuilder::build`] validates the public key. Qualified
//! operations validate and independently verify each returned signature
//! against that key and the final payload before emitting an artifact.
//! [`ProviderSigningKeyBuilder::build_unqualified`] retains key and signature
//! structure checks but skips that verification. Operation failures should
//! return [`SignError::KeyOperationFailure`]; validation failures and resource
//! rejection before signing make no callback calls. An admitted signing
//! operation calls once, including when a later YAML size check rejects output.
//!
//! # Borrow mutable local state
//!
//! Replace the example key operation with your initialized SDK session. Public
//! bytes bind the callback's output without requiring private-key export.
//!
//! ```
//! use std::{cell::RefCell, rc::Rc};
//! use yaml_sigil_core::AlgorithmId;
//! use yaml_sigil_signing::{
//!     OutputForm, ProviderSignRequest, ProviderSigningKeyBuilder,
//!     ProviderSigningKeys, SignError, SignOutcome, sign_with_provider,
//! };
//!
//! // A fixed key is only a documentation fixture.
//! let native_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
//! let key = ProviderSigningKeyBuilder::ed25519(native_key.verifying_key().as_bytes())
//!     .build()?;
//! let request = ProviderSignRequest {
//!     payload: b"example: signed",
//!     algorithm: AlgorithmId::Ed25519,
//!     key: ProviderSigningKeys::Ed25519(&key),
//!     keyid: None,
//!     append_missing_final_newline: true,
//!     output_form: OutputForm::Yaml,
//!     algorithm_parameters: &[],
//! };
//! let local_messages = Rc::new(RefCell::new(Vec::new()));
//! let mut calls = 0;
//! for _ in 0..2 {
//!     let outcome = sign_with_provider(&request, |message| {
//!         calls += 1;
//!         local_messages.borrow_mut().push(message.to_vec());
//!         let signature: ed25519_dalek::Signature =
//!             signature::Signer::try_sign(&native_key, message)
//!                 .map_err(|_| SignError::KeyOperationFailure)?;
//!         Ok(signature.to_bytes())
//!     });
//!     assert!(matches!(outcome, SignOutcome::Success(_)));
//! }
//! assert_eq!(calls, 2);
//! assert_eq!(local_messages.borrow()[0], b"example: signed\n");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Share a provider across threads
//!
//! Existing `signature` 3.0 adapters can use [`signature_signing_callback`].
//! Only a callback moved to another thread needs the corresponding thread
//! bounds. Each operation supplies its own callback and shares the binding.
//!
//! ```
//! use yaml_sigil_core::AlgorithmId;
//! use yaml_sigil_signing::{
//!     OutputForm, ProviderSignRequest, ProviderSigningKeyBuilder,
//!     ProviderSigningKeys, SignOutcome, sign_with_provider, signature_signing_callback,
//! };
//!
//! struct Adapter(ed25519_dalek::SigningKey);
//! impl signature::Signer<[u8; 64]> for Adapter {
//!     fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
//!         let signature: ed25519_dalek::Signature =
//!             signature::Signer::try_sign(&self.0, message)?;
//!         Ok(signature.to_bytes())
//!     }
//! }
//! let adapter = Adapter(ed25519_dalek::SigningKey::from_bytes(&[8; 32]));
//! let key = ProviderSigningKeyBuilder::ed25519(adapter.0.verifying_key().as_bytes())
//!     .build()?;
//! let request = ProviderSignRequest {
//!     payload: b"shared payload",
//!     algorithm: AlgorithmId::Ed25519,
//!     key: ProviderSigningKeys::Ed25519(&key),
//!     keyid: None,
//!     append_missing_final_newline: false,
//!     output_form: OutputForm::Protobuf,
//!     algorithm_parameters: &[],
//! };
//! std::thread::scope(|scope| {
//!     for _ in 0..2 {
//!         scope.spawn(|| {
//!             assert!(matches!(
//!                 sign_with_provider(&request, signature_signing_callback(&adapter)),
//!                 SignOutcome::Success(_),
//!             ));
//!         });
//!     }
//! });
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! These callbacks supply only cryptography. The separate high-level
//! [`crate::Signer`] trait owns the complete signing operation.

use std::fmt;

use thiserror::Error;
use yaml_sigil_traits::AlgorithmId;
use yaml_sigil_traits::signing::{
    SignRequest as GenericSignRequest, SigningKey as GenericSigningKey,
};

use crate::SignError;
use crate::provider_crypto::{
    ProviderPublicKey, provider_signature_is_structurally_valid, resolve_provider_public_key,
    verify_provider_signature,
};

/// Why a provider signing key could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderSigningKeyErrorKind {
    /// The public-key bytes do not satisfy the selected YamlSigil algorithm.
    InvalidPublicKey,
}

/// Redacted failure while validating a provider's public-key binding.
#[derive(Error)]
#[error("provider signing key could not be constructed")]
pub struct ProviderSigningKeyError {
    kind: ProviderSigningKeyErrorKind,
    algorithm: AlgorithmId,
}

impl ProviderSigningKeyError {
    pub(crate) fn invalid_public_key(algorithm: AlgorithmId) -> Self {
        Self {
            kind: ProviderSigningKeyErrorKind::InvalidPublicKey,
            algorithm,
        }
    }

    /// Return the stable error category.
    pub fn kind(&self) -> ProviderSigningKeyErrorKind {
        self.kind
    }

    /// Return the algorithm whose public key was rejected.
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }
}

impl fmt::Debug for ProviderSigningKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSigningKeyError")
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Builder that validates canonical public-key bytes before provider signing.
///
/// No signer or callback is stored or invoked. The caller supplies the signing
/// operation separately, and qualified operations check each real output.
pub struct ProviderSigningKeyBuilder {
    algorithm: AlgorithmId,
    public_key_bytes: Vec<u8>,
}

pub(crate) fn bounded_public_key_copy(algorithm: AlgorithmId, public_key_bytes: &[u8]) -> Vec<u8> {
    let expected_len = match algorithm {
        AlgorithmId::Ed25519 => 32,
        AlgorithmId::EcdsaP256Sha256 => 65,
    };
    if public_key_bytes.len() == expected_len {
        public_key_bytes.to_vec()
    } else {
        Vec::new()
    }
}

impl ProviderSigningKeyBuilder {
    /// Select Ed25519 with its 32-octet compressed public key.
    pub fn ed25519(public_key_bytes: &[u8]) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            public_key_bytes: bounded_public_key_copy(AlgorithmId::Ed25519, public_key_bytes),
        }
    }

    /// Select P-256 with its 65-octet uncompressed public key from
    /// *Standards for Efficient Cryptography 1 (SEC 1)*.
    ///
    /// The binding supports both message and digest callbacks. The operation
    /// selects which input the callback receives.
    pub fn ecdsa_p256_sha256(public_key_bytes: &[u8]) -> Self {
        Self {
            algorithm: AlgorithmId::EcdsaP256Sha256,
            public_key_bytes: bounded_public_key_copy(
                AlgorithmId::EcdsaP256Sha256,
                public_key_bytes,
            ),
        }
    }

    /// Build the preferred key, which self-verifies every real provider
    /// signature before an artifact can be returned.
    pub fn build(self) -> Result<ProviderSigningKey, ProviderSigningKeyError> {
        let public_key = self.resolve_public_key()?;
        Ok(ProviderSigningKey { public_key })
    }

    /// Build an explicitly unqualified key that skips cryptographic
    /// self-verification of provider output.
    ///
    /// Public-key admissibility and signature-structure validation still run.
    /// The caller remains responsible for binding callback output to this key
    /// and the final payload.
    pub fn build_unqualified(
        self,
    ) -> Result<UnqualifiedProviderSigningKey, ProviderSigningKeyError> {
        let public_key = self.resolve_public_key()?;
        Ok(UnqualifiedProviderSigningKey { public_key })
    }

    fn resolve_public_key(&self) -> Result<ProviderPublicKey, ProviderSigningKeyError> {
        resolve_provider_public_key(self.algorithm, &self.public_key_bytes).ok_or(
            ProviderSigningKeyError {
                kind: ProviderSigningKeyErrorKind::InvalidPublicKey,
                algorithm: self.algorithm,
            },
        )
    }
}

impl fmt::Debug for ProviderSigningKeyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSigningKeyBuilder")
            .field("algorithm", &self.algorithm)
            .field("public_key", &"***")
            .finish()
    }
}

/// Validated public key used to self-verify each real callback output.
pub struct ProviderSigningKey {
    public_key: ProviderPublicKey,
}

// Store only public key material so bindings and requests stay Send + Sync.
// Provider handles belong to per-operation closures; Rust enforces each
// closure's thread restrictions without weakening the shared binding types.
pub(crate) trait BoundKey {
    const SELF_VERIFY: bool;

    fn public_key(&self) -> &ProviderPublicKey;

    fn algorithm(&self) -> AlgorithmId {
        self.public_key().algorithm()
    }

    fn try_sign(
        &self,
        message: &[u8],
        callback: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
    ) -> Result<[u8; 64], SignError> {
        let signature = callback(message)?;
        if !provider_signature_is_structurally_valid(self.algorithm(), &signature)
            || (Self::SELF_VERIFY
                && !verify_provider_signature(self.public_key(), message, &signature))
        {
            return Err(SignError::KeyOperationFailure);
        }
        Ok(signature)
    }
}

impl BoundKey for ProviderSigningKey {
    const SELF_VERIFY: bool = true;

    fn public_key(&self) -> &ProviderPublicKey {
        &self.public_key
    }
}

impl fmt::Debug for ProviderSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSigningKey")
            .field("algorithm", &self.algorithm())
            .field("public_key", &"***")
            .finish()
    }
}

/// Validated public key for signing that skips output self-verification.
pub struct UnqualifiedProviderSigningKey {
    public_key: ProviderPublicKey,
}

impl BoundKey for UnqualifiedProviderSigningKey {
    const SELF_VERIFY: bool = false;

    fn public_key(&self) -> &ProviderPublicKey {
        &self.public_key
    }
}

impl fmt::Debug for UnqualifiedProviderSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnqualifiedProviderSigningKey")
            .field("algorithm", &self.algorithm())
            .field("public_key", &"***")
            .finish()
    }
}

/// Algorithm-indexed qualified provider signing keys.
pub type ProviderSigningKeys<'a> = GenericSigningKey<'a, ProviderSigningKey, ProviderSigningKey>;

/// Unified request using qualified provider signing keys.
pub type ProviderSignRequest<'a> = GenericSignRequest<'a, ProviderSigningKey, ProviderSigningKey>;

/// Algorithm-indexed explicitly unqualified provider signing keys.
pub type UnqualifiedProviderSigningKeys<'a> =
    GenericSigningKey<'a, UnqualifiedProviderSigningKey, UnqualifiedProviderSigningKey>;

/// Unified request using explicitly unqualified provider signing keys.
pub type UnqualifiedProviderSignRequest<'a> =
    GenericSignRequest<'a, UnqualifiedProviderSigningKey, UnqualifiedProviderSigningKey>;

/// Forward one message-signing operation to a `signature` 3.0 adapter.
///
/// Adapter errors become [`SignError::KeyOperationFailure`]. This helper
/// neither hashes the message nor changes the returned bytes. P-256 adapters
/// must hash once and return big-endian `r || s`; Ed25519 adapters return
/// canonical `R || S`. The borrowed adapter needs no unconditional thread
/// bound. See the [module examples](self) for local and shared operations.
pub fn signature_signing_callback<S>(
    signer: &S,
) -> impl FnOnce(&[u8]) -> Result<[u8; 64], SignError> + '_
where
    S: signature::Signer<[u8; 64]> + ?Sized,
{
    |message| {
        signer
            .try_sign(message)
            .map_err(|_| SignError::KeyOperationFailure)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ed25519_dalek::SigningKey;

    use super::*;

    struct RecordingEd25519Signer {
        key: SigningKey,
        calls: AtomicUsize,
        messages: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingEd25519Signer {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                calls: AtomicUsize::new(0),
                messages: Mutex::new(Vec::new()),
            }
        }
    }

    impl signature::Signer<[u8; 64]> for RecordingEd25519Signer {
        fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.messages.lock().unwrap().push(message.to_vec());
            let signature: ed25519_dalek::Signature =
                signature::Signer::try_sign(&self.key, message)?;
            Ok(signature.to_bytes())
        }
    }

    struct FixedSigner([u8; 64]);

    impl signature::Signer<[u8; 64]> for FixedSigner {
        fn try_sign(&self, _message: &[u8]) -> Result<[u8; 64], signature::Error> {
            Ok(self.0)
        }
    }

    #[test]
    fn provider_keys_and_requests_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<ProviderSigningKeyBuilder>();
        assert_send_sync::<ProviderSigningKey>();
        assert_send_sync::<UnqualifiedProviderSigningKey>();
        assert_send_sync::<ProviderSignRequest<'static>>();
        assert_send_sync::<UnqualifiedProviderSignRequest<'static>>();
    }

    #[test]
    fn qualified_builder_does_not_request_a_synthetic_signature() {
        let signer = RecordingEd25519Signer::new(3);
        let public_key = signer.key.verifying_key().to_bytes();

        let key = ProviderSigningKeyBuilder::ed25519(&public_key)
            .build()
            .unwrap();

        assert_eq!(signer.calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            key.try_sign(b"real payload\n", signature_signing_callback(&signer))
                .unwrap()
                .len(),
            64
        );
        assert_eq!(signer.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            signer.messages.lock().unwrap().as_slice(),
            [b"real payload\n"]
        );
    }

    #[test]
    fn qualified_key_rejects_output_for_another_bound_public_key() {
        let signer = RecordingEd25519Signer::new(4);
        let other = SigningKey::from_bytes(&[5; 32]);
        let key = ProviderSigningKeyBuilder::ed25519(other.verifying_key().as_bytes())
            .build()
            .unwrap();

        assert!(matches!(
            key.try_sign(b"payload", signature_signing_callback(&signer)),
            Err(SignError::KeyOperationFailure)
        ));
        assert_eq!(signer.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unqualified_key_still_rejects_malformed_signature_octets() {
        let signer = FixedSigner([0xff; 64]);
        let signing_key = SigningKey::from_bytes(&[6; 32]);
        let key = ProviderSigningKeyBuilder::ed25519(signing_key.verifying_key().as_bytes())
            .build_unqualified()
            .unwrap();

        assert!(matches!(
            key.try_sign(b"payload", signature_signing_callback(&signer)),
            Err(SignError::KeyOperationFailure)
        ));
    }

    #[test]
    fn builders_reject_inadmissible_public_key_encodings() {
        let ed_error = ProviderSigningKeyBuilder::ed25519(&[0; 31])
            .build()
            .unwrap_err();
        assert_eq!(
            ed_error.kind(),
            ProviderSigningKeyErrorKind::InvalidPublicKey
        );
        assert_eq!(ed_error.algorithm(), AlgorithmId::Ed25519);

        let p256_key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let compressed = p256_key.verifying_key().to_sec1_point(true);
        let p256_error = ProviderSigningKeyBuilder::ecdsa_p256_sha256(compressed.as_bytes())
            .build_unqualified()
            .unwrap_err();
        assert_eq!(
            p256_error.kind(),
            ProviderSigningKeyErrorKind::InvalidPublicKey
        );
        assert_eq!(p256_error.algorithm(), AlgorithmId::EcdsaP256Sha256);
    }

    #[test]
    fn qualified_p256_signing_accepts_the_high_s_representative() {
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[10; 32]).unwrap();
        let message = b"high-S provider output";
        let signature: p256::ecdsa::Signature =
            signature::Signer::try_sign(&signing_key, message).unwrap();
        let low_signature = signature.normalize_s();
        let (r, _) = low_signature.split_bytes();
        let high_s: p256::FieldBytes = (-low_signature.s()).into();
        let high_signature = p256::ecdsa::Signature::from_scalars(r, high_s)
            .unwrap()
            .to_bytes()
            .into();
        let signer = FixedSigner(high_signature);
        let public_key = signing_key.verifying_key().to_sec1_point(false);
        let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public_key.as_bytes())
            .build()
            .unwrap();

        assert_eq!(
            key.try_sign(message, signature_signing_callback(&signer))
                .unwrap(),
            high_signature
        );
    }

    #[test]
    fn provider_signing_debug_output_is_redacted() {
        let signer = RecordingEd25519Signer::new(8);
        let public_key = signer.key.verifying_key().to_bytes();
        let builder = ProviderSigningKeyBuilder::ed25519(&public_key);
        let debug = format!("{builder:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains(&format!("{public_key:?}")));

        let key = builder.build().unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains(&format!("{public_key:?}")));

        let error = ProviderSigningKeyBuilder::ed25519(&[9; 31])
            .build()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider signing key could not be constructed"
        );
        assert!(!format!("{error:?}").contains("[9"));
    }
}
