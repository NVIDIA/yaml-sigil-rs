// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local cryptographic-provider signing adapters.
//!
//! Adapters implement `signature::Signer<[u8; 64]>`; YamlSigil passes the
//! exact final message bytes and never asks for a prehash. Ed25519 output is
//! canonical RFC 8032 `R || S`. P-256 output is big-endian `r || s`, and the
//! adapter applies SHA-256 exactly once.
//!
//! [`ProviderSigningKeyBuilder::build`] validates the canonical public key
//! bound to the opaque signer and self-verifies every real output. It does not
//! issue a synthetic signing request. The explicitly unqualified builder
//! retains public-key and signature-structure checks but skips output
//! self-verification.

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

/// Redacted failure while binding a provider signer to its public key.
#[derive(Error)]
#[error("provider signing key could not be constructed")]
pub struct ProviderSigningKeyError {
    kind: ProviderSigningKeyErrorKind,
    algorithm: AlgorithmId,
}

impl ProviderSigningKeyError {
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

/// Builder that binds an initialized provider signer to canonical public-key
/// bytes without requesting an extra signature.
pub struct ProviderSigningKeyBuilder<'a> {
    algorithm: AlgorithmId,
    signer: &'a dyn signature::Signer<[u8; 64]>,
    public_key_bytes: Vec<u8>,
}

fn bounded_public_key_copy(algorithm: AlgorithmId, public_key_bytes: &[u8]) -> Vec<u8> {
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

impl<'a> ProviderSigningKeyBuilder<'a> {
    /// Bind an Ed25519 signer to its 32-octet compressed public key.
    ///
    /// `public_key_bytes` must correspond to `signer`. The qualified build
    /// path enforces that relationship by checking each real output.
    pub fn ed25519(signer: &'a dyn signature::Signer<[u8; 64]>, public_key_bytes: &[u8]) -> Self {
        Self {
            algorithm: AlgorithmId::Ed25519,
            signer,
            public_key_bytes: bounded_public_key_copy(AlgorithmId::Ed25519, public_key_bytes),
        }
    }

    /// Bind a P-256 signer to its 65-octet uncompressed public key from
    /// *Standards for Efficient Cryptography 1 (SEC 1)*.
    ///
    /// The signer receives message bytes and must apply SHA-256 once before
    /// producing the fixed-width signature. `public_key_bytes` must
    /// correspond to `signer`.
    pub fn ecdsa_p256_sha256(
        signer: &'a dyn signature::Signer<[u8; 64]>,
        public_key_bytes: &[u8],
    ) -> Self {
        Self {
            algorithm: AlgorithmId::EcdsaP256Sha256,
            signer,
            public_key_bytes: bounded_public_key_copy(
                AlgorithmId::EcdsaP256Sha256,
                public_key_bytes,
            ),
        }
    }

    /// Build the preferred key, which self-verifies every real provider
    /// signature before an artifact can be returned.
    pub fn build(self) -> Result<ProviderSigningKey<'a>, ProviderSigningKeyError> {
        let public_key = self.resolve_public_key()?;
        Ok(ProviderSigningKey {
            signer: self.signer,
            public_key,
        })
    }

    /// Build an explicitly unqualified key that skips cryptographic
    /// self-verification of provider output.
    ///
    /// Public-key admissibility and signature-structure validation still run.
    /// The caller remains responsible for the signer-to-public-key binding.
    pub fn build_unqualified(
        self,
    ) -> Result<UnqualifiedProviderSigningKey<'a>, ProviderSigningKeyError> {
        let public_key = self.resolve_public_key()?;
        Ok(UnqualifiedProviderSigningKey {
            signer: self.signer,
            public_key,
        })
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

impl fmt::Debug for ProviderSigningKeyBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSigningKeyBuilder")
            .field("algorithm", &self.algorithm)
            .field("signer", &"***")
            .field("public_key", &"***")
            .finish()
    }
}

/// Provider signer whose real outputs are self-verified by YamlSigil.
pub struct ProviderSigningKey<'a> {
    signer: &'a dyn signature::Signer<[u8; 64]>,
    public_key: ProviderPublicKey,
}

impl ProviderSigningKey<'_> {
    pub(crate) fn algorithm(&self) -> AlgorithmId {
        self.public_key.algorithm()
    }

    pub(crate) fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        let signature = self
            .signer
            .try_sign(message)
            .map_err(|_| SignError::KeyOperationFailure)?;
        if !provider_signature_is_structurally_valid(self.algorithm(), &signature)
            || !verify_provider_signature(&self.public_key, message, &signature)
        {
            return Err(SignError::KeyOperationFailure);
        }
        Ok(signature)
    }
}

impl fmt::Debug for ProviderSigningKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderSigningKey")
            .field("algorithm", &self.algorithm())
            .field("signer", &"***")
            .field("public_key", &"***")
            .finish()
    }
}

/// Provider signer that deliberately skips cryptographic self-verification.
pub struct UnqualifiedProviderSigningKey<'a> {
    signer: &'a dyn signature::Signer<[u8; 64]>,
    public_key: ProviderPublicKey,
}

impl UnqualifiedProviderSigningKey<'_> {
    pub(crate) fn algorithm(&self) -> AlgorithmId {
        self.public_key.algorithm()
    }

    pub(crate) fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        let signature = self
            .signer
            .try_sign(message)
            .map_err(|_| SignError::KeyOperationFailure)?;
        if !provider_signature_is_structurally_valid(self.algorithm(), &signature) {
            return Err(SignError::KeyOperationFailure);
        }
        Ok(signature)
    }
}

impl fmt::Debug for UnqualifiedProviderSigningKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnqualifiedProviderSigningKey")
            .field("algorithm", &self.algorithm())
            .field("signer", &"***")
            .field("public_key", &"***")
            .finish()
    }
}

/// Algorithm-indexed qualified provider signing keys.
pub type ProviderSigningKeys<'a> =
    GenericSigningKey<'a, ProviderSigningKey<'a>, ProviderSigningKey<'a>>;

/// Unified request using qualified provider signing keys.
pub type ProviderSignRequest<'a> =
    GenericSignRequest<'a, ProviderSigningKey<'a>, ProviderSigningKey<'a>>;

/// Algorithm-indexed explicitly unqualified provider signing keys.
pub type UnqualifiedProviderSigningKeys<'a> =
    GenericSigningKey<'a, UnqualifiedProviderSigningKey<'a>, UnqualifiedProviderSigningKey<'a>>;

/// Unified request using explicitly unqualified provider signing keys.
pub type UnqualifiedProviderSignRequest<'a> =
    GenericSignRequest<'a, UnqualifiedProviderSigningKey<'a>, UnqualifiedProviderSigningKey<'a>>;

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use ed25519_dalek::SigningKey;

    use super::*;

    struct RecordingEd25519Signer {
        key: SigningKey,
        calls: Cell<usize>,
        messages: RefCell<Vec<Vec<u8>>>,
    }

    impl RecordingEd25519Signer {
        fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_bytes(&[seed; 32]),
                calls: Cell::new(0),
                messages: RefCell::new(Vec::new()),
            }
        }
    }

    impl signature::Signer<[u8; 64]> for RecordingEd25519Signer {
        fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
            self.calls.set(self.calls.get() + 1);
            self.messages.borrow_mut().push(message.to_vec());
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
    fn qualified_builder_does_not_request_a_synthetic_signature() {
        let signer = RecordingEd25519Signer::new(3);
        let public_key = signer.key.verifying_key().to_bytes();

        let key = ProviderSigningKeyBuilder::ed25519(&signer, &public_key)
            .build()
            .unwrap();

        assert_eq!(signer.calls.get(), 0);
        assert_eq!(key.try_sign(b"real payload\n").unwrap().len(), 64);
        assert_eq!(signer.calls.get(), 1);
        assert_eq!(signer.messages.borrow().as_slice(), [b"real payload\n"]);
    }

    #[test]
    fn qualified_key_rejects_output_for_another_bound_public_key() {
        let signer = RecordingEd25519Signer::new(4);
        let other = SigningKey::from_bytes(&[5; 32]);
        let key = ProviderSigningKeyBuilder::ed25519(&signer, other.verifying_key().as_bytes())
            .build()
            .unwrap();

        assert!(matches!(
            key.try_sign(b"payload"),
            Err(SignError::KeyOperationFailure)
        ));
        assert_eq!(signer.calls.get(), 1);
    }

    #[test]
    fn unqualified_key_still_rejects_malformed_signature_octets() {
        let signer = FixedSigner([0xff; 64]);
        let signing_key = SigningKey::from_bytes(&[6; 32]);
        let key =
            ProviderSigningKeyBuilder::ed25519(&signer, signing_key.verifying_key().as_bytes())
                .build_unqualified()
                .unwrap();

        assert!(matches!(
            key.try_sign(b"payload"),
            Err(SignError::KeyOperationFailure)
        ));
    }

    #[test]
    fn builders_reject_inadmissible_public_key_encodings() {
        let signer = FixedSigner([0; 64]);
        let ed_error = ProviderSigningKeyBuilder::ed25519(&signer, &[0; 31])
            .build()
            .unwrap_err();
        assert_eq!(
            ed_error.kind(),
            ProviderSigningKeyErrorKind::InvalidPublicKey
        );
        assert_eq!(ed_error.algorithm(), AlgorithmId::Ed25519);

        let p256_key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let compressed = p256_key.verifying_key().to_encoded_point(true);
        let p256_error =
            ProviderSigningKeyBuilder::ecdsa_p256_sha256(&signer, compressed.as_bytes())
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
        let low_signature = signature.normalize_s().unwrap_or(signature);
        let (r, _) = low_signature.split_bytes();
        let high_s: p256::FieldBytes = (-low_signature.s()).into();
        let high_signature = p256::ecdsa::Signature::from_scalars(r, high_s)
            .unwrap()
            .to_bytes()
            .into();
        let signer = FixedSigner(high_signature);
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(&signer, public_key.as_bytes())
            .build()
            .unwrap();

        assert_eq!(key.try_sign(message).unwrap(), high_signature);
    }

    #[test]
    fn provider_signing_debug_output_is_redacted() {
        let signer = RecordingEd25519Signer::new(8);
        let public_key = signer.key.verifying_key().to_bytes();
        let builder = ProviderSigningKeyBuilder::ed25519(&signer, &public_key);
        let debug = format!("{builder:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains(&format!("{public_key:?}")));

        let key = builder.build().unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("***"));
        assert!(!debug.contains(&format!("{public_key:?}")));

        let error = ProviderSigningKeyBuilder::ed25519(&signer, &[9; 31])
            .build()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider signing key could not be constructed"
        );
        assert!(!format!("{error:?}").contains("[9"));
    }
}
