// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Qualification and binding for local verification providers.
//!
//! The RFC 8032 test vector and Ed25519 qualification constructions below are
//! third-party RFC material or adaptations of it. They are not relicensed
//! under this file's Apache-2.0 declaration. See the crate's
//! `THIRD_PARTY_NOTICES.md` for attribution and applicable terms.
//!
//! [`VerificationProviderBuilder::qualify`] consumes one exact adapter
//! instance and runs a bounded, public-only fixed suite independently for its
//! Ed25519 and P-256 slots. The resulting state is opaque and
//! non-serializable. Replacing or reconfiguring the adapter requires
//! qualification again. A qualified provider result is authoritative; the
//! operation path does not retry it through RustCrypto.

use std::fmt;

use yaml_sigil_traits::AlgorithmId;
use yaml_sigil_traits::verification::PublicKeys as GenericPublicKeys;

use crate::crypto::provider_public_key_is_admissible;

/// Provider result after YamlSigil has completed structural validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderVerificationOutcome {
    /// The signature is valid for the supplied message and bound key.
    Verified,
    /// The signature is structurally valid but does not verify.
    SignatureMismatch,
    /// The provider could not complete the operation.
    ProviderFailure,
}

/// A `signature` 2.2 verifier that preserves YamlSigil's provider-failure
/// distinction.
pub trait ProviderVerifier: signature::Verifier<[u8; 64]> {
    /// Verify and classify the provider result.
    ///
    /// The default is suitable only for local verifiers whose `signature`
    /// error always denotes a signature mismatch. Providers with fallible key
    /// access or operation machinery must override this method.
    fn verify_provider(&self, message: &[u8], signature: &[u8; 64]) -> ProviderVerificationOutcome {
        match signature::Verifier::verify(self, message, signature) {
            Ok(()) => ProviderVerificationOutcome::Verified,
            Err(_) => ProviderVerificationOutcome::SignatureMismatch,
        }
    }
}

/// Factory that binds canonical public-key bytes to an opaque provider
/// verifier owned by one exact in-process configuration instance.
pub trait ProviderVerifierFactory {
    /// Bind one supported algorithm and public key.
    ///
    /// The returned verifier may borrow the factory, but it must not borrow
    /// `canonical_public_key`. It therefore remains bound to the factory
    /// instance that was qualified.
    ///
    /// The implementation must bind the returned opaque handle to exactly the
    /// supplied canonical key. It must not substitute a configured default or
    /// ignore the bytes.
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error>;
}

/// Why a provider verification slot failed qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderQualificationErrorKind {
    /// The provider could not bind a public qualification key.
    KeyBindingFailed,
    /// The provider rejected a signature the YamlSigil slot accepts.
    ValidSignatureRejected,
    /// The provider accepted a signature for the wrong message.
    InvalidSignatureAccepted,
    /// The provider reported an operational failure during qualification.
    ProviderFailure,
}

/// Redacted qualification failure for one algorithm slot.
pub struct ProviderQualificationError {
    kind: ProviderQualificationErrorKind,
    algorithm: AlgorithmId,
}

impl fmt::Display for ProviderQualificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verification provider did not qualify for {:?}",
            self.algorithm
        )
    }
}

impl std::error::Error for ProviderQualificationError {}

impl ProviderQualificationError {
    /// Return the stable failure category.
    pub fn kind(&self) -> ProviderQualificationErrorKind {
        self.kind
    }

    /// Return the failed algorithm slot.
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }
}

impl fmt::Debug for ProviderQualificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderQualificationError")
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Qualification state for one provider algorithm slot.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProviderQualificationStatus {
    /// The exact provider instance passed the bounded qualification suite.
    Qualified,
    /// The slot is unavailable through qualified verification operations.
    Rejected(ProviderQualificationError),
}

impl ProviderQualificationStatus {
    /// Return whether this slot passed qualification.
    pub fn is_qualified(&self) -> bool {
        matches!(self, Self::Qualified)
    }
}

/// Why a provider verification key could not be bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderKeyBindingErrorKind {
    /// The public-key bytes are not admissible for the selected algorithm.
    InvalidPublicKey,
    /// The selected algorithm slot did not pass qualification.
    AlgorithmNotQualified,
    /// The provider failed to bind its opaque verification handle.
    ProviderBindingFailed,
}

/// Redacted failure while binding a provider verification key.
pub struct ProviderKeyBindingError {
    kind: ProviderKeyBindingErrorKind,
    algorithm: AlgorithmId,
}

impl fmt::Display for ProviderKeyBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("provider verification key could not be bound")
    }
}

impl std::error::Error for ProviderKeyBindingError {}

impl ProviderKeyBindingError {
    /// Return the stable failure category.
    pub fn kind(&self) -> ProviderKeyBindingErrorKind {
        self.kind
    }

    /// Return the selected algorithm.
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }
}

impl fmt::Debug for ProviderKeyBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderKeyBindingError")
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Builder for an exact in-process verification provider instance.
pub struct VerificationProviderBuilder<P> {
    provider: P,
}

impl<P> VerificationProviderBuilder<P> {
    /// Begin configuring one provider instance.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: ProviderVerifierFactory> VerificationProviderBuilder<P> {
    /// Run the public-only fixed suite independently for both algorithm slots.
    ///
    /// Finite qualification establishes that this exact instance passed the
    /// included suite. It is not a proof over every input or future provider
    /// configuration, and it does not establish FIPS validation.
    pub fn qualify(self) -> QualifiedVerificationProvider<P> {
        let ed25519 = qualification_status(
            AlgorithmId::Ed25519,
            qualify_ed25519_provider(&self.provider),
        );
        let ecdsa_p256_sha256 = qualification_status(
            AlgorithmId::EcdsaP256Sha256,
            qualify_p256_provider(&self.provider),
        );
        QualifiedVerificationProvider {
            provider: self.provider,
            ed25519,
            ecdsa_p256_sha256,
        }
    }

    /// Skip the fixed-vector suite and require explicitly unqualified verify
    /// operations for every key bound through this provider.
    pub fn build_unqualified(self) -> UnqualifiedVerificationProvider<P> {
        UnqualifiedVerificationProvider {
            provider: self.provider,
        }
    }
}

impl<P> fmt::Debug for VerificationProviderBuilder<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationProviderBuilder")
            .field("provider", &"***")
            .finish()
    }
}

/// An exact provider instance with independently qualified algorithm slots.
pub struct QualifiedVerificationProvider<P> {
    provider: P,
    ed25519: ProviderQualificationStatus,
    ecdsa_p256_sha256: ProviderQualificationStatus,
}

impl<P: ProviderVerifierFactory> QualifiedVerificationProvider<P> {
    /// Return the qualification status for an algorithm slot.
    pub fn status(&self, algorithm: AlgorithmId) -> &ProviderQualificationStatus {
        match algorithm {
            AlgorithmId::Ed25519 => &self.ed25519,
            AlgorithmId::EcdsaP256Sha256 => &self.ecdsa_p256_sha256,
        }
    }

    /// Bind an admissible Ed25519 key when that slot qualified.
    pub fn bind_ed25519(
        &self,
        canonical_public_key: &[u8],
    ) -> Result<ProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        self.bind(AlgorithmId::Ed25519, canonical_public_key)
    }

    /// Bind an admissible P-256 key when that slot qualified.
    pub fn bind_ecdsa_p256_sha256(
        &self,
        canonical_public_key: &[u8],
    ) -> Result<ProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        self.bind(AlgorithmId::EcdsaP256Sha256, canonical_public_key)
    }

    fn bind(
        &self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<ProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        validate_public_key(algorithm, canonical_public_key)?;
        if !self.status(algorithm).is_qualified() {
            return Err(binding_error(
                algorithm,
                ProviderKeyBindingErrorKind::AlgorithmNotQualified,
            ));
        }
        let verifier = self
            .provider
            .bind(algorithm, canonical_public_key)
            .map_err(|_| {
                binding_error(
                    algorithm,
                    ProviderKeyBindingErrorKind::ProviderBindingFailed,
                )
            })?;
        Ok(ProviderVerifyingKey {
            algorithm,
            canonical_public_key: canonical_public_key.to_vec(),
            verifier,
        })
    }
}

impl<P> fmt::Debug for QualifiedVerificationProvider<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QualifiedVerificationProvider")
            .field("provider", &"***")
            .field("ed25519", &self.ed25519)
            .field("ecdsa_p256_sha256", &self.ecdsa_p256_sha256)
            .finish()
    }
}

/// Provider instance that deliberately skips fixed-vector qualification.
pub struct UnqualifiedVerificationProvider<P> {
    provider: P,
}

impl<P: ProviderVerifierFactory> UnqualifiedVerificationProvider<P> {
    /// Bind an admissible Ed25519 key without provider qualification.
    pub fn bind_ed25519(
        &self,
        canonical_public_key: &[u8],
    ) -> Result<UnqualifiedProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        self.bind(AlgorithmId::Ed25519, canonical_public_key)
    }

    /// Bind an admissible P-256 key without provider qualification.
    pub fn bind_ecdsa_p256_sha256(
        &self,
        canonical_public_key: &[u8],
    ) -> Result<UnqualifiedProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        self.bind(AlgorithmId::EcdsaP256Sha256, canonical_public_key)
    }

    fn bind(
        &self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<UnqualifiedProviderVerifyingKey<'_>, ProviderKeyBindingError> {
        validate_public_key(algorithm, canonical_public_key)?;
        let verifier = self
            .provider
            .bind(algorithm, canonical_public_key)
            .map_err(|_| {
                binding_error(
                    algorithm,
                    ProviderKeyBindingErrorKind::ProviderBindingFailed,
                )
            })?;
        Ok(UnqualifiedProviderVerifyingKey {
            algorithm,
            canonical_public_key: canonical_public_key.to_vec(),
            verifier,
        })
    }
}

impl<P> fmt::Debug for UnqualifiedVerificationProvider<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnqualifiedVerificationProvider")
            .field("provider", &"***")
            .finish()
    }
}

/// A public key bound through a qualified provider algorithm slot.
pub struct ProviderVerifyingKey<'a> {
    algorithm: AlgorithmId,
    canonical_public_key: Vec<u8>,
    verifier: Box<dyn ProviderVerifier + 'a>,
}

impl ProviderVerifyingKey<'_> {
    pub(crate) fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    pub(crate) fn canonical_public_key(&self) -> &[u8] {
        &self.canonical_public_key
    }

    pub(crate) fn verify(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> ProviderVerificationOutcome {
        self.verifier.verify_provider(message, signature)
    }
}

impl fmt::Debug for ProviderVerifyingKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderVerifyingKey")
            .field("algorithm", &self.algorithm)
            .field("public_key", &"***")
            .field("verifier", &"***")
            .finish()
    }
}

/// A public key bound without provider qualification.
pub struct UnqualifiedProviderVerifyingKey<'a> {
    algorithm: AlgorithmId,
    canonical_public_key: Vec<u8>,
    verifier: Box<dyn ProviderVerifier + 'a>,
}

impl UnqualifiedProviderVerifyingKey<'_> {
    pub(crate) fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    pub(crate) fn canonical_public_key(&self) -> &[u8] {
        &self.canonical_public_key
    }

    pub(crate) fn verify(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> ProviderVerificationOutcome {
        self.verifier.verify_provider(message, signature)
    }
}

impl fmt::Debug for UnqualifiedProviderVerifyingKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnqualifiedProviderVerifyingKey")
            .field("algorithm", &self.algorithm)
            .field("public_key", &"***")
            .field("verifier", &"***")
            .finish()
    }
}

/// Algorithm-indexed keys bound through qualified provider slots.
pub type ProviderPublicKeys<'a> =
    GenericPublicKeys<'a, ProviderVerifyingKey<'a>, ProviderVerifyingKey<'a>>;

/// Algorithm-indexed keys bound through explicitly unqualified provider slots.
pub type UnqualifiedProviderPublicKeys<'a> =
    GenericPublicKeys<'a, UnqualifiedProviderVerifyingKey<'a>, UnqualifiedProviderVerifyingKey<'a>>;

fn validate_public_key(
    algorithm: AlgorithmId,
    canonical_public_key: &[u8],
) -> Result<(), ProviderKeyBindingError> {
    if provider_public_key_is_admissible(algorithm, canonical_public_key) {
        Ok(())
    } else {
        Err(binding_error(
            algorithm,
            ProviderKeyBindingErrorKind::InvalidPublicKey,
        ))
    }
}

fn binding_error(
    algorithm: AlgorithmId,
    kind: ProviderKeyBindingErrorKind,
) -> ProviderKeyBindingError {
    ProviderKeyBindingError { kind, algorithm }
}

fn qualification_status(
    algorithm: AlgorithmId,
    result: Result<(), ProviderQualificationErrorKind>,
) -> ProviderQualificationStatus {
    match result {
        Ok(()) => ProviderQualificationStatus::Qualified,
        Err(kind) => {
            ProviderQualificationStatus::Rejected(ProviderQualificationError { kind, algorithm })
        }
    }
}

fn expect_provider_result(
    outcome: ProviderVerificationOutcome,
    expected: ProviderVerificationOutcome,
) -> Result<(), ProviderQualificationErrorKind> {
    if outcome == expected {
        return Ok(());
    }
    match outcome {
        ProviderVerificationOutcome::ProviderFailure => {
            Err(ProviderQualificationErrorKind::ProviderFailure)
        }
        ProviderVerificationOutcome::Verified => {
            Err(ProviderQualificationErrorKind::InvalidSignatureAccepted)
        }
        ProviderVerificationOutcome::SignatureMismatch => {
            Err(ProviderQualificationErrorKind::ValidSignatureRejected)
        }
    }
}

const RFC8032_TEST_1_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

const RFC8032_TEST_1_SIGNATURE: [u8; 64] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

// Locally generated fixed vectors that exercise the cofactored equation with
// a mixed-order `R` point and a mixed-order public key. These are public
// qualification inputs, not production signing keys or provider operations.
const ED25519_MIXED_R_MESSAGE: &[u8] = b"YamlSigil Ed25519 mixed R qualification";
const ED25519_MIXED_R_PUBLIC_KEY: [u8; 32] = [
    0xb8, 0x62, 0x40, 0x9f, 0xb5, 0xc4, 0xc4, 0x12, 0x3d, 0xf2, 0xab, 0xf7, 0x46, 0x2b, 0x88, 0xf0,
    0x41, 0xad, 0x36, 0xdd, 0x68, 0x64, 0xce, 0x87, 0x2f, 0xd5, 0x47, 0x2b, 0xe3, 0x63, 0xc5, 0xb1,
];
const ED25519_MIXED_R_SIGNATURE: [u8; 64] = [
    0xc8, 0x91, 0xdd, 0x2f, 0xc0, 0xca, 0x87, 0xa7, 0x46, 0x01, 0x93, 0x89, 0x5e, 0x04, 0x6a, 0x91,
    0x4c, 0x11, 0xb6, 0x6f, 0xdf, 0xfa, 0x8e, 0x6b, 0x7c, 0x3b, 0xa8, 0x31, 0x38, 0x49, 0x9c, 0x70,
    0x60, 0xe4, 0x42, 0xf8, 0xcd, 0xcf, 0xda, 0x4b, 0xcf, 0x5f, 0xf4, 0x18, 0x62, 0x71, 0xe1, 0x69,
    0x96, 0x2e, 0x40, 0xab, 0x92, 0x36, 0x45, 0x62, 0x76, 0x0b, 0x99, 0xec, 0x91, 0x99, 0x67, 0x0e,
];
const ED25519_MIXED_A_MESSAGE: &[u8] = b"YamlSigil Ed25519 mixed A qualification";
const ED25519_MIXED_A_PUBLIC_KEY: [u8; 32] = [
    0xe9, 0xb2, 0xfe, 0x98, 0x15, 0x87, 0xef, 0xae, 0x64, 0x78, 0xf4, 0x8b, 0xa1, 0xfa, 0x60, 0xce,
    0xc6, 0x12, 0x6d, 0x0e, 0x26, 0xdd, 0xe7, 0x2a, 0x0a, 0x24, 0xf6, 0x40, 0xdc, 0xd7, 0x83, 0xe5,
];
const ED25519_MIXED_A_SIGNATURE: [u8; 64] = [
    0x13, 0x37, 0x03, 0x6a, 0xc3, 0x2d, 0x8f, 0x30, 0xd4, 0x58, 0x9c, 0x3c, 0x1c, 0x59, 0x58, 0x12,
    0xce, 0x0f, 0xff, 0x40, 0xe3, 0x7c, 0x6f, 0x5a, 0x97, 0xab, 0x21, 0x3f, 0x31, 0x82, 0x90, 0xad,
    0x4f, 0x77, 0x53, 0x17, 0x4a, 0x7f, 0x11, 0xe9, 0x72, 0x16, 0x75, 0x31, 0xf9, 0x64, 0xed, 0x73,
    0x10, 0x1f, 0x0a, 0xdf, 0xec, 0xf8, 0x2e, 0xb5, 0x5f, 0xb5, 0x19, 0xe4, 0xd9, 0xa7, 0x7e, 0x07,
];

// Locally generated fixed qualification vector. The public key uses the
// uncompressed point encoding from *Standards for Efficient Cryptography 1
// (SEC 1)*. The two signatures share `r` and use the mathematically equivalent
// low-S and high-S representatives required by the YamlSigil P-256 slot.
const P256_QUALIFICATION_PUBLIC_KEY: [u8; 65] = [
    0x04, 0x1e, 0x18, 0x53, 0x2f, 0xd4, 0x75, 0x4c, 0x02, 0xf3, 0x04, 0x1d, 0x9c, 0x75, 0xce, 0xb3,
    0x3b, 0x83, 0xff, 0xd8, 0x1a, 0xc7, 0xce, 0x4f, 0xe8, 0x82, 0xcc, 0xb1, 0xc9, 0x8b, 0xc5, 0x89,
    0x6e, 0xa4, 0x6c, 0x31, 0x1c, 0x4e, 0x2f, 0xf4, 0x0d, 0xd9, 0x6a, 0x36, 0x53, 0xe6, 0xe4, 0x54,
    0x45, 0xd3, 0x2d, 0xfe, 0x48, 0x6e, 0xce, 0xd7, 0x5c, 0x7a, 0x90, 0xc6, 0xa1, 0x88, 0x81, 0xc0,
    0xa3,
];

const P256_QUALIFICATION_LOW_SIGNATURE: [u8; 64] = [
    0xb6, 0xc6, 0x64, 0x31, 0x44, 0xa6, 0x2c, 0x53, 0x5d, 0x06, 0xa8, 0x0d, 0xc8, 0x54, 0x36, 0xf8,
    0xd6, 0x07, 0x99, 0x77, 0x8e, 0xc2, 0xef, 0x85, 0x27, 0xae, 0x22, 0xbe, 0xe8, 0x4c, 0xc9, 0x91,
    0x32, 0xaa, 0xd3, 0x55, 0x2c, 0x8a, 0x59, 0x6a, 0x73, 0x1d, 0x9d, 0x02, 0xb7, 0xa9, 0xcd, 0x14,
    0xb5, 0x6b, 0x3f, 0x0c, 0x7b, 0xd5, 0xe8, 0xc9, 0xec, 0x08, 0xcc, 0x60, 0x3c, 0x75, 0xa8, 0xf1,
];

const P256_QUALIFICATION_HIGH_SIGNATURE: [u8; 64] = [
    0xb6, 0xc6, 0x64, 0x31, 0x44, 0xa6, 0x2c, 0x53, 0x5d, 0x06, 0xa8, 0x0d, 0xc8, 0x54, 0x36, 0xf8,
    0xd6, 0x07, 0x99, 0x77, 0x8e, 0xc2, 0xef, 0x85, 0x27, 0xae, 0x22, 0xbe, 0xe8, 0x4c, 0xc9, 0x91,
    0xcd, 0x55, 0x2c, 0xa9, 0xd3, 0x75, 0xa6, 0x96, 0x8c, 0xe2, 0x62, 0xfd, 0x48, 0x56, 0x32, 0xeb,
    0x07, 0x7b, 0xbb, 0xa1, 0x2b, 0x41, 0xb5, 0xbb, 0x07, 0xb0, 0xfe, 0x62, 0xbf, 0xed, 0x7c, 0x60,
];

fn qualify_ed25519_provider<P: ProviderVerifierFactory>(
    provider: &P,
) -> Result<(), ProviderQualificationErrorKind> {
    let standard = provider
        .bind(AlgorithmId::Ed25519, &RFC8032_TEST_1_PUBLIC_KEY)
        .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
    expect_provider_result(
        standard.verify_provider(b"", &RFC8032_TEST_1_SIGNATURE),
        ProviderVerificationOutcome::Verified,
    )?;
    expect_provider_result(
        standard.verify_provider(b"not empty", &RFC8032_TEST_1_SIGNATURE),
        ProviderVerificationOutcome::SignatureMismatch,
    )?;

    for (public_key, message, signature) in [
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
        let verifier = provider
            .bind(AlgorithmId::Ed25519, public_key)
            .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
        expect_provider_result(
            verifier.verify_provider(message, signature),
            ProviderVerificationOutcome::Verified,
        )?;
    }
    Ok(())
}

fn qualify_p256_provider<P: ProviderVerifierFactory>(
    provider: &P,
) -> Result<(), ProviderQualificationErrorKind> {
    const MESSAGE: &[u8] = b"YamlSigil P-256 SHA-256 qualification";

    let verifier = provider
        .bind(AlgorithmId::EcdsaP256Sha256, &P256_QUALIFICATION_PUBLIC_KEY)
        .map_err(|_| ProviderQualificationErrorKind::KeyBindingFailed)?;
    expect_provider_result(
        verifier.verify_provider(MESSAGE, &P256_QUALIFICATION_LOW_SIGNATURE),
        ProviderVerificationOutcome::Verified,
    )?;
    expect_provider_result(
        verifier.verify_provider(MESSAGE, &P256_QUALIFICATION_HIGH_SIGNATURE),
        ProviderVerificationOutcome::Verified,
    )?;
    expect_provider_result(
        verifier.verify_provider(b"different", &P256_QUALIFICATION_LOW_SIGNATURE),
        ProviderVerificationOutcome::SignatureMismatch,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    enum ReferenceKey {
        Ed25519(ed25519_dalek::VerifyingKey),
        EcdsaP256Sha256(p256::ecdsa::VerifyingKey),
    }

    struct ReferenceVerifier {
        key: ReferenceKey,
        strict_ed25519: bool,
        calls: Rc<Cell<usize>>,
    }

    impl signature::Verifier<[u8; 64]> for ReferenceVerifier {
        fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
            self.calls.set(self.calls.get() + 1);
            let verified = match &self.key {
                ReferenceKey::Ed25519(key) if self.strict_ed25519 => {
                    let signature = ed25519_dalek::Signature::from_bytes(signature);
                    key.verify_strict(message, &signature).is_ok()
                }
                ReferenceKey::Ed25519(key) => {
                    crate::crypto::verify_ed25519(key, message, signature).is_ok()
                }
                ReferenceKey::EcdsaP256Sha256(key) => {
                    crate::crypto::verify_ecdsa_p256_sha256(key, message, signature).is_ok()
                }
            };
            verified.then_some(()).ok_or_else(signature::Error::new)
        }
    }

    impl ProviderVerifier for ReferenceVerifier {}

    struct ReferenceFactory {
        strict_ed25519: bool,
        binds: Rc<Cell<usize>>,
        verifications: Rc<Cell<usize>>,
    }

    impl ReferenceFactory {
        fn new(strict_ed25519: bool) -> Self {
            Self {
                strict_ed25519,
                binds: Rc::new(Cell::new(0)),
                verifications: Rc::new(Cell::new(0)),
            }
        }
    }

    impl ProviderVerifierFactory for ReferenceFactory {
        fn bind<'factory>(
            &'factory self,
            algorithm: AlgorithmId,
            canonical_public_key: &[u8],
        ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
            self.binds.set(self.binds.get() + 1);
            let key = match algorithm {
                AlgorithmId::Ed25519 => ReferenceKey::Ed25519(
                    crate::crypto::resolve_ed25519_verifying_key(canonical_public_key)
                        .map_err(|_| signature::Error::new())?,
                ),
                AlgorithmId::EcdsaP256Sha256 => ReferenceKey::EcdsaP256Sha256(
                    crate::crypto::resolve_p256_verifying_key(canonical_public_key)
                        .map_err(|_| signature::Error::new())?,
                ),
            };
            Ok(Box::new(ReferenceVerifier {
                key,
                strict_ed25519: self.strict_ed25519,
                calls: Rc::clone(&self.verifications),
            }))
        }
    }

    struct FailingVerifier;

    impl signature::Verifier<[u8; 64]> for FailingVerifier {
        fn verify(&self, _message: &[u8], _signature: &[u8; 64]) -> Result<(), signature::Error> {
            Err(signature::Error::new())
        }
    }

    impl ProviderVerifier for FailingVerifier {
        fn verify_provider(
            &self,
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> ProviderVerificationOutcome {
            ProviderVerificationOutcome::ProviderFailure
        }
    }

    struct FailingFactory;

    impl ProviderVerifierFactory for FailingFactory {
        fn bind<'factory>(
            &'factory self,
            _algorithm: AlgorithmId,
            _canonical_public_key: &[u8],
        ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
            Ok(Box::new(FailingVerifier))
        }
    }

    #[test]
    fn reference_provider_qualifies_both_slots() {
        let provider = VerificationProviderBuilder::new(ReferenceFactory::new(false)).qualify();

        assert!(provider.status(AlgorithmId::Ed25519).is_qualified());
        assert!(provider.status(AlgorithmId::EcdsaP256Sha256).is_qualified());
        assert_eq!(provider.provider.binds.get(), 4);
        assert_eq!(provider.provider.verifications.get(), 7);
    }

    #[test]
    fn qualification_rejects_only_the_incompatible_algorithm_slot() {
        let provider = VerificationProviderBuilder::new(ReferenceFactory::new(true)).qualify();

        let ProviderQualificationStatus::Rejected(error) = provider.status(AlgorithmId::Ed25519)
        else {
            panic!("strict Ed25519 verification must reject the cofactored vector");
        };
        assert_eq!(
            error.kind(),
            ProviderQualificationErrorKind::ValidSignatureRejected
        );
        assert_eq!(error.algorithm(), AlgorithmId::Ed25519);
        assert!(provider.status(AlgorithmId::EcdsaP256Sha256).is_qualified());
    }

    #[test]
    fn provider_failure_remains_distinct_during_qualification() {
        let provider = VerificationProviderBuilder::new(FailingFactory).qualify();

        for algorithm in [AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256] {
            let ProviderQualificationStatus::Rejected(error) = provider.status(algorithm) else {
                panic!("failing provider must not qualify");
            };
            assert_eq!(
                error.kind(),
                ProviderQualificationErrorKind::ProviderFailure
            );
            assert_eq!(error.algorithm(), algorithm);
        }
    }

    #[test]
    fn inadmissible_keys_are_rejected_before_provider_binding() {
        let factory = ReferenceFactory::new(false);
        let binds = Rc::clone(&factory.binds);
        let provider = VerificationProviderBuilder::new(factory).build_unqualified();

        let error = provider.bind_ed25519(&[0; 31]).unwrap_err();
        assert_eq!(error.kind(), ProviderKeyBindingErrorKind::InvalidPublicKey);
        assert_eq!(error.algorithm(), AlgorithmId::Ed25519);
        assert_eq!(binds.get(), 0);
    }

    #[test]
    fn rejected_slot_cannot_bind_and_errors_are_redacted() {
        let provider = VerificationProviderBuilder::new(ReferenceFactory::new(true)).qualify();
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32])
            .verifying_key()
            .to_bytes();

        let error = provider.bind_ed25519(&key).unwrap_err();
        assert_eq!(
            error.kind(),
            ProviderKeyBindingErrorKind::AlgorithmNotQualified
        );
        assert_eq!(
            error.to_string(),
            "provider verification key could not be bound"
        );
        assert!(!format!("{error:?}").contains(&format!("{key:?}")));
        assert!(format!("{provider:?}").contains("provider: \"***\""));
    }

    fn pre_verified_vector(
        algorithm: AlgorithmId,
        message: &[u8],
        signature: &[u8; 64],
    ) -> crate::PreVerifyResponse {
        crate::PreVerifyResponse {
            outcome: crate::PreVerifyOutcome::Ok,
            form: crate::ArtifactForm::Proto,
            unverified_payload_bytes: Some(message.to_vec()),
            unverified_signature: Some(crate::UnverifiedSignature {
                algorithm,
                keyid: None,
                signature_octets: signature.to_vec(),
            }),
            parser_observations: Vec::new(),
        }
    }

    #[test]
    fn qualified_operation_path_preserves_accepted_ed25519_and_p256_cases() {
        let provider = VerificationProviderBuilder::new(ReferenceFactory::new(false)).qualify();

        for (public_key, message, signature) in [
            (
                &RFC8032_TEST_1_PUBLIC_KEY,
                b"".as_slice(),
                &RFC8032_TEST_1_SIGNATURE,
            ),
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
            let key = provider.bind_ed25519(public_key).unwrap();
            let keys = ProviderPublicKeys {
                ed25519: Some(&key),
                p256: None,
            };
            assert_eq!(
                crate::verify_from_pre_verify_with_provider(
                    &pre_verified_vector(AlgorithmId::Ed25519, message, signature),
                    &keys,
                    crate::VerifierOptions::default(),
                ),
                Ok(crate::VerifierState::Verified {
                    payload: message.to_vec(),
                    algorithm: AlgorithmId::Ed25519,
                })
            );
        }

        let key = provider
            .bind_ecdsa_p256_sha256(&P256_QUALIFICATION_PUBLIC_KEY)
            .unwrap();
        let keys = ProviderPublicKeys {
            ed25519: None,
            p256: Some(&key),
        };
        for signature in [
            &P256_QUALIFICATION_LOW_SIGNATURE,
            &P256_QUALIFICATION_HIGH_SIGNATURE,
        ] {
            assert_eq!(
                crate::verify_from_pre_verify_with_provider(
                    &pre_verified_vector(
                        AlgorithmId::EcdsaP256Sha256,
                        b"YamlSigil P-256 SHA-256 qualification",
                        signature,
                    ),
                    &keys,
                    crate::VerifierOptions::default(),
                ),
                Ok(crate::VerifierState::Verified {
                    payload: b"YamlSigil P-256 SHA-256 qualification".to_vec(),
                    algorithm: AlgorithmId::EcdsaP256Sha256,
                })
            );
        }
    }

    #[test]
    fn qualified_operation_rejects_bad_keys_and_signatures_before_provider_work() {
        let factory = ReferenceFactory::new(false);
        let binds = Rc::clone(&factory.binds);
        let verifications = Rc::clone(&factory.verifications);
        let provider = VerificationProviderBuilder::new(factory).qualify();

        let binds_after_qualification = binds.get();
        let mut small_order_key = [0; 32];
        small_order_key[0] = 1;
        let error = provider.bind_ed25519(&small_order_key).unwrap_err();
        assert_eq!(error.kind(), ProviderKeyBindingErrorKind::InvalidPublicKey);
        assert_eq!(binds.get(), binds_after_qualification);

        let ed25519_key = provider.bind_ed25519(&RFC8032_TEST_1_PUBLIC_KEY).unwrap();
        let ed25519_keys = ProviderPublicKeys {
            ed25519: Some(&ed25519_key),
            p256: None,
        };
        let calls_before_malformed = verifications.get();
        assert_eq!(
            crate::verify_from_pre_verify_with_provider(
                &pre_verified_vector(AlgorithmId::Ed25519, b"", &[0xff; 64]),
                &ed25519_keys,
                crate::VerifierOptions::default(),
            ),
            Ok(crate::VerifierState::MalformedAttemptedSigned)
        );
        assert_eq!(verifications.get(), calls_before_malformed);

        let p256_key = provider
            .bind_ecdsa_p256_sha256(&P256_QUALIFICATION_PUBLIC_KEY)
            .unwrap();
        let p256_keys = ProviderPublicKeys {
            ed25519: None,
            p256: Some(&p256_key),
        };
        assert_eq!(
            crate::verify_from_pre_verify_with_provider(
                &pre_verified_vector(
                    AlgorithmId::EcdsaP256Sha256,
                    b"YamlSigil P-256 SHA-256 qualification",
                    &[0; 64],
                ),
                &p256_keys,
                crate::VerifierOptions::default(),
            ),
            Ok(crate::VerifierState::MalformedAttemptedSigned)
        );
        assert_eq!(verifications.get(), calls_before_malformed);
    }
}
