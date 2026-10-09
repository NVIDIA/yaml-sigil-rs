// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use crate::{ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceLimits};
use alloc::vec::Vec;
#[path = "async_provider.rs"]
pub mod async_provider;
#[path = "crypto.rs"]
mod crypto;
#[cfg(feature = "protobuf")]
#[path = "proto_verify.rs"]
mod proto_verify;
#[path = "provider.rs"]
pub mod provider;
#[cfg(feature = "yaml")]
#[path = "yaml_verify.rs"]
mod yaml_verify;

pub use yaml_sigil_core::p256_encoding::{
    P256EncodingError, p256_der_signature_to_raw, p256_public_key_to_uncompressed,
};

#[cfg(test)]
#[path = "async_provider_tests.rs"]
mod async_provider_tests;

pub use async_provider::{
    AsyncProviderPublicKeys, AsyncProviderVerifier, AsyncProviderVerifierFactory,
    AsyncProviderVerifyingKey, AsyncVerificationProviderBuilder, ProviderAsyncVerifier,
    QualifiedAsyncVerificationProvider, UnqualifiedAsyncProviderPublicKeys,
    UnqualifiedAsyncProviderVerifyingKey, UnqualifiedAsyncVerificationProvider,
    UnqualifiedProviderAsyncVerifier, verify_from_pre_verify_with_async_provider,
    verify_from_pre_verify_with_unqualified_async_provider, verify_with_async_provider,
    verify_with_unqualified_async_provider,
};

use yaml_sigil_core::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
};

pub use provider::{
    ProviderKeyBindingError, ProviderKeyBindingErrorKind, ProviderPublicKeys,
    ProviderQualificationError, ProviderQualificationErrorKind, ProviderQualificationStatus,
    ProviderVerificationOutcome, ProviderVerifier, ProviderVerifierFactory, ProviderVerifyingKey,
    QualifiedVerificationProvider, UnqualifiedProviderPublicKeys, UnqualifiedProviderVerifyingKey,
    UnqualifiedVerificationProvider, VerificationProviderBuilder,
};
pub use yaml_sigil_core::ArtifactResourceForm;
// The portable traits and DTOs live in `yaml-sigil-traits`. This implementation
// binds the generic key-bearing DTO to its RustCrypto key types and owns key
// parsing, retaining established `yaml_sigil_verification` paths.
use yaml_sigil_traits::verification::PublicKeys as GenericPublicKeys;
pub use yaml_sigil_traits::verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, InvocationError, PreVerifyOptions,
    PreVerifyOutcome, PreVerifyResponse, UnverifiedSignature, Verifier, VerifierCapabilities,
    VerifierOptions, VerifierState, VerifyError, VerifyResult,
};

/// Caller-supplied verification keys supported by this RustCrypto implementation.
pub type PublicKeys<'a> =
    GenericPublicKeys<'a, ed25519_dalek::VerifyingKey, p256::ecdsa::VerifyingKey>;

/// Resolve a 32-byte compressed Ed25519 public key into an admissible typed key.
///
/// The input must use a canonical point encoding and identify a key accepted
/// by this implementation.
///
/// You can own an application key wrapper and implement `TryFrom` into this
/// existing public type. This validates public bytes without exporting a
/// private key or requiring a new library-owned key abstraction.
///
/// ```
/// use yaml_sigil_verification::v1alpha1::{InvocationError, resolve_ed25519_verifying_key};
///
/// struct ApplicationPublicKey([u8; 32]);
/// impl TryFrom<ApplicationPublicKey> for ed25519_dalek::VerifyingKey {
///     type Error = InvocationError;
///     fn try_from(key: ApplicationPublicKey) -> Result<Self, Self::Error> {
///         resolve_ed25519_verifying_key(&key.0)
///     }
/// }
/// let public = ed25519_dalek::SigningKey::from_bytes(&[12; 32]).verifying_key();
/// let resolved: ed25519_dalek::VerifyingKey = ApplicationPublicKey(public.to_bytes()).try_into()?;
/// assert_eq!(resolved, public);
/// # Ok::<(), InvocationError>(())
/// ```
///
/// # Errors
///
/// Returns [`InvocationError::KeyResolutionFailure`] when the input has the
/// wrong length, is not a canonical point encoding, or resolves to a key this
/// implementation does not accept.
pub fn resolve_ed25519_verifying_key(
    bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, InvocationError> {
    crypto::resolve_ed25519_verifying_key(bytes)
}

/// Resolve a 65-byte uncompressed P-256 public key encoded according to
/// *Standards for Efficient Cryptography 1 (SEC 1)* into a typed key.
///
/// The SEC 1 encoding rule is third-party standards material, not material
/// relicensed under this file's Apache-2.0 declaration. See the crate's
/// `THIRD_PARTY_NOTICES.md` for the source notice and patent/IP caveat.
///
/// The same application-owned conversion works for P-256. Use `From` only
/// when the wrapper already holds a validated key and conversion is infallible.
///
/// ```
/// use yaml_sigil_verification::v1alpha1::{InvocationError, resolve_p256_verifying_key};
///
/// struct ApplicationPublicKey(Vec<u8>);
/// impl TryFrom<ApplicationPublicKey> for p256::ecdsa::VerifyingKey {
///     type Error = InvocationError;
///     fn try_from(key: ApplicationPublicKey) -> Result<Self, Self::Error> {
///         resolve_p256_verifying_key(&key.0)
///     }
/// }
/// let signing = p256::ecdsa::SigningKey::from_slice(&[12; 32]).unwrap();
/// let public = signing.verifying_key().to_sec1_point(false);
/// let resolved: p256::ecdsa::VerifyingKey =
///     ApplicationPublicKey(public.as_bytes().to_vec()).try_into()?;
/// assert_eq!(&resolved, signing.verifying_key());
/// # Ok::<(), InvocationError>(())
/// ```
///
/// # Errors
///
/// Returns [`InvocationError::KeyResolutionFailure`] when the input is not the
/// required `0x04 || X || Y` encoding of an admissible P-256 public key.
pub fn resolve_p256_verifying_key(
    bytes: &[u8],
) -> Result<p256::ecdsa::VerifyingKey, InvocationError> {
    crypto::resolve_p256_verifying_key(bytes)
}

/// Returns the capability surface for this build.
pub fn verifier_capabilities() -> VerifierCapabilities {
    let unknown_policies = yaml_sigil_core::yaml_unknown_field_policies();
    // Advertise Permissive unconditionally. The spec requires
    // Strict / SignatureStrict to reject duplicate known singular fields on
    // **both** wire forms; this workspace's protobuf inner-decode path uses
    // the private protobuf decoder, which applies last-wins (Permissive) to
    // duplicate scalars. Advertising Strict in any build would be
    // non-conforming because the "uniform across forms" requirement is not
    // satisfied. See docs/conformance-validation.md. The YAML side is
    // stricter-than-required on the duplicate-key axis because duplicate keys
    // are rejected at parse.
    let conformance_profile = AdvertisedConformanceProfile::Permissive;

    VerifierCapabilities {
        conformance_profile,
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy: yaml_sigil_core::DEFAULT_YAML_UNKNOWN_FIELD_POLICY,
        yaml_signature_unknown_field_policies: unknown_policies,
        supported_forms: &[
            #[cfg(feature = "yaml")]
            ArtifactForm::Yaml,
            #[cfg(feature = "protobuf")]
            ArtifactForm::Proto,
        ],
        supported_algorithms: &[AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256],
        supports_can_pre_verify: true,
        supports_pre_verify: true,
        implementation_name: env!("CARGO_PKG_NAME"),
        implementation_version: env!("CARGO_PKG_VERSION"),
    }
}

/// Verify an artifact using the selected form and request-carried input policy.
/// Returned payload bytes borrow only `input_bytes`.
pub fn verify<'input>(
    input_bytes: &'input [u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    verify_with_provider_keys(input_bytes, form, keys, options)
}
fn resource_form(form: ArtifactForm) -> ArtifactResourceForm {
    match form {
        ArtifactForm::Yaml => ArtifactResourceForm::Yaml,
        ArtifactForm::Proto => ArtifactResourceForm::Protobuf,
    }
}
fn validate_verify_options(
    form: ArtifactForm,
    options: &VerifierOptions<'_>,
) -> Result<(), InvocationError> {
    if !verifier_capabilities().supported_forms.contains(&form) {
        return Err(InvocationError::InvalidOrUnsupportedForm);
    }
    if !options.algorithm_parameters.is_empty() {
        return Err(InvocationError::InvalidAlgorithmParameters);
    }
    Ok(())
}
fn verify_with_provider_keys<
    'input,
    Ed25519: Ed25519VerificationKey + ?Sized,
    P256: P256VerificationKey + ?Sized,
>(
    input_bytes: &'input [u8],
    form: ArtifactForm,
    keys: &GenericPublicKeys<'_, Ed25519, P256>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    options
        .resource_limits
        .check_input_size(resource_form(form), input_bytes)?;
    validate_verify_options(form, &options)?;
    let pre = pre_verify(
        input_bytes,
        form,
        PreVerifyOptions {
            allow_unsigned: false,
            include_parser_observations: options.include_parser_observations,
            resource_limits: options.resource_limits.clone(),
        },
    )?;
    let state = match pre.outcome {
        PreVerifyOutcome::Ok => verify_from_pre_verify_with_keys(&pre, keys, &options)?,
        PreVerifyOutcome::Unsigned => VerifierState::Unsigned,
        PreVerifyOutcome::StructuralFailure | PreVerifyOutcome::MetadataParseFailure => {
            VerifierState::MalformedAttemptedSigned
        }
    };
    Ok(VerifyResult {
        state,
        parser_observations: pre.parser_observations,
    })
}
fn verify_from_pre_verify_with_keys<
    'input,
    Ed25519: Ed25519VerificationKey + ?Sized,
    P256: P256VerificationKey + ?Sized,
>(
    pre: &PreVerifyResponse<'input>,
    keys: &GenericPublicKeys<'_, Ed25519, P256>,
    options: &VerifierOptions<'_>,
) -> Result<VerifierState<'input>, InvocationError> {
    if pre.outcome != PreVerifyOutcome::Ok {
        return Err(InvocationError::InvalidPreVerifyResult);
    }
    let payload = pre
        .unverified_payload_bytes
        .ok_or(InvocationError::InvalidPreVerifyResult)?;
    let signature = pre
        .unverified_signature
        .as_ref()
        .ok_or(InvocationError::InvalidPreVerifyResult)?;
    let wire_algorithm = match signature.algorithm {
        AlgorithmId::Ed25519 => 1,
        AlgorithmId::EcdsaP256Sha256 => 2,
    };
    verify_extracted_signature_with_keys(
        payload,
        wire_algorithm,
        &signature.signature_octets,
        keys,
        options,
    )
}
fn from_pre_with_keys<
    'input,
    Ed25519: Ed25519VerificationKey + ?Sized,
    P256: P256VerificationKey + ?Sized,
>(
    pre: &PreVerifyResponse<'input>,
    keys: &GenericPublicKeys<'_, Ed25519, P256>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    options
        .resource_limits
        .check_input_size(resource_form(pre.form), pre.source_artifact)?;
    validate_verify_options(pre.form, &options)?;
    let state = verify_from_pre_verify_with_keys(pre, keys, &options)?;
    Ok(VerifyResult {
        state,
        parser_observations: if options.include_parser_observations {
            pre.parser_observations.clone()
        } else {
            Vec::new()
        },
    })
}
/// Verify through a qualified provider; its verdict is authoritative.
pub fn verify_with_provider<'input>(
    input: &'input [u8],
    form: ArtifactForm,
    keys: &ProviderPublicKeys<'_>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    verify_with_provider_keys(input, form, keys, options)
}
/// Complete verification using qualified provider keys and the original input policy.
pub fn verify_from_pre_verify_with_provider<'input>(
    pre: &PreVerifyResponse<'input>,
    keys: &ProviderPublicKeys<'_>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    from_pre_with_keys(pre, keys, options)
}
/// Verify through an explicitly unqualified provider.
pub fn verify_with_unqualified_provider<'input>(
    input: &'input [u8],
    form: ArtifactForm,
    keys: &UnqualifiedProviderPublicKeys<'_>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    verify_with_provider_keys(input, form, keys, options)
}
/// Complete verification using explicitly unqualified provider keys.
pub fn verify_from_pre_verify_with_unqualified_provider<'input>(
    pre: &PreVerifyResponse<'input>,
    keys: &UnqualifiedProviderPublicKeys<'_>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    from_pre_with_keys(pre, keys, options)
}

/// Cryptographic verification from extracted payload + wire algorithm + signature octets.
#[cfg(test)]
pub(crate) fn verify_extracted_signature<'input>(
    payload: &'input [u8],
    wire_alg: i32,
    sig_octets: &[u8],
    keys: &PublicKeys<'_>,
    options: &VerifierOptions<'_>,
) -> Result<VerifierState<'input>, InvocationError> {
    verify_extracted_signature_with_keys(payload, wire_alg, sig_octets, keys, options)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyVerificationOutcome {
    Verified,
    MalformedSignature,
    SignatureMismatch,
    ProviderFailure,
}

trait Ed25519KeyValidation {
    fn is_admissible(&self) -> bool;
}

trait Ed25519VerificationKey: Ed25519KeyValidation {
    fn verify_signature(&self, payload: &[u8], signature: &[u8; 64]) -> KeyVerificationOutcome;
}

trait P256KeyValidation {
    fn is_admissible(&self) -> bool;
}

trait P256VerificationKey: P256KeyValidation {
    fn verify_signature(&self, payload: &[u8], signature: &[u8; 64]) -> KeyVerificationOutcome;
}

impl Ed25519KeyValidation for ed25519_dalek::VerifyingKey {
    fn is_admissible(&self) -> bool {
        crypto::ed25519_verifying_key_is_admissible(self)
    }
}

impl Ed25519VerificationKey for ed25519_dalek::VerifyingKey {
    fn verify_signature(&self, payload: &[u8], signature: &[u8; 64]) -> KeyVerificationOutcome {
        if crypto::verify_ed25519(self, payload, signature).is_ok() {
            KeyVerificationOutcome::Verified
        } else {
            KeyVerificationOutcome::SignatureMismatch
        }
    }
}

impl P256KeyValidation for p256::ecdsa::VerifyingKey {
    fn is_admissible(&self) -> bool {
        true
    }
}

impl P256VerificationKey for p256::ecdsa::VerifyingKey {
    fn verify_signature(&self, payload: &[u8], signature: &[u8; 64]) -> KeyVerificationOutcome {
        match crypto::verify_ecdsa_p256_sha256(self, payload, signature) {
            Ok(()) => KeyVerificationOutcome::Verified,
            Err(crypto::EcdsaVerifyError::MalformedSignature) => {
                KeyVerificationOutcome::MalformedSignature
            }
            Err(crypto::EcdsaVerifyError::EquationFailure) => {
                KeyVerificationOutcome::SignatureMismatch
            }
        }
    }
}

macro_rules! impl_provider_verification_key {
    ($key:ty) => {
        impl Ed25519KeyValidation for $key {
            fn is_admissible(&self) -> bool {
                self.algorithm() == AlgorithmId::Ed25519
                    && crypto::provider_public_key_is_admissible(
                        AlgorithmId::Ed25519,
                        self.canonical_public_key(),
                    )
            }
        }

        impl Ed25519VerificationKey for $key {
            fn verify_signature(
                &self,
                payload: &[u8],
                signature: &[u8; 64],
            ) -> KeyVerificationOutcome {
                provider_outcome(self.verify(payload, signature))
            }
        }

        impl P256KeyValidation for $key {
            fn is_admissible(&self) -> bool {
                self.algorithm() == AlgorithmId::EcdsaP256Sha256
                    && crypto::provider_public_key_is_admissible(
                        AlgorithmId::EcdsaP256Sha256,
                        self.canonical_public_key(),
                    )
            }
        }

        impl P256VerificationKey for $key {
            fn verify_signature(
                &self,
                payload: &[u8],
                signature: &[u8; 64],
            ) -> KeyVerificationOutcome {
                provider_outcome(self.verify(payload, signature))
            }
        }
    };
}

impl_provider_verification_key!(ProviderVerifyingKey<'_>);
impl_provider_verification_key!(UnqualifiedProviderVerifyingKey<'_>);

fn provider_outcome(outcome: ProviderVerificationOutcome) -> KeyVerificationOutcome {
    match outcome {
        ProviderVerificationOutcome::Verified => KeyVerificationOutcome::Verified,
        ProviderVerificationOutcome::SignatureMismatch => KeyVerificationOutcome::SignatureMismatch,
        ProviderVerificationOutcome::ProviderFailure => KeyVerificationOutcome::ProviderFailure,
    }
}

fn verification_state_from_outcome<'input>(
    outcome: KeyVerificationOutcome,
    payload: &'input [u8],
    algorithm: AlgorithmId,
) -> Result<VerifierState<'input>, InvocationError> {
    match outcome {
        KeyVerificationOutcome::Verified => Ok(VerifierState::Verified { payload, algorithm }),
        KeyVerificationOutcome::MalformedSignature => Ok(VerifierState::MalformedAttemptedSigned),
        KeyVerificationOutcome::SignatureMismatch => Ok(VerifierState::SignedButFailedVerification),
        KeyVerificationOutcome::ProviderFailure => Err(InvocationError::KeyResolutionFailure),
    }
}

fn verify_extracted_signature_with_keys<'input, Ed25519, P256>(
    payload: &'input [u8],
    wire_alg: i32,
    sig_octets: &[u8],
    keys: &GenericPublicKeys<'_, Ed25519, P256>,
    options: &VerifierOptions<'_>,
) -> Result<VerifierState<'input>, InvocationError>
where
    Ed25519: Ed25519VerificationKey + ?Sized,
    P256: P256VerificationKey + ?Sized,
{
    let (outcome, algorithm) =
        match prepare_signature_verification(wire_alg, sig_octets, keys, options)? {
            PreparedVerification::Complete(state) => return Ok(state),
            PreparedVerification::Ed25519(key, signature) => (
                key.verify_signature(payload, signature),
                AlgorithmId::Ed25519,
            ),
            PreparedVerification::P256(key, signature) => (
                key.verify_signature(payload, signature),
                AlgorithmId::EcdsaP256Sha256,
            ),
        };
    verification_state_from_outcome(outcome, payload, algorithm)
}

// Only a validated work item can reach either a synchronous or an awaited
// operation. Keep validation ordering here so both paths classify the same
// combination of malformed bytes, disabled algorithms, and missing keys.
enum PreparedVerification<'a, Ed25519: ?Sized, P256: ?Sized> {
    Complete(VerifierState<'static>),
    Ed25519(&'a Ed25519, &'a [u8; 64]),
    P256(&'a P256, &'a [u8; 64]),
}

fn prepare_signature_verification<'a, Ed25519, P256>(
    wire_alg: i32,
    sig_octets: &'a [u8],
    keys: &'a GenericPublicKeys<'_, Ed25519, P256>,
    options: &VerifierOptions<'_>,
) -> Result<PreparedVerification<'a, Ed25519, P256>, InvocationError>
where
    Ed25519: Ed25519KeyValidation + ?Sized,
    P256: P256KeyValidation + ?Sized,
{
    // Form-agnostic. YAML-envelope payload rules (UTF-8, no BOM, line-terminator)
    // are the responsibility of `yaml_verify::pre_verify_yaml` per the spec's
    // "Applies to: YAML form only" row in the metadata-extraction table.
    // Protobuf form imposes no payload checks. See
    // docs/conformance-validation.md §3f.

    if wire_alg <= 0 {
        return Ok(PreparedVerification::Complete(
            VerifierState::MalformedAttemptedSigned,
        ));
    }

    let alg = match AlgorithmId::from_i32(wire_alg) {
        Some(a) => a,
        None => {
            return Ok(PreparedVerification::Complete(
                VerifierState::MalformedAttemptedSigned,
            ));
        }
    };

    if sig_octets.is_empty() {
        return Ok(PreparedVerification::Complete(
            VerifierState::MalformedAttemptedSigned,
        ));
    }

    // Both supported algorithms specify a fixed 64-octet `R || S` wire
    // format. A wrong-length signature byte string is structurally malformed
    // (not a crypto failure) — surface that distinction at the byte stage,
    // before invoking the crypto library. See
    // covered by the wrong-size signature fixtures.
    if sig_octets.len() != 64 {
        return Ok(PreparedVerification::Complete(
            VerifierState::MalformedAttemptedSigned,
        ));
    }

    match alg {
        AlgorithmId::Ed25519 => {
            if !options.verify_ed25519 {
                return Ok(PreparedVerification::Complete(
                    VerifierState::SignedButAlgorithmUnsupported { algorithm: alg },
                ));
            }
            // Apply the slot's canonical `R` point and `S` scalar requirements
            // before the cofactored equation so malformed signature octets keep
            // their specified verifier-state classification.
            if !crypto::ed25519_signature_is_canonical(sig_octets) {
                return Ok(PreparedVerification::Complete(
                    VerifierState::MalformedAttemptedSigned,
                ));
            }
            let vk = keys.ed25519.ok_or(InvocationError::KeyResolutionFailure)?;
            // `PublicKeys` accepts an already constructed verifying key, so
            // callers are not required to use the byte-oriented resolver.
            // Enforce the same key-admissibility rule at the point of use.
            if !vk.is_admissible() {
                return Err(InvocationError::KeyResolutionFailure);
            }
            let signature: &[u8; 64] = sig_octets
                .try_into()
                .expect("the fixed signature length was checked above");
            Ok(PreparedVerification::Ed25519(vk, signature))
        }
        AlgorithmId::EcdsaP256Sha256 => {
            if !options.verify_ecdsa_p256_sha256 {
                return Ok(PreparedVerification::Complete(
                    VerifierState::SignedButAlgorithmUnsupported { algorithm: alg },
                ));
            }
            let vk = keys.p256.ok_or(InvocationError::KeyResolutionFailure)?;
            if !crypto::ecdsa_p256_signature_is_well_formed(sig_octets) {
                return Ok(PreparedVerification::Complete(
                    VerifierState::MalformedAttemptedSigned,
                ));
            }
            if !vk.is_admissible() {
                return Err(InvocationError::KeyResolutionFailure);
            }
            let signature: &[u8; 64] = sig_octets
                .try_into()
                .expect("the fixed signature length was checked above");
            Ok(PreparedVerification::P256(vk, signature))
        }
    }
}

/// Extract structural and signature metadata after checking the raw input policy.
/// Payload and source artifact borrow the caller's bytes.
pub fn pre_verify<'input>(
    input_bytes: &'input [u8],
    form: ArtifactForm,
    options: PreVerifyOptions,
) -> Result<PreVerifyResponse<'input>, VerifyError> {
    options
        .resource_limits
        .check_input_size(resource_form(form), input_bytes)?;
    if !verifier_capabilities().supported_forms.contains(&form) {
        return Err(InvocationError::InvalidOrUnsupportedForm.into());
    }
    match form {
        ArtifactForm::Yaml => {
            #[cfg(feature = "yaml")]
            {
                Ok(yaml_verify::pre_verify_yaml(
                    input_bytes,
                    options.allow_unsigned,
                    options.include_parser_observations,
                ))
            }
            #[cfg(not(feature = "yaml"))]
            {
                Err(InvocationError::InvalidOrUnsupportedForm.into())
            }
        }
        ArtifactForm::Proto => {
            #[cfg(feature = "protobuf")]
            {
                Ok(proto_verify::pre_verify_proto(
                    input_bytes,
                    options.include_parser_observations,
                ))
            }
            #[cfg(not(feature = "protobuf"))]
            {
                Err(InvocationError::InvalidOrUnsupportedForm.into())
            }
        }
    }
}
/// Summarize pre-verification using the same options and fallible contract.
pub fn can_pre_verify(
    input: &[u8],
    form: ArtifactForm,
    options: PreVerifyOptions,
) -> Result<bool, VerifyError> {
    let allow_unsigned = options.allow_unsigned;
    Ok(match pre_verify(input, form, options)?.outcome {
        PreVerifyOutcome::Ok => true,
        PreVerifyOutcome::Unsigned => allow_unsigned,
        PreVerifyOutcome::StructuralFailure | PreVerifyOutcome::MetadataParseFailure => false,
    })
}
/// Complete cryptographic verification, applying limits to the original encoded artifact.
pub fn verify_from_pre_verify<'input>(
    pre: &PreVerifyResponse<'input>,
    keys: &PublicKeys<'_>,
    options: VerifierOptions<'_>,
) -> Result<VerifyResult<'input>, VerifyError> {
    from_pre_with_keys(pre, keys, options)
}

/// In-process verifier using the free functions.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultVerifier;
impl Verifier for DefaultVerifier {
    type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
    type P256VerifyingKey = p256::ecdsa::VerifyingKey;
    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }
    fn pre_verify<'input>(
        &self,
        input: &'input [u8],
        form: ArtifactForm,
        options: PreVerifyOptions,
    ) -> Result<PreVerifyResponse<'input>, VerifyError> {
        pre_verify(input, form, options)
    }
    fn verify<'input>(
        &self,
        input: &'input [u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions<'_>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        verify(input, form, keys, options)
    }
    fn verify_from_pre_verify<'input>(
        &self,
        pre: &PreVerifyResponse<'input>,
        keys: &PublicKeys<'_>,
        options: VerifierOptions<'_>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        verify_from_pre_verify(pre, keys, options)
    }
}
/// In-process async verifier. Work runs on the polling thread.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAsyncVerifier;
impl AsyncVerifier for DefaultAsyncVerifier {
    type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
    type P256VerifyingKey = p256::ecdsa::VerifyingKey;
    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }
    async fn pre_verify<'call, 'input: 'call>(
        &'call self,
        input: &'input [u8],
        form: ArtifactForm,
        options: PreVerifyOptions,
    ) -> Result<PreVerifyResponse<'input>, VerifyError> {
        pre_verify(input, form, options)
    }
    async fn verify<'call, 'input: 'call>(
        &'call self,
        input: &'input [u8],
        form: ArtifactForm,
        keys: &'call PublicKeys<'_>,
        options: VerifierOptions<'call>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        verify(input, form, keys, options)
    }
    async fn verify_from_pre_verify<'call, 'input: 'call>(
        &'call self,
        pre: &'call PreVerifyResponse<'input>,
        keys: &'call PublicKeys<'_>,
        options: VerifierOptions<'call>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        verify_from_pre_verify(pre, keys, options)
    }
}
/// Validate an optional carrier key identifier without format dependencies.
fn keyid_is_valid(keyid: &str) -> bool {
    (1..=1024).contains(&keyid.len()) && !keyid.contains(['\r', '\n'])
}

#[cfg(test)]
mod trait_smoke_tests {
    use super::*;

    #[test]
    fn default_verifier_capabilities_match_free_function() {
        let v = DefaultVerifier;
        assert_eq!(v.capabilities(), verifier_capabilities());
    }

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(core::num::NonZeroUsize::new(maximum).unwrap())
    }

    fn no_keys() -> PublicKeys<'static> {
        PublicKeys {
            ed25519: None,
            p256: None,
        }
    }

    #[test]
    fn input_resource_check_precedes_invalid_options_and_malformed_bytes() {
        let options = VerifierOptions {
            algorithm_parameters: &[1],
            ..VerifierOptions::default()
        };
        let error = verify(
            &[0xff, 0xff],
            ArtifactForm::Proto,
            &no_keys(),
            yaml_sigil_traits::verification::VerifierOptions {
                resource_limits: finite(1).clone(),
                ..options
            },
        )
        .map(|result| result.state)
        .unwrap_err();
        let error = match error {
            VerifyError::Resource(error) => error,
            other => panic!("expected resource error: {other:?}"),
        };
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(error.artifact_form(), Some(ArtifactResourceForm::Protobuf));
        assert_eq!(error.observed_or_projected_artifact_bytes(), Some(2));

        let metadata_error = verify(
            &[0xff, 0xff],
            ArtifactForm::Yaml,
            &no_keys(),
            yaml_sigil_traits::verification::VerifierOptions {
                resource_limits: finite(1).clone(),
                include_parser_observations: true,
                ..VerifierOptions {
                    algorithm_parameters: &[1],
                    ..VerifierOptions::default()
                }
            },
        )
        .unwrap_err();
        let metadata_error = match metadata_error {
            VerifyError::Resource(error) => error,
            other => panic!("expected resource error: {other:?}"),
        };
        assert_eq!(
            metadata_error.kind(),
            ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(
            metadata_error.artifact_form(),
            Some(ArtifactResourceForm::Yaml)
        );
    }

    #[test]
    fn all_structural_entry_points_use_the_original_input_boundary() {
        let input = [0xff, 0xfe];
        let limits = finite(1);
        assert!(
            pre_verify(
                &input,
                ArtifactForm::Yaml,
                yaml_sigil_traits::verification::PreVerifyOptions {
                    allow_unsigned: false,
                    include_parser_observations: true,
                    resource_limits: limits.clone()
                }
            )
            .is_err()
        );
        assert!(
            pre_verify(
                &input,
                yaml_sigil_traits::verification::ArtifactForm::Yaml,
                yaml_sigil_traits::verification::PreVerifyOptions {
                    allow_unsigned: false,
                    include_parser_observations: false,
                    resource_limits: limits.clone()
                }
            )
            .is_err()
        );
        assert!(
            pre_verify(
                &input,
                yaml_sigil_traits::verification::ArtifactForm::Proto,
                yaml_sigil_traits::verification::PreVerifyOptions {
                    allow_unsigned: false,
                    include_parser_observations: false,
                    resource_limits: limits.clone()
                }
            )
            .is_err()
        );
        assert!(
            verify(
                &input,
                yaml_sigil_traits::verification::ArtifactForm::Yaml,
                &no_keys(),
                yaml_sigil_traits::verification::VerifierOptions {
                    resource_limits: limits.clone(),
                    ..VerifierOptions::default()
                }
            )
            .map(|result| result.state)
            .is_err()
        );
        assert!(
            can_pre_verify(
                &input,
                ArtifactForm::Proto,
                yaml_sigil_traits::verification::PreVerifyOptions {
                    allow_unsigned: false,
                    include_parser_observations: false,
                    resource_limits: limits.clone()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn protobuf_input_rejection_precedes_all_characterized_wire_shapes() {
        let inputs = [
            vec![0xff, 0xff],
            vec![0x0a, 0x80],
            vec![0x00, 0x00],
            vec![0x0f, 0x00],
            vec![0x80; 11],
            vec![0x50, 0x01],
            vec![0x53, 0x08, 0x01, 0x54],
            vec![0x0a, 0x01, b'a', 0x0a, 0x01, b'b'],
        ];

        for input in inputs {
            let limits = finite(1);
            let verify_error = verify(
                &input,
                yaml_sigil_traits::verification::ArtifactForm::Proto,
                &no_keys(),
                yaml_sigil_traits::verification::VerifierOptions {
                    resource_limits: limits.clone(),
                    ..VerifierOptions::default()
                },
            )
            .map(|result| result.state)
            .unwrap_err();
            let verify_error = match verify_error {
                VerifyError::Resource(error) => error,
                other => panic!("expected resource error: {other:?}"),
            };
            let pre_verify_error = pre_verify(
                &input,
                yaml_sigil_traits::verification::ArtifactForm::Proto,
                yaml_sigil_traits::verification::PreVerifyOptions {
                    allow_unsigned: false,
                    include_parser_observations: false,
                    resource_limits: limits.clone(),
                },
            )
            .unwrap_err();
            let pre_verify_error = match pre_verify_error {
                VerifyError::Resource(error) => error,
                other => panic!("expected resource error: {other:?}"),
            };
            let can_pre_verify_error = can_pre_verify(
                &input,
                ArtifactForm::Proto,
                yaml_sigil_traits::verification::PreVerifyOptions {
                    allow_unsigned: false,
                    include_parser_observations: false,
                    resource_limits: limits.clone(),
                },
            )
            .unwrap_err();
            let can_pre_verify_error = match can_pre_verify_error {
                VerifyError::Resource(error) => error,
                other => panic!("expected resource error: {other:?}"),
            };

            for error in [verify_error, pre_verify_error, can_pre_verify_error] {
                assert_eq!(
                    error.kind(),
                    ArtifactResourceErrorKind::InputArtifactTooLarge
                );
                assert_eq!(error.artifact_form(), Some(ArtifactResourceForm::Protobuf));
                assert_eq!(
                    error.observed_or_projected_artifact_bytes(),
                    Some(input.len())
                );
            }
        }
    }

    #[test]
    fn pre_verify_handoff_preserves_the_original_encoded_artifact() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let artifact = yaml_sigil_signing::sign(&yaml_sigil_signing::SignRequest {
            resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
            output_form: yaml_sigil_signing::OutputForm::Yaml,
            algorithm_parameters: &[],
            payload: b"handoff: true\n",
            algorithm: AlgorithmId::Ed25519,
            key: yaml_sigil_signing::SigningKey::Ed25519(&signing_key),
            keyid: None,
            append_missing_final_newline: false,
        })
        .map(|success| success.artifact)
        .unwrap();
        let limits = finite(artifact.len());
        let pre = pre_verify(
            &artifact,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            yaml_sigil_traits::verification::PreVerifyOptions {
                allow_unsigned: false,
                include_parser_observations: false,
                resource_limits: limits.clone(),
            },
        )
        .unwrap();
        assert_eq!(pre.outcome, PreVerifyOutcome::Ok);

        let verifying_key = signing_key.verifying_key();
        let keys = PublicKeys {
            ed25519: Some(&verifying_key),
            p256: None,
        };
        assert!(matches!(
            verify_from_pre_verify(&pre, &keys, VerifierOptions::default())
                .map(|result| result.state)
                .unwrap(),
            VerifierState::Verified { .. }
        ));
    }

    #[test]
    fn default_p256_missing_key_precedence_is_unchanged() {
        assert_eq!(
            verify_extracted_signature(
                b"payload",
                2,
                &[0; 64],
                &no_keys(),
                &VerifierOptions::default(),
            ),
            Err(InvocationError::KeyResolutionFailure)
        );
    }

    // The concrete RustCrypto bindings must remain expressible on a
    // synchronous trait object.
    #[test]
    fn default_verifier_supports_a_trait_object_with_explicit_bindings() {
        let verifier: &dyn Verifier<
            Ed25519VerifyingKey = ed25519_dalek::VerifyingKey,
            P256VerifyingKey = p256::ecdsa::VerifyingKey,
        > = &DefaultVerifier;
        assert_eq!(verifier.capabilities(), verifier_capabilities());
    }

    #[test]
    fn default_verifier_unsigned_yaml_matches_free_function() {
        let payload = b"a: b\n";
        let direct = verify(
            payload,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            &PublicKeys {
                ed25519: None,
                p256: None,
            },
            VerifierOptions::default(),
        )
        .map(|result| result.state);
        let via_trait = DefaultVerifier
            .verify(
                payload,
                ArtifactForm::Yaml,
                &PublicKeys {
                    ed25519: None,
                    p256: None,
                },
                VerifierOptions::default(),
            )
            .map(|result| result.state);
        assert_eq!(direct, via_trait);
    }

    #[tokio::test]
    async fn default_async_verifier_unsigned_yaml_matches_free_function() {
        let payload = b"a: b\n";
        let direct = verify(
            payload,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            &PublicKeys {
                ed25519: None,
                p256: None,
            },
            VerifierOptions::default(),
        )
        .map(|result| result.state);
        let via_async_trait = AsyncVerifier::verify(
            &DefaultAsyncVerifier,
            payload,
            ArtifactForm::Yaml,
            &PublicKeys {
                ed25519: None,
                p256: None,
            },
            VerifierOptions::default(),
        )
        .await
        .map(|result| result.state);
        assert_eq!(direct, via_async_trait);
        assert_eq!(
            AsyncVerifier::capabilities(&DefaultAsyncVerifier),
            verifier_capabilities()
        );
    }
}
