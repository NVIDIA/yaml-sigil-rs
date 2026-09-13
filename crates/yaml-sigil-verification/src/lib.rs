// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YamlSigil v1alpha1 verification: five verifier states, invocation errors, Ed25519 + ECDSA P-256 SHA-256.
//!
//! Algorithm slot 0 (`ALGORITHM_UNSPECIFIED`) and unknown wire `alg` values map
//! to [`VerifierState::MalformedAttemptedSigned`]. Slot 1 is
//! `ED25519_PUREEDDSA_RAW_RS64_CANONICAL` (Ed25519 RFC 8032, raw `R || S`); slot
//! 2 is `ECDSA_SECP256R1_SHA256_RAW_RS64` (raw `R || S` 64 octets).
//!
//! # Resource boundaries
//!
//! Resource-aware verification and pre-verification check the original input
//! before option, artifact, or cryptographic processing. Existing entry points
//! retain their unbounded behavior. A local resource-policy rejection remains
//! separate from invocation errors, artifact validity, cryptographic results,
//! and YamlSigil `v1alpha1` conformance.
//!
//! YAML signature metadata retains its independent 16,384-octet carrier
//! constraint and parser safeguards. The private protobuf decoder retains its
//! format and implementation safeguards.
//!
//! # Layered resource results
//!
//! The outer result reports local resource admission. The inner result keeps
//! the existing verification contract.
//!
//! ```no_run
//! use yaml_sigil_verification::{
//!     ArtifactForm, ArtifactResourceLimits, PublicKeys, VerifierOptions,
//!     VerifierState, verify_with_resource_limits,
//! };
//!
//! # fn verify_bounded(
//! #     input: &[u8],
//! #     keys: &PublicKeys<'_>,
//! # ) -> Result<VerifierState, Box<dyn std::error::Error>> {
//! let admitted = verify_with_resource_limits(
//!     input,
//!     ArtifactForm::Yaml,
//!     keys,
//!     VerifierOptions::default(),
//!     &ArtifactResourceLimits::default(),
//! )?;
//! Ok(admitted?)
//! # }
//! ```
//!
//! Apply the standalone zero-copy input filter before an existing async trait
//! call when you need the portable trait surface.
//!
//! ```no_run
//! use yaml_sigil_verification::{
//!     ArtifactForm, ArtifactResourceForm, ArtifactResourceLimits,
//!     ArtifactResourceResult, AsyncVerifier, DefaultAsyncVerifier,
//! };
//!
//! # async fn pre_verify_bounded(input: &[u8]) -> ArtifactResourceResult<()> {
//! let limits = ArtifactResourceLimits::default();
//! let input = limits.check_input_size(ArtifactResourceForm::Yaml, input)?;
//! let _ = AsyncVerifier::pre_verify(
//!     &DefaultAsyncVerifier,
//!     input,
//!     ArtifactForm::Yaml,
//!     false,
//!     false,
//! )
//! .await;
//! Ok(())
//! # }
//! ```

mod crypto;
mod proto_verify;
mod yaml_verify;

use yaml_sigil_core::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
};

pub use yaml_sigil_core::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
// The portable traits and DTOs live in `yaml-sigil-traits`. This implementation
// binds the generic key-bearing DTO to its RustCrypto key types and owns key
// parsing, retaining established `yaml_sigil_verification` paths.
use yaml_sigil_traits::verification::PublicKeys as GenericPublicKeys;
pub use yaml_sigil_traits::verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, InvocationError, PreVerifyOutcome,
    PreVerifyResponse, UnverifiedSignature, Verifier, VerifierCapabilities, VerifierOptions,
    VerifierState, VerifyResult,
};

/// Caller-supplied verification keys supported by this RustCrypto implementation.
pub type PublicKeys<'a> =
    GenericPublicKeys<'a, ed25519_dalek::VerifyingKey, p256::ecdsa::VerifyingKey>;

/// Resolve a 32-byte compressed Ed25519 public key into an admissible typed key.
///
/// The input must use a canonical point encoding and identify a key accepted
/// by this implementation.
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
        supported_forms: &[ArtifactForm::Yaml, ArtifactForm::Proto],
        supported_algorithms: &[AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256],
        supports_can_pre_verify: true,
        supports_pre_verify: true,
        implementation_name: env!("CARGO_PKG_NAME"),
        implementation_version: env!("CARGO_PKG_VERSION"),
    }
}

/// Verify `input_bytes` using the selected artifact form (mirrors `Verify` with a `Form` enum).
///
/// # Resource usage
///
/// Both forms accept a complete artifact without adding an implementation-local
/// input limit. Use [`verify_with_resource_limits`] to apply the shared policy
/// first.
#[tracing::instrument(level = "info", skip_all, fields(len = input_bytes.len(), form = ?form))]
pub fn verify(
    input_bytes: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify_with_metadata(input_bytes, form, keys, options, false).map(|r| r.state)
}

fn resource_form(form: ArtifactForm) -> ArtifactResourceForm {
    match form {
        ArtifactForm::Yaml => ArtifactResourceForm::Yaml,
        ArtifactForm::Proto => ArtifactResourceForm::Protobuf,
    }
}

/// Verify after applying an explicit complete-input resource policy.
///
/// The raw input length is checked before form, option, artifact, or
/// cryptographic processing. The inner result retains the existing invocation
/// error and verifier-state contract.
#[tracing::instrument(level = "info", skip_all, fields(len = input_bytes.len(), form = ?form))]
pub fn verify_with_resource_limits(
    input_bytes: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<VerifierState, InvocationError>> {
    limits.check_input_size(resource_form(form), input_bytes)?;
    Ok(verify(input_bytes, form, keys, options))
}

/// Verify with optional parser observations (IDL `VerifyRequest.include_parser_observations`).
///
/// # Resource usage
///
/// Both forms have the resource behavior documented on [`verify`].
#[tracing::instrument(level = "info", skip_all, fields(len = input_bytes.len(), form = ?form))]
pub fn verify_with_metadata(
    input_bytes: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
    include_parser_observations: bool,
) -> Result<VerifyResult, InvocationError> {
    let caps = verifier_capabilities();
    if !caps.supported_forms.contains(&form) {
        return Err(InvocationError::InvalidOrUnsupportedForm);
    }
    if !options.algorithm_parameters.is_empty() {
        return Err(InvocationError::InvalidAlgorithmParameters);
    }
    let (state, parser_observations) = match form {
        ArtifactForm::Yaml => {
            yaml_verify::verify_yaml(input_bytes, keys, &options, include_parser_observations)?
        }
        ArtifactForm::Proto => {
            proto_verify::verify_proto(input_bytes, keys, &options, include_parser_observations)?
        }
    };
    Ok(VerifyResult {
        state,
        parser_observations,
    })
}

/// Verify with metadata after applying an explicit complete-input policy.
#[tracing::instrument(level = "info", skip_all, fields(len = input_bytes.len(), form = ?form))]
pub fn verify_with_metadata_and_resource_limits(
    input_bytes: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
    include_parser_observations: bool,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<VerifyResult, InvocationError>> {
    limits.check_input_size(resource_form(form), input_bytes)?;
    Ok(verify_with_metadata(
        input_bytes,
        form,
        keys,
        options,
        include_parser_observations,
    ))
}

/// Verify a YAML artifact byte sequence.
///
/// Use [`verify_yaml_with_resource_limits`] to apply the shared complete-input
/// policy. The markerless signature carrier has a separate 16,384-octet
/// constraint.
#[tracing::instrument(level = "info", skip_all, fields(len = artifact.len()))]
pub fn verify_yaml(
    artifact: &[u8],
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify(artifact, ArtifactForm::Yaml, keys, options)
}

/// Verify a YAML artifact after applying an explicit complete-input policy.
pub fn verify_yaml_with_resource_limits(
    artifact: &[u8],
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<VerifierState, InvocationError>> {
    limits.check_input_size(ArtifactResourceForm::Yaml, artifact)?;
    Ok(verify_yaml(artifact, keys, options))
}

/// Verify protobuf `SignedYamlArtifact` wire bytes.
///
/// # Resource usage
///
/// Protobuf pre-verification has the resource behavior documented on
/// [`pre_verify_proto`]. A successful verification also copies the payload
/// into the returned [`VerifierState`], with work and allocation linear in
/// payload size.
#[tracing::instrument(level = "info", skip_all, fields(len = wire.len()))]
pub fn verify_proto(
    wire: &[u8],
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify(wire, ArtifactForm::Proto, keys, options)
}

/// Verify protobuf wire after applying an explicit complete-input policy.
pub fn verify_proto_with_resource_limits(
    wire: &[u8],
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<VerifierState, InvocationError>> {
    limits.check_input_size(ArtifactResourceForm::Protobuf, wire)?;
    Ok(verify_proto(wire, keys, options))
}

/// Cryptographic verification from extracted payload + wire algorithm + signature octets.
pub(crate) fn verify_extracted_signature(
    payload: &[u8],
    wire_alg: i32,
    sig_octets: &[u8],
    keys: &PublicKeys<'_>,
    options: &VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    // Form-agnostic. YAML-envelope payload rules (UTF-8, no BOM, line-terminator)
    // are the responsibility of `yaml_verify::pre_verify_yaml` per the spec's
    // "Applies to: YAML form only" row in the metadata-extraction table.
    // Protobuf form imposes no payload checks. See
    // docs/conformance-validation.md §3f.

    if wire_alg <= 0 {
        return Ok(VerifierState::MalformedAttemptedSigned);
    }

    let alg = match AlgorithmId::from_i32(wire_alg) {
        Some(a) => a,
        None => return Ok(VerifierState::MalformedAttemptedSigned),
    };

    if sig_octets.is_empty() {
        return Ok(VerifierState::MalformedAttemptedSigned);
    }

    // Both supported algorithms specify a fixed 64-octet `R || S` wire
    // format. A wrong-length signature byte string is structurally malformed
    // (not a crypto failure) — surface that distinction at the byte stage,
    // before invoking the crypto library. See
    // covered by the wrong-size signature fixtures.
    if sig_octets.len() != 64 {
        return Ok(VerifierState::MalformedAttemptedSigned);
    }

    match alg {
        AlgorithmId::Ed25519 => {
            if !options.verify_ed25519 {
                return Ok(VerifierState::SignedButAlgorithmUnsupported { algorithm: alg });
            }
            // Apply the slot's canonical `R` point and `S` scalar requirements
            // before the cofactored equation so malformed signature octets keep
            // their specified verifier-state classification.
            if !crypto::ed25519_signature_is_canonical(sig_octets) {
                return Ok(VerifierState::MalformedAttemptedSigned);
            }
            let vk = keys.ed25519.ok_or(InvocationError::KeyResolutionFailure)?;
            // `PublicKeys` accepts an already constructed verifying key, so
            // callers are not required to use the byte-oriented resolver.
            // Enforce the same key-admissibility rule at the point of use.
            if !crypto::ed25519_verifying_key_is_admissible(vk) {
                return Err(InvocationError::KeyResolutionFailure);
            }
            if crypto::verify_ed25519(vk, payload, sig_octets).is_ok() {
                Ok(VerifierState::Verified {
                    payload: payload.to_vec(),
                    algorithm: alg,
                })
            } else {
                Ok(VerifierState::SignedButFailedVerification)
            }
        }
        AlgorithmId::EcdsaP256Sha256 => {
            if !options.verify_ecdsa_p256_sha256 {
                return Ok(VerifierState::SignedButAlgorithmUnsupported { algorithm: alg });
            }
            let vk = keys.p256.ok_or(InvocationError::KeyResolutionFailure)?;
            match crypto::verify_ecdsa_p256_sha256(vk, payload, sig_octets) {
                Ok(()) => Ok(VerifierState::Verified {
                    payload: payload.to_vec(),
                    algorithm: alg,
                }),
                Err(crypto::EcdsaVerifyError::MalformedSignature) => {
                    Ok(VerifierState::MalformedAttemptedSigned)
                }
                Err(crypto::EcdsaVerifyError::EquationFailure) => {
                    Ok(VerifierState::SignedButFailedVerification)
                }
            }
        }
    }
}

/// Structural + metadata pre-verify (IDL `PreVerify`).
///
/// # Resource usage
///
/// Both forms accept a complete artifact without adding an implementation-local
/// input limit. Use [`pre_verify_with_resource_limits`] to apply the shared
/// policy first.
pub fn pre_verify(
    input_bytes: &[u8],
    form: ArtifactForm,
    allow_unsigned: bool,
    include_parser_observations: bool,
) -> PreVerifyResponse {
    match form {
        ArtifactForm::Yaml => {
            yaml_verify::pre_verify_yaml(input_bytes, allow_unsigned, include_parser_observations)
        }
        ArtifactForm::Proto => {
            let _ = allow_unsigned;
            proto_verify::pre_verify_proto(input_bytes, include_parser_observations)
        }
    }
}

/// Pre-verify after applying an explicit complete-input policy.
///
/// Enforcement occurs once while the original encoded artifact is available.
/// Continue with the existing [`verify_from_pre_verify`] function; it neither
/// reconstructs nor rechecks complete-artifact size.
pub fn pre_verify_with_resource_limits(
    input_bytes: &[u8],
    form: ArtifactForm,
    allow_unsigned: bool,
    include_parser_observations: bool,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<PreVerifyResponse> {
    limits.check_input_size(resource_form(form), input_bytes)?;
    Ok(pre_verify(
        input_bytes,
        form,
        allow_unsigned,
        include_parser_observations,
    ))
}

/// Lightweight structural peek for YAML with no keys or cryptography.
///
/// This function has the YAML resource behavior documented on [`verify_yaml`].
pub fn pre_verify_yaml(artifact: &[u8], allow_unsigned: bool) -> PreVerifyResponse {
    pre_verify(artifact, ArtifactForm::Yaml, allow_unsigned, false)
}

/// Pre-verify YAML after applying an explicit complete-input policy.
pub fn pre_verify_yaml_with_resource_limits(
    artifact: &[u8],
    allow_unsigned: bool,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<PreVerifyResponse> {
    limits.check_input_size(ArtifactResourceForm::Yaml, artifact)?;
    Ok(pre_verify_yaml(artifact, allow_unsigned))
}

/// Lightweight structural peek for protobuf wire (no keys, no crypto).
///
/// # Resource usage
///
/// This path delegates to [`yaml_sigil_core::decompose_proto_outer`] without
/// adding a deployment-specific complete-artifact limit. It copies recognized
/// outer and inner fields into owned buffers with work and allocation linear
/// in field size. Applications accepting potentially untrusted input should
/// apply their chosen input bound before this call.
pub fn pre_verify_proto(wire: &[u8]) -> PreVerifyResponse {
    pre_verify(wire, ArtifactForm::Proto, false, false)
}

/// Pre-verify protobuf wire after applying an explicit complete-input policy.
pub fn pre_verify_proto_with_resource_limits(
    wire: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<PreVerifyResponse> {
    limits.check_input_size(ArtifactResourceForm::Protobuf, wire)?;
    Ok(pre_verify_proto(wire))
}

/// Boolean summary of [`pre_verify`] without crypto (IDL `CanPreVerify`).
///
/// # Resource usage
///
/// Both forms have the resource behavior documented on [`pre_verify`].
pub fn can_pre_verify(input_bytes: &[u8], form: ArtifactForm, allow_unsigned: bool) -> bool {
    match pre_verify(input_bytes, form, allow_unsigned, false).outcome {
        PreVerifyOutcome::Ok => true,
        PreVerifyOutcome::Unsigned if allow_unsigned && form == ArtifactForm::Yaml => true,
        _ => false,
    }
}

/// Report pre-verification capability after applying an explicit input policy.
pub fn can_pre_verify_with_resource_limits(
    input_bytes: &[u8],
    form: ArtifactForm,
    allow_unsigned: bool,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<bool> {
    limits.check_input_size(resource_form(form), input_bytes)?;
    Ok(can_pre_verify(input_bytes, form, allow_unsigned))
}

/// Run only the verification stage using a prior YAML [`PreVerifyResponse`].
///
/// This function does not receive the original encoded artifact. Apply any
/// input policy before creating `pre`.
pub fn verify_from_pre_verify_yaml(
    pre: &PreVerifyResponse,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    if !options.algorithm_parameters.is_empty() {
        return Err(InvocationError::InvalidAlgorithmParameters);
    }
    yaml_verify::verify_from_pre_verify(pre, keys, &options)
}

/// Run only the verification stage using a prior protobuf [`PreVerifyResponse`].
///
/// # Resource usage
///
/// This function does not decode protobuf wire input. It operates on the owned
/// buffers in `pre`, and successful verification copies the payload into the
/// returned [`VerifierState`], with work and allocation linear in payload
/// size. Apply any input policy before constructing `pre` from potentially
/// untrusted data.
pub fn verify_from_pre_verify_proto(
    pre: &PreVerifyResponse,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    if !options.algorithm_parameters.is_empty() {
        return Err(InvocationError::InvalidAlgorithmParameters);
    }
    proto_verify::verify_from_pre_verify_proto(pre, keys, &options)
}

/// Run only the verification stage using a successful [`PreVerifyResponse`] (IDL `VerifyFromPreVerify`).
///
/// # Resource usage
///
/// The form-specific methods document why any encoded-input policy must run
/// before constructing `pre`.
pub fn verify_from_pre_verify(
    pre: &PreVerifyResponse,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    match pre.form {
        ArtifactForm::Yaml => verify_from_pre_verify_yaml(pre, keys, options),
        ArtifactForm::Proto => verify_from_pre_verify_proto(pre, keys, options),
    }
}

/// In-process default verifier that delegates to the crate's free functions.
///
/// Its entry points retain the unbounded resource behavior documented on
/// [`pre_verify`] and [`verify`]. Use the resource-aware free functions when
/// you need the shared policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultVerifier;

impl Verifier for DefaultVerifier {
    type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
    type P256VerifyingKey = p256::ecdsa::VerifyingKey;

    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }
    fn pre_verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> PreVerifyResponse {
        pre_verify(
            input_bytes,
            form,
            allow_unsigned,
            include_parser_observations,
        )
    }
    fn verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        verify(input_bytes, form, keys, options)
    }
    fn verify_with_metadata(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError> {
        verify_with_metadata(
            input_bytes,
            form,
            keys,
            options,
            include_parser_observations,
        )
    }
    fn verify_from_pre_verify(
        &self,
        pre: &PreVerifyResponse,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        verify_from_pre_verify(pre, keys, options)
    }
}

/// In-process default async verifier that delegates to the crate's free
/// functions. Bodies are `async { sync_fn(...) }` — verification work is
/// CPU-bound; no `tokio::spawn_blocking` is used.
///
/// Its entry points retain the unconfigured resource behavior documented on
/// [`pre_verify`] and [`verify`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAsyncVerifier;

impl AsyncVerifier for DefaultAsyncVerifier {
    type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
    type P256VerifyingKey = p256::ecdsa::VerifyingKey;

    fn capabilities(&self) -> VerifierCapabilities {
        verifier_capabilities()
    }
    async fn pre_verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        allow_unsigned: bool,
        include_parser_observations: bool,
    ) -> PreVerifyResponse {
        pre_verify(
            input_bytes,
            form,
            allow_unsigned,
            include_parser_observations,
        )
    }
    async fn verify(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        verify(input_bytes, form, keys, options)
    }
    async fn verify_with_metadata(
        &self,
        input_bytes: &[u8],
        form: ArtifactForm,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
        include_parser_observations: bool,
    ) -> Result<VerifyResult, InvocationError> {
        verify_with_metadata(
            input_bytes,
            form,
            keys,
            options,
            include_parser_observations,
        )
    }
    async fn verify_from_pre_verify(
        &self,
        pre: &PreVerifyResponse,
        keys: &PublicKeys<'_>,
        options: VerifierOptions,
    ) -> Result<VerifierState, InvocationError> {
        verify_from_pre_verify(pre, keys, options)
    }
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
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(maximum).unwrap())
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
            algorithm_parameters: vec![1],
            ..VerifierOptions::default()
        };
        let error = verify_with_resource_limits(
            &[0xff, 0xff],
            ArtifactForm::Proto,
            &no_keys(),
            options,
            &finite(1),
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(error.artifact_form(), Some(ArtifactResourceForm::Protobuf));
        assert_eq!(error.observed_or_projected_artifact_bytes(), Some(2));

        let metadata_error = verify_with_metadata_and_resource_limits(
            &[0xff, 0xff],
            ArtifactForm::Yaml,
            &no_keys(),
            VerifierOptions {
                algorithm_parameters: vec![1],
                ..VerifierOptions::default()
            },
            true,
            &finite(1),
        )
        .unwrap_err();
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
            pre_verify_with_resource_limits(&input, ArtifactForm::Yaml, false, true, &limits,)
                .is_err()
        );
        assert!(pre_verify_yaml_with_resource_limits(&input, false, &limits).is_err());
        assert!(pre_verify_proto_with_resource_limits(&input, &limits).is_err());
        assert!(
            verify_yaml_with_resource_limits(
                &input,
                &no_keys(),
                VerifierOptions::default(),
                &limits,
            )
            .is_err()
        );
        assert!(
            can_pre_verify_with_resource_limits(&input, ArtifactForm::Proto, false, &limits,)
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
            let verify_error = verify_proto_with_resource_limits(
                &input,
                &no_keys(),
                VerifierOptions::default(),
                &limits,
            )
            .unwrap_err();
            let pre_verify_error =
                pre_verify_proto_with_resource_limits(&input, &limits).unwrap_err();
            let can_pre_verify_error =
                can_pre_verify_with_resource_limits(&input, ArtifactForm::Proto, false, &limits)
                    .unwrap_err();

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
    fn bounded_pre_verify_handoff_does_not_recheck_an_encoded_artifact() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let artifact = yaml_sigil_signing::sign_yaml(&yaml_sigil_signing::SignYamlParams {
            payload: b"handoff: true\n",
            algorithm: AlgorithmId::Ed25519,
            key: yaml_sigil_signing::SigningKey::Ed25519(&signing_key),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap();
        let limits = finite(artifact.len());
        let pre = pre_verify_yaml_with_resource_limits(&artifact, false, &limits).unwrap();
        assert_eq!(pre.outcome, PreVerifyOutcome::Ok);

        let verifying_key = signing_key.verifying_key();
        let keys = PublicKeys {
            ed25519: Some(&verifying_key),
            p256: None,
        };
        assert!(matches!(
            verify_from_pre_verify(&pre, &keys, VerifierOptions::default()).unwrap(),
            VerifierState::Verified { .. }
        ));
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
        let direct = verify_yaml(
            payload,
            &PublicKeys {
                ed25519: None,
                p256: None,
            },
            VerifierOptions::default(),
        );
        let via_trait = DefaultVerifier.verify(
            payload,
            ArtifactForm::Yaml,
            &PublicKeys {
                ed25519: None,
                p256: None,
            },
            VerifierOptions::default(),
        );
        assert_eq!(direct, via_trait);
    }

    #[tokio::test]
    async fn default_async_verifier_unsigned_yaml_matches_free_function() {
        let payload = b"a: b\n";
        let direct = verify_yaml(
            payload,
            &PublicKeys {
                ed25519: None,
                p256: None,
            },
            VerifierOptions::default(),
        );
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
        .await;
        assert_eq!(direct, via_async_trait);
        assert_eq!(
            AsyncVerifier::capabilities(&DefaultAsyncVerifier),
            verifier_capabilities()
        );
    }
}
