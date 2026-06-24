// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YamlSigil v1alpha1 verification: five verifier states, invocation errors, Ed25519 + ECDSA P-256 SHA-256.
//!
//! Algorithm slot 0 (`ALGORITHM_UNSPECIFIED`) and unknown wire `alg` values map
//! to [`VerifierState::MalformedAttemptedSigned`]. Slot 1 is
//! `ED25519_PUREEDDSA_RAW_RS64_CANONICAL` (Ed25519 RFC 8032, raw `R || S`); slot
//! 2 is `ECDSA_SECP256R1_SHA256_RAW_RS64` (raw `R || S` 64 octets).

mod crypto;
mod proto_verify;
mod yaml_verify;

use yaml_sigil_core::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
};

// The `Verifier` / `AsyncVerifier` trait pair, the verifier DTOs, and the
// key-resolution helpers now live in `yaml-sigil-traits`; re-exported here so
// existing `yaml_sigil_verification::{Verifier, VerifierState, ...}` paths keep working.
pub use yaml_sigil_traits::verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, InvocationError, PreVerifyOutcome,
    PreVerifyResponse, PublicKeys, UnverifiedSignature, Verifier, VerifierCapabilities,
    VerifierOptions, VerifierState, VerifyResult, resolve_ed25519_verifying_key,
    resolve_p256_verifying_key,
};

/// Returns the capability surface for this build.
pub fn verifier_capabilities() -> VerifierCapabilities {
    let unknown_policies = yaml_sigil_core::yaml_unknown_field_policies();
    // Advertise Permissive unconditionally. The spec requires
    // Strict / SignatureStrict to reject duplicate known singular fields on
    // **both** wire forms; this workspace's protobuf inner-decode path uses
    // the stock buffa decoder, which applies last-wins (Permissive) to
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
#[tracing::instrument(level = "info", skip_all, fields(len = input_bytes.len(), form = ?form))]
pub fn verify(
    input_bytes: &[u8],
    form: ArtifactForm,
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify_with_metadata(input_bytes, form, keys, options, false).map(|r| r.state)
}

/// Verify with optional parser observations (IDL `VerifyRequest.include_parser_observations`).
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

/// Verify a YAML artifact byte sequence.
#[tracing::instrument(level = "info", skip_all, fields(len = artifact.len()))]
pub fn verify_yaml(
    artifact: &[u8],
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify(artifact, ArtifactForm::Yaml, keys, options)
}

/// Verify protobuf `SignedYamlArtifact` wire bytes.
#[tracing::instrument(level = "info", skip_all, fields(len = wire.len()))]
pub fn verify_proto(
    wire: &[u8],
    keys: &PublicKeys<'_>,
    options: VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    verify(wire, ArtifactForm::Proto, keys, options)
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
            // Strict-variant canonical-encoding pre-check (R y-coord < p, S < L).
            // `ed25519-dalek`'s `VerifyingKey::verify` collapses non-canonical
            // rejection and signature-equation failure into one `SignatureError`;
            // wrapping it with the spec's two structural compares preserves the
            // verifier-state distinction (malformed-artifact signal vs.
            // tampering/wrong-key signal). See
            // covered by the noncanonical Ed25519 fixtures.
            if !crypto::ed25519_signature_is_canonical(sig_octets) {
                return Ok(VerifierState::MalformedAttemptedSigned);
            }
            let vk = keys.ed25519.ok_or(InvocationError::KeyResolutionFailure)?;
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
            if crypto::verify_ecdsa_p256_sha256(vk, payload, sig_octets).is_ok() {
                Ok(VerifierState::Verified {
                    payload: payload.to_vec(),
                    algorithm: alg,
                })
            } else {
                Ok(VerifierState::SignedButFailedVerification)
            }
        }
    }
}

/// Structural + metadata pre-verify (IDL `PreVerify`).
pub fn pre_verify(
    input_bytes: &[u8],
    form: ArtifactForm,
    allow_unsigned: bool,
    include_parser_observations: bool,
) -> PreVerifyResponse {
    match form {
        ArtifactForm::Yaml => yaml_verify::pre_verify_yaml(
            input_bytes,
            allow_unsigned,
            include_parser_observations,
            &VerifierOptions::default(),
        ),
        ArtifactForm::Proto => {
            let _ = allow_unsigned;
            proto_verify::pre_verify_proto(input_bytes, include_parser_observations)
        }
    }
}

/// Lightweight structural peek for YAML (no keys, no crypto).
pub fn pre_verify_yaml(artifact: &[u8], allow_unsigned: bool) -> PreVerifyResponse {
    pre_verify(artifact, ArtifactForm::Yaml, allow_unsigned, false)
}

/// Lightweight structural peek for protobuf wire (no keys, no crypto).
pub fn pre_verify_proto(wire: &[u8]) -> PreVerifyResponse {
    pre_verify(wire, ArtifactForm::Proto, false, false)
}

/// Boolean summary of [`pre_verify`] without crypto (IDL `CanPreVerify`).
pub fn can_pre_verify(input_bytes: &[u8], form: ArtifactForm, allow_unsigned: bool) -> bool {
    match pre_verify(input_bytes, form, allow_unsigned, false).outcome {
        PreVerifyOutcome::Ok => true,
        PreVerifyOutcome::Unsigned if allow_unsigned && form == ArtifactForm::Yaml => true,
        _ => false,
    }
}

/// Run only the verification stage using a prior YAML [`PreVerifyResponse`].
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
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultVerifier;

impl Verifier for DefaultVerifier {
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
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAsyncVerifier;

impl AsyncVerifier for DefaultAsyncVerifier {
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
