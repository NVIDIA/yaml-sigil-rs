// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Branch coverage for the generic YAML signature conformance suite.

use yaml_sigil_conformance::yaml_signature::{
    run_yaml_signature_suite, run_yaml_signature_suite_async,
};
use yaml_sigil_core::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};
use yaml_sigil_verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, PreVerifyOptions, PreVerifyOutcome,
    PreVerifyResponse, PublicKeys, Verifier, VerifierCapabilities, VerifierOptions, VerifierState,
    VerifyError, VerifyResult,
};

#[derive(Clone, Copy)]
struct FakeVerifier {
    profile: AdvertisedConformanceProfile,
}

fn capabilities(profile: AdvertisedConformanceProfile) -> VerifierCapabilities {
    VerifierCapabilities {
        conformance_profile: profile,
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policies: &[
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        ],
        supported_forms: &[ArtifactForm::Yaml],
        supported_algorithms: &[AlgorithmId::Ed25519],
        supports_can_pre_verify: true,
        supports_pre_verify: true,
        implementation_name: "yaml-signature-suite-test",
        implementation_version: "0.0.0",
    }
}

fn state_for_fixture(input_bytes: &[u8]) -> VerifierState<'_> {
    let text = std::str::from_utf8(input_bytes).expect("YAML signature fixtures are UTF-8");
    let schema_identity_failure = !text.contains("\nschema: YamlSigilSignature.v1alpha1\n");
    let duplicate_known_key = ["schema", "alg", "keyid", "signature"]
        .iter()
        .any(|key| text.matches(&format!("\n{key}:")).count() > 1);
    let oversized_carrier = input_bytes
        .windows(5)
        .rposition(|window| window == b"\n---\n")
        .is_some_and(|marker| input_bytes.len() - (marker + 5) > 16 * 1024);
    let multiple_documents = text.contains("\n...\n--- # second YAML document\n");
    let non_string_declared_field = [
        "\nschema: !!int ",
        "\nalg: !!bool ",
        "\nkeyid: !!int ",
        "\nsignature: !!int ",
    ]
    .iter()
    .any(|spelling| text.contains(spelling));
    if schema_identity_failure
        || duplicate_known_key
        || oversized_carrier
        || multiple_documents
        || non_string_declared_field
        || text.contains("\nbogus:")
    {
        VerifierState::MalformedAttemptedSigned
    } else {
        VerifierState::SignedButFailedVerification
    }
}

fn pre_verify_response(input_bytes: &[u8], form: ArtifactForm) -> PreVerifyResponse<'_> {
    let outcome = if state_for_fixture(input_bytes) == VerifierState::MalformedAttemptedSigned {
        PreVerifyOutcome::MetadataParseFailure
    } else {
        PreVerifyOutcome::Ok
    };
    PreVerifyResponse {
        source_artifact: input_bytes,

        outcome,
        form,
        unverified_payload_bytes: None,
        unverified_signature: None,
        parser_observations: Vec::new(),
    }
}

impl Verifier for FakeVerifier {
    type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
    type P256VerifyingKey = p256::ecdsa::VerifyingKey;
    fn capabilities(&self) -> VerifierCapabilities {
        capabilities(self.profile)
    }
    fn pre_verify<'input>(
        &self,
        input: &'input [u8],
        form: ArtifactForm,
        _options: PreVerifyOptions,
    ) -> Result<PreVerifyResponse<'input>, VerifyError> {
        Ok(pre_verify_response(input, form))
    }
    fn verify<'input>(
        &self,
        input: &'input [u8],
        _form: ArtifactForm,
        _keys: &PublicKeys<'_>,
        _options: VerifierOptions<'_>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        Ok(VerifyResult {
            state: state_for_fixture(input),
            parser_observations: Vec::new(),
        })
    }
    fn verify_from_pre_verify<'input>(
        &self,
        _pre: &PreVerifyResponse<'input>,
        _keys: &PublicKeys<'_>,
        _options: VerifierOptions<'_>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        Ok(VerifyResult {
            state: VerifierState::SignedButFailedVerification,
            parser_observations: Vec::new(),
        })
    }
}

impl AsyncVerifier for FakeVerifier {
    type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
    type P256VerifyingKey = p256::ecdsa::VerifyingKey;
    fn capabilities(&self) -> VerifierCapabilities {
        capabilities(self.profile)
    }
    async fn pre_verify<'call, 'input: 'call>(
        &'call self,
        input: &'input [u8],
        form: ArtifactForm,
        _options: PreVerifyOptions,
    ) -> Result<PreVerifyResponse<'input>, VerifyError> {
        Ok(pre_verify_response(input, form))
    }
    async fn verify<'call, 'input: 'call>(
        &'call self,
        input: &'input [u8],
        _form: ArtifactForm,
        _keys: &'call PublicKeys<'_>,
        _options: VerifierOptions<'call>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        Ok(VerifyResult {
            state: state_for_fixture(input),
            parser_observations: Vec::new(),
        })
    }
    async fn verify_from_pre_verify<'call, 'input: 'call>(
        &'call self,
        _pre: &'call PreVerifyResponse<'input>,
        _keys: &'call PublicKeys<'_>,
        _options: VerifierOptions<'call>,
    ) -> Result<VerifyResult<'input>, VerifyError> {
        Ok(VerifyResult {
            state: VerifierState::SignedButFailedVerification,
            parser_observations: Vec::new(),
        })
    }
}

#[test]
fn suite_covers_strict_profile_branch() {
    run_yaml_signature_suite(&FakeVerifier {
        profile: AdvertisedConformanceProfile::Strict,
    });
}

#[test]
fn suite_covers_signature_strict_profile_branch() {
    run_yaml_signature_suite(&FakeVerifier {
        profile: AdvertisedConformanceProfile::SignatureStrict,
    });
}

#[test]
fn suite_covers_permissive_profile_branch() {
    run_yaml_signature_suite(&FakeVerifier {
        profile: AdvertisedConformanceProfile::Permissive,
    });
}

#[tokio::test]
async fn async_suite_covers_strict_profile_branch() {
    run_yaml_signature_suite_async(&FakeVerifier {
        profile: AdvertisedConformanceProfile::Strict,
    })
    .await;
}

#[tokio::test]
async fn async_suite_covers_signature_strict_profile_branch() {
    run_yaml_signature_suite_async(&FakeVerifier {
        profile: AdvertisedConformanceProfile::SignatureStrict,
    })
    .await;
}

#[tokio::test]
async fn async_suite_covers_permissive_profile_branch() {
    run_yaml_signature_suite_async(&FakeVerifier {
        profile: AdvertisedConformanceProfile::Permissive,
    })
    .await;
}
