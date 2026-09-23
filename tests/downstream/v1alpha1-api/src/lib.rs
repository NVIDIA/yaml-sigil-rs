// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Independent consumer of explicit and default paths with one traits contract.

use yaml_sigil_signing::v1alpha1 as signing;

/// Use a versioned implementation through the separately selected trait.
pub fn capabilities(
    signer: &impl yaml_sigil_traits::v1alpha1::signing::Signer,
) -> signing::SignerCapabilities {
    signer.capabilities()
}

#[cfg(test)]
mod tests {
    use super::*;
    use yaml_sigil_core::{self as core, v1alpha1 as contract};
    use yaml_sigil_traits::{self as default_traits, v1alpha1 as traits};
    use yaml_sigil_transcription::{self as default_transcription, v1alpha1 as transcription};
    use yaml_sigil_verification::{self as default_verification, v1alpha1 as verification};

    type SigningKey = <signing::DefaultSigner as traits::signing::Signer>::Ed25519SigningKey;

    #[test]
    fn signing_and_verification_share_requests_keys_and_the_selected_traits() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key();
        let keys: default_verification::PublicKeys<'_> = verification::PublicKeys {
            ed25519: Some(&public),
            p256: None,
        };
        assert_eq!(
            capabilities(&signing::DefaultSigner),
            yaml_sigil_signing::signer_capabilities()
        );

        for (output_form, form) in [
            (signing::OutputForm::Yaml, verification::ArtifactForm::Yaml),
            (
                signing::OutputForm::Protobuf,
                verification::ArtifactForm::Proto,
            ),
        ] {
            let request: yaml_sigil_signing::SignRequest<'_> = signing::SignRequest {
                payload: b"namespace: v1alpha1\n",
                algorithm: contract::AlgorithmId::Ed25519,
                key: signing::SigningKey::Ed25519(&key),
                keyid: None,
                append_missing_final_newline: false,
                output_form,
                algorithm_parameters: &[],
            };
            let signing::SignOutcome::Success(explicit) =
                signing::Signer::sign(&yaml_sigil_signing::DefaultSigner, &request)
            else {
                panic!("versioned signing failed");
            };
            let default_traits::signing::SignOutcome::Success(default) =
                traits::signing::Signer::sign(&signing::DefaultSigner, &request)
            else {
                panic!("selected trait signing failed");
            };
            assert_eq!(explicit.artifact, default.artifact);

            let options: verification::VerifierOptions =
                default_verification::VerifierOptions::default();
            assert_eq!(
                default_verification::verify(&explicit.artifact, form, &keys, options.clone())
                    .unwrap(),
                verification::VerifierState::Verified {
                    payload: request.payload.to_vec(),
                    algorithm: contract::AlgorithmId::Ed25519,
                }
            );
            assert_eq!(
                traits::verification::Verifier::verify(
                    &verification::DefaultVerifier,
                    &default.artifact,
                    form,
                    &keys,
                    options.clone(),
                )
                .unwrap(),
                traits::verification::VerifierState::Verified {
                    payload: request.payload.to_vec(),
                    algorithm: contract::AlgorithmId::Ed25519,
                }
            );

            let limits: verification::ArtifactResourceLimits =
                signing::ArtifactResourceLimits::default();
            let _: &core::ArtifactResourceLimits = &limits;
            assert_eq!(
                verification::verify_with_resource_limits(
                    &explicit.artifact,
                    form,
                    &keys,
                    options,
                    &limits,
                )
                .unwrap()
                .unwrap(),
                default_verification::VerifierState::Verified {
                    payload: request.payload.to_vec(),
                    algorithm: contract::AlgorithmId::Ed25519,
                }
            );
        }
    }

    #[test]
    fn transcription_accepts_cross_path_requests_and_trait_objects() {
        let transcriber: &dyn traits::transcription::Transcriber =
            &transcription::DefaultTranscriber;
        let transcriber: &dyn default_traits::transcription::Transcriber = transcriber;
        for (form, outer_conformance) in [
            (transcription::TranscriptionForm::Yaml, None),
            (
                transcription::TranscriptionForm::Protobuf,
                Some(core::OuterConformance::Strict),
            ),
        ] {
            let request = transcription::ComposeRequest {
                payload: b"namespace: shared\n",
                signature_carrier: b"opaque carrier\n",
                form,
            };
            let default_transcription::ComposeOutcome::Success(composed) =
                transcriber.compose(&request)
            else {
                panic!("compose failed");
            };
            let request = default_transcription::DecomposeRequest {
                artifact: &composed.artifact,
                form,
                outer_conformance,
            };
            let traits::transcription::DecomposeResponse::Structural(split) =
                transcription::decompose(&request)
            else {
                panic!("decompose failed");
            };
            assert_eq!(split.outcome, transcription::DecomposeOutcome::Ok);
            assert_eq!(
                split.payload.as_deref(),
                Some(b"namespace: shared\n".as_slice())
            );
            assert_eq!(
                split.signature_carrier.as_deref(),
                Some(b"opaque carrier\n".as_slice())
            );
        }
    }

    #[test]
    fn core_facades_share_owned_and_borrowed_values() {
        let algorithm: default_traits::AlgorithmId = traits::AlgorithmId::Ed25519;
        let signature: core::pb::YamlSigilSignature =
            contract::pb::YamlSigilSignature::new(algorithm, vec![1, 2, 3]);
        let artifact: contract::pb::SignedYamlArtifact =
            core::pb::SignedYamlArtifact::new(b"shared\n".to_vec(), Some(signature));
        let wire = artifact.encode_to_vec().unwrap();
        assert_eq!(
            contract::pb::SignedYamlArtifact::decode(&wire).unwrap(),
            artifact
        );
        let borrowed: core::pb::SignedYamlArtifactRef<'_> =
            contract::pb::SignedYamlArtifactRef::decode(&wire).unwrap();
        assert_eq!(borrowed.payload(), b"shared\n");

        let document: core::SignatureDocument = contract::SignatureDocument {
            schema: contract::SCHEMA_V1ALPHA1.into(),
            alg: traits::AlgorithmId::Ed25519.as_yaml_str().into(),
            keyid: None,
            signature: "A".repeat(86),
        };
        let yaml = contract::serialize_signature_document(&document).unwrap();
        let parsed: contract::SignatureDocument =
            core::parse_signature_document(yaml.as_bytes()).unwrap();
        assert_eq!(parsed, document);
        #[cfg(feature = "json-schema-validate")]
        contract::signature_document_validates_tier_a_schema(&parsed).unwrap();
    }

    #[test]
    fn provider_aliases_share_the_existing_key_bound_contract() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let public = key.verifying_key();
        let provider_key: yaml_sigil_signing::provider::ProviderSigningKey =
            signing::provider::ProviderSigningKeyBuilder::ed25519(public.as_bytes())
                .build()
                .unwrap();
        let request: signing::ProviderSignRequest<'_> = yaml_sigil_signing::ProviderSignRequest {
            payload: b"provider: shared\n",
            algorithm: contract::AlgorithmId::Ed25519,
            key: signing::ProviderSigningKeys::Ed25519(&provider_key),
            keyid: None,
            append_missing_final_newline: false,
            output_form: signing::OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let traits::signing::SignOutcome::Success(signed) =
            signing::sign_with_provider(&request, |payload| {
                let signature: ed25519_dalek::Signature =
                    ed25519_dalek::Signer::try_sign(&key, payload)
                        .map_err(|_| signing::SignError::KeyOperationFailure)?;
                Ok(signature.to_bytes())
            })
        else {
            panic!("provider signing failed");
        };
        assert_eq!(
            verification::verify_yaml(
                &signed.artifact,
                &default_verification::PublicKeys {
                    ed25519: Some(&public),
                    p256: None
                },
                verification::VerifierOptions::default(),
            )
            .unwrap(),
            verification::VerifierState::Verified {
                payload: request.payload.to_vec(),
                algorithm: contract::AlgorithmId::Ed25519,
            }
        );
    }
}
