// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![forbid(unsafe_code)]

pub fn allocator_free_contract() -> bool {
    use yaml_sigil_core::v1alpha1::{ArtifactResourceForm, ArtifactResourceLimits};
    let input = b"document: true\n";
    let checked = ArtifactResourceLimits::default()
        .check_input_size(ArtifactResourceForm::Yaml, input)
        .unwrap();
    #[cfg(feature = "bare")]
    {
        let raw =
            yaml_sigil_core::v1alpha1::p256_der_signature_to_raw(&[0x30, 6, 2, 1, 1, 2, 1, 1])
                .unwrap();
        assert_eq!((raw[31], raw[63]), (1, 1));
    }
    yaml_sigil_core::v1alpha1::validate_payload_stream(checked).is_ok()
        && yaml_sigil_traits::v1alpha1::AlgorithmId::from_i32(1)
            == Some(yaml_sigil_traits::v1alpha1::AlgorithmId::Ed25519)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    use core::num::NonZeroUsize;
    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    use yaml_sigil_core::v1alpha1::{AlgorithmId, ArtifactResourceLimits};
    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    use yaml_sigil_signing::v1alpha1::{OutputForm, SignRequest, SigningKey};
    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    use yaml_sigil_transcription::v1alpha1::{DecomposeRequest, TranscriptionForm};
    use yaml_sigil_verification::v1alpha1::{ArtifactForm, PreVerifyOptions, VerifyError};
    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    use yaml_sigil_verification::v1alpha1::{PublicKeys, VerifierOptions, VerifierState};

    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    fn limit(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(NonZeroUsize::new(maximum).unwrap())
    }

    #[cfg(any(feature = "yaml", feature = "protobuf"))]
    fn round_trip(
        output_form: OutputForm,
        form: ArtifactForm,
        transcription_form: TranscriptionForm,
    ) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let payload = b"portable: true\n";
        let artifact = yaml_sigil_signing::v1alpha1::sign(&SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&signing_key),
            keyid: None,
            append_missing_final_newline: false,
            output_form,
            algorithm_parameters: &[],
            resource_limits: ArtifactResourceLimits::unbounded(),
        })
        .unwrap()
        .artifact;
        let decomposed = {
            let request = DecomposeRequest {
                artifact: &artifact,
                form: transcription_form,
                outer_conformance: if transcription_form == TranscriptionForm::Protobuf {
                    Some(yaml_sigil_traits::OuterConformance::SignatureStrict)
                } else {
                    None
                },
                resource_limits: limit(artifact.len()),
            };
            yaml_sigil_transcription::v1alpha1::decompose(&request).unwrap()
        };
        let recomposed = yaml_sigil_transcription::v1alpha1::compose(
            &yaml_sigil_transcription::v1alpha1::ComposeRequest {
                payload: decomposed.payload.unwrap(),
                signature_carrier: decomposed.signature_carrier.unwrap(),
                form: transcription_form,
                resource_limits: limit(artifact.len()),
            },
        )
        .unwrap();
        assert_eq!(recomposed.artifact, artifact);
        let borrowed_payload = decomposed.payload.unwrap();
        assert_eq!(borrowed_payload, payload);
        let verified = {
            let pre = yaml_sigil_verification::v1alpha1::pre_verify(
                &artifact,
                form,
                PreVerifyOptions::default(),
            )
            .unwrap();
            assert_eq!(pre.source_artifact.as_ptr(), artifact.as_ptr());
            assert_eq!(
                pre.unverified_payload_bytes.unwrap().as_ptr(),
                borrowed_payload.as_ptr()
            );
            let public_key = signing_key.verifying_key();
            let keys = PublicKeys {
                ed25519: Some(&public_key),
                p256: None,
            };
            let rejected = yaml_sigil_verification::v1alpha1::verify_from_pre_verify(
                &pre,
                &keys,
                VerifierOptions {
                    resource_limits: limit(artifact.len() - 1),
                    ..VerifierOptions::default()
                },
            )
            .unwrap_err();
            assert!(matches!(rejected, VerifyError::Resource(_)));
            yaml_sigil_verification::v1alpha1::verify_from_pre_verify(
                &pre,
                &keys,
                VerifierOptions {
                    resource_limits: limit(artifact.len()),
                    ..VerifierOptions::default()
                },
            )
            .unwrap()
        };
        let VerifierState::Verified {
            payload: verified_payload,
            ..
        } = verified.state
        else {
            panic!("expected verification")
        };
        assert_eq!(verified_payload.as_ptr(), borrowed_payload.as_ptr());
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn yaml_operations_borrow_the_artifact() {
        round_trip(
            OutputForm::Yaml,
            ArtifactForm::Yaml,
            TranscriptionForm::Yaml,
        );
    }

    #[cfg(feature = "protobuf")]
    #[test]
    fn protobuf_operations_borrow_the_artifact() {
        round_trip(
            OutputForm::Protobuf,
            ArtifactForm::Proto,
            TranscriptionForm::Protobuf,
        );
    }

    #[test]
    fn capabilities_match_enabled_formats() {
        let capabilities = yaml_sigil_verification::v1alpha1::verifier_capabilities();
        assert_eq!(
            capabilities.supported_forms.contains(&ArtifactForm::Yaml),
            cfg!(feature = "yaml")
        );
        assert_eq!(
            capabilities.supported_forms.contains(&ArtifactForm::Proto),
            cfg!(feature = "protobuf")
        );
        for (form, enabled) in [
            (ArtifactForm::Yaml, cfg!(feature = "yaml")),
            (ArtifactForm::Proto, cfg!(feature = "protobuf")),
        ] {
            if !enabled {
                assert!(matches!(
                    yaml_sigil_verification::v1alpha1::pre_verify(
                        b"invalid",
                        form,
                        PreVerifyOptions::default()
                    ),
                    Err(VerifyError::Invocation(_))
                ));
            }
        }
    }
}

#[cfg(test)]
#[test]
fn allocator_free_types_and_byte_validation_are_available() {
    assert!(allocator_free_contract());
}

#[cfg(all(test, feature = "alloc", any(feature = "yaml", feature = "protobuf")))]
mod entropy_tests {
    use yaml_sigil_core::v1alpha1::{AlgorithmId, ArtifactResourceLimits};
    use yaml_sigil_signing::v1alpha1::{
        OutputForm, SignError, SignRequest, SigningKey, sign, sign_with_rng,
    };
    use yaml_sigil_verification::v1alpha1::{
        ArtifactForm, PublicKeys, VerifierOptions, VerifierState, verify,
    };

    // Scripted entropy exercises the caller boundary. It is not a production RNG.
    struct FixtureRng {
        fail: bool,
        calls: usize,
    }
    impl rand_core::TryRng for FixtureRng {
        type Error = core::fmt::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(core::fmt::Error)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(core::fmt::Error)
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.fail {
                return Err(core::fmt::Error);
            }
            destination.fill(17);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixtureRng {}

    #[test]
    fn p256_uses_fallible_caller_entropy_without_a_system_rng() {
        let key = p256::ecdsa::SigningKey::from_slice(&[23; 32]).unwrap();
        let form = if cfg!(feature = "yaml") {
            OutputForm::Yaml
        } else {
            OutputForm::Protobuf
        };
        let request = SignRequest {
            payload: b"entropy: supplied\n",
            algorithm: AlgorithmId::EcdsaP256Sha256,
            key: SigningKey::EcdsaP256Sha256(&key),
            keyid: None,
            append_missing_final_newline: false,
            output_form: form,
            algorithm_parameters: &[],
            resource_limits: ArtifactResourceLimits::unbounded(),
        };
        assert!(matches!(sign(&request), Err(SignError::Invocation(_))));
        let mut rng = FixtureRng {
            fail: false,
            calls: 0,
        };
        let artifact = sign_with_rng(&request, &mut rng).unwrap().artifact;
        assert_eq!(rng.calls, 1);
        let keys = PublicKeys {
            ed25519: None,
            p256: Some(key.verifying_key()),
        };
        let artifact_form = if form == OutputForm::Yaml {
            ArtifactForm::Yaml
        } else {
            ArtifactForm::Proto
        };
        assert!(matches!(
            verify(&artifact, artifact_form, &keys, VerifierOptions::default())
                .unwrap()
                .state,
            VerifierState::Verified { .. }
        ));
        let mut failed = FixtureRng {
            fail: true,
            calls: 0,
        };
        assert!(matches!(
            sign_with_rng(&request, &mut failed),
            Err(SignError::KeyOperationFailure)
        ));
        assert_eq!(failed.calls, 1);
    }
}
