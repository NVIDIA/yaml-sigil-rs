// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for verifier states, pre-verify, and crypto branches.

use ed25519_dalek::SigningKey as EdSigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::Generate;
use rand::rngs::SysRng;
use yaml_sigil_core::{
    AlgorithmId, CoreError, DecompositionOutcome, ProtobufWireDecodeAdvertisement,
    YamlSignatureDocumentDuplicateKeyPolicy, YamlSignatureDocumentUnknownFieldPolicy,
    decode_signed_yaml_artifact, decompose_artifact, view_signed_yaml_artifact,
};
use yaml_sigil_signing::{
    SignRequest, SigningKey, TranscodeError, sign, signed_yaml_stream_to_proto_wire,
};
use yaml_sigil_verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, DefaultAsyncVerifier,
    InvocationError, PreVerifyOutcome, PreVerifyResponse, PublicKeys, UnverifiedSignature,
    VerifierOptions, VerifierState, can_pre_verify, pre_verify, resolve_ed25519_verifying_key,
    verifier_capabilities, verify, verify_from_pre_verify,
};

const SIGNATURE_CARRIER_MAX_BYTES: usize = 16 * 1024;

fn ed25519_pair() -> (EdSigningKey, ed25519_dalek::VerifyingKey) {
    let sk = EdSigningKey::from_bytes(&[11u8; 32]);
    let vk = ed25519_dalek::VerifyingKey::from(&sk);
    (sk, vk)
}

fn p256_pair() -> (P256SigningKey, p256::ecdsa::VerifyingKey) {
    let sk = P256SigningKey::try_generate_from_rng(&mut SysRng).expect("generate key");
    let vk = *sk.verifying_key();
    (sk, vk)
}

fn append_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn append_len_delimited_field(out: &mut Vec<u8>, field_number: u64, value: &[u8]) {
    append_varint(out, (field_number << 3) | 2);
    append_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn quote_signature_with_whitespace(artifact: &[u8], leading: &str, trailing: &str) -> Vec<u8> {
    let text = std::str::from_utf8(artifact).expect("signer emits UTF-8 YAML");
    let marker = "signature: ";
    let value_start = text.rfind(marker).expect("signature field") + marker.len();
    let value_end = value_start
        + text[value_start..]
            .find('\n')
            .expect("signature line terminator");
    let mut mutated = String::with_capacity(text.len() + leading.len() + trailing.len() + 2);
    mutated.push_str(&text[..value_start]);
    mutated.push('"');
    mutated.push_str(leading);
    mutated.push_str(&text[value_start..value_end]);
    mutated.push_str(trailing);
    mutated.push('"');
    mutated.push_str(&text[value_end..]);
    mutated.into_bytes()
}

fn strict_verifier_options() -> VerifierOptions<'static> {
    VerifierOptions {
        reject_unknown_signature_document_fields: true,
        ..VerifierOptions::default()
    }
}

fn signed_yaml_for_metadata_budget_tests() -> Vec<u8> {
    let (sk, _) = ed25519_pair();
    sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"metadata-budget: test\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap()
}

fn yaml_with_oversized_signature_carrier() -> Vec<u8> {
    let mut artifact = signed_yaml_for_metadata_budget_tests();
    artifact.push(b'#');
    artifact.extend(std::iter::repeat_n(b'x', SIGNATURE_CARRIER_MAX_BYTES));
    artifact.push(b'\n');
    artifact
}

fn yaml_with_too_many_signature_fields() -> Vec<u8> {
    let mut artifact = signed_yaml_for_metadata_budget_tests();
    for index in 0..9 {
        artifact.extend_from_slice(format!("extra_{index}: value\n").as_bytes());
    }
    artifact
}

fn yaml_with_signature_carrier_length(artifact: &[u8], target_len: usize) -> Vec<u8> {
    let DecompositionOutcome::Signed(ranges) = decompose_artifact(
        artifact,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .expect("unbounded artifact policy") else {
        panic!("expected signed YAML artifact");
    };
    let carrier_len = ranges.signature_carrier.len();
    assert!(carrier_len + 2 <= target_len);

    let mut padded = artifact.to_vec();
    padded.push(b'#');
    padded.extend(std::iter::repeat_n(b'x', target_len - carrier_len - 2));
    padded.push(b'\n');

    let DecompositionOutcome::Signed(ranges) = decompose_artifact(
        &padded,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .expect("unbounded artifact policy") else {
        panic!("expected padded signed YAML artifact");
    };
    assert_eq!(ranges.signature_carrier.len(), target_len);
    padded
}

#[test]
fn verify_yaml_ed25519_sign_then_verify_and_display() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: Some("kid"),
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let st = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st.to_string(), "Verified");
    let VerifierState::Verified { payload, algorithm } = st else {
        panic!("expected Verified");
    };
    assert_eq!(payload, b"k: v\n");
    assert_eq!(algorithm, AlgorithmId::Ed25519);
}

#[test]
fn verify_yaml_ecdsa_sign_then_verify() {
    let (sk, vk) = p256_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"x: y\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let keys = PublicKeys {
        ed25519: None,
        p256: Some(&vk),
    };
    let st = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert!(matches!(
        st,
        VerifierState::Verified {
            algorithm: AlgorithmId::EcdsaP256Sha256,
            ..
        }
    ));
}

#[test]
fn verify_proto_ed25519_and_ecdsa() {
    let (sk_ed, vk_ed) = ed25519_pair();
    let wire_ed = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"a: b\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk_ed),
        keyid: Some("k"),
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let st = verify(
        &wire_ed,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &PublicKeys {
            ed25519: Some(&vk_ed),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));

    let (sk_p, vk_p) = p256_pair();
    let wire_p = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"z: 9\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk_p),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let st = verify(
        &wire_p,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &PublicKeys {
            ed25519: None,
            p256: Some(&vk_p),
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}

#[test]
fn verify_proto_malformed_wire() {
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let st = verify(
        b"\xffnot-protobuf",
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &keys,
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_proto_rejects_out_of_range_field_alias() {
    let (sk, vk) = ed25519_pair();
    let mut wire = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"authorized: true\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    append_len_delimited_field(&mut wire, (1_u64 << 29) + 1, b"authorized: false\n");

    let state = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_malformed_unsigned_disallowed() {
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let st = verify(
        b"unsigned: only\n",
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
    assert_eq!(st.to_string(), "MalformedAttemptedSigned");
}

#[test]
fn strict_verify_rejects_oversized_carrier_before_key_resolution() {
    let artifact = yaml_with_oversized_signature_carrier();
    assert_eq!(
        pre_verify(
            &artifact,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            yaml_sigil_traits::verification::PreVerifyOptions {
                allow_unsigned: false,
                include_parser_observations: false,
                resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded()
            }
        )
        .unwrap()
        .outcome,
        PreVerifyOutcome::MetadataParseFailure
    );

    let state = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: None,
            p256: None,
        },
        strict_verifier_options(),
    )
    .map(|result| result.state)
    .expect("metadata failure must not reach key resolution");
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn strict_verify_rejects_excess_mapping_keys_before_key_resolution() {
    let artifact = yaml_with_too_many_signature_fields();
    assert_eq!(
        pre_verify(
            &artifact,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            yaml_sigil_traits::verification::PreVerifyOptions {
                allow_unsigned: false,
                include_parser_observations: false,
                resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded()
            }
        )
        .unwrap()
        .outcome,
        PreVerifyOutcome::MetadataParseFailure
    );

    let state = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: None,
            p256: None,
        },
        strict_verifier_options(),
    )
    .map(|result| result.state)
    .expect("metadata failure must not reach key resolution");
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[tokio::test]
async fn async_strict_verify_matches_sync_for_metadata_budget_failures() {
    let artifacts = [
        yaml_with_oversized_signature_carrier(),
        yaml_with_too_many_signature_fields(),
    ];
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };

    for artifact in artifacts {
        let sync = verify(
            &artifact,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            &keys,
            strict_verifier_options(),
        )
        .map(|result| result.state);
        let asynchronous = AsyncVerifier::verify(
            &DefaultAsyncVerifier,
            &artifact,
            ArtifactForm::Yaml,
            &keys,
            strict_verifier_options(),
        )
        .await
        .map(|result| result.state);
        assert_eq!(asynchronous, sync);
        assert_eq!(sync.unwrap(), VerifierState::MalformedAttemptedSigned);
    }
}

#[test]
fn yaml_to_proto_uses_markerless_carrier_byte_limit() {
    const PAYLOAD: &[u8] = b"carrier-boundary: test\n";
    let (sk, vk) = ed25519_pair();
    let baseline = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: PAYLOAD,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: Some("carrier-boundary"),
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let expected_wire = signed_yaml_stream_to_proto_wire(
        &baseline,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .unwrap();
    let expected_artifact = decode_signed_yaml_artifact(
        &expected_wire,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .unwrap();
    let expected = view_signed_yaml_artifact(&expected_artifact).unwrap();

    assert_eq!(expected.payload, PAYLOAD);
    assert_eq!(expected.alg_wire, 1);
    assert_eq!(expected.signature.len(), 64);
    assert_eq!(expected.keyid.as_deref(), Some("carrier-boundary"));

    for carrier_len in [16_380, 16_381, SIGNATURE_CARRIER_MAX_BYTES] {
        let artifact = yaml_with_signature_carrier_length(&baseline, carrier_len);
        assert_eq!(
            verify(
                &artifact,
                yaml_sigil_traits::verification::ArtifactForm::Yaml,
                &keys,
                strict_verifier_options()
            )
            .map(|result| result.state)
            .unwrap(),
            VerifierState::Verified {
                payload: PAYLOAD,
                algorithm: AlgorithmId::Ed25519,
            }
        );

        let wire = signed_yaml_stream_to_proto_wire(
            &artifact,
            &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        )
        .unwrap();
        let decoded = decode_signed_yaml_artifact(
            &wire,
            &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        )
        .unwrap();
        let actual = view_signed_yaml_artifact(&decoded).unwrap();
        assert_eq!(actual.payload, expected.payload);
        assert_eq!(actual.alg_wire, expected.alg_wire);
        assert_eq!(actual.signature, expected.signature);
        assert_eq!(actual.keyid, expected.keyid);
    }

    let oversized = yaml_with_signature_carrier_length(&baseline, SIGNATURE_CARRIER_MAX_BYTES + 1);
    assert_eq!(
        verify(
            &oversized,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            &keys,
            strict_verifier_options()
        )
        .map(|result| result.state)
        .unwrap(),
        VerifierState::MalformedAttemptedSigned
    );
    assert!(matches!(
        signed_yaml_stream_to_proto_wire(
            &oversized,
            &yaml_sigil_core::ArtifactResourceLimits::unbounded()
        ),
        Err(TranscodeError::Core(CoreError::SignatureYaml(_)))
    ));
}

#[test]
fn verify_yaml_rejects_noncanonical_algorithm_whitespace() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let text = String::from_utf8(artifact).unwrap();
    let noncanonical = text.replace(
        "alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
        "alg: \" ED25519_PUREEDDSA_RAW_RS64_CANONICAL\"",
    );
    let state = verify(
        noncanonical.as_bytes(),
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_rejects_signature_whitespace() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();

    for (leading, trailing) in [(" ", ""), ("", " "), (" ", " ")] {
        let mutated = quote_signature_with_whitespace(&artifact, leading, trailing);
        let state = verify(
            &mutated,
            yaml_sigil_traits::verification::ArtifactForm::Yaml,
            &PublicKeys {
                ed25519: Some(&vk),
                p256: None,
            },
            VerifierOptions::default(),
        )
        .map(|result| result.state)
        .unwrap();
        assert_eq!(state, VerifierState::MalformedAttemptedSigned);
    }
}

#[test]
fn pre_verify_unsigned_allow_unsigned() {
    let pre = pre_verify(
        b"u: 1\n",
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        yaml_sigil_traits::verification::PreVerifyOptions {
            allow_unsigned: true,
            include_parser_observations: false,
            resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        },
    )
    .unwrap();
    assert_eq!(pre.outcome, PreVerifyOutcome::Unsigned);
    assert!(pre.unverified_signature.is_none());
}

#[test]
fn verify_ed25519_wrong_key_fails() {
    let (sk, _vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"p: q\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let other = EdSigningKey::from_bytes(&[3u8; 32]);
    let wrong_vk = ed25519_dalek::VerifyingKey::from(&other);
    let st = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: Some(&wrong_vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::SignedButFailedVerification);
    assert_eq!(st.to_string(), "SignedButFailedVerification");
}

#[test]
fn verify_ed25519_rejects_direct_weak_public_key() {
    use yaml_sigil_core::encode_signed_yaml_artifact;
    use yaml_sigil_core::pb::{SignedYamlArtifact, YamlSigilSignature};

    // The identity point is a valid typed dalek key but is small-order. Pairing
    // it with identity R and zero S satisfies dalek's ordinary verification
    // equation for arbitrary payloads unless the key is rejected first.
    let mut identity_encoding = [0u8; 32];
    identity_encoding[0] = 1;
    let weak_vk = ed25519_dalek::VerifyingKey::from_bytes(&identity_encoding)
        .expect("identity point is a valid encoded point");
    assert!(weak_vk.is_weak());

    let mut forged_signature = vec![0u8; 64];
    forged_signature[0] = 1;
    let inner = YamlSigilSignature::new(AlgorithmId::Ed25519, forged_signature);
    let outer = SignedYamlArtifact::new(b"attacker: chosen\n".to_vec(), Some(inner));
    let wire = encode_signed_yaml_artifact(
        &outer,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .unwrap();

    let error = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &PublicKeys {
            ed25519: Some(&weak_vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .expect_err("small-order keys must fail at key resolution");
    assert_eq!(
        error,
        yaml_sigil_traits::verification::VerifyError::Invocation(
            InvocationError::KeyResolutionFailure
        )
    );
}

// The public resolver must enforce canonical encoding in addition to the
// underlying key constructor's acceptance rules.
#[test]
fn ed25519_resolver_rejects_noncanonical_compressed_key() {
    let mut noncanonical = [0xFF; 32];
    noncanonical[0] = 0xF0;
    noncanonical[31] = 0x7F;

    let typed = ed25519_dalek::VerifyingKey::from_bytes(&noncanonical)
        .expect("typed key construction for point-of-use check");
    assert!(!typed.is_weak());
    assert_eq!(
        resolve_ed25519_verifying_key(&noncanonical),
        Err(InvocationError::KeyResolutionFailure)
    );
}

// The public byte-oriented API reports all non-32-byte inputs as key
// resolution failures without partial parsing.
#[test]
fn ed25519_resolver_rejects_wrong_key_lengths() {
    let short = [0u8; 31];
    let long = [0u8; 33];

    for bytes in [short.as_slice(), long.as_slice()] {
        assert_eq!(
            resolve_ed25519_verifying_key(bytes),
            Err(InvocationError::KeyResolutionFailure)
        );
    }
}

#[test]
fn verify_ed25519_algorithm_disabled() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"p: q\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let opts = VerifierOptions {
        verify_ed25519: false,
        verify_ecdsa_p256_sha256: true,
        ..VerifierOptions::default()
    };
    let st = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        opts,
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(
        st,
        VerifierState::SignedButAlgorithmUnsupported {
            algorithm: AlgorithmId::Ed25519
        }
    );
    assert_eq!(st.to_string(), "SignedButAlgorithmUnsupported");
}

#[test]
fn verify_ecdsa_algorithm_disabled() {
    let (sk, vk) = p256_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"p: q\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let opts = VerifierOptions {
        verify_ed25519: true,
        verify_ecdsa_p256_sha256: false,
        ..VerifierOptions::default()
    };
    let st = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: None,
            p256: Some(&vk),
        },
        opts,
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(
        st,
        VerifierState::SignedButAlgorithmUnsupported {
            algorithm: AlgorithmId::EcdsaP256Sha256
        }
    );
}

#[test]
fn verify_ed25519_missing_public_key_errors() {
    let (sk, _) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"p: q\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let err = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: None,
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap_err();
    assert_eq!(
        err,
        yaml_sigil_traits::verification::VerifyError::Invocation(
            InvocationError::KeyResolutionFailure
        )
    );
    assert!(err.to_string().contains("key material"));
}

#[test]
fn verify_from_pre_verify_rejects_invalid_pre() {
    let pre = PreVerifyResponse {
        source_artifact: &[],

        outcome: PreVerifyOutcome::StructuralFailure,
        form: ArtifactForm::Yaml,
        unverified_payload_bytes: None,
        unverified_signature: None,
        parser_observations: Vec::new(),
    };
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let err = verify_from_pre_verify(&pre, &keys, VerifierOptions::default())
        .map(|result| result.state)
        .unwrap_err();
    assert_eq!(
        err,
        yaml_sigil_traits::verification::VerifyError::Invocation(
            InvocationError::InvalidPreVerifyResult
        )
    );
}

#[test]
fn verify_from_pre_verify_uses_the_recorded_artifact_form() {
    let pre = PreVerifyResponse {
        source_artifact: &[],

        outcome: PreVerifyOutcome::Ok,
        form: ArtifactForm::Proto,
        unverified_payload_bytes: Some(b"x\n"),
        unverified_signature: Some(UnverifiedSignature {
            algorithm: AlgorithmId::Ed25519,
            keyid: None,
            signature_octets: vec![1, 2, 3],
        }),
        parser_observations: Vec::new(),
    };
    let (sk, vk) = ed25519_pair();
    let _ = sk;
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let state = verify_from_pre_verify(&pre, &keys, VerifierOptions::default())
        .map(|result| result.state)
        .unwrap();
    // The primary handoff selects its form from the pre-response. This
    // protobuf attempt reaches signature structure checks, not a YAML-only API.
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_bad_schema_is_malformed() {
    let artifact = b"root: ok\n---\nschema: Wrong\n\
                     alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: Zm9v\n";
    let (_, vk) = ed25519_pair();
    let st = verify(
        artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_unknown_alg_is_malformed() {
    let artifact =
        b"r: 1\n---\nschema: YamlSigilSignature.v1alpha1\nalg: NOT_AN_ALG\nsignature: Zm9v\n";
    let (_, vk) = ed25519_pair();
    let st = verify(
        artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_proto_accepts_non_yaml_fit_payload() {
    use yaml_sigil_core::encode_signed_yaml_artifact;
    use yaml_sigil_core::pb::{SignedYamlArtifact, YamlSigilSignature};

    // The protobuf form imposes no UTF-8 / BOM / line-terminator rule on the
    // payload. An artifact whose payload would never be YAML-fit (here, a
    // BOM-prefixed stream) must reach the crypto stage rather than failing
    // structurally. The placeholder all-zero signature still won't verify,
    // so the outcome is `SignedButFailedVerification`. See
    // docs/conformance-validation.md §3f and §5.r (§5b resolved).
    let inner = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![0u8; 64]);
    let outer = SignedYamlArtifact::new(vec![0xEF, 0xBB, 0xBF, b'h', b'i', b'\n'], Some(inner));
    let wire = encode_signed_yaml_artifact(
        &outer,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .unwrap();
    let (_, vk) = ed25519_pair();
    let st = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::SignedButFailedVerification);
}

#[test]
fn verify_proto_unspecified_alg_wire() {
    use yaml_sigil_core::encode_signed_yaml_artifact;
    use yaml_sigil_core::pb::{SignedYamlArtifact, YamlSigilSignature};

    let mut inner = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
    inner.set_algorithm_wire_value(0);
    let outer = SignedYamlArtifact::new(b"ok\n".to_vec(), Some(inner));
    let wire = encode_signed_yaml_artifact(
        &outer,
        &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
    )
    .unwrap();
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let st = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &keys,
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_from_pre_verify_yaml_happy_path() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"path: test\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let pre = pre_verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        yaml_sigil_traits::verification::PreVerifyOptions {
            allow_unsigned: false,
            include_parser_observations: false,
            resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        },
    )
    .unwrap();
    assert_eq!(pre.outcome, PreVerifyOutcome::Ok);
    let st = verify_from_pre_verify(
        &pre,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}

#[test]
fn verify_proto_ecdsa_missing_p256_key_errors() {
    let (sk, _) = p256_pair();
    let wire = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"p: q\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let (sk_ed, vk_ed) = ed25519_pair();
    let _ = sk_ed;
    let err = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &PublicKeys {
            ed25519: Some(&vk_ed),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .map(|result| result.state)
    .unwrap_err();
    assert_eq!(
        err,
        yaml_sigil_traits::verification::VerifyError::Invocation(
            InvocationError::KeyResolutionFailure
        )
    );
}

#[test]
fn verifier_capabilities_surface() {
    let c = verifier_capabilities();
    assert!(c.supports_can_pre_verify);
    assert!(c.supports_pre_verify);
    // `DefaultVerifier` advertises Permissive unconditionally. The spec requires
    // Strict / SignatureStrict to reject duplicate known singular fields on
    // both wire forms; the private protobuf decoder applies last-wins behavior
    // to duplicate scalars, so Strict would be non-conforming. See
    // docs/conformance-validation.md.
    assert_eq!(
        c.conformance_profile,
        AdvertisedConformanceProfile::Permissive
    );
    assert_eq!(
        c.protobuf_wire_decode,
        ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder
    );
    assert_eq!(
        c.yaml_signature_duplicate_key_policy,
        YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse
    );
    assert_eq!(
        c.yaml_signature_unknown_field_policy,
        YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse
    );
    assert!(c.supported_forms.contains(&ArtifactForm::Yaml));
    assert!(c.supported_forms.contains(&ArtifactForm::Proto));
}

#[test]
fn unified_verify_matches_per_form_helpers() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Yaml,
        algorithm_parameters: &[],
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let opt = VerifierOptions::default();
    let st_yaml = verify(
        &artifact,
        yaml_sigil_traits::verification::ArtifactForm::Yaml,
        &keys,
        opt.clone(),
    )
    .map(|result| result.state)
    .unwrap();
    let st_unified = verify(&artifact, ArtifactForm::Yaml, &keys, opt.clone())
        .map(|result| result.state)
        .unwrap();
    assert_eq!(st_yaml, st_unified);

    let wire = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let st_proto = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &keys,
        opt.clone(),
    )
    .map(|result| result.state)
    .unwrap();
    let st_u2 = verify(&wire, ArtifactForm::Proto, &keys, opt)
        .map(|result| result.state)
        .unwrap();
    assert_eq!(st_proto, st_u2);
}

#[test]
fn artifact_form_try_from_idl_discriminants() {
    assert_eq!(ArtifactForm::try_from(1).unwrap(), ArtifactForm::Yaml);
    assert_eq!(ArtifactForm::try_from(2).unwrap(), ArtifactForm::Proto);
    assert_eq!(
        ArtifactForm::try_from(0).unwrap_err(),
        InvocationError::InvalidOrUnsupportedForm
    );
}

#[test]
fn can_pre_verify_yaml_unsigned_respects_allow_unsigned() {
    assert!(
        !can_pre_verify(
            b"a: 1\n",
            ArtifactForm::Yaml,
            yaml_sigil_traits::verification::PreVerifyOptions {
                allow_unsigned: false,
                include_parser_observations: false,
                resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded()
            }
        )
        .unwrap()
    );
    assert!(
        can_pre_verify(
            b"a: 1\n",
            ArtifactForm::Yaml,
            yaml_sigil_traits::verification::PreVerifyOptions {
                allow_unsigned: true,
                include_parser_observations: false,
                resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded()
            }
        )
        .unwrap()
    );
}

#[test]
fn can_pre_verify_proto_happy_path() {
    let (sk, _) = ed25519_pair();
    let wire = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"z: 9\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    assert!(
        can_pre_verify(
            &wire,
            ArtifactForm::Proto,
            yaml_sigil_traits::verification::PreVerifyOptions {
                allow_unsigned: false,
                include_parser_observations: false,
                resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded()
            }
        )
        .unwrap()
    );
}

#[test]
fn verify_from_pre_verify_proto_matches_verify_proto() {
    let (sk, vk) = ed25519_pair();
    let wire = sign(&SignRequest {
        resource_limits: yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        output_form: yaml_sigil_signing::OutputForm::Protobuf,
        algorithm_parameters: &[],
        payload: b"m: n\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .map(|success| success.artifact)
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let opt = VerifierOptions::default();
    let full = verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        &keys,
        opt.clone(),
    )
    .map(|result| result.state)
    .unwrap();
    let pre = pre_verify(
        &wire,
        yaml_sigil_traits::verification::ArtifactForm::Proto,
        yaml_sigil_traits::verification::PreVerifyOptions {
            allow_unsigned: false,
            include_parser_observations: false,
            resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        },
    )
    .unwrap();
    let step = verify_from_pre_verify(&pre, &keys, opt)
        .map(|result| result.state)
        .unwrap();
    assert_eq!(full, step);
}

#[test]
fn invocation_error_variants_stringify() {
    assert!(
        InvocationError::InvalidAlgorithmParameters
            .to_string()
            .contains("algorithm")
    );
    assert!(
        InvocationError::TrustPolicyConfigurationError
            .to_string()
            .contains("trust")
    );
    assert!(
        InvocationError::InvalidOrUnsupportedForm
            .to_string()
            .contains("form")
    );
    assert!(
        InvocationError::InvalidPreVerifyResult
            .to_string()
            .contains("pre-verify")
    );
}

#[test]
fn verifier_state_display_variants() {
    assert_eq!(VerifierState::Unsigned.to_string(), "Unsigned");
    assert_eq!(
        VerifierState::Verified {
            payload: &[],
            algorithm: AlgorithmId::Ed25519,
        }
        .to_string(),
        "Verified"
    );
}
