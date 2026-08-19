// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for verifier states, pre-verify, and crypto branches.

use ed25519_dalek::SigningKey as EdSigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand_core::OsRng;
use yaml_sigil_core::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};
use yaml_sigil_signing::{SignProtoParams, SignYamlParams, SigningKey, sign_proto, sign_yaml};
use yaml_sigil_verification::{
    AdvertisedConformanceProfile, ArtifactForm, InvocationError, PreVerifyOutcome,
    PreVerifyResponse, PublicKeys, UnverifiedSignature, VerifierOptions, VerifierState,
    can_pre_verify, pre_verify_proto, pre_verify_yaml, resolve_ed25519_verifying_key,
    verifier_capabilities, verify, verify_from_pre_verify_proto, verify_from_pre_verify_yaml,
    verify_proto, verify_yaml,
};

fn ed25519_pair() -> (EdSigningKey, ed25519_dalek::VerifyingKey) {
    let sk = EdSigningKey::from_bytes(&[11u8; 32]);
    let vk = ed25519_dalek::VerifyingKey::from(&sk);
    (sk, vk)
}

fn p256_pair() -> (P256SigningKey, p256::ecdsa::VerifyingKey) {
    let sk = P256SigningKey::random(&mut OsRng);
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

#[test]
fn verify_yaml_ed25519_sign_then_verify_and_display() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: Some("kid"),
        append_missing_final_newline: false,
    })
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let st = verify_yaml(&artifact, &keys, VerifierOptions::default()).unwrap();
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
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"x: y\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let keys = PublicKeys {
        ed25519: None,
        p256: Some(&vk),
    };
    let st = verify_yaml(&artifact, &keys, VerifierOptions::default()).unwrap();
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
    let wire_ed = sign_proto(&SignProtoParams {
        payload: b"a: b\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk_ed),
        keyid: Some("k"),
        append_missing_final_newline: false,
    })
    .unwrap();
    let st = verify_proto(
        &wire_ed,
        &PublicKeys {
            ed25519: Some(&vk_ed),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));

    let (sk_p, vk_p) = p256_pair();
    let wire_p = sign_proto(&SignProtoParams {
        payload: b"z: 9\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk_p),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let st = verify_proto(
        &wire_p,
        &PublicKeys {
            ed25519: None,
            p256: Some(&vk_p),
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}

#[test]
fn verify_proto_malformed_wire() {
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let st = verify_proto(b"\xffnot-protobuf", &keys, VerifierOptions::default()).unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_proto_rejects_out_of_range_field_alias() {
    let (sk, vk) = ed25519_pair();
    let mut wire = sign_proto(&SignProtoParams {
        payload: b"authorized: true\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    append_len_delimited_field(&mut wire, (1_u64 << 29) + 1, b"authorized: false\n");

    let state = verify_proto(
        &wire,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_malformed_unsigned_disallowed() {
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let st = verify_yaml(b"unsigned: only\n", &keys, VerifierOptions::default()).unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
    assert_eq!(st.to_string(), "MalformedAttemptedSigned");
}

#[test]
fn verify_yaml_rejects_noncanonical_algorithm_whitespace() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let text = String::from_utf8(artifact).unwrap();
    let noncanonical = text.replace(
        "alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
        "alg: \" ED25519_PUREEDDSA_RAW_RS64_CANONICAL\"",
    );
    let state = verify_yaml(
        noncanonical.as_bytes(),
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert_eq!(state, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_rejects_signature_whitespace() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();

    for (leading, trailing) in [(" ", ""), ("", " "), (" ", " ")] {
        let mutated = quote_signature_with_whitespace(&artifact, leading, trailing);
        let state = verify_yaml(
            &mutated,
            &PublicKeys {
                ed25519: Some(&vk),
                p256: None,
            },
            VerifierOptions::default(),
        )
        .unwrap();
        assert_eq!(state, VerifierState::MalformedAttemptedSigned);
    }
}

#[test]
fn pre_verify_unsigned_allow_unsigned() {
    let pre = pre_verify_yaml(b"u: 1\n", true);
    assert_eq!(pre.outcome, PreVerifyOutcome::Unsigned);
    assert!(pre.unverified_signature.is_none());
}

#[test]
fn verify_ed25519_wrong_key_fails() {
    let (sk, _vk) = ed25519_pair();
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"p: q\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let other = EdSigningKey::from_bytes(&[3u8; 32]);
    let wrong_vk = ed25519_dalek::VerifyingKey::from(&other);
    let st = verify_yaml(
        &artifact,
        &PublicKeys {
            ed25519: Some(&wrong_vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert_eq!(st, VerifierState::SignedButFailedVerification);
    assert_eq!(st.to_string(), "SignedButFailedVerification");
}

#[test]
fn verify_ed25519_rejects_direct_weak_public_key() {
    use buffa::MessageField;
    use yaml_sigil_core::encode_signed_yaml_artifact;
    use yaml_sigil_core::pb::{Algorithm, SignedYamlArtifact, YamlSigilSignature};

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
    let inner = YamlSigilSignature {
        alg: Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL.into(),
        signature: forged_signature,
        ..Default::default()
    };
    let outer = SignedYamlArtifact {
        payload: b"attacker: chosen\n".to_vec(),
        signature: MessageField::from(inner),
        ..Default::default()
    };
    let wire = encode_signed_yaml_artifact(&outer);

    let error = verify_proto(
        &wire,
        &PublicKeys {
            ed25519: Some(&weak_vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .expect_err("small-order keys must fail at key resolution");
    assert_eq!(error, InvocationError::KeyResolutionFailure);
}

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
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"p: q\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let opts = VerifierOptions {
        verify_ed25519: false,
        verify_ecdsa_p256_sha256: true,
        ..VerifierOptions::default()
    };
    let st = verify_yaml(
        &artifact,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        opts,
    )
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
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"p: q\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let opts = VerifierOptions {
        verify_ed25519: true,
        verify_ecdsa_p256_sha256: false,
        ..VerifierOptions::default()
    };
    let st = verify_yaml(
        &artifact,
        &PublicKeys {
            ed25519: None,
            p256: Some(&vk),
        },
        opts,
    )
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
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"p: q\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let err = verify_yaml(
        &artifact,
        &PublicKeys {
            ed25519: None,
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, InvocationError::KeyResolutionFailure);
    assert!(err.to_string().contains("key material"));
}

#[test]
fn verify_from_pre_verify_rejects_invalid_pre() {
    let pre = PreVerifyResponse {
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
    let err = verify_from_pre_verify_yaml(&pre, &keys, VerifierOptions::default()).unwrap_err();
    assert_eq!(err, InvocationError::InvalidPreVerifyResult);
}

#[test]
fn verify_from_pre_verify_yaml_rejects_proto_shaped_pre() {
    let pre = PreVerifyResponse {
        outcome: PreVerifyOutcome::Ok,
        form: ArtifactForm::Proto,
        unverified_payload_bytes: Some(b"x\n".to_vec()),
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
    let err = verify_from_pre_verify_yaml(&pre, &keys, VerifierOptions::default()).unwrap_err();
    assert_eq!(err, InvocationError::InvalidPreVerifyResult);
}

#[test]
fn verify_yaml_bad_schema_is_malformed() {
    let artifact = b"root: ok\n---\nschema: Wrong\n\
                     alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: Zm9v\n";
    let (_, vk) = ed25519_pair();
    let st = verify_yaml(
        artifact,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_yaml_unknown_alg_is_malformed() {
    let artifact =
        b"r: 1\n---\nschema: YamlSigilSignature.v1alpha1\nalg: NOT_AN_ALG\nsignature: Zm9v\n";
    let (_, vk) = ed25519_pair();
    let st = verify_yaml(
        artifact,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_proto_accepts_non_yaml_fit_payload() {
    use buffa::MessageField;
    use yaml_sigil_core::encode_signed_yaml_artifact;
    use yaml_sigil_core::pb::{Algorithm, SignedYamlArtifact, YamlSigilSignature};

    // The protobuf form imposes no UTF-8 / BOM / line-terminator rule on the
    // payload. An artifact whose payload would never be YAML-fit (here, a
    // BOM-prefixed stream) must reach the crypto stage rather than failing
    // structurally. The placeholder all-zero signature still won't verify,
    // so the outcome is `SignedButFailedVerification`. See
    // docs/conformance-validation.md §3f and §5.r (§5b resolved).
    let inner = YamlSigilSignature {
        alg: Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL.into(),
        signature: vec![0u8; 64],
        ..Default::default()
    };
    let outer = SignedYamlArtifact {
        payload: vec![0xEF, 0xBB, 0xBF, b'h', b'i', b'\n'],
        signature: MessageField::from(inner),
        ..Default::default()
    };
    let wire = encode_signed_yaml_artifact(&outer);
    let (_, vk) = ed25519_pair();
    let st = verify_proto(
        &wire,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert_eq!(st, VerifierState::SignedButFailedVerification);
}

#[test]
fn verify_proto_unspecified_alg_wire() {
    use buffa::MessageField;
    use yaml_sigil_core::encode_signed_yaml_artifact;
    use yaml_sigil_core::pb::{Algorithm, SignedYamlArtifact, YamlSigilSignature};

    let inner = YamlSigilSignature {
        alg: Algorithm::ALGORITHM_UNSPECIFIED.into(),
        signature: vec![1, 2, 3],
        ..Default::default()
    };
    let outer = SignedYamlArtifact {
        payload: b"ok\n".to_vec(),
        signature: MessageField::from(inner),
        ..Default::default()
    };
    let wire = encode_signed_yaml_artifact(&outer);
    let keys = PublicKeys {
        ed25519: None,
        p256: None,
    };
    let st = verify_proto(&wire, &keys, VerifierOptions::default()).unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_from_pre_verify_yaml_happy_path() {
    let (sk, vk) = ed25519_pair();
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"path: test\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let pre = pre_verify_yaml(&artifact, false);
    assert_eq!(pre.outcome, PreVerifyOutcome::Ok);
    let st = verify_from_pre_verify_yaml(
        &pre,
        &PublicKeys {
            ed25519: Some(&vk),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}

#[test]
fn verify_proto_ecdsa_missing_p256_key_errors() {
    let (sk, _) = p256_pair();
    let wire = sign_proto(&SignProtoParams {
        payload: b"p: q\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let (sk_ed, vk_ed) = ed25519_pair();
    let _ = sk_ed;
    let err = verify_proto(
        &wire,
        &PublicKeys {
            ed25519: Some(&vk_ed),
            p256: None,
        },
        VerifierOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err, InvocationError::KeyResolutionFailure);
}

#[test]
fn verifier_capabilities_surface() {
    let c = verifier_capabilities();
    assert!(c.supports_can_pre_verify);
    assert!(c.supports_pre_verify);
    // `DefaultVerifier` advertises Permissive unconditionally. The spec requires
    // Strict / SignatureStrict to reject duplicate known singular fields on
    // both wire forms; the stock buffa decoder applies last-wins behavior to
    // duplicate scalars, so Strict would be non-conforming. See
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
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let opt = VerifierOptions::default();
    let st_yaml = verify_yaml(&artifact, &keys, opt.clone()).unwrap();
    let st_unified = verify(&artifact, ArtifactForm::Yaml, &keys, opt.clone()).unwrap();
    assert_eq!(st_yaml, st_unified);

    let wire = sign_proto(&SignProtoParams {
        payload: b"k: v\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let st_proto = verify_proto(&wire, &keys, opt.clone()).unwrap();
    let st_u2 = verify(&wire, ArtifactForm::Proto, &keys, opt).unwrap();
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
    assert!(!can_pre_verify(b"a: 1\n", ArtifactForm::Yaml, false));
    assert!(can_pre_verify(b"a: 1\n", ArtifactForm::Yaml, true));
}

#[test]
fn can_pre_verify_proto_happy_path() {
    let (sk, _) = ed25519_pair();
    let wire = sign_proto(&SignProtoParams {
        payload: b"z: 9\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    assert!(can_pre_verify(&wire, ArtifactForm::Proto, false));
}

#[test]
fn verify_from_pre_verify_proto_matches_verify_proto() {
    let (sk, vk) = ed25519_pair();
    let wire = sign_proto(&SignProtoParams {
        payload: b"m: n\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    let opt = VerifierOptions::default();
    let full = verify_proto(&wire, &keys, opt.clone()).unwrap();
    let pre = pre_verify_proto(&wire);
    let step = verify_from_pre_verify_proto(&pre, &keys, opt).unwrap();
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
            payload: vec![],
            algorithm: AlgorithmId::Ed25519,
        }
        .to_string(),
        "Verified"
    );
}
