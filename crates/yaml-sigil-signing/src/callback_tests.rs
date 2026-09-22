// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Behavioral regressions for synchronous provider callbacks.
//!
//! Fixed keys and deterministic P-256 signatures below are test fixtures for
//! payload binding and call counts, not examples of production nonce sampling.

use std::cell::{Cell, RefCell};
use std::num::NonZeroUsize;
use std::rc::Rc;

use signature::hazmat::PrehashSigner as _;

use super::*;

fn request<'a, K>(
    payload: &'a [u8],
    algorithm: AlgorithmId,
    output_form: OutputForm,
    key: &'a K,
) -> GenericSignRequest<'a, K, K> {
    GenericSignRequest {
        payload,
        algorithm,
        key: match algorithm {
            AlgorithmId::Ed25519 => GenericSigningKey::Ed25519(key),
            AlgorithmId::EcdsaP256Sha256 => GenericSigningKey::EcdsaP256Sha256(key),
        },
        keyid: None,
        append_missing_final_newline: true,
        output_form,
        algorithm_parameters: &[],
    }
}

fn finite(maximum: usize) -> ArtifactResourceLimits {
    ArtifactResourceLimits::unbounded().with_max_artifact_bytes(NonZeroUsize::new(maximum).unwrap())
}

fn success(outcome: SignOutcome) -> SignSuccess {
    let SignOutcome::Success(success) = outcome else {
        panic!("expected signing success, got {outcome:?}");
    };
    success
}

fn ed_signature(key: &ed25519_dalek::SigningKey, payload: &[u8]) -> [u8; 64] {
    let signature: ed25519_dalek::Signature = signature::Signer::try_sign(key, payload).unwrap();
    signature.to_bytes()
}

fn p256_signature(key: &p256::ecdsa::SigningKey, digest: &[u8]) -> [u8; 64] {
    let signature: p256::ecdsa::Signature = key.sign_prehash(digest).unwrap();
    signature.to_bytes().into()
}

#[test]
fn message_callbacks_reuse_a_borrowed_mutable_thread_confined_session() {
    struct LocalSession {
        key: ed25519_dalek::SigningKey,
        messages: Rc<RefCell<Vec<Vec<u8>>>>,
        calls: usize,
    }

    impl LocalSession {
        fn sign(&mut self, message: &[u8]) -> [u8; 64] {
            self.calls += 1;
            self.messages.borrow_mut().push(message.to_vec());
            ed_signature(&self.key, message)
        }
    }

    let messages = Rc::new(RefCell::new(Vec::new()));
    let mut session = LocalSession {
        key: ed25519_dalek::SigningKey::from_bytes(&[30; 32]),
        messages: Rc::clone(&messages),
        calls: 0,
    };
    let key = ProviderSigningKeyBuilder::ed25519(session.key.verifying_key().as_bytes())
        .build()
        .unwrap();
    for (form, payload, expected) in [
        (
            OutputForm::Yaml,
            b"local: value".as_slice(),
            b"local: value\n".as_slice(),
        ),
        (
            OutputForm::Protobuf,
            b"\xff\0\x80".as_slice(),
            b"\xff\0\x80".as_slice(),
        ),
        (OutputForm::Yaml, b"".as_slice(), b"".as_slice()),
        (OutputForm::Protobuf, b"".as_slice(), b"".as_slice()),
    ] {
        let req = request(payload, AlgorithmId::Ed25519, form, &key);
        let before = session.calls;
        success(sign_with_provider(
            &req,
            |message| Ok(session.sign(message)),
        ));
        assert_eq!(session.calls, before + 1);
        assert_eq!(messages.borrow().last().unwrap(), expected);
    }
}

#[test]
fn callbacks_can_consume_owned_state() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let key = ProviderSigningKeyBuilder::ed25519(signer.verifying_key().as_bytes())
        .build()
        .unwrap();
    let req = request(b"payload", AlgorithmId::Ed25519, OutputForm::Protobuf, &key);
    let ticket = String::from("one operation");
    let mut consumed = None;
    success(sign_with_provider(&req, |message| {
        // Moving a String out of the capture requires FnOnce, not FnMut.
        consumed = Some(ticket);
        Ok(ed_signature(&signer, message))
    }));
    assert_eq!(consumed.as_deref(), Some("one operation"));
}

#[test]
fn signature_adapter_helper_accepts_local_adapters_and_maps_errors_once() {
    struct FailingLocalAdapter(Rc<Cell<usize>>);

    impl signature::Signer<[u8; 64]> for FailingLocalAdapter {
        fn try_sign(&self, _: &[u8]) -> Result<[u8; 64], signature::Error> {
            self.0.set(self.0.get() + 1);
            Err(signature::Error::new())
        }
    }

    let calls = Rc::new(Cell::new(0));
    let adapter = FailingLocalAdapter(Rc::clone(&calls));
    let native = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
    let key = ProviderSigningKeyBuilder::ed25519(native.verifying_key().as_bytes())
        .build()
        .unwrap();
    let req = request(b"payload", AlgorithmId::Ed25519, OutputForm::Protobuf, &key);
    assert!(matches!(
        sign_with_provider(&req, signature_signing_callback(&adapter)),
        SignOutcome::Signer(SignError::KeyOperationFailure),
    ));
    assert_eq!(calls.get(), 1);
}

#[test]
fn message_paths_reject_bad_requests_without_calling() {
    let native = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
    let bytes = native.verifying_key().to_bytes();
    let qualified = ProviderSigningKeyBuilder::ed25519(&bytes).build().unwrap();
    let unqualified = ProviderSigningKeyBuilder::ed25519(&bytes)
        .build_unqualified()
        .unwrap();

    macro_rules! check {
        ($key:expr, $sign:ident, $bounded:ident) => {{
            let mut req = request(b"\xff", AlgorithmId::Ed25519, OutputForm::Yaml, $key);
            req.algorithm_parameters = &[1];
            assert!(matches!(
                $sign(&req, |_| panic!("invalid invocation called provider")),
                SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters),
            ));
            assert!(matches!(
                $bounded(&req, &finite(1), |_| panic!(
                    "invalid shape called provider"
                ))
                .unwrap()
                .unwrap(),
                SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters),
            ));
            req.algorithm_parameters = &[];
            req.keyid = Some("line\nbreak");
            assert!(matches!(
                $sign(&req, |_| panic!("invalid keyid called provider")),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid),
            ));
            // Bounded preflight rejects size before scanning keyid or payload.
            assert!($bounded(&req, &finite(1), |_| panic!("preflight called provider")).is_err());
            assert!(matches!(
                $bounded(&req, &ArtifactResourceLimits::unbounded(), |_| panic!(
                    "keyid called provider"
                ))
                .unwrap()
                .unwrap(),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid),
            ));
            req.keyid = None;
            for payload in [b"\xff".as_slice(), b"\xef\xbb\xbfkey: value\n"] {
                req.payload = payload;
                assert!(matches!(
                    $sign(&req, |_| panic!("invalid YAML called provider")),
                    SignOutcome::Signer(SignError::InvalidPayloadBytes),
                ));
            }
            req.payload = b"key: value";
            req.append_missing_final_newline = false;
            assert!(matches!(
                $sign(&req, |_| panic!("missing newline called provider")),
                SignOutcome::Signer(SignError::PayloadLineTerminatorRefusal),
            ));
            // Neither the enum slot nor the key's actual algorithm may differ.
            req.algorithm = AlgorithmId::EcdsaP256Sha256;
            assert!(matches!(
                $sign(&req, |_| panic!("wrong slot called provider")),
                SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
            ));
            req.key = GenericSigningKey::EcdsaP256Sha256($key);
            assert!(matches!(
                $bounded(&req, &finite(1), |_| panic!(
                    "wrong binding called provider"
                ))
                .unwrap()
                .unwrap(),
                SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
            ));
        }};
    }
    check!(
        &qualified,
        sign_with_provider,
        sign_with_provider_and_resource_limits
    );
    check!(
        &unqualified,
        sign_with_unqualified_provider,
        sign_with_unqualified_provider_and_resource_limits
    );
}

#[test]
fn both_algorithm_binding_mismatches_are_rejected_before_provider_work() {
    let ed = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let p256 = p256::ecdsa::SigningKey::from_slice(&[43; 32]).unwrap();
    let public = p256.verifying_key().to_sec1_point(false);
    let ed_key = ProviderSigningKeyBuilder::ed25519(ed.verifying_key().as_bytes())
        .build()
        .unwrap();
    let p256_key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public.as_bytes())
        .build()
        .unwrap();
    for (key, algorithm) in [
        (&ed_key, AlgorithmId::EcdsaP256Sha256),
        (&p256_key, AlgorithmId::Ed25519),
    ] {
        let req = request(b"\xff", algorithm, OutputForm::Yaml, key);
        assert!(matches!(
            sign_with_provider(&req, |_| panic!("algorithm mismatch called provider")),
            SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
        ));
        assert!(matches!(
            sign_with_provider_and_resource_limits(&req, &finite(1), |_| panic!(
                "algorithm mismatch called provider"
            ))
            .unwrap()
            .unwrap(),
            SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
        ));
    }
}

#[test]
fn digest_callbacks_receive_final_payload_hashes_and_can_consume_local_state() {
    let native = p256::ecdsa::SigningKey::from_slice(&[34; 32]).unwrap();
    let bytes = native.verifying_key().to_sec1_point(false);
    let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(bytes.as_bytes())
        .build()
        .unwrap();
    for (form, payload, expected) in [
        (
            OutputForm::Yaml,
            b"digest: value".as_slice(),
            b"digest: value\n".as_slice(),
        ),
        (OutputForm::Yaml, b"".as_slice(), b"".as_slice()),
        (
            OutputForm::Protobuf,
            b"\xff\0\x80".as_slice(),
            b"\xff\0\x80".as_slice(),
        ),
        (OutputForm::Protobuf, b"".as_slice(), b"".as_slice()),
    ] {
        let req = request(payload, AlgorithmId::EcdsaP256Sha256, form, &key);
        let seen = Rc::new(RefCell::new(Vec::new()));
        let mut calls = 0;
        let ticket = String::from("digest operation");
        let mut consumed = None;
        let signed = success(sign_with_p256_digest_provider(&req, |digest: &[u8; 32]| {
            consumed = Some(ticket);
            calls += 1;
            seen.borrow_mut().push(*digest);
            Ok(p256_signature(&native, digest))
        }));
        assert_eq!(calls, 1);
        assert_eq!(consumed.as_deref(), Some("digest operation"));
        let expected_digest: [u8; 32] = Sha256::digest(expected).into();
        assert_eq!(*seen.borrow(), [expected_digest]);
        assert_eq!(
            signed.modified_payload,
            if payload == expected { b"" } else { expected }
        );
    }
}

#[test]
fn digest_path_rejects_other_algorithms_and_invalid_payloads_without_calling() {
    let ed = ed25519_dalek::SigningKey::from_bytes(&[35; 32]);
    let ed_key = ProviderSigningKeyBuilder::ed25519(ed.verifying_key().as_bytes())
        .build()
        .unwrap();
    let mut req = request(b"\xff", AlgorithmId::Ed25519, OutputForm::Yaml, &ed_key);
    assert!(matches!(
        sign_with_p256_digest_provider(&req, |_| panic!("Ed25519 called digest provider")),
        SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
    ));
    assert!(matches!(
        sign_with_p256_digest_provider_and_resource_limits(&req, &finite(1), |_| panic!(
            "Ed25519 called digest provider"
        ))
        .unwrap()
        .unwrap(),
        SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
    ));
    req.algorithm = AlgorithmId::EcdsaP256Sha256;
    req.key = ProviderSigningKeys::EcdsaP256Sha256(&ed_key);
    assert!(matches!(
        sign_with_p256_digest_provider(&req, |_| panic!("wrong binding called digest provider")),
        SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm),
    ));

    let p256 = p256::ecdsa::SigningKey::from_slice(&[36; 32]).unwrap();
    let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(
        p256.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .build()
    .unwrap();
    let mut req = request(
        b"key: value",
        AlgorithmId::EcdsaP256Sha256,
        OutputForm::Yaml,
        &key,
    );
    req.algorithm_parameters = &[1];
    assert!(matches!(
        sign_with_p256_digest_provider(&req, |_| panic!(
            "invalid invocation called digest provider"
        )),
        SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters),
    ));
    req.algorithm_parameters = &[];
    req.append_missing_final_newline = false;
    assert!(matches!(
        sign_with_p256_digest_provider(&req, |_| panic!("missing newline called digest provider")),
        SignOutcome::Signer(SignError::PayloadLineTerminatorRefusal),
    ));
    req.payload = b"\xff";
    assert!(matches!(
        sign_with_p256_digest_provider_and_resource_limits(&req, &finite(4096), |_| panic!(
            "invalid payload called digest provider"
        ))
        .unwrap()
        .unwrap(),
        SignOutcome::Signer(SignError::InvalidPayloadBytes),
    ));
}

#[test]
fn all_callback_paths_preserve_exact_resource_boundaries_and_call_counts() {
    let native = p256::ecdsa::SigningKey::from_slice(&[37; 32]).unwrap();
    let public = native.verifying_key().to_sec1_point(false);
    let qualified = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public.as_bytes())
        .build()
        .unwrap();
    let unqualified = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public.as_bytes())
        .build_unqualified()
        .unwrap();

    macro_rules! check {
        ($key:expr, $sign:ident, $bounded:ident, $sign_input:expr) => {{
            for form in [OutputForm::Yaml, OutputForm::Protobuf] {
                let mut req = request(b"resource: value", AlgorithmId::EcdsaP256Sha256, form, $key);
                // Escaping leaves a gap between YAML's lower bound and exact size.
                req.keyid = Some("\"\\\t\0");
                let mut calls = 0;
                let signed = success($sign(&req, |input| {
                    calls += 1;
                    Ok(($sign_input)(input))
                }));
                assert_eq!(calls, 1);
                for maximum in [1, signed.artifact.len() - 1, signed.artifact.len()] {
                    calls = 0;
                    let result = $bounded(&req, &finite(maximum), |input| {
                        calls += 1;
                        Ok(($sign_input)(input))
                    });
                    if maximum == signed.artifact.len() {
                        assert_eq!(success(result.unwrap().unwrap()).artifact, signed.artifact);
                        assert_eq!(calls, 1);
                    } else {
                        assert!(result.is_err());
                        let late_yaml_check = form == OutputForm::Yaml && maximum > 1;
                        assert_eq!(calls, usize::from(late_yaml_check));
                    }
                }
            }
        }};
    }
    check!(
        &qualified,
        sign_with_provider,
        sign_with_provider_and_resource_limits,
        |message: &[u8]| p256_signature(&native, &Sha256::digest(message))
    );
    check!(
        &unqualified,
        sign_with_unqualified_provider,
        sign_with_unqualified_provider_and_resource_limits,
        |message: &[u8]| p256_signature(&native, &Sha256::digest(message))
    );
    check!(
        &qualified,
        sign_with_p256_digest_provider,
        sign_with_p256_digest_provider_and_resource_limits,
        |digest: &[u8; 32]| p256_signature(&native, digest)
    );
}

#[test]
fn digest_path_rejects_wrong_message_wrong_key_double_hash_and_malformed_output() {
    let native = p256::ecdsa::SigningKey::from_slice(&[38; 32]).unwrap();
    let other = p256::ecdsa::SigningKey::from_slice(&[39; 32]).unwrap();
    let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(
        native.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .build()
    .unwrap();
    let req = request(
        b"digest: value",
        AlgorithmId::EcdsaP256Sha256,
        OutputForm::Yaml,
        &key,
    );
    let final_digest = Sha256::digest(b"digest: value\n");
    for invalid in [
        p256_signature(&native, &Sha256::digest(req.payload)),
        p256_signature(&native, &Sha256::digest(b"another payload\n")),
        p256_signature(&other, &final_digest),
        p256_signature(&native, &Sha256::digest(final_digest)),
        [0; 64],
        [0xff; 64],
    ] {
        let mut calls = 0;
        assert!(matches!(
            sign_with_p256_digest_provider(&req, |_| {
                calls += 1;
                Ok(invalid)
            }),
            SignOutcome::Signer(SignError::KeyOperationFailure),
        ));
        assert_eq!(calls, 1);
    }
}

#[test]
fn qualified_message_output_must_match_the_final_payload() {
    let native = ed25519_dalek::SigningKey::from_bytes(&[40; 32]);
    let key = ProviderSigningKeyBuilder::ed25519(native.verifying_key().as_bytes())
        .build()
        .unwrap();
    let req = request(
        b"expected: payload",
        AlgorithmId::Ed25519,
        OutputForm::Yaml,
        &key,
    );
    let mut calls = 0;
    assert!(matches!(
        sign_with_provider(&req, |_| {
            calls += 1;
            Ok(ed_signature(&native, req.payload))
        }),
        SignOutcome::Signer(SignError::KeyOperationFailure),
    ));
    assert_eq!(calls, 1);
}

#[test]
fn callback_errors_and_malformed_unqualified_output_are_not_retried() {
    let native = p256::ecdsa::SigningKey::from_slice(&[41; 32]).unwrap();
    let public = native.verifying_key().to_sec1_point(false);
    let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public.as_bytes())
        .build()
        .unwrap();
    let req = request(
        b"payload",
        AlgorithmId::EcdsaP256Sha256,
        OutputForm::Protobuf,
        &key,
    );
    let mut calls = 0;
    assert!(matches!(
        sign_with_p256_digest_provider_and_resource_limits(&req, &finite(4096), |_| {
            calls += 1;
            Err(SignError::KeyOperationFailure)
        })
        .unwrap()
        .unwrap(),
        SignOutcome::Signer(SignError::KeyOperationFailure),
    ));
    assert_eq!(calls, 1);

    let unqualified = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public.as_bytes())
        .build_unqualified()
        .unwrap();
    let req = request(
        b"payload",
        AlgorithmId::EcdsaP256Sha256,
        OutputForm::Protobuf,
        &unqualified,
    );
    for response in [Err(SignError::InvalidPayloadBytes), Ok([0; 64])] {
        let expected = if response.is_err() {
            SignError::InvalidPayloadBytes
        } else {
            SignError::KeyOperationFailure
        };
        calls = 0;
        let outcome = sign_with_unqualified_provider(&req, |_| {
            calls += 1;
            response
        });
        let SignOutcome::Signer(error) = outcome else {
            panic!("expected callback rejection");
        };
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected)
        );
        assert_eq!(calls, 1);
    }
}
