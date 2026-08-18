// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use js_sys::Uint8Array;
use p256::ecdsa::SigningKey as P256SigningKey;
use wasm_bindgen_test::wasm_bindgen_test;
use yaml_sigil_wasm::{compose, decompose, sign, verify};

#[cfg(feature = "browser-tests")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const ED25519: &str = "ED25519_PUREEDDSA_RAW_RS64_CANONICAL";
const P256: &str = "ECDSA_SECP256R1_SHA256_RAW_RS64";
const PAYLOAD: &[u8] = b"name: browser\n";

fn bytes(value: &[u8]) -> Uint8Array {
    Uint8Array::from(value)
}

fn init() {
    console_error_panic_hook::set_once();
}

fn ed25519_keys(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let signing = Ed25519SigningKey::from_bytes(&[seed; 32]);
    (
        signing.to_bytes().to_vec(),
        signing.verifying_key().to_bytes().to_vec(),
    )
}

fn p256_keys(scalar: u8) -> (Vec<u8>, Vec<u8>) {
    let signing = P256SigningKey::from_slice(&[scalar; 32]).expect("valid test scalar");
    let verifying = signing.verifying_key().to_encoded_point(true);
    (signing.to_bytes().to_vec(), verifying.as_bytes().to_vec())
}

#[wasm_bindgen_test]
fn compose_and_decompose_yaml_and_protobuf() {
    init();
    let carrier = b"schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: AA\n";

    for (form, outer) in [("yaml", None), ("protobuf", Some("strict".to_string()))] {
        let composed = compose(bytes(PAYLOAD), bytes(carrier), form);
        assert_eq!(composed.status(), "success");
        assert!(composed.has_artifact());

        let decomposed = decompose(composed.artifact(), form, outer);
        assert_eq!(decomposed.status(), "ok");
        assert!(decomposed.has_payload());
        assert!(decomposed.has_signature_carrier());
        assert_eq!(decomposed.payload().to_vec(), PAYLOAD);
        assert_eq!(decomposed.signature_carrier().to_vec(), carrier);
    }
}

#[wasm_bindgen_test]
fn sign_and_verify_every_algorithm_and_form() {
    init();
    let key_sets = [(ED25519, ed25519_keys(7)), (P256, p256_keys(3))];

    for (algorithm, (signing_key, verifying_key)) in key_sets {
        for form in ["yaml", "protobuf"] {
            let signed = sign(
                bytes(PAYLOAD),
                algorithm,
                bytes(&signing_key),
                Some("browser-test".to_string()),
                false,
                form,
            );
            assert_eq!(signed.status(), "success");
            assert!(signed.has_artifact());
            assert!(!signed.has_modified_payload());

            let verified = verify(signed.artifact(), form, algorithm, bytes(&verifying_key));
            assert_eq!(verified.status(), "verified");
            assert_eq!(verified.algorithm().as_deref(), Some(algorithm));
            assert_eq!(verified.payload().to_vec(), PAYLOAD);
        }
    }
}

#[wasm_bindgen_test]
fn wrong_keys_and_algorithm_mismatches_have_stable_states() {
    init();
    let (ed_signing, ed_verifying) = ed25519_keys(11);
    let (_, wrong_ed_verifying) = ed25519_keys(12);
    let (_, p256_verifying) = p256_keys(4);
    let signed = sign(
        bytes(PAYLOAD),
        ED25519,
        bytes(&ed_signing),
        None,
        false,
        "yaml",
    );

    let wrong = verify(
        signed.artifact(),
        "yaml",
        ED25519,
        bytes(&wrong_ed_verifying),
    );
    assert_eq!(wrong.status(), "signed_but_failed_verification");

    let unsupported = verify(signed.artifact(), "yaml", P256, bytes(&p256_verifying));
    assert_eq!(unsupported.status(), "signed_but_algorithm_unsupported");
    assert_eq!(unsupported.algorithm().as_deref(), Some(ED25519));

    let verified = verify(signed.artifact(), "yaml", ED25519, bytes(&ed_verifying));
    assert_eq!(verified.status(), "verified");
}

#[wasm_bindgen_test]
fn expected_failures_return_typed_results_without_key_material() {
    init();
    let sentinel = vec![0x5a; 31];

    let bad_sign = sign(
        bytes(PAYLOAD),
        ED25519,
        bytes(&sentinel),
        None,
        false,
        "yaml",
    );
    assert_eq!(bad_sign.status(), "invocation_error");
    assert_eq!(bad_sign.code().as_deref(), Some("invalid_signing_key"));

    let bad_verify = verify(bytes(PAYLOAD), "yaml", ED25519, bytes(&sentinel));
    assert_eq!(bad_verify.status(), "invocation_error");
    assert_eq!(bad_verify.code().as_deref(), Some("key_resolution_failure"));

    for text in [
        bad_sign.status(),
        bad_sign.code().unwrap(),
        bad_verify.status(),
        bad_verify.code().unwrap(),
    ] {
        assert!(!text.contains("ZZZZ"));
        assert!(!text.contains("5a5a"));
    }
}

#[wasm_bindgen_test]
fn malformed_bytes_and_selectors_are_distinguished() {
    init();
    let invalid_utf8 = compose(bytes(&[0xff]), bytes(b"signature: AA\n"), "yaml");
    assert_eq!(invalid_utf8.status(), "error");
    assert_eq!(
        invalid_utf8.code().as_deref(),
        Some("invalid_payload_bytes")
    );

    let bad_form = compose(bytes(PAYLOAD), bytes(b"signature: AA\n"), "YAML");
    assert_eq!(bad_form.status(), "invocation_error");
    assert_eq!(
        bad_form.code().as_deref(),
        Some("invalid_or_unsupported_form")
    );

    let (signing_key, verifying_key) = ed25519_keys(21);
    let bad_algorithm = sign(
        bytes(PAYLOAD),
        "ed25519",
        bytes(&signing_key),
        None,
        false,
        "yaml",
    );
    assert_eq!(bad_algorithm.status(), "invocation_error");
    assert_eq!(
        bad_algorithm.code().as_deref(),
        Some("invalid_or_unsupported_algorithm")
    );

    let carrier = b"schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: AA\n";
    let malformed = compose(bytes(PAYLOAD), bytes(carrier), "yaml");
    let result = verify(malformed.artifact(), "yaml", ED25519, bytes(&verifying_key));
    assert_eq!(result.status(), "malformed_attempted_signed");

    let outer = decompose(bytes(PAYLOAD), "protobuf", None);
    assert_eq!(outer.status(), "invocation_error");
    assert_eq!(
        outer.code().as_deref(),
        Some("invalid_or_unsupported_outer_conformance")
    );
}

#[wasm_bindgen_test]
fn byte_inputs_and_result_getters_have_copy_semantics() {
    init();
    let (signing_key, verifying_key) = ed25519_keys(31);
    let payload = bytes(PAYLOAD);
    let key = bytes(&signing_key);
    let signed = sign(payload.clone(), ED25519, key.clone(), None, false, "yaml");
    assert_eq!(signed.status(), "success");

    payload.set_index(0, b'X');
    key.set_index(0, 0);
    let verified = verify(signed.artifact(), "yaml", ED25519, bytes(&verifying_key));
    assert_eq!(verified.status(), "verified");
    assert_eq!(verified.payload().to_vec(), PAYLOAD);

    let first_artifact = signed.artifact();
    let original_first = first_artifact.get_index(0);
    first_artifact.set_index(0, original_first.wrapping_add(1));
    assert_eq!(signed.artifact().get_index(0), original_first);

    let first_payload = verified.payload();
    first_payload.set_index(0, b'X');
    assert_eq!(verified.payload().to_vec(), PAYLOAD);
}

#[cfg(feature = "json-schema-validate")]
#[wasm_bindgen_test]
fn embedded_schema_validates_without_runtime_filesystem_access() {
    init();
    use yaml_sigil_core::{parse_signature_document, signature_document_validates_tier_a_schema};

    let valid = parse_signature_document(
        b"schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: AA\n",
    )
    .expect("valid document parses");
    signature_document_validates_tier_a_schema(&valid).expect("embedded schema accepts document");

    let invalid = parse_signature_document(
        b"schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nkeyid: \"\"\nsignature: AA\n",
    )
    .expect("structurally valid document parses");
    assert!(signature_document_validates_tier_a_schema(&invalid).is_err());
}
