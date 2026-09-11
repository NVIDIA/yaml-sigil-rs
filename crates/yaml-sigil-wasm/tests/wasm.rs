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
    // These point encodings follow *Standards for Efficient Cryptography 1
    // (SEC 1)*. That standards material is not relicensed under this file's
    // Apache-2.0 declaration.
    let signing = P256SigningKey::from_slice(&[scalar; 32]).expect("valid test scalar");
    let verifying = signing.verifying_key().to_encoded_point(false);
    (signing.to_bytes().to_vec(), verifying.as_bytes().to_vec())
}

fn append_short_len_delimited(out: &mut Vec<u8>, field_number: u8, value: &[u8]) {
    assert!(field_number < 16);
    assert!(value.len() < 128);
    out.push((field_number << 3) | 2);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
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
fn protobuf_compose_preserves_arbitrary_payload_bytes() {
    init();
    let carrier = b"signature carrier";

    for payload in [
        &[0xff, 0x00][..],
        b"no final newline".as_slice(),
        b"\xef\xbb\xbfleading BOM\n".as_slice(),
    ] {
        let composed = compose(bytes(payload), bytes(carrier), "protobuf");
        assert_eq!(composed.status(), "success");

        let decomposed = decompose(composed.artifact(), "protobuf", Some("strict".to_string()));
        assert_eq!(decomposed.status(), "ok");
        assert_eq!(decomposed.payload().to_vec(), payload);
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
fn unsigned_yaml_decomposes_and_verification_refuses_it() {
    init();
    let decomposed = decompose(bytes(PAYLOAD), "yaml", None);
    assert_eq!(decomposed.status(), "unsigned");
    assert!(!decomposed.has_payload());
    assert!(!decomposed.has_signature_carrier());
    assert!(decomposed.payload().to_vec().is_empty());
    assert!(decomposed.signature_carrier().to_vec().is_empty());

    let (_, verifying_key) = ed25519_keys(13);
    let verified = verify(bytes(PAYLOAD), "yaml", ED25519, bytes(&verifying_key));
    assert_eq!(verified.status(), "malformed_attempted_signed");
    assert!(!verified.has_payload());
    assert!(!verified.has_algorithm());
    assert!(verified.payload().to_vec().is_empty());
}

#[wasm_bindgen_test]
fn newline_repair_reports_modified_payload() {
    init();
    let payload_without_newline = b"name: browser";
    let (signing_key, verifying_key) = ed25519_keys(14);

    let refused = sign(
        bytes(payload_without_newline),
        ED25519,
        bytes(&signing_key),
        None,
        false,
        "yaml",
    );
    assert_eq!(refused.status(), "signer_error");
    assert_eq!(
        refused.code().as_deref(),
        Some("payload_line_terminator_refusal")
    );
    assert!(!refused.has_artifact());
    assert!(!refused.has_modified_payload());
    assert!(refused.artifact().to_vec().is_empty());
    assert!(refused.modified_payload().to_vec().is_empty());

    let repaired = sign(
        bytes(payload_without_newline),
        ED25519,
        bytes(&signing_key),
        None,
        true,
        "yaml",
    );
    assert_eq!(repaired.status(), "success");
    assert!(repaired.has_artifact());
    assert!(repaired.has_modified_payload());
    assert_eq!(repaired.modified_payload().to_vec(), PAYLOAD);

    let verified = verify(repaired.artifact(), "yaml", ED25519, bytes(&verifying_key));
    assert_eq!(verified.status(), "verified");
    assert_eq!(verified.payload().to_vec(), PAYLOAD);
}

#[wasm_bindgen_test]
fn invalid_keyids_and_p256_encodings_have_stable_codes() {
    init();
    let (ed25519_signing_key, _) = ed25519_keys(15);
    for keyid in [String::new(), "bad\nid".to_string(), "x".repeat(1025)] {
        let result = sign(
            bytes(PAYLOAD),
            ED25519,
            bytes(&ed25519_signing_key),
            Some(keyid),
            false,
            "yaml",
        );
        assert_eq!(result.status(), "invocation_error");
        assert_eq!(result.code().as_deref(), Some("invalid_keyid"));
    }

    let zero_scalar = sign(bytes(PAYLOAD), P256, bytes(&[0; 32]), None, false, "yaml");
    assert_eq!(zero_scalar.status(), "invocation_error");
    assert_eq!(zero_scalar.code().as_deref(), Some("invalid_signing_key"));

    for length in 24..32 {
        let wrong_length = sign(
            bytes(PAYLOAD),
            P256,
            bytes(&vec![1; length]),
            None,
            false,
            "yaml",
        );
        assert_eq!(wrong_length.status(), "invocation_error");
        assert_eq!(wrong_length.code().as_deref(), Some("invalid_signing_key"));
    }

    let (_, uncompressed_point) = p256_keys(16);
    let compressed_point = P256SigningKey::from_slice(&[16; 32])
        .expect("valid test scalar")
        .verifying_key()
        .to_encoded_point(true);
    let compressed = verify(
        bytes(PAYLOAD),
        "yaml",
        P256,
        bytes(compressed_point.as_bytes()),
    );
    assert_eq!(compressed.status(), "invocation_error");
    assert_eq!(compressed.code().as_deref(), Some("key_resolution_failure"));

    let unsigned = verify(bytes(PAYLOAD), "yaml", P256, bytes(&uncompressed_point));
    assert_eq!(unsigned.status(), "malformed_attempted_signed");

    let mut zero_point = vec![0; 65];
    zero_point[0] = 4;
    for (case, invalid_point) in [
        ("invalid SEC1 tag", vec![1; 33]),
        ("zero point", zero_point),
    ] {
        let result = verify(bytes(PAYLOAD), "yaml", P256, bytes(&invalid_point));
        assert_eq!(result.status(), "invocation_error", "{case}");
        assert_eq!(
            result.code().as_deref(),
            Some("key_resolution_failure"),
            "{case}"
        );
    }
}

#[wasm_bindgen_test]
fn ed25519_small_order_key_reaches_implementation_resolver() {
    init();
    // The compressed identity point has the required length and a canonical
    // encoding, but it is small-order and must be rejected by the
    // implementation-owned key resolver.
    let mut identity = [0; 32];
    identity[0] = 1;

    let result = verify(bytes(PAYLOAD), "yaml", ED25519, bytes(&identity));
    assert_eq!(result.status(), "invocation_error");
    assert_eq!(result.code().as_deref(), Some("key_resolution_failure"));
}

#[wasm_bindgen_test]
fn signature_strict_rejects_duplicate_signature_fields() {
    init();
    let carrier = b"signature carrier";
    let composed = compose(bytes(PAYLOAD), bytes(carrier), "protobuf");
    assert_eq!(composed.status(), "success");

    let mut duplicate = composed.artifact().to_vec();
    append_short_len_delimited(&mut duplicate, 2, b"duplicate");
    let decomposed = decompose(
        bytes(&duplicate),
        "protobuf",
        Some("signature_strict".to_string()),
    );
    assert_eq!(decomposed.status(), "malformed_attempted_signed");
    assert!(!decomposed.has_payload());
    assert!(!decomposed.has_signature_carrier());
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

#[cfg(feature = "json-schema-validate")]
#[wasm_bindgen_test]
fn schema_invalid_artifact_is_rejected_by_exported_verify() {
    init();
    let (_, verifying_key) = ed25519_keys(32);
    let carrier = b"schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nkeyid: \"\"\nsignature: AA\n";
    let composed = compose(bytes(PAYLOAD), bytes(carrier), "yaml");
    assert_eq!(composed.status(), "success");

    let verified = verify(composed.artifact(), "yaml", ED25519, bytes(&verifying_key));
    assert_eq!(verified.status(), "malformed_attempted_signed");
    assert!(!verified.has_payload());
    assert!(!verified.has_algorithm());
}
