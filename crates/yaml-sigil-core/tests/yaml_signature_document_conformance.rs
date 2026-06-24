// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Empirical YAML signature-document parser behavior checks.

use yaml_sigil_core::{CoreError, parse_signature_document};

const MIN_OK: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: Zm9v
"#;

const DUPLICATE_ALG: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
alg: ECDSA_SECP256R1_SHA256_RAW_RS64
signature: Zm9v
"#;

const DUPLICATE_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: AAA
signature: Zm9v
"#;

const UNKNOWN_FIELD: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: Zm9v
x_yaml_sigil_probe: ignored
"#;

const WRONG_SCHEMA: &[u8] = br#"schema: wrong.schema.id
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: Zm9v
"#;

const MISSING_ALG: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
signature: Zm9v
"#;

const MISSING_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
"#;

const UNKNOWN_ALG: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: NOT_A_REAL_ALG
signature: Zm9v
"#;

const MERGE_KEY_WITH_REQUIRED_FIELDS: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: Zm9v
<<: {signature: AAA}
"#;

const MERGE_KEY_CANNOT_SUPPLY_REQUIRED_FIELD: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
<<: {signature: Zm9v}
"#;

const ANCHORED_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: &sig Zm9v
"#;

const ALIASED_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
x_yaml_sigil_probe: &sig Zm9v
signature: *sig
"#;

const CUSTOM_TAG_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: !YamlSigilSignature Zm9v
"#;

const CORE_TAG_STRINGS: &[u8] = br#"schema: !!str YamlSigilSignature.v1alpha1
alg: !!str ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: !!str Zm9v
"#;

const MULTI_DOCUMENT_STREAM: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: Zm9v
---
schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: AAA
"#;

const UNQUOTED_BOOLEAN_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: true
"#;

const QUOTED_BOOLEAN_SIGNATURE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: "true"
"#;

fn assert_parse_err_contains_duplicate(yaml: &[u8]) {
    let err = parse_signature_document(yaml).unwrap_err();
    let CoreError::SignatureYaml(msg) = err else {
        panic!("expected SignatureYaml error, got {err:?}");
    };
    let lower = msg.to_lowercase();
    assert!(
        lower.contains("duplicate"),
        "expected duplicate-key style error, got: {msg}"
    );
}

#[test]
fn duplicate_alg_rejected() {
    assert_parse_err_contains_duplicate(DUPLICATE_ALG);
}

#[test]
fn duplicate_signature_rejected() {
    assert_parse_err_contains_duplicate(DUPLICATE_SIGNATURE);
}

#[test]
fn unknown_top_level_field_rejected() {
    let err = parse_signature_document(UNKNOWN_FIELD).unwrap_err();
    assert!(matches!(err, CoreError::SignatureYaml(_)));
}

#[test]
fn min_document_ok() {
    parse_signature_document(MIN_OK).unwrap();
}

#[test]
fn wrong_schema_const_parses() {
    let doc = parse_signature_document(WRONG_SCHEMA).unwrap();
    assert_eq!(doc.schema, "wrong.schema.id");
    assert!(doc.validate_schema().is_err());
}

#[test]
fn missing_alg_rejected() {
    assert!(parse_signature_document(MISSING_ALG).is_err());
}

#[test]
fn missing_signature_rejected() {
    assert!(parse_signature_document(MISSING_SIGNATURE).is_err());
}

#[test]
fn unknown_alg_string_parses() {
    let doc = parse_signature_document(UNKNOWN_ALG).unwrap();
    assert_eq!(doc.alg, "NOT_A_REAL_ALG");
}

#[test]
fn merge_key_is_ordinary_unknown_field_and_rejected() {
    let err = parse_signature_document(MERGE_KEY_WITH_REQUIRED_FIELDS).unwrap_err();
    assert!(matches!(err, CoreError::SignatureYaml(_)));
}

#[test]
fn merge_key_does_not_supply_required_fields() {
    assert!(parse_signature_document(MERGE_KEY_CANNOT_SUPPLY_REQUIRED_FIELD).is_err());
}

#[test]
fn anchors_and_aliases_are_rejected() {
    let err = parse_signature_document(ANCHORED_SIGNATURE).unwrap_err();
    assert!(matches!(err, CoreError::SignatureYaml(_)));
    let err = parse_signature_document(ALIASED_SIGNATURE).unwrap_err();
    assert!(matches!(err, CoreError::SignatureYaml(_)));
}

#[test]
fn custom_tags_are_rejected() {
    let err = parse_signature_document(CUSTOM_TAG_SIGNATURE).unwrap_err();
    assert!(matches!(err, CoreError::SignatureYaml(_)));
}

#[test]
fn core_string_tags_are_allowed() {
    let doc = parse_signature_document(CORE_TAG_STRINGS).unwrap();
    assert_eq!(doc.schema, "YamlSigilSignature.v1alpha1");
    assert_eq!(doc.signature, "Zm9v");
}

#[test]
fn multi_document_stream_parses_first_document() {
    let doc = parse_signature_document(MULTI_DOCUMENT_STREAM).unwrap();
    assert_eq!(doc.signature, "Zm9v");
}

#[test]
fn scalar_resolution_must_still_produce_strings() {
    assert!(parse_signature_document(UNQUOTED_BOOLEAN_SIGNATURE).is_err());
    let doc = parse_signature_document(QUOTED_BOOLEAN_SIGNATURE).unwrap();
    assert_eq!(doc.signature, "true");
}
