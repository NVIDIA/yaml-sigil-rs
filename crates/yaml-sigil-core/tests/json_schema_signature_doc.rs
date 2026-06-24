// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! JSON Schema draft 2020-12 validation for Tier A signature documents.

#![cfg(feature = "json-schema-validate")]

use std::fs;
use std::path::PathBuf;

use serde_json::{Value as JsonValue, json};

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("spec/schema/YamlSigilSignature.v1alpha1.schema.json")
}

fn compiled_schema() -> jsonschema::Validator {
    let schema_src = fs::read_to_string(schema_path()).expect("read schema");
    let schema: JsonValue = serde_json::from_str(&schema_src).expect("parse schema JSON");
    jsonschema::validator_for(&schema).expect("compile schema")
}

#[test]
fn tier_a_document_shape_matches_vendored_json_schema() {
    let compiled = compiled_schema();
    let fixtures = [
        json!({
            "schema": "YamlSigilSignature.v1alpha1",
            "alg": "ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
            "signature": "Zm9v",
        }),
        json!({
            "schema": "YamlSigilSignature.v1alpha1",
            "alg": "ECDSA_SECP256R1_SHA256_RAW_RS64",
            "keyid": "kid-1",
            "signature": "YWJj",
        }),
    ];

    for instance in fixtures {
        compiled
            .validate(&instance)
            .expect("instance should validate");
    }
}

#[test]
fn wrong_alg_string_fails_schema() {
    let compiled = compiled_schema();
    let instance = json!({
        "schema": "YamlSigilSignature.v1alpha1",
        "alg": "ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
        "signature": "Zm9v",
    });
    assert!(compiled.validate(&instance).is_err());
}
