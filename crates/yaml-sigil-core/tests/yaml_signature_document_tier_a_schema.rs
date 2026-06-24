// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Tier A JSON Schema validation after YAML parse.

#![cfg(feature = "json-schema-validate")]

use yaml_sigil_core::{parse_signature_document, signature_document_validates_tier_a_schema};

const TIER_A: &[&str] = &[
    "schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: Zm9v\n",
    "schema: YamlSigilSignature.v1alpha1\nalg: ECDSA_SECP256R1_SHA256_RAW_RS64\nkeyid: kid-1\nsignature: YWJj\n",
    "schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: YWI\n",
    "schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: \"\"\n",
];

#[test]
fn tier_a_fixtures_validate_schema() {
    for (i, yaml) in TIER_A.iter().enumerate() {
        let doc = parse_signature_document(yaml.as_bytes())
            .unwrap_or_else(|e| panic!("fixture {i}: {e}"));
        signature_document_validates_tier_a_schema(&doc)
            .unwrap_or_else(|e| panic!("fixture {i} schema: {e}"));
    }
}
