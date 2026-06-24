// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Vendored JSON Schema validation for parsed [`SignatureDocument`] values.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde_json::Value as JsonValue;

use crate::error::CoreError;
use crate::signature_doc::SignatureDocument;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("spec/schema/YamlSigilSignature.v1alpha1.schema.json")
}

fn compiled_schema() -> Result<&'static jsonschema::Validator, CoreError> {
    static SCHEMA: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
    let validator = SCHEMA.get_or_init(|| {
        let schema_src =
            std::fs::read_to_string(schema_path()).map_err(|e| format!("read schema: {e}"))?;
        let schema: JsonValue =
            serde_json::from_str(&schema_src).map_err(|e| format!("parse schema JSON: {e}"))?;
        jsonschema::validator_for(&schema).map_err(|e| format!("compile schema: {e}"))
    });
    match validator {
        Ok(v) => Ok(v),
        Err(msg) => Err(CoreError::SignatureYaml(msg.clone())),
    }
}

/// Validate a parsed document against Tier A JSON Schema (fields present after parse only).
pub fn signature_document_validates_tier_a_schema(
    doc: &SignatureDocument,
) -> Result<(), CoreError> {
    let instance =
        serde_json::to_value(doc).map_err(|e| CoreError::SignatureYaml(e.to_string()))?;
    compiled_schema()?
        .validate(&instance)
        .map_err(|e| CoreError::SignatureYaml(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::SCHEMA_V1ALPHA1;

    fn valid_doc() -> SignatureDocument {
        SignatureDocument {
            schema: SCHEMA_V1ALPHA1.to_string(),
            alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".to_string(),
            keyid: Some("kid-1".to_string()),
            signature: "Zm9v".to_string(),
        }
    }

    fn assert_schema_rejects(doc: SignatureDocument) {
        let err = signature_document_validates_tier_a_schema(&doc).unwrap_err();
        assert!(matches!(err, CoreError::SignatureYaml(_)));
    }

    #[test]
    fn valid_document_compiles_and_reuses_schema() {
        let doc = valid_doc();
        signature_document_validates_tier_a_schema(&doc).expect("valid Tier A document");
        signature_document_validates_tier_a_schema(&doc).expect("cached validator remains usable");
    }

    #[test]
    fn schema_const_mismatch_rejects() {
        let mut doc = valid_doc();
        doc.schema = "YamlSigilSignature.v2".to_string();
        assert_schema_rejects(doc);
    }

    #[test]
    fn unknown_algorithm_string_rejects() {
        let mut doc = valid_doc();
        doc.alg = "NOT_A_REAL_ALGORITHM".to_string();
        assert_schema_rejects(doc);
    }

    #[test]
    fn empty_keyid_rejects() {
        let mut doc = valid_doc();
        doc.keyid = Some(String::new());
        assert_schema_rejects(doc);
    }

    #[test]
    fn padded_or_standard_base64_signature_rejects() {
        let mut padded = valid_doc();
        padded.signature = "Zm8=".to_string();
        assert_schema_rejects(padded);

        let mut standard_alphabet = valid_doc();
        standard_alphabet.signature = "////".to_string();
        assert_schema_rejects(standard_alphabet);
    }
}
