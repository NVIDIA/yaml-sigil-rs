// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Strict signature-document subset: serde model + YAML parser.

use crate::algorithm::SCHEMA_V1ALPHA1;
use crate::error::CoreError;
use serde::{Deserialize, Serialize};

/// Top-level keys allowed in a Tier A signature document mapping.
pub const TIER_A_TOP_LEVEL_KEYS: &[&str] = &["schema", "alg", "keyid", "signature"];

/// Parsed `YamlSigilSignature.v1alpha1` YAML mapping (transport form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureDocument {
    pub schema: String,
    pub alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    pub signature: String,
}

impl SignatureDocument {
    pub fn validate_schema(&self) -> Result<(), CoreError> {
        if self.schema != SCHEMA_V1ALPHA1 {
            return Err(CoreError::SchemaMismatch);
        }
        Ok(())
    }
}

#[tracing::instrument(level = "debug", skip(bytes), fields(len = bytes.len()))]
pub fn parse_signature_document(bytes: &[u8]) -> Result<SignatureDocument, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidUtf8)?;
    let config = signature_document_parser_config();
    let documents = noyalib::load_all_with_config(text, &config)
        .map_err(|e| CoreError::SignatureYaml(e.to_string()))?;
    if documents.len() != 1 {
        return Err(CoreError::SignatureYaml(
            "signature carrier must contain exactly one YAML document".into(),
        ));
    }
    noyalib::from_str_with_config(text, &config)
        .map_err(|e| CoreError::SignatureYaml(e.to_string()))
}

fn signature_document_parser_config() -> noyalib::ParserConfig {
    noyalib::ParserConfig::new()
        .duplicate_key_policy(noyalib::DuplicateKeyPolicy::Error)
        .merge_key_policy(noyalib::MergeKeyPolicy::AsOrdinary)
        .with_policy(noyalib::policy::DenyAnchors)
        .with_policy(noyalib::policy::DenyTags)
}

/// Enumerate top-level mapping keys in a signature-document YAML fragment (UTF-8).
///
/// Used for verifier-option preflight checks and diagnostic policy code. The
/// default parser also rejects unknown fields through [`SignatureDocument`].
pub fn signature_document_top_level_keys(
    bytes: &[u8],
) -> Result<std::collections::BTreeSet<String>, CoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidUtf8)?;
    Ok(top_level_keys_flat_line_scan(text))
}

/// True when `bytes` contains a top-level key outside [`TIER_A_TOP_LEVEL_KEYS`].
pub fn has_unknown_signature_document_fields(bytes: &[u8]) -> Result<bool, CoreError> {
    let keys = signature_document_top_level_keys(bytes)?;
    Ok(keys
        .iter()
        .any(|k| !TIER_A_TOP_LEVEL_KEYS.contains(&k.as_str())))
}

/// Top-level keys from a flat YAML mapping (Tier A signature-document shape).
fn top_level_keys_flat_line_scan(text: &str) -> std::collections::BTreeSet<String> {
    let mut keys = std::collections::BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((key, _)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if !key.is_empty() {
            keys.insert(key.to_string());
        }
    }
    keys
}

fn quote_yaml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\0' => out.push_str("\\0"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\u{1b}' => out.push_str("\\e"),
            ch if ch <= '\u{1f}'
                || ('\u{7f}'..='\u{9f}').contains(&ch)
                || matches!(ch, '\u{2028}' | '\u{2029}') =>
            {
                out.push_str(&format!("\\u{:04X}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Serialize a canonical YAML signature carrier.
pub fn serialize_signature_document(doc: &SignatureDocument) -> Result<String, CoreError> {
    let mut out = format!("schema: {}\nalg: {}\n", doc.schema, doc.alg);
    if let Some(keyid) = &doc.keyid {
        out.push_str("keyid: ");
        out.push_str(&quote_yaml_string(keyid));
        out.push('\n');
    }
    out.push_str("signature: ");
    out.push_str(&doc.signature);
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::error::CoreError;

    use super::SignatureDocument;

    #[test]
    fn validate_schema_rejects_wrong_schema() {
        let doc = SignatureDocument {
            schema: "wrong".into(),
            alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".into(),
            keyid: None,
            signature: "Zm9v".into(),
        };
        assert!(doc.validate_schema().is_err());
    }

    #[test]
    fn parse_rejects_invalid_utf8() {
        let err = super::parse_signature_document(&[0xff, 0xfe]).unwrap_err();
        assert!(matches!(err, CoreError::InvalidUtf8));
    }

    #[test]
    fn parse_rejects_invalid_yaml() {
        let err = super::parse_signature_document(b"not: [\n").unwrap_err();
        assert!(matches!(err, CoreError::SignatureYaml(_)));
    }

    #[test]
    fn serialize_uses_canonical_carrier() {
        let doc = SignatureDocument {
            schema: crate::SCHEMA_V1ALPHA1.into(),
            alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".into(),
            keyid: Some("kid-\"1\"".into()),
            signature: "eA".into(),
        };
        let carrier = super::serialize_signature_document(&doc).unwrap();
        assert_eq!(
            carrier,
            "schema: YamlSigilSignature.v1alpha1\n\
             alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\n\
             keyid: \"kid-\\\"1\\\"\"\n\
             signature: eA\n"
        );
        assert_eq!(
            super::parse_signature_document(carrier.as_bytes()).unwrap(),
            doc
        );
    }
}
