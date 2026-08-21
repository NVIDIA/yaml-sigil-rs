// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Strict signature-document subset: serde model + YAML parser.

use base64::Engine;

use crate::algorithm::{AlgorithmId, SCHEMA_V1ALPHA1};
use crate::error::CoreError;
use serde::{Deserialize, Serialize};

const SIGNATURE_DOCUMENT_MAX_BYTES: usize = 16 * 1024;
const SIGNATURE_DOCUMENT_MAX_DEPTH: usize = 16;
const SIGNATURE_DOCUMENT_MAX_ALIAS_EXPANSIONS: usize = 0;
const SIGNATURE_DOCUMENT_MAX_MAPPING_KEYS: usize = 8;
const SIGNATURE_DOCUMENT_MAX_SEQUENCE_LENGTH: usize = 16;
const SIGNATURE_DOCUMENT_MAX_EVENTS: usize = 128;
const SIGNATURE_DOCUMENT_MAX_NODES: usize = 64;
const SIGNATURE_DOCUMENT_MAX_TOTAL_SCALAR_BYTES: usize = 8 * 1024;
const SIGNATURE_DOCUMENT_MAX_DOCUMENTS: usize = 1;
const SIGNATURE_DOCUMENT_MAX_MERGE_KEYS: usize = 8;

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

/// Parse one unauthenticated YAML signature document with bounded parser
/// resources.
///
/// The parser accepts at most 16 KiB and independently limits nesting depth,
/// parser events, constructed nodes, cumulative scalar bytes, collection
/// sizes, documents, merge keys, and alias expansion. It rejects anchors,
/// aliases, and custom tags.
#[tracing::instrument(level = "debug", skip(bytes), fields(len = bytes.len()))]
pub fn parse_signature_document(bytes: &[u8]) -> Result<SignatureDocument, CoreError> {
    ensure_signature_document_byte_budget(bytes)?;
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
        .max_document_length(SIGNATURE_DOCUMENT_MAX_BYTES)
        .max_depth(SIGNATURE_DOCUMENT_MAX_DEPTH)
        .max_alias_expansions(SIGNATURE_DOCUMENT_MAX_ALIAS_EXPANSIONS)
        .max_mapping_keys(SIGNATURE_DOCUMENT_MAX_MAPPING_KEYS)
        .max_sequence_length(SIGNATURE_DOCUMENT_MAX_SEQUENCE_LENGTH)
        .max_events(SIGNATURE_DOCUMENT_MAX_EVENTS)
        .max_nodes(SIGNATURE_DOCUMENT_MAX_NODES)
        .max_total_scalar_bytes(SIGNATURE_DOCUMENT_MAX_TOTAL_SCALAR_BYTES)
        .max_documents(SIGNATURE_DOCUMENT_MAX_DOCUMENTS)
        .max_merge_keys(SIGNATURE_DOCUMENT_MAX_MERGE_KEYS)
        .alias_anchor_ratio(Some(1.0))
        .duplicate_key_policy(noyalib::DuplicateKeyPolicy::Error)
        .merge_key_policy(noyalib::MergeKeyPolicy::AsOrdinary)
        .with_policy(noyalib::policy::DenyAnchors)
        .with_policy(noyalib::policy::DenyTags)
}

fn ensure_signature_document_byte_budget(bytes: &[u8]) -> Result<(), CoreError> {
    if bytes.len() > SIGNATURE_DOCUMENT_MAX_BYTES {
        return Err(CoreError::SignatureYaml(
            "signature carrier exceeds the maximum supported byte length".into(),
        ));
    }
    Ok(())
}

/// Enumerate top-level mapping keys in a signature-document YAML fragment (UTF-8).
///
/// The scan is bounded by the same byte budget as the default parser. The
/// default parser also rejects unknown fields through [`SignatureDocument`].
pub fn signature_document_top_level_keys(
    bytes: &[u8],
) -> Result<std::collections::BTreeSet<String>, CoreError> {
    ensure_signature_document_byte_budget(bytes)?;
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

fn plain_yaml_scalar_round_trips_as_string(value: &str) -> bool {
    noyalib::from_str::<String>(value).is_ok_and(|parsed| parsed == value)
}

/// Serialize a canonical YAML signature carrier.
///
/// Rejects noncanonical fixed identifiers and invalid base64url signatures.
/// Base64url values that YAML would reinterpret use double-quoted scalar form.
pub fn serialize_signature_document(doc: &SignatureDocument) -> Result<String, CoreError> {
    // Keep the reference emitter fail-closed for noncanonical identifiers and
    // invalid signature encodings. If a concrete lossless parse/re-emit use
    // case emerges, consider a separately specified serializer instead of
    // making canonical emission accept arbitrary field values.
    doc.validate_schema()?;
    if AlgorithmId::from_yaml_str(&doc.alg).is_none() {
        return Err(CoreError::SignatureYaml(
            "signature document alg is not a canonical v1alpha1 algorithm".into(),
        ));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(doc.signature.as_bytes())
        .map_err(|_| CoreError::InvalidBase64)?;

    let mut out = format!("schema: {}\nalg: {}\n", doc.schema, doc.alg);
    if let Some(keyid) = &doc.keyid {
        out.push_str("keyid: ");
        out.push_str(&quote_yaml_string(keyid));
        out.push('\n');
    }
    out.push_str("signature: ");
    if plain_yaml_scalar_round_trips_as_string(&doc.signature) {
        out.push_str(&doc.signature);
    } else {
        out.push_str(&quote_yaml_string(&doc.signature));
    }
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
    fn parser_uses_signature_document_resource_budgets() {
        let config = super::signature_document_parser_config();
        assert_eq!(
            config.max_document_length,
            super::SIGNATURE_DOCUMENT_MAX_BYTES
        );
        assert_eq!(config.max_depth, super::SIGNATURE_DOCUMENT_MAX_DEPTH);
        assert_eq!(
            config.max_alias_expansions,
            super::SIGNATURE_DOCUMENT_MAX_ALIAS_EXPANSIONS
        );
        assert_eq!(
            config.max_mapping_keys,
            super::SIGNATURE_DOCUMENT_MAX_MAPPING_KEYS
        );
        assert_eq!(config.max_nodes, super::SIGNATURE_DOCUMENT_MAX_NODES);
        assert_eq!(config.max_documents, 1);
    }

    #[test]
    fn parse_checks_byte_budget_before_utf8() {
        let mut oversized = vec![b'x'; super::SIGNATURE_DOCUMENT_MAX_BYTES + 1];
        oversized[super::SIGNATURE_DOCUMENT_MAX_BYTES] = 0xff;

        let err = super::parse_signature_document(&oversized).unwrap_err();
        assert!(matches!(err, CoreError::SignatureYaml(_)));
    }

    #[test]
    fn parse_rejects_document_over_byte_budget() {
        let oversized = format!(
            "#{}\nschema: YamlSigilSignature.v1alpha1\n\
             alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\n\
             signature: Zm9v\n",
            "x".repeat(super::SIGNATURE_DOCUMENT_MAX_BYTES)
        );
        let err = super::parse_signature_document(oversized.as_bytes()).unwrap_err();
        assert!(matches!(err, CoreError::SignatureYaml(_)));
    }

    #[test]
    fn top_level_key_scan_rejects_input_over_byte_budget() {
        let oversized = vec![b'x'; super::SIGNATURE_DOCUMENT_MAX_BYTES + 1];
        let err = super::signature_document_top_level_keys(&oversized).unwrap_err();
        assert!(matches!(err, CoreError::SignatureYaml(_)));
    }

    #[test]
    fn parse_rejects_document_over_mapping_key_budget() {
        let mut carrier = String::new();
        for index in 0..=super::SIGNATURE_DOCUMENT_MAX_MAPPING_KEYS {
            carrier.push_str(&format!("field_{index}: value\n"));
        }

        let err = super::parse_signature_document(carrier.as_bytes()).unwrap_err();
        let CoreError::SignatureYaml(message) = err else {
            panic!("expected YAML parser error");
        };
        assert!(message.contains("max_mapping_keys budget exceeded"));
    }

    #[test]
    fn parse_accepts_markerless_carrier_at_exact_byte_budget() {
        let baseline = "schema: YamlSigilSignature.v1alpha1\n\
                        alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\n\
                        signature: Zm9v\n";
        let comment_bytes = super::SIGNATURE_DOCUMENT_MAX_BYTES - baseline.len() - 2;
        let carrier = format!("#{}\n{baseline}", "x".repeat(comment_bytes));

        assert_eq!(carrier.len(), super::SIGNATURE_DOCUMENT_MAX_BYTES);
        super::parse_signature_document(carrier.as_bytes())
            .expect("markerless carrier at the byte limit must parse");
    }

    #[test]
    fn parse_rejects_document_over_depth_budget() {
        let nesting = super::SIGNATURE_DOCUMENT_MAX_DEPTH + 2;
        let deeply_nested = format!(
            "schema: YamlSigilSignature.v1alpha1\n\
             alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\n\
             signature: Zm9v\n\
             extra: {}x{}\n",
            "[".repeat(nesting),
            "]".repeat(nesting)
        );
        let err = super::parse_signature_document(deeply_nested.as_bytes()).unwrap_err();
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

    #[test]
    fn serialize_rejects_parsed_signature_field_injection() {
        let carrier = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
signature: "Zm9v\nkeyid: \"evil\""
"#;
        let doc = super::parse_signature_document(carrier).unwrap();
        assert_eq!(doc.keyid, None);
        assert_eq!(doc.signature, "Zm9v\nkeyid: \"evil\"");

        let err = super::serialize_signature_document(&doc).unwrap_err();
        assert!(matches!(err, CoreError::InvalidBase64));
    }

    #[test]
    fn serialize_rejects_noncanonical_schema_and_algorithm() {
        let mut doc = SignatureDocument {
            schema: crate::SCHEMA_V1ALPHA1.into(),
            alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".into(),
            keyid: None,
            signature: "Zm9v".into(),
        };

        doc.schema = "YamlSigilSignature.v1alpha1\nkeyid: evil".into();
        let err = super::serialize_signature_document(&doc).unwrap_err();
        assert!(matches!(err, CoreError::SchemaMismatch));

        doc.schema = crate::SCHEMA_V1ALPHA1.into();
        doc.alg = "ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nkeyid: evil".into();
        let err = super::serialize_signature_document(&doc).unwrap_err();
        assert!(matches!(err, CoreError::SignatureYaml(_)));
    }

    #[test]
    fn serialize_rejects_invalid_signature_base64_spellings() {
        for signature in [
            "Zm9v\nkeyid: evil",
            "Zm9v: evil",
            "Zm9v\"evil",
            "Zm9v #evil",
            " Zm9v",
            "Zm8=",
            "////",
            "Zh",
        ] {
            let doc = SignatureDocument {
                schema: crate::SCHEMA_V1ALPHA1.into(),
                alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".into(),
                keyid: None,
                signature: signature.into(),
            };

            let err = super::serialize_signature_document(&doc).unwrap_err();
            assert!(
                matches!(err, CoreError::InvalidBase64),
                "unexpected error for {signature:?}: {err:?}"
            );
        }
    }

    #[test]
    fn serialize_quotes_base64_that_is_not_a_plain_yaml_string() {
        for signature in ["", "true", "null", "1234"] {
            let doc = SignatureDocument {
                schema: crate::SCHEMA_V1ALPHA1.into(),
                alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".into(),
                keyid: None,
                signature: signature.into(),
            };

            let carrier = super::serialize_signature_document(&doc).unwrap();
            assert!(
                carrier.ends_with(&format!("signature: \"{signature}\"\n")),
                "unexpected carrier for {signature:?}: {carrier:?}"
            );
            assert_eq!(
                super::parse_signature_document(carrier.as_bytes()).unwrap(),
                doc
            );
        }
    }

    #[test]
    fn serialize_quotes_keyid_field_injection() {
        let doc = SignatureDocument {
            schema: crate::SCHEMA_V1ALPHA1.into(),
            alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".into(),
            keyid: Some("trusted\nsignature: evil".into()),
            signature: "Zm9v".into(),
        };

        let carrier = super::serialize_signature_document(&doc).unwrap();
        assert!(carrier.contains("keyid: \"trusted\\nsignature: evil\"\n"));
        assert_eq!(
            super::parse_signature_document(carrier.as_bytes()).unwrap(),
            doc
        );
    }

    #[test]
    fn serialize_accepts_both_canonical_algorithms() {
        for alg in [
            "ED25519_PUREEDDSA_RAW_RS64_CANONICAL",
            "ECDSA_SECP256R1_SHA256_RAW_RS64",
        ] {
            let doc = SignatureDocument {
                schema: crate::SCHEMA_V1ALPHA1.into(),
                alg: alg.into(),
                keyid: None,
                signature: "Zm9v".into(),
            };

            let carrier = super::serialize_signature_document(&doc).unwrap();
            assert!(carrier.contains(&format!("alg: {alg}\n")));
            assert!(carrier.ends_with("signature: Zm9v\n"));
            assert_eq!(
                super::parse_signature_document(carrier.as_bytes()).unwrap(),
                doc
            );
        }
    }
}
