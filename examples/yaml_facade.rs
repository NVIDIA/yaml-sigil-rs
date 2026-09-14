// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Read and write a YAML signature carrier through the public core facade.
//!
//! No concrete YAML library is imported here. The carrier is the signature
//! document alone, not a complete signed YAML artifact. Its signature value
//! encodes the illustrative bytes [1, 2, 3]; this example performs no cryptography.

use anyhow::{Result, ensure};
use yaml_sigil_core::{parse_signature_document, serialize_signature_document};

const SAMPLE: &[u8] = br#"schema: YamlSigilSignature.v1alpha1
alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL
keyid: 'demo: "quoted" # key'
signature: AQID
"#;

fn main() -> Result<()> {
    println!("YAML signature carrier with illustrative signature data.");
    let canonical = round_trip(SAMPLE)?;
    print!("{canonical}");
    println!("Parse -> serialize -> parse preserved the document fields.");
    Ok(())
}

fn round_trip(carrier: &[u8]) -> Result<String> {
    // This entry point applies the signature-carrier byte limit and parser
    // policies. A direct Serde deserializer does not supply those policies.
    let document = parse_signature_document(carrier)?;

    // The core serializer produces canonical YAML, including quoting keyid.
    // It checks schema, algorithm spelling, and base64url encoding, but does
    // not verify that the signature belongs to any payload or trusted key.
    let canonical = serialize_signature_document(&document)?;
    let reparsed = parse_signature_document(canonical.as_bytes())?;

    // Compare values. Comments, quoting style, and original bytes need not
    // survive serialization; retain the input bytes for lossless forwarding.
    ensure!(
        reparsed == document,
        "YAML round trip changed document fields"
    );
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yaml_sigil_core::{AlgorithmId, SCHEMA_V1ALPHA1, SignatureDocument};

    #[test]
    fn preserves_quoted_keyid_and_signature_fields() -> Result<()> {
        let canonical = round_trip(SAMPLE)?;
        assert_eq!(
            parse_signature_document(canonical.as_bytes())?,
            SignatureDocument {
                schema: SCHEMA_V1ALPHA1.into(),
                alg: AlgorithmId::Ed25519.as_yaml_str().into(),
                keyid: Some("demo: \"quoted\" # key".into()),
                signature: "AQID".into(),
            }
        );
        Ok(())
    }

    #[test]
    fn keeps_absent_keyid_omitted() -> Result<()> {
        let carrier = b"schema: YamlSigilSignature.v1alpha1\n\
            alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\n\
            signature: AQID\n";
        let canonical = round_trip(carrier)?;
        assert_eq!(parse_signature_document(canonical.as_bytes())?.keyid, None);
        assert!(!canonical.lines().any(|line| line.starts_with("keyid:")));
        Ok(())
    }
}
