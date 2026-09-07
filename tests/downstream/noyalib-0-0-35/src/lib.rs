// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Downstream Serde interoperability characterization with `noyalib` 0.0.35.
//!
//! The exact dependency pin verifies one independently resolved release. It
//! does not make `noyalib` part of the public API or establish a compatibility
//! guarantee for this or any other release.

#[cfg(test)]
mod tests {
    use yaml_sigil_core::{
        SCHEMA_V1ALPHA1, SignatureDocument, parse_signature_document, serialize_signature_document,
    };

    fn document(keyid: Option<&str>) -> SignatureDocument {
        SignatureDocument {
            schema: SCHEMA_V1ALPHA1.to_owned(),
            alg: "ED25519_PUREEDDSA_RAW_RS64_CANONICAL".to_owned(),
            keyid: keyid.map(str::to_owned),
            signature: "Zm9v".to_owned(),
        }
    }

    #[test]
    fn noyalib_serialization_parses_through_the_authoritative_entry_point() {
        let expected = document(Some("key-1"));
        let yaml = noyalib::to_string(&expected).expect("serialize with noyalib 0.0.35");

        let parsed = parse_signature_document(yaml.as_bytes())
            .expect("parse noyalib 0.0.35 output through yaml-sigil-core");

        assert_eq!(parsed, expected);
    }

    #[test]
    fn canonical_yaml_deserializes_with_noyalib() {
        let expected = document(Some("key-1"));
        let yaml = serialize_signature_document(&expected)
            .expect("serialize with the canonical yaml-sigil-core emitter");

        let parsed: SignatureDocument =
            noyalib::from_str(&yaml).expect("deserialize with noyalib 0.0.35");

        assert_eq!(parsed, expected);
    }

    #[test]
    fn absent_keyid_round_trips_in_both_directions() {
        let expected = document(None);

        let old_yaml = noyalib::to_string(&expected).expect("serialize with noyalib 0.0.35");
        let parsed_by_core = parse_signature_document(old_yaml.as_bytes())
            .expect("parse noyalib 0.0.35 output through yaml-sigil-core");
        assert_eq!(parsed_by_core, expected);

        let canonical_yaml = serialize_signature_document(&expected)
            .expect("serialize with the canonical yaml-sigil-core emitter");
        let parsed_by_old: SignatureDocument =
            noyalib::from_str(&canonical_yaml).expect("deserialize with noyalib 0.0.35");
        assert_eq!(parsed_by_old, expected);
    }

    #[test]
    fn direct_deserialization_rejects_unknown_fields() {
        let yaml = "schema: YamlSigilSignature.v1alpha1\n\
                    alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\n\
                    signature: Zm9v\n\
                    unexpected: true\n";

        assert!(noyalib::from_str::<SignatureDocument>(yaml).is_err());
    }
}
