// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Downstream fixture whose only direct dependency is `yaml-sigil-core`.

use yaml_sigil_core::{ArtifactDecodeError, ArtifactResourceLimits, pb::SignedYamlArtifactRef};

/// Borrow payload bytes after admitting the original encoded artifact.
pub fn payload<'input>(
    input: &'input [u8],
    limits: &ArtifactResourceLimits,
) -> Result<&'input [u8], ArtifactDecodeError> {
    Ok(SignedYamlArtifactRef::decode(input, limits)?.payload())
}

#[cfg(test)]
mod tests {
    use yaml_sigil_core::{
        AlgorithmId, ArtifactResourceLimits, SCHEMA_V1ALPHA1, SignatureDocument,
        parse_signature_document,
        pb::{SignedYamlArtifact, YamlSigilSignature},
        serialize_signature_document,
    };

    #[test]
    fn constructs_encodes_and_decodes_without_a_direct_buffa_dependency() {
        let signature = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
        let artifact = SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));
        let wire = artifact
            .encode_to_vec(&yaml_sigil_core::ArtifactResourceLimits::unbounded())
            .unwrap();

        assert_eq!(
            SignedYamlArtifact::decode(
                &wire,
                &yaml_sigil_core::ArtifactResourceLimits::unbounded()
            )
            .unwrap(),
            artifact
        );
        assert_eq!(
            super::payload(&wire, &ArtifactResourceLimits::unbounded()).unwrap(),
            b"message\n"
        );
        assert_eq!(
            super::payload(&wire, &ArtifactResourceLimits::default(),).unwrap(),
            b"message\n"
        );
        assert_eq!(
            artifact
                .encode_to_vec(&ArtifactResourceLimits::default())
                .unwrap(),
            wire
        );
    }

    #[test]
    fn reads_and_writes_yaml_without_a_direct_backend_dependency() {
        for keyid in [None, Some("demo: \"quoted\" # key")] {
            let document = SignatureDocument {
                schema: SCHEMA_V1ALPHA1.into(),
                alg: AlgorithmId::Ed25519.as_yaml_str().into(),
                keyid: keyid.map(str::to_owned),
                signature: "AQID".into(),
            };
            let yaml = serialize_signature_document(&document).unwrap();
            assert_eq!(parse_signature_document(yaml.as_bytes()).unwrap(), document);
        }
    }
}
