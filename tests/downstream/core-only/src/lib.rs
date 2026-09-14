// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Downstream fixture whose only direct dependency is `yaml-sigil-core`.

use yaml_sigil_core::{
    ArtifactResourceLimits, ArtifactResourceResult,
    pb::{DecodeError, SignedYamlArtifactRef},
};

/// Borrow the payload through the public protobuf facade.
pub fn payload(input: &[u8]) -> Result<&[u8], DecodeError> {
    Ok(SignedYamlArtifactRef::decode(input)?.payload())
}

/// Borrow the payload after applying an explicit core-only input policy.
pub fn payload_with_resource_limits<'a>(
    input: &'a [u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<&'a [u8], DecodeError>> {
    Ok(
        SignedYamlArtifactRef::decode_with_resource_limits(input, limits)?
            .map(|artifact| artifact.payload()),
    )
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
        let wire = artifact.encode_to_vec().unwrap();

        assert_eq!(SignedYamlArtifact::decode(&wire).unwrap(), artifact);
        assert_eq!(super::payload(&wire).unwrap(), b"message\n");
        assert_eq!(
            super::payload_with_resource_limits(&wire, &ArtifactResourceLimits::default(),)
                .unwrap()
                .unwrap(),
            b"message\n"
        );
        assert_eq!(
            artifact
                .encode_to_vec_with_resource_limits(&ArtifactResourceLimits::default())
                .unwrap()
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
