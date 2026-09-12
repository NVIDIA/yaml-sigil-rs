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
    Ok(SignedYamlArtifactRef::decode_with_resource_limits(input, limits)?
        .map(|artifact| artifact.payload()))
}

#[cfg(test)]
mod tests {
    use yaml_sigil_core::{
        AlgorithmId, ArtifactResourceLimits,
        pb::{SignedYamlArtifact, YamlSigilSignature},
    };

    #[test]
    fn constructs_encodes_and_borrows_without_a_direct_buffa_dependency() {
        let signature = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
        let artifact = SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));
        let wire = artifact.encode_to_vec().unwrap();

        assert_eq!(super::payload(&wire).unwrap(), b"message\n");
        assert_eq!(
            super::payload_with_resource_limits(
                &wire,
                &ArtifactResourceLimits::default(),
            )
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
}
