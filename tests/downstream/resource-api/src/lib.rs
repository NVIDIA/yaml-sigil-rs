// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Downstream resource-API fixture with no direct `yaml-sigil-traits` dependency.

use yaml_sigil_core::{ArtifactResourceLimits, ArtifactResourceResult};

/// Apply the common policy through each high-level crate's re-export.
pub fn check_shared_reexports<'a>(
    input: &'a [u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<&'a [u8]> {
    let input = yaml_sigil_signing::ArtifactResourceLimits::check_input_size(
        limits,
        yaml_sigil_signing::ArtifactResourceForm::Yaml,
        input,
    )?;
    let input = yaml_sigil_verification::ArtifactResourceLimits::check_input_size(
        limits,
        yaml_sigil_verification::ArtifactResourceForm::Yaml,
        input,
    )?;
    yaml_sigil_transcription::ArtifactResourceLimits::check_input_size(
        limits,
        yaml_sigil_transcription::ArtifactResourceForm::Yaml,
        input,
    )
}

/// Prove that both protobuf-producing high-level crates expose the same core
/// format error type.
pub fn share_protobuf_encode_error(
    error: yaml_sigil_signing::EncodeError,
) -> yaml_sigil_transcription::EncodeError {
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(error: &yaml_sigil_core::ArtifactResourceError) -> &'static str {
        match error.kind() {
            yaml_sigil_core::ArtifactResourceErrorKind::InputArtifactTooLarge => "input",
            yaml_sigil_core::ArtifactResourceErrorKind::OutputArtifactTooLarge => "output",
            yaml_sigil_core::ArtifactResourceErrorKind::SizeComputationOverflow => "overflow",
            _ => "future",
        }
    }

    fn describe_form(form: yaml_sigil_core::ArtifactResourceForm) -> &'static str {
        match form {
            yaml_sigil_core::ArtifactResourceForm::Yaml => "YAML",
            yaml_sigil_core::ArtifactResourceForm::Protobuf => "protobuf",
            _ => "future",
        }
    }

    #[test]
    fn all_high_level_crates_consume_one_resource_policy_type() {
        let limits = yaml_sigil_signing::ArtifactResourceLimits::default();
        let _: &yaml_sigil_verification::ArtifactResourceLimits = &limits;
        let _: &yaml_sigil_transcription::ArtifactResourceLimits = &limits;
        assert_eq!(
            yaml_sigil_signing::DEFAULT_MAX_ARTIFACT_BYTES,
            yaml_sigil_verification::DEFAULT_MAX_ARTIFACT_BYTES
        );
        assert_eq!(
            yaml_sigil_signing::DEFAULT_MAX_ARTIFACT_BYTES,
            yaml_sigil_transcription::DEFAULT_MAX_ARTIFACT_BYTES
        );

        let input = b"downstream: true\n";
        let checked = check_shared_reexports(input, &limits).unwrap();
        assert_eq!(checked.as_ptr(), input.as_ptr());
        assert_eq!(
            describe_form(yaml_sigil_core::ArtifactResourceForm::Yaml),
            "YAML"
        );

        let rejected = yaml_sigil_core::ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(1).unwrap())
            .check_input_size(yaml_sigil_core::ArtifactResourceForm::Yaml, input)
            .unwrap_err();
        assert_eq!(classify(&rejected), "input");
        assert_eq!(
            yaml_sigil_core::pb::check_encoded_message_size(0).unwrap(),
            0
        );

        let composed = yaml_sigil_transcription::compose_with_resource_limits(
            &yaml_sigil_transcription::ComposeRequest {
                payload: input,
                signature_carrier: b"carrier",
                form: yaml_sigil_transcription::TranscriptionForm::Protobuf,
            },
            &limits,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            composed,
            yaml_sigil_transcription::ComposeOutcome::Success(_)
        ));

        let pre = yaml_sigil_verification::pre_verify_yaml_with_resource_limits(
            input,
            true,
            &limits,
        )
        .unwrap();
        assert_eq!(
            pre.outcome,
            yaml_sigil_verification::PreVerifyOutcome::Unsigned
        );

        // Referencing these concrete function items proves that the signing
        // and transcoding resource surface is usable without naming a
        // `yaml-sigil-traits` type in this downstream manifest.
        let _ = yaml_sigil_signing::sign_with_resource_limits;
        let _ = yaml_sigil_signing::sign_yaml_with_resource_limits;
        let _ = yaml_sigil_signing::sign_proto_with_resource_limits;
        let _ = yaml_sigil_signing::signed_yaml_stream_to_proto_wire_with_resource_limits;
        let _ = yaml_sigil_signing::proto_wire_to_signed_yaml_stream_with_resource_limits;
    }
}
