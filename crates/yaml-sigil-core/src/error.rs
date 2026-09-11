// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Errors surfaced by `yaml-sigil-core`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid UTF-8 in artifact")]
    InvalidUtf8,
    #[error("protobuf decode error: {0}")]
    ProtobufDecode(String),
    #[error("YAML signature document parse error: {0}")]
    SignatureYaml(String),
    #[error("invalid base64 in signature field")]
    InvalidBase64,
    #[error("signature document schema mismatch")]
    SchemaMismatch,
    #[error("empty decoded signature octets")]
    EmptySignature,
}

impl From<buffa::DecodeError> for CoreError {
    fn from(e: buffa::DecodeError) -> Self {
        CoreError::ProtobufDecode(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::CoreError;

    #[test]
    fn display_messages() {
        assert!(CoreError::InvalidUtf8.to_string().contains("UTF-8"));
        assert!(
            CoreError::ProtobufDecode("x".into())
                .to_string()
                .contains("protobuf")
        );
        assert!(
            CoreError::SignatureYaml("y".into())
                .to_string()
                .contains("YAML")
        );
        assert!(CoreError::InvalidBase64.to_string().contains("base64"));
        assert!(CoreError::SchemaMismatch.to_string().contains("schema"));
        assert!(CoreError::EmptySignature.to_string().contains("empty"));
    }
}
