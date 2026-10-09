// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Payload stream invariants shared by protobuf verification and signing.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PayloadInvariantError {
    #[error("payload is not valid UTF-8")]
    InvalidUtf8,
    #[error("payload must not start with a UTF-8 BOM")]
    BomAtOffset0,
    #[error("non-empty payload must end with a line terminator (LF, optional CR before LF)")]
    MissingTrailingLineTerminator,
}

fn bom_at_zero(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF
}

/// Validate UTF-8, no BOM, and trailing line terminator for non-empty payloads.
pub fn validate_payload_stream(payload: &[u8]) -> Result<(), PayloadInvariantError> {
    if core::str::from_utf8(payload).is_err() {
        return Err(PayloadInvariantError::InvalidUtf8);
    }
    if bom_at_zero(payload) {
        return Err(PayloadInvariantError::BomAtOffset0);
    }
    if payload.is_empty() {
        return Ok(());
    }
    let last = *payload.last().expect("non-empty");
    if last != b'\n' {
        return Err(PayloadInvariantError::MissingTrailingLineTerminator);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ok() {
        validate_payload_stream(b"").unwrap();
    }

    #[test]
    fn needs_trailing_newline() {
        assert_eq!(
            validate_payload_stream(b"a: 1"),
            Err(PayloadInvariantError::MissingTrailingLineTerminator)
        );
        validate_payload_stream(b"a: 1\n").unwrap();
    }
}
