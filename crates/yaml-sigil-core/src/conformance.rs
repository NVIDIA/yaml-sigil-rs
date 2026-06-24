// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! What this workspace **advertises** about YAML signature-document and protobuf wire behavior.
//!
//! These are **not** the upstream protobuf `ConformanceProfile` enum values; they describe observable
//! semantics for callers building UIs or policy around this implementation.

pub use yaml_sigil_traits::{
    OuterConformance, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};

/// Default unknown-field policy for this build.
pub const DEFAULT_YAML_UNKNOWN_FIELD_POLICY: YamlSignatureDocumentUnknownFieldPolicy =
    YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse;

/// Policies available for YAML signature-document unknown fields in this build.
pub fn yaml_unknown_field_policies() -> Vec<YamlSignatureDocumentUnknownFieldPolicy> {
    vec![DEFAULT_YAML_UNKNOWN_FIELD_POLICY]
}
