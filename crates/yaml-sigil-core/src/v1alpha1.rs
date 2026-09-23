// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API.
//!
//! These re-exports name the same definitions as the crate's unqualified
//! `v1alpha1` default. Values and trait implementations work through either
//! path without conversion. The specification identifier is independent of
//! the crate's package version.
//! Optional operations retain their existing feature gates.

pub use crate::{
    AlgorithmId, ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm,
    ArtifactResourceLimits, ArtifactResourceResult, CoreError, DEFAULT_MAX_ARTIFACT_BYTES,
    DEFAULT_YAML_UNKNOWN_FIELD_POLICY, DecompositionOutcome, OuterConformance,
    PayloadInvariantError, ProtoArtifactView, ProtoOuterDecomposeOutcome,
    ProtobufWireDecodeAdvertisement, SCHEMA_V1ALPHA1, SignatureDocument, SignatureRanges,
    TIER_A_TOP_LEVEL_KEYS, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy, algorithm, compose_proto_outer,
    compose_proto_outer_with_resource_limits, conformance, decode_signature_carrier,
    decode_signed_yaml_artifact, decode_signed_yaml_artifact_with_resource_limits,
    decompose_artifact, decompose_artifact_with_resource_limits, decompose_proto_outer,
    decompose_proto_outer_with_resource_limits, decomposition, encode_signed_yaml_artifact,
    encode_signed_yaml_artifact_with_resource_limits, error, has_unknown_signature_document_fields,
    parse_signature_document, payload, pb, proto_outer, resource, serialize_signature_document,
    signature_doc, signature_document_top_level_keys, validate_payload_stream,
    view_signature_carrier, view_signed_yaml_artifact, wire, yaml_unknown_field_policies,
};

#[cfg(feature = "p256-encoding")]
pub use crate::{
    P256EncodingError, p256_der_signature_to_raw, p256_encoding, p256_public_key_to_uncompressed,
};

#[cfg(feature = "json-schema-validate")]
pub use crate::{signature_document_validates_tier_a_schema, tier_a_schema};
