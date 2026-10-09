// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API, identical to the default exports.

pub use crate::{
    AlgorithmId, ArtifactDecodeError, ArtifactEncodeError, ArtifactResourceError,
    ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES, DEFAULT_YAML_UNKNOWN_FIELD_POLICY,
    DecodeError, DecodeErrorKind, DecompositionOutcome, EncodeError, EncodeErrorKind,
    OuterConformance, PayloadInvariantError, ProtobufWireDecodeAdvertisement, SCHEMA_V1ALPHA1,
    SignatureRanges, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy, algorithm, conformance, decompose_artifact,
    decomposition, payload, resource, validate_payload_stream, yaml_unknown_field_policies,
};
#[cfg(feature = "alloc")]
pub use crate::{CoreError, error};
#[cfg(feature = "p256-encoding")]
pub use crate::{
    P256EncodingError, p256_der_signature_to_raw, p256_encoding, p256_public_key_to_uncompressed,
};
#[cfg(feature = "protobuf")]
pub use crate::{
    ProtoArtifactView, ProtoOuterDecomposeOutcome, compose_proto_outer, decode_signature_carrier,
    decode_signed_yaml_artifact, decompose_proto_outer, encode_signed_yaml_artifact, pb,
    proto_outer, view_signature_carrier, view_signed_yaml_artifact, wire,
};
#[cfg(feature = "yaml")]
pub use crate::{
    SignatureDocument, TIER_A_TOP_LEVEL_KEYS, has_unknown_signature_document_fields,
    parse_signature_document, serialize_signature_document, signature_doc,
    signature_document_top_level_keys,
};
#[cfg(feature = "json-schema-validate")]
pub use crate::{signature_document_validates_tier_a_schema, tier_a_schema};
