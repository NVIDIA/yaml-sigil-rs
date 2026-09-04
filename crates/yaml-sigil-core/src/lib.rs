// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared YamlSigil v1alpha1 primitives: artifact decomposition, payload invariants,
//! algorithm string mapping, and protobuf wire types via `buffa`.

pub mod algorithm;
pub mod conformance;
pub mod decomposition;
pub mod error;
pub mod payload;
pub mod proto_outer;
pub mod signature_doc;
#[cfg(feature = "json-schema-validate")]
pub mod tier_a_schema;
pub mod wire;

/// Generated protobuf message types.
///
/// # Resource usage
///
/// These types implement [`buffa::Message`] and expose its direct decode and merge APIs. Those
/// APIs impose no deployment-specific size limits on artifact, payload, or signature-carrier
/// data. Decoding copies length-delimited fields into owned message buffers, so allocation and
/// copying are linear in field size. Callers handling untrusted data must enforce
/// deployment-appropriate size limits before decoding. Direct consumers can set a top-level input
/// bound with [`buffa::DecodeOptions::with_max_message_size`] and then decode through
/// [`buffa::DecodeOptions::decode_from_slice`].
pub mod pb {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/yaml_sigil_include.rs"));
    pub use self::yaml_sigil::v1alpha1::{Algorithm, SignedYamlArtifact, YamlSigilSignature};
}

pub use algorithm::{AlgorithmId, SCHEMA_V1ALPHA1};
pub use conformance::{
    DEFAULT_YAML_UNKNOWN_FIELD_POLICY, OuterConformance, ProtobufWireDecodeAdvertisement,
    YamlSignatureDocumentDuplicateKeyPolicy, YamlSignatureDocumentUnknownFieldPolicy,
    yaml_unknown_field_policies,
};
pub use decomposition::{DecompositionOutcome, SignatureRanges, decompose_artifact};
pub use error::CoreError;
pub use payload::{PayloadInvariantError, validate_payload_stream};
pub use proto_outer::{
    ProtoOuterDecomposeOutcome, compose_proto_outer, decode_signature_carrier,
    decompose_proto_outer,
};
pub use signature_doc::{
    SignatureDocument, TIER_A_TOP_LEVEL_KEYS, has_unknown_signature_document_fields,
    parse_signature_document, serialize_signature_document, signature_document_top_level_keys,
};
#[cfg(feature = "json-schema-validate")]
pub use tier_a_schema::signature_document_validates_tier_a_schema;
pub use wire::{
    ProtoArtifactView, decode_signed_yaml_artifact, encode_signed_yaml_artifact,
    view_signature_carrier, view_signed_yaml_artifact,
};
