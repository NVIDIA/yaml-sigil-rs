// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared YamlSigil `v1alpha1` operations for artifact decomposition, payload
//! validation, algorithm mapping, and protobuf wire types.
//!
//! Select [`v1alpha1`] explicitly. The unqualified paths remain the
//! `v1alpha1` default and name the same types, modules, and operations.
//! The specification identifier is independent of the crate's SemVer.
//!
//! # Resource boundaries
//!
//! YamlSigil `v1alpha1` defines no maximum complete YAML or protobuf artifact
//! size. The primary codec arguments and operation requests let callers
//! select implementation-local complete-artifact byte limits. Operation
//! options default to unbounded; an explicit default resource policy is 4 MiB.
//!
//! To enforce a limit, use a resource-aware entry point at the affected trust
//! boundary or enforce an equivalent earlier bound on the original raw input. The
//! 16,384-octet YAML signature-carrier constraint remains independent of a
//! complete-artifact bound. Protobuf format limits, parser safeguards,
//! address-space limits, allocator limits, and deployment controls still
//! apply.

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

#[cfg(feature = "protobuf")]
mod generated_proto {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/yaml_sigil_include.rs"));
}

pub mod v1alpha1;

pub mod algorithm;
pub mod conformance;
pub mod decomposition;
#[cfg(feature = "alloc")]
pub mod error;
#[cfg(feature = "p256-encoding")]
pub mod p256_encoding;
pub mod payload;
#[cfg(feature = "protobuf")]
pub mod pb;
#[cfg(feature = "protobuf")]
pub mod proto_outer;
pub mod resource;
#[cfg(feature = "yaml")]
pub mod signature_doc;
#[cfg(feature = "json-schema-validate")]
pub mod tier_a_schema;
#[cfg(feature = "protobuf")]
pub mod wire;

pub use algorithm::{AlgorithmId, SCHEMA_V1ALPHA1};
pub use conformance::{
    DEFAULT_YAML_UNKNOWN_FIELD_POLICY, OuterConformance, ProtobufWireDecodeAdvertisement,
    YamlSignatureDocumentDuplicateKeyPolicy, YamlSignatureDocumentUnknownFieldPolicy,
    yaml_unknown_field_policies,
};
pub use decomposition::{DecompositionOutcome, SignatureRanges, decompose_artifact};
#[cfg(feature = "alloc")]
pub use error::CoreError;
#[cfg(feature = "p256-encoding")]
pub use p256_encoding::{
    P256EncodingError, p256_der_signature_to_raw, p256_public_key_to_uncompressed,
};
pub use payload::{PayloadInvariantError, validate_payload_stream};
#[cfg(feature = "protobuf")]
pub use proto_outer::{
    ProtoOuterDecomposeOutcome, compose_proto_outer, decode_signature_carrier,
    decompose_proto_outer,
};
pub use resource::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
#[cfg(feature = "yaml")]
pub use signature_doc::{
    SignatureDocument, TIER_A_TOP_LEVEL_KEYS, has_unknown_signature_document_fields,
    parse_signature_document, serialize_signature_document, signature_document_top_level_keys,
};
#[cfg(feature = "json-schema-validate")]
pub use tier_a_schema::signature_document_validates_tier_a_schema;
#[cfg(feature = "protobuf")]
pub use wire::{
    ProtoArtifactView, decode_signed_yaml_artifact, encode_signed_yaml_artifact,
    view_signature_carrier, view_signed_yaml_artifact,
};
pub use yaml_sigil_traits::codec::{
    ArtifactDecodeError, ArtifactEncodeError, DecodeError, DecodeErrorKind, EncodeError,
    EncodeErrorKind,
};
