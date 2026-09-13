// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Stable protobuf messages and zero-copy borrowed views.
//!
//! The generated protobuf implementation is private to `yaml-sigil-core`.
//! Consumers exchange protobuf bytes through these types, so their Buffa
//! dependency version does not become part of this crate's public contract.
//!
//! YamlSigil `v1alpha1` defines no maximum complete artifact size. These
//! types provide explicit resource-aware decode and encode variants. Existing
//! methods retain their unbounded behavior. The protobuf format's own size
//! ceiling and the decoder's implementation safeguards still apply.
//!
//! # Construction and borrowed inspection
//!
//! Construct owned messages without importing Buffa. Encoding is fallible and
//! can append to a reusable allocation. Borrowed decoding keeps byte and
//! string fields in the input buffer.
//!
//! ```
//! use yaml_sigil_core::{
//!     AlgorithmId,
//!     pb::{SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature},
//! };
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let signature =
//!     YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
//! let artifact =
//!     SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));
//!
//! let mut wire = Vec::with_capacity(artifact.encoded_len()?);
//! artifact.encode_into(&mut wire)?;
//!
//! let decoded = SignedYamlArtifactRef::decode(&wire)?;
//! assert_eq!(decoded.payload(), b"message\n");
//! assert_eq!(
//!     decoded.signature().unwrap().algorithm(),
//!     Some(AlgorithmId::Ed25519),
//! );
//!
//! wire.clear();
//! artifact.encode_into(&mut wire)?;
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
//!
//! # External input boundaries
//!
//! Use [`SignedYamlArtifact::decode_with_resource_limits`] or
//! [`SignedYamlArtifactRef::decode_with_resource_limits`] to check the original
//! wire length before Buffa parses or copies fields. The borrowed form keeps
//! payload and signature bytes in the admitted input allocation.
//!
//! ```
//! use yaml_sigil_core::{
//!     AlgorithmId, ArtifactResourceLimits,
//!     pb::{
//!         SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature,
//!     },
//! };
//!
//! let signature =
//!     YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
//! let wire = SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature))
//!     .encode_to_vec_with_resource_limits(&ArtifactResourceLimits::default())
//!     .unwrap()
//!     .unwrap();
//!
//! let owned = SignedYamlArtifact::decode_with_resource_limits(
//!     &wire,
//!     &ArtifactResourceLimits::default(),
//! )
//! .unwrap()
//! .unwrap();
//! let borrowed = SignedYamlArtifactRef::decode_with_resource_limits(
//!     &wire,
//!     &ArtifactResourceLimits::default(),
//! )
//! .unwrap()
//! .unwrap();
//! assert_eq!(owned.payload(), borrowed.payload());
//! assert_eq!(borrowed.payload().as_ptr(), wire[2..].as_ptr());
//! ```
//!
//! Resource-aware encoding computes and checks the exact message size before
//! reserving or appending. Every returned error leaves a reusable destination
//! unchanged.
//!
//! ```
//! use core::num::NonZeroUsize;
//! use yaml_sigil_core::{
//!     AlgorithmId, ArtifactResourceLimits,
//!     pb::{SignedYamlArtifact, YamlSigilSignature},
//! };
//!
//! let signature =
//!     YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
//! let artifact =
//!     SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));
//! let encoded_size = artifact.encoded_len().unwrap();
//! let mut output = Vec::with_capacity(2 + encoded_size);
//! output.extend_from_slice(&[0xaa, 0xbb]);
//! let allocation = output.as_ptr();
//! artifact
//!     .encode_into_with_resource_limits(
//!         &mut output,
//!         &ArtifactResourceLimits::default(),
//!     )
//!     .unwrap()
//!     .unwrap();
//! assert_eq!(output.as_ptr(), allocation);
//!
//! let before = output.clone();
//! let too_small = ArtifactResourceLimits::unbounded()
//!     .with_max_artifact_bytes(NonZeroUsize::new(encoded_size - 1).unwrap());
//! assert!(
//!     artifact
//!         .encode_into_with_resource_limits(&mut output, &too_small)
//!         .is_err()
//! );
//! assert_eq!(output, before);
//! ```
//!
//! A local rejection does not make an artifact malformed or non-conforming.
//! The `v1alpha1` 16,384-octet YAML signature-carrier constraint is separate.

use std::fmt;

use buffa::MessageView as _;

use crate::generated_proto::yaml_sigil::v1alpha1::{
    SignedYamlArtifact as GeneratedSignedYamlArtifact,
    SignedYamlArtifactView as GeneratedSignedYamlArtifactView,
    YamlSigilSignature as GeneratedYamlSigilSignature,
    YamlSigilSignatureView as GeneratedYamlSigilSignatureView,
};
use crate::{AlgorithmId, ArtifactResourceForm, ArtifactResourceLimits, ArtifactResourceResult};

/// Stable categories for protobuf decoding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The input ended before the current value was complete.
    UnexpectedEnd,
    /// A varint exceeded the protobuf encoding width.
    InvalidVarint,
    /// A tag contained field number zero or an unrepresentable field number.
    InvalidFieldNumber,
    /// A tag used a wire type that protobuf does not define.
    InvalidWireType,
    /// A known field used a wire type other than its schema-defined type.
    UnexpectedWireType,
    /// A protobuf `string` field was not valid UTF-8.
    InvalidUtf8,
    /// The input exceeded the protobuf message-size ceiling.
    MessageTooLarge,
    /// The input exceeded the decoder's nesting safeguard.
    RecursionLimitExceeded,
    /// The input exceeded the decoder's unknown-field safeguard.
    UnknownFieldLimitExceeded,
    /// The input exceeded the decoder's element-memory safeguard.
    ElementMemoryLimitExceeded,
    /// A protobuf group was incomplete or had a mismatched terminator.
    InvalidGroup,
    /// A decoder failure did not match another stable category.
    Other,
}

impl DecodeErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::UnexpectedEnd => "unexpected end of input",
            Self::InvalidVarint => "invalid varint",
            Self::InvalidFieldNumber => "invalid field number",
            Self::InvalidWireType => "invalid wire type",
            Self::UnexpectedWireType => "unexpected wire type for field",
            Self::InvalidUtf8 => "invalid UTF-8 string field",
            Self::MessageTooLarge => "message exceeds the protobuf size ceiling",
            Self::RecursionLimitExceeded => "decoder recursion safeguard exceeded",
            Self::UnknownFieldLimitExceeded => "decoder unknown-field safeguard exceeded",
            Self::ElementMemoryLimitExceeded => "decoder element-memory safeguard exceeded",
            Self::InvalidGroup => "invalid protobuf group",
            Self::Other => "other protobuf decode failure",
        }
    }
}

/// Opaque, redacted protobuf decoding error.
#[derive(Clone, PartialEq, Eq)]
pub struct DecodeError {
    kind: DecodeErrorKind,
}

impl DecodeError {
    /// Return the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> DecodeErrorKind {
        self.kind
    }

    fn from_buffa(error: buffa::DecodeError) -> Self {
        let kind = match error {
            buffa::DecodeError::UnexpectedEof => DecodeErrorKind::UnexpectedEnd,
            buffa::DecodeError::VarintTooLong => DecodeErrorKind::InvalidVarint,
            buffa::DecodeError::InvalidWireType(_) => DecodeErrorKind::InvalidWireType,
            buffa::DecodeError::InvalidFieldNumber => DecodeErrorKind::InvalidFieldNumber,
            buffa::DecodeError::MessageTooLarge => DecodeErrorKind::MessageTooLarge,
            buffa::DecodeError::WireTypeMismatch { .. } => DecodeErrorKind::UnexpectedWireType,
            buffa::DecodeError::InvalidUtf8 => DecodeErrorKind::InvalidUtf8,
            buffa::DecodeError::RecursionLimitExceeded => DecodeErrorKind::RecursionLimitExceeded,
            buffa::DecodeError::InvalidEndGroup(_) => DecodeErrorKind::InvalidGroup,
            buffa::DecodeError::UnknownFieldLimitExceeded => {
                DecodeErrorKind::UnknownFieldLimitExceeded
            }
            buffa::DecodeError::ElementMemoryLimitExceeded => {
                DecodeErrorKind::ElementMemoryLimitExceeded
            }
            _ => DecodeErrorKind::Other,
        };
        Self { kind }
    }
}

impl fmt::Debug for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "protobuf decode failed: {}",
            self.kind.description()
        )
    }
}

impl std::error::Error for DecodeError {}

/// Stable categories for protobuf encoding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeErrorKind {
    /// The encoded message would exceed the protobuf size ceiling.
    MessageTooLarge,
    /// An encoder failure did not match another stable category.
    Other,
}

impl EncodeErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::MessageTooLarge => "message exceeds the protobuf size ceiling",
            Self::Other => "other protobuf encode failure",
        }
    }
}

/// Opaque, redacted protobuf encoding error.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodeError {
    kind: EncodeErrorKind,
}

impl EncodeError {
    /// Return the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> EncodeErrorKind {
        self.kind
    }

    const fn message_too_large() -> Self {
        Self {
            kind: EncodeErrorKind::MessageTooLarge,
        }
    }

    const fn other() -> Self {
        Self {
            kind: EncodeErrorKind::Other,
        }
    }
}

impl fmt::Debug for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodeError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "protobuf encode failed: {}",
            self.kind.description()
        )
    }
}

impl std::error::Error for EncodeError {}

fn algorithm_wire_value(algorithm: AlgorithmId) -> i32 {
    match algorithm {
        AlgorithmId::Ed25519 => 1,
        AlgorithmId::EcdsaP256Sha256 => 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SizeComputationOverflow;

#[derive(Debug, Default)]
struct CheckedSizeSink {
    size: u64,
    overflowed: bool,
}

impl CheckedSizeSink {
    fn add_u64(&mut self, amount: u64) {
        match self.size.checked_add(amount) {
            Some(size) => self.size = size,
            None => self.overflowed = true,
        }
    }

    fn add_usize(&mut self, amount: usize) {
        match u64::try_from(amount) {
            Ok(amount) => self.add_u64(amount),
            Err(_) => self.overflowed = true,
        }
    }

    fn finish(self) -> Result<u64, SizeComputationOverflow> {
        if self.overflowed {
            Err(SizeComputationOverflow)
        } else {
            Ok(self.size)
        }
    }
}

impl buffa::EncodeSink for CheckedSizeSink {
    fn put_u8(&mut self, _: u8) {
        self.add_u64(1);
    }

    fn put_slice(&mut self, source: &[u8]) {
        self.add_usize(source.len());
    }

    fn put_u32_le(&mut self, _: u32) {
        self.add_u64(4);
    }

    fn put_u64_le(&mut self, _: u64) {
        self.add_u64(8);
    }
}

/// Check a complete encoded protobuf message size against the facade's format
/// ceiling.
///
/// This check does not apply [`ArtifactResourceLimits`]. Resource-aware output
/// paths compute an exact size, apply their selected resource policy, and then
/// call this function so a format rejection remains an [`EncodeError`].
pub fn check_encoded_message_size(encoded_size: usize) -> Result<usize, EncodeError> {
    let encoded_size_u64 =
        u64::try_from(encoded_size).map_err(|_| EncodeError::message_too_large())?;
    if encoded_size_u64 > u64::from(buffa::MAX_MESSAGE_BYTES) {
        Err(EncodeError::message_too_large())
    } else {
        Ok(encoded_size)
    }
}

fn check_protobuf_size(raw_size: u64) -> Result<usize, EncodeError> {
    let encoded_size = usize::try_from(raw_size).map_err(|_| EncodeError::message_too_large())?;
    check_encoded_message_size(encoded_size)
}

fn push_varint(destination: &mut impl buffa::EncodeSink, mut value: u64) {
    while value >= 0x80 {
        destination.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    destination.put_u8(value as u8);
}

fn push_tag(destination: &mut impl buffa::EncodeSink, field_number: u32, wire_type: u8) {
    push_varint(
        destination,
        (u64::from(field_number) << 3) | u64::from(wire_type),
    );
}

fn push_len_field(
    destination: &mut impl buffa::EncodeSink,
    field_number: u32,
    value: &[u8],
) -> Result<(), SizeComputationOverflow> {
    let value_len = u64::try_from(value.len()).map_err(|_| SizeComputationOverflow)?;
    push_tag(destination, field_number, 2);
    push_varint(destination, value_len);
    destination.put_slice(value);
    Ok(())
}

trait FacadeEncode {
    fn write_facade_wire(
        &self,
        destination: &mut impl buffa::EncodeSink,
    ) -> Result<(), SizeComputationOverflow>;
}

fn raw_facade_encoded_len(value: &impl FacadeEncode) -> Result<u64, SizeComputationOverflow> {
    let mut counter = CheckedSizeSink::default();
    value.write_facade_wire(&mut counter)?;
    counter.finish()
}

fn facade_encoded_len(value: &impl FacadeEncode) -> Result<usize, EncodeError> {
    let raw_size = raw_facade_encoded_len(value).map_err(|_| EncodeError::message_too_large())?;
    check_protobuf_size(raw_size)
}

fn resource_facade_encoded_len(
    value: &impl FacadeEncode,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    let raw_size = match raw_facade_encoded_len(value) {
        Ok(size) => size,
        Err(_) => {
            return Err(limits.size_computation_overflow(ArtifactResourceForm::Protobuf));
        }
    };
    resource_protobuf_size_preflight(raw_size, limits)
}

fn resource_protobuf_size_preflight(
    raw_size: u64,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    let platform_maximum = u64::try_from(usize::MAX).unwrap_or(u64::MAX);
    resource_protobuf_size_preflight_for_platform(raw_size, platform_maximum, limits)
}

fn resource_raw_outer_size_preflight(
    raw_size: u64,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    resource_protobuf_size_preflight(raw_size, limits)
}

fn resource_protobuf_size_preflight_for_platform(
    raw_size: u64,
    platform_maximum: u64,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    if raw_size > platform_maximum {
        return Err(limits.size_computation_overflow(ArtifactResourceForm::Protobuf));
    }
    let encoded_len = usize::try_from(raw_size)
        .map_err(|_| limits.size_computation_overflow(ArtifactResourceForm::Protobuf))?;
    limits.check_output_size(ArtifactResourceForm::Protobuf, encoded_len)?;
    Ok(check_protobuf_size(raw_size))
}

fn encode_facade_to_vec(value: &impl FacadeEncode) -> Result<Vec<u8>, EncodeError> {
    let encoded_len = facade_encoded_len(value)?;
    let mut destination = Vec::with_capacity(encoded_len);
    value
        .write_facade_wire(&mut destination)
        .map_err(|_| EncodeError::message_too_large())?;
    debug_assert_eq!(destination.len(), encoded_len);
    Ok(destination)
}

fn encode_facade_into(
    value: &impl FacadeEncode,
    destination: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let encoded_len = facade_encoded_len(value)?;
    let original_len = destination.len();
    destination.reserve(encoded_len);
    match value.write_facade_wire(destination) {
        Ok(()) => {
            debug_assert_eq!(destination.len() - original_len, encoded_len);
            Ok(())
        }
        Err(_) => {
            destination.truncate(original_len);
            Err(EncodeError::message_too_large())
        }
    }
}

fn encode_facade_to_vec_with_resource_limits(
    value: &impl FacadeEncode,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, EncodeError>> {
    let encoded_len = match resource_facade_encoded_len(value, limits)? {
        Ok(size) => size,
        Err(error) => return Ok(Err(error)),
    };
    let mut destination = Vec::with_capacity(encoded_len);
    if value.write_facade_wire(&mut destination).is_err() {
        return Ok(Err(EncodeError::other()));
    }
    debug_assert_eq!(destination.len(), encoded_len);
    Ok(Ok(destination))
}

fn encode_facade_into_with_resource_limits(
    value: &impl FacadeEncode,
    destination: &mut Vec<u8>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<(), EncodeError>> {
    let encoded_len = match resource_facade_encoded_len(value, limits)? {
        Ok(size) => size,
        Err(error) => return Ok(Err(error)),
    };
    let original_len = destination.len();
    destination.reserve(encoded_len);
    match value.write_facade_wire(destination) {
        Ok(()) => {
            debug_assert_eq!(destination.len() - original_len, encoded_len);
            Ok(Ok(()))
        }
        Err(_) => {
            destination.truncate(original_len);
            Ok(Err(EncodeError::other()))
        }
    }
}

/// Owned `YamlSigilSignature` protobuf message.
#[derive(Clone, PartialEq)]
pub struct YamlSigilSignature {
    algorithm_wire_value: i32,
    keyid: Option<String>,
    signature: Vec<u8>,
    unknown_fields: buffa::UnknownFields,
}

impl Eq for YamlSigilSignature {}

impl Default for YamlSigilSignature {
    fn default() -> Self {
        Self {
            algorithm_wire_value: 0,
            keyid: None,
            signature: Vec::new(),
            unknown_fields: buffa::UnknownFields::new(),
        }
    }
}

impl fmt::Debug for YamlSigilSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YamlSigilSignature")
            .field("algorithm_wire_value", &self.algorithm_wire_value)
            .field("keyid", &self.keyid)
            .field("signature_len", &self.signature.len())
            .field("has_unknown_fields", &self.has_unknown_fields())
            .finish()
    }
}

impl YamlSigilSignature {
    /// Protobuf type URL for this message.
    pub const TYPE_URL: &'static str = "type.googleapis.com/yaml_sigil.v1alpha1.YamlSigilSignature";

    /// Construct a signature message with a recognized algorithm.
    #[must_use]
    pub fn new(algorithm: AlgorithmId, signature: Vec<u8>) -> Self {
        Self {
            algorithm_wire_value: algorithm_wire_value(algorithm),
            signature,
            ..Self::default()
        }
    }

    /// Decode an owned signature message.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        decode_generated_signature(input, &buffa::DecodeOptions::new())
    }

    /// Alias for [`Self::decode`].
    pub fn decode_from_slice(input: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(input)
    }

    /// Return the recognized algorithm, or `None` for zero or an unknown wire value.
    #[must_use]
    pub fn algorithm(&self) -> Option<AlgorithmId> {
        AlgorithmId::from_i32(self.algorithm_wire_value)
    }

    /// Return the raw protobuf enum number, including unknown values.
    #[must_use]
    pub const fn algorithm_wire_value(&self) -> i32 {
        self.algorithm_wire_value
    }

    /// Set the algorithm to a recognized value.
    pub fn set_algorithm(&mut self, algorithm: AlgorithmId) {
        self.algorithm_wire_value = algorithm_wire_value(algorithm);
    }

    /// Set the raw protobuf enum number for forwarding an unknown value.
    pub fn set_algorithm_wire_value(&mut self, algorithm_wire_value: i32) {
        self.algorithm_wire_value = algorithm_wire_value;
    }

    /// Return the optional key identifier exactly as encoded.
    #[must_use]
    pub fn keyid(&self) -> Option<&str> {
        self.keyid.as_deref()
    }

    /// Mutably borrow the optional key identifier.
    pub fn keyid_mut(&mut self) -> Option<&mut String> {
        self.keyid.as_mut()
    }

    /// Replace the optional key identifier.
    pub fn set_keyid(&mut self, keyid: Option<String>) {
        self.keyid = keyid;
    }

    /// Return the raw signature octets.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Mutably borrow the raw signature octets.
    pub fn signature_mut(&mut self) -> &mut Vec<u8> {
        &mut self.signature
    }

    /// Replace the raw signature octets.
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }

    /// Return whether decoding retained any schema-unknown fields.
    #[must_use]
    pub fn has_unknown_fields(&self) -> bool {
        !self.unknown_fields.is_empty()
    }

    /// Discard all schema-unknown fields retained by this message.
    pub fn discard_unknown_fields(&mut self) {
        self.unknown_fields.clear();
    }

    /// Return the encoded protobuf size.
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        facade_encoded_len(self)
    }

    /// Encode into a new byte vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        encode_facade_to_vec(self)
    }

    /// Append the encoded message to a reusable destination.
    ///
    /// If this method returns an error, `destination` is unchanged.
    pub fn encode_into(&self, destination: &mut Vec<u8>) -> Result<(), EncodeError> {
        encode_facade_into(self, destination)
    }

    fn from_generated(generated: GeneratedYamlSigilSignature) -> Self {
        Self {
            algorithm_wire_value: generated.alg.to_i32(),
            keyid: generated.keyid,
            signature: generated.signature,
            unknown_fields: generated.__buffa_unknown_fields,
        }
    }
}

impl FacadeEncode for YamlSigilSignature {
    fn write_facade_wire(
        &self,
        destination: &mut impl buffa::EncodeSink,
    ) -> Result<(), SizeComputationOverflow> {
        if self.algorithm_wire_value != 0 {
            push_tag(destination, 1, 0);
            push_varint(destination, self.algorithm_wire_value as i64 as u64);
        }
        if let Some(keyid) = &self.keyid {
            push_len_field(destination, 2, keyid.as_bytes())?;
        }
        if !self.signature.is_empty() {
            push_len_field(destination, 3, &self.signature)?;
        }
        self.unknown_fields.write_to(destination);
        Ok(())
    }
}

/// Owned `SignedYamlArtifact` protobuf message.
#[derive(Clone, PartialEq)]
pub struct SignedYamlArtifact {
    payload: Vec<u8>,
    signature: Option<YamlSigilSignature>,
    unknown_fields: buffa::UnknownFields,
}

impl Eq for SignedYamlArtifact {}

impl Default for SignedYamlArtifact {
    fn default() -> Self {
        Self {
            payload: Vec::new(),
            signature: None,
            unknown_fields: buffa::UnknownFields::new(),
        }
    }
}

impl fmt::Debug for SignedYamlArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedYamlArtifact")
            .field("payload_len", &self.payload.len())
            .field("signature", &self.signature)
            .field("has_unknown_fields", &self.has_unknown_fields())
            .finish()
    }
}

impl SignedYamlArtifact {
    /// Protobuf type URL for this message.
    pub const TYPE_URL: &'static str = "type.googleapis.com/yaml_sigil.v1alpha1.SignedYamlArtifact";

    /// Construct an artifact from owned payload and signature fields.
    #[must_use]
    pub fn new(payload: Vec<u8>, signature: Option<YamlSigilSignature>) -> Self {
        Self {
            payload,
            signature,
            unknown_fields: buffa::UnknownFields::new(),
        }
    }

    /// Decode an owned artifact.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        decode_generated_artifact(input, &buffa::DecodeOptions::new())
    }

    /// Decode an owned artifact after applying an explicit input policy.
    pub fn decode_with_resource_limits(
        input: &[u8],
        limits: &ArtifactResourceLimits,
    ) -> ArtifactResourceResult<Result<Self, DecodeError>> {
        let input = limits.check_input_size(ArtifactResourceForm::Protobuf, input)?;
        Ok(Self::decode(input))
    }

    /// Alias for [`Self::decode`].
    pub fn decode_from_slice(input: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(input)
    }

    /// Return the arbitrary payload octets.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Mutably borrow the payload octets.
    pub fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.payload
    }

    /// Replace the payload octets.
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    /// Return the optional signature message.
    #[must_use]
    pub fn signature(&self) -> Option<&YamlSigilSignature> {
        self.signature.as_ref()
    }

    /// Mutably borrow the optional signature message.
    pub fn signature_mut(&mut self) -> Option<&mut YamlSigilSignature> {
        self.signature.as_mut()
    }

    /// Replace the optional signature message.
    pub fn set_signature(&mut self, signature: Option<YamlSigilSignature>) {
        self.signature = signature;
    }

    /// Remove and return the optional signature message.
    pub fn take_signature(&mut self) -> Option<YamlSigilSignature> {
        self.signature.take()
    }

    /// Return whether this artifact or its nested signature retained unknown fields.
    #[must_use]
    pub fn has_unknown_fields(&self) -> bool {
        !self.unknown_fields.is_empty()
            || self
                .signature
                .as_ref()
                .is_some_and(YamlSigilSignature::has_unknown_fields)
    }

    /// Discard unknown fields from the artifact and nested signature message.
    pub fn discard_unknown_fields(&mut self) {
        self.unknown_fields.clear();
        if let Some(signature) = &mut self.signature {
            signature.discard_unknown_fields();
        }
    }

    /// Return the encoded protobuf size.
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        facade_encoded_len(self)
    }

    /// Encode into a new byte vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        encode_facade_to_vec(self)
    }

    /// Encode into a new byte vector after applying an explicit output policy.
    pub fn encode_to_vec_with_resource_limits(
        &self,
        limits: &ArtifactResourceLimits,
    ) -> ArtifactResourceResult<Result<Vec<u8>, EncodeError>> {
        encode_facade_to_vec_with_resource_limits(self, limits)
    }

    /// Append the encoded message to a reusable destination.
    ///
    /// If this method returns an error, `destination` is unchanged.
    pub fn encode_into(&self, destination: &mut Vec<u8>) -> Result<(), EncodeError> {
        encode_facade_into(self, destination)
    }

    /// Append after applying an explicit output policy.
    ///
    /// The artifact size excludes pre-existing destination bytes and capacity.
    /// Every returned error leaves `destination` unchanged.
    pub fn encode_into_with_resource_limits(
        &self,
        destination: &mut Vec<u8>,
        limits: &ArtifactResourceLimits,
    ) -> ArtifactResourceResult<Result<(), EncodeError>> {
        encode_facade_into_with_resource_limits(self, destination, limits)
    }

    fn from_generated(generated: GeneratedSignedYamlArtifact) -> Self {
        Self {
            payload: generated.payload,
            signature: generated
                .signature
                .into_option()
                .map(YamlSigilSignature::from_generated),
            unknown_fields: generated.__buffa_unknown_fields,
        }
    }
}

impl FacadeEncode for SignedYamlArtifact {
    fn write_facade_wire(
        &self,
        destination: &mut impl buffa::EncodeSink,
    ) -> Result<(), SizeComputationOverflow> {
        if !self.payload.is_empty() {
            push_len_field(destination, 1, &self.payload)?;
        }
        if let Some(signature) = &self.signature {
            let signature_len = raw_facade_encoded_len(signature)?;
            push_tag(destination, 2, 2);
            push_varint(destination, signature_len);
            signature.write_facade_wire(destination)?;
        }
        self.unknown_fields.write_to(destination);
        Ok(())
    }
}

/// Zero-copy borrowed view of a `SignedYamlArtifact` protobuf message.
///
/// The view cannot outlive the input buffer:
///
/// ```compile_fail
/// use yaml_sigil_core::pb::SignedYamlArtifactRef;
///
/// fn invalid() -> SignedYamlArtifactRef<'static> {
///     let wire = vec![0x12, 0x00];
///     SignedYamlArtifactRef::decode(&wire).unwrap()
/// }
/// ```
pub struct SignedYamlArtifactRef<'a> {
    inner: GeneratedSignedYamlArtifactView<'a>,
}

impl fmt::Debug for SignedYamlArtifactRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedYamlArtifactRef")
            .field("payload_len", &self.payload().len())
            .field("has_signature", &self.signature().is_some())
            .field("has_unknown_fields", &self.has_unknown_fields())
            .finish()
    }
}

impl<'a> SignedYamlArtifactRef<'a> {
    /// Decode a borrowed artifact view without copying byte fields.
    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        decode_generated_artifact_ref(input, &buffa::DecodeOptions::new())
    }

    /// Decode a borrowed view after applying an explicit input policy.
    pub fn decode_with_resource_limits(
        input: &'a [u8],
        limits: &ArtifactResourceLimits,
    ) -> ArtifactResourceResult<Result<Self, DecodeError>> {
        let input = limits.check_input_size(ArtifactResourceForm::Protobuf, input)?;
        Ok(Self::decode(input))
    }

    /// Alias for [`Self::decode`].
    pub fn decode_from_slice(input: &'a [u8]) -> Result<Self, DecodeError> {
        Self::decode(input)
    }

    /// Return the arbitrary payload octets borrowed from the input.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.inner.payload
    }

    /// Return the optional borrowed signature message.
    #[must_use]
    pub fn signature(&self) -> Option<YamlSigilSignatureRef<'_>> {
        self.inner
            .signature
            .as_option()
            .map(|inner| YamlSigilSignatureRef {
                inner: SignatureRefInner::Nested(inner),
            })
    }

    /// Return whether this artifact or its nested signature retained unknown fields.
    #[must_use]
    pub fn has_unknown_fields(&self) -> bool {
        !self.inner.__buffa_unknown_fields.is_empty()
            || self
                .inner
                .signature
                .as_option()
                .is_some_and(|signature| !signature.__buffa_unknown_fields.is_empty())
    }

    /// Copy borrowed fields once into the corresponding owned facade type.
    pub fn to_owned(&self) -> Result<SignedYamlArtifact, DecodeError> {
        self.inner
            .to_owned_message()
            .map(SignedYamlArtifact::from_generated)
            .map_err(DecodeError::from_buffa)
    }

    /// Return the encoded protobuf size after normal protobuf merge semantics.
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        facade_encoded_len(self)
    }

    /// Re-encode the borrowed view into a new byte vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        encode_facade_to_vec(self)
    }

    /// Re-encode into a new byte vector after applying an explicit output policy.
    pub fn encode_to_vec_with_resource_limits(
        &self,
        limits: &ArtifactResourceLimits,
    ) -> ArtifactResourceResult<Result<Vec<u8>, EncodeError>> {
        encode_facade_to_vec_with_resource_limits(self, limits)
    }

    /// Append the re-encoded view to a reusable destination.
    ///
    /// If this method returns an error, `destination` is unchanged.
    pub fn encode_into(&self, destination: &mut Vec<u8>) -> Result<(), EncodeError> {
        encode_facade_into(self, destination)
    }

    /// Append after applying an explicit output policy.
    ///
    /// The artifact size excludes pre-existing destination bytes and capacity.
    /// Every returned error leaves `destination` unchanged.
    pub fn encode_into_with_resource_limits(
        &self,
        destination: &mut Vec<u8>,
        limits: &ArtifactResourceLimits,
    ) -> ArtifactResourceResult<Result<(), EncodeError>> {
        encode_facade_into_with_resource_limits(self, destination, limits)
    }
}

impl FacadeEncode for SignedYamlArtifactRef<'_> {
    fn write_facade_wire(
        &self,
        destination: &mut impl buffa::EncodeSink,
    ) -> Result<(), SizeComputationOverflow> {
        if !self.inner.payload.is_empty() {
            push_len_field(destination, 1, self.inner.payload)?;
        }
        if let Some(signature) = self.signature() {
            let signature_len = raw_facade_encoded_len(&signature)?;
            push_tag(destination, 2, 2);
            push_varint(destination, signature_len);
            signature.write_facade_wire(destination)?;
        }
        self.inner.__buffa_unknown_fields.write_to(destination);
        Ok(())
    }
}

enum SignatureRefInner<'a> {
    Direct(GeneratedYamlSigilSignatureView<'a>),
    Nested(&'a GeneratedYamlSigilSignatureView<'a>),
}

/// Zero-copy borrowed view of a `YamlSigilSignature` protobuf message.
pub struct YamlSigilSignatureRef<'a> {
    inner: SignatureRefInner<'a>,
}

impl fmt::Debug for YamlSigilSignatureRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YamlSigilSignatureRef")
            .field("algorithm_wire_value", &self.algorithm_wire_value())
            .field("keyid", &self.keyid())
            .field("signature_len", &self.signature().len())
            .field("has_unknown_fields", &self.has_unknown_fields())
            .finish()
    }
}

impl<'a> YamlSigilSignatureRef<'a> {
    /// Decode a borrowed signature view without copying string or byte fields.
    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        decode_generated_signature_ref(input, &buffa::DecodeOptions::new())
    }

    /// Alias for [`Self::decode`].
    pub fn decode_from_slice(input: &'a [u8]) -> Result<Self, DecodeError> {
        Self::decode(input)
    }

    fn generated(&self) -> &GeneratedYamlSigilSignatureView<'a> {
        match &self.inner {
            SignatureRefInner::Direct(inner) => inner,
            SignatureRefInner::Nested(inner) => inner,
        }
    }

    /// Return the recognized algorithm, or `None` for zero or an unknown wire value.
    #[must_use]
    pub fn algorithm(&self) -> Option<AlgorithmId> {
        AlgorithmId::from_i32(self.algorithm_wire_value())
    }

    /// Return the raw protobuf enum number, including unknown values.
    #[must_use]
    pub fn algorithm_wire_value(&self) -> i32 {
        self.generated().alg.to_i32()
    }

    /// Return the optional key identifier borrowed from the input.
    #[must_use]
    pub fn keyid(&self) -> Option<&'a str> {
        self.generated().keyid
    }

    /// Return the raw signature octets borrowed from the input.
    #[must_use]
    pub fn signature(&self) -> &'a [u8] {
        self.generated().signature
    }

    /// Return whether decoding retained any schema-unknown fields.
    #[must_use]
    pub fn has_unknown_fields(&self) -> bool {
        !self.generated().__buffa_unknown_fields.is_empty()
    }

    /// Copy borrowed fields once into the corresponding owned facade type.
    pub fn to_owned(&self) -> Result<YamlSigilSignature, DecodeError> {
        self.generated()
            .to_owned_message()
            .map(YamlSigilSignature::from_generated)
            .map_err(DecodeError::from_buffa)
    }

    /// Return the encoded protobuf size after normal protobuf merge semantics.
    pub fn encoded_len(&self) -> Result<usize, EncodeError> {
        facade_encoded_len(self)
    }

    /// Re-encode the borrowed view into a new byte vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        encode_facade_to_vec(self)
    }

    /// Append the re-encoded view to a reusable destination.
    ///
    /// If this method returns an error, `destination` is unchanged.
    pub fn encode_into(&self, destination: &mut Vec<u8>) -> Result<(), EncodeError> {
        encode_facade_into(self, destination)
    }
}

impl FacadeEncode for YamlSigilSignatureRef<'_> {
    fn write_facade_wire(
        &self,
        destination: &mut impl buffa::EncodeSink,
    ) -> Result<(), SizeComputationOverflow> {
        let generated = self.generated();
        let algorithm_wire_value = generated.alg.to_i32();
        if algorithm_wire_value != 0 {
            push_tag(destination, 1, 0);
            push_varint(destination, algorithm_wire_value as i64 as u64);
        }
        if let Some(keyid) = generated.keyid {
            push_len_field(destination, 2, keyid.as_bytes())?;
        }
        if !generated.signature.is_empty() {
            push_len_field(destination, 3, generated.signature)?;
        }
        generated.__buffa_unknown_fields.write_to(destination);
        Ok(())
    }
}

fn decode_generated_artifact(
    input: &[u8],
    options: &buffa::DecodeOptions,
) -> Result<SignedYamlArtifact, DecodeError> {
    options
        .decode_from_slice::<GeneratedSignedYamlArtifact>(input)
        .map(SignedYamlArtifact::from_generated)
        .map_err(DecodeError::from_buffa)
}

fn decode_generated_signature(
    input: &[u8],
    options: &buffa::DecodeOptions,
) -> Result<YamlSigilSignature, DecodeError> {
    options
        .decode_from_slice::<GeneratedYamlSigilSignature>(input)
        .map(YamlSigilSignature::from_generated)
        .map_err(DecodeError::from_buffa)
}

fn decode_generated_artifact_ref<'a>(
    input: &'a [u8],
    options: &buffa::DecodeOptions,
) -> Result<SignedYamlArtifactRef<'a>, DecodeError> {
    options
        .decode_view::<GeneratedSignedYamlArtifactView<'a>>(input)
        .map(|inner| SignedYamlArtifactRef { inner })
        .map_err(DecodeError::from_buffa)
}

fn decode_generated_signature_ref<'a>(
    input: &'a [u8],
    options: &buffa::DecodeOptions,
) -> Result<YamlSigilSignatureRef<'a>, DecodeError> {
    options
        .decode_view::<GeneratedYamlSigilSignatureView<'a>>(input)
        .map(|inner| YamlSigilSignatureRef {
            inner: SignatureRefInner::Direct(inner),
        })
        .map_err(DecodeError::from_buffa)
}

pub(crate) enum RawOuterDecomposeOutcome {
    Malformed,
    Ok {
        payload: Vec<u8>,
        signature_carrier: Vec<u8>,
    },
}

const MAX_PROTOBUF_FIELD_NUMBER: u64 = (1 << 29) - 1;

fn read_varint(bytes: &[u8], mut index: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if shift == 63 {
            if byte > 1 {
                return None;
            }
            result |= u64::from(byte) << 63;
            return Some((result, index));
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((result, index));
        }
        shift += 7;
    }
    None
}

fn read_tag(bytes: &[u8], index: usize) -> Option<(u32, u32, usize)> {
    let (tag, next) = read_varint(bytes, index)?;
    let field = tag >> 3;
    if !(1..=MAX_PROTOBUF_FIELD_NUMBER).contains(&field) {
        return None;
    }
    Some((field as u32, (tag & 7) as u32, next))
}

fn read_length(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let (length, next) = read_varint(bytes, index)?;
    Some((usize::try_from(length).ok()?, next))
}

fn skip_field(wire_type: u32, bytes: &[u8], index: usize) -> Option<usize> {
    match wire_type {
        0 => read_varint(bytes, index).map(|(_, next)| next),
        1 => (index + 8 <= bytes.len()).then_some(index + 8),
        2 => {
            let (length, next) = read_length(bytes, index)?;
            let end = next.checked_add(length)?;
            (end <= bytes.len()).then_some(end)
        }
        5 => (index + 4 <= bytes.len()).then_some(index + 4),
        _ => None,
    }
}

struct RawOuter<'a> {
    payload: &'a [u8],
    signature_carrier: &'a [u8],
}

impl FacadeEncode for RawOuter<'_> {
    fn write_facade_wire(
        &self,
        destination: &mut impl buffa::EncodeSink,
    ) -> Result<(), SizeComputationOverflow> {
        // Raw transcription always emits both fields, including explicit
        // zero-length values. The stable message facade uses protobuf's normal
        // default-value omission rules instead.
        push_len_field(destination, 1, self.payload)?;
        push_len_field(destination, 2, self.signature_carrier)?;
        Ok(())
    }
}

pub(crate) fn compose_raw_outer(payload: &[u8], signature_carrier: &[u8]) -> Vec<u8> {
    let raw = RawOuter {
        payload,
        signature_carrier,
    };
    let raw_size = raw_facade_encoded_len(&raw)
        .expect("two addressable slices have a representable protobuf wire length");
    let encoded_len = usize::try_from(raw_size)
        .expect("two addressable slices have a platform-representable wire length");
    let mut output = Vec::with_capacity(encoded_len);
    raw.write_facade_wire(&mut output)
        .expect("raw outer size was checked before emission");
    debug_assert_eq!(output.len(), encoded_len);
    output
}

pub(crate) fn compose_raw_outer_with_resource_limits(
    payload: &[u8],
    signature_carrier: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, EncodeError>> {
    let raw = RawOuter {
        payload,
        signature_carrier,
    };
    let raw_size = raw_facade_encoded_len(&raw)
        .map_err(|_| limits.size_computation_overflow(ArtifactResourceForm::Protobuf))?;
    let encoded_len = match resource_raw_outer_size_preflight(raw_size, limits)? {
        Ok(size) => size,
        Err(error) => return Ok(Err(error)),
    };

    let mut output = Vec::with_capacity(encoded_len);
    if raw.write_facade_wire(&mut output).is_err() {
        return Ok(Err(EncodeError::other()));
    }
    debug_assert_eq!(output.len(), encoded_len);
    Ok(Ok(output))
}

pub(crate) fn decompose_raw_outer(
    wire: &[u8],
    mode: crate::OuterConformance,
) -> RawOuterDecomposeOutcome {
    let mut payload: Option<Vec<u8>> = None;
    let mut payload_count = 0u32;
    let mut signature_carrier: Option<Vec<u8>> = None;
    let mut signature_count = 0u32;
    let mut index = 0usize;

    while index < wire.len() {
        let (field, wire_type, next) = match read_tag(wire, index) {
            Some(value) => value,
            None => return RawOuterDecomposeOutcome::Malformed,
        };
        index = next;

        if wire_type != 2 {
            if mode == crate::OuterConformance::Strict {
                return RawOuterDecomposeOutcome::Malformed;
            }
            index = match skip_field(wire_type, wire, index) {
                Some(next) => next,
                None => return RawOuterDecomposeOutcome::Malformed,
            };
            continue;
        }

        let (length, next) = match read_length(wire, index) {
            Some(value) => value,
            None => return RawOuterDecomposeOutcome::Malformed,
        };
        index = next;
        if index.checked_add(length).is_none_or(|end| end > wire.len()) {
            return RawOuterDecomposeOutcome::Malformed;
        }
        let value = &wire[index..index + length];
        index += length;

        match field {
            1 => {
                payload_count += 1;
                if mode == crate::OuterConformance::Strict && payload_count > 1 {
                    return RawOuterDecomposeOutcome::Malformed;
                }
                payload = Some(value.to_vec());
            }
            2 => {
                signature_count += 1;
                if signature_count > 1 {
                    return RawOuterDecomposeOutcome::Malformed;
                }
                signature_carrier = Some(value.to_vec());
            }
            _ => {
                if mode == crate::OuterConformance::Strict {
                    return RawOuterDecomposeOutcome::Malformed;
                }
            }
        }
    }

    match signature_carrier {
        Some(signature_carrier) => RawOuterDecomposeOutcome::Ok {
            payload: payload.unwrap_or_default(),
            signature_carrier,
        },
        None => RawOuterDecomposeOutcome::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    fn assert_send_sync<T: Send + Sync>() {}

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(NonZeroUsize::new(maximum).unwrap())
    }

    #[test]
    fn public_message_types_are_send_and_sync() {
        assert_send_sync::<DecodeErrorKind>();
        assert_send_sync::<DecodeError>();
        assert_send_sync::<EncodeErrorKind>();
        assert_send_sync::<EncodeError>();
        assert_send_sync::<SignedYamlArtifact>();
        assert_send_sync::<YamlSigilSignature>();
        assert_send_sync::<SignedYamlArtifactRef<'static>>();
        assert_send_sync::<YamlSigilSignatureRef<'static>>();
    }

    #[test]
    fn facade_encode_failure_is_transactional() {
        use std::cell::Cell;

        struct Rejected;

        impl FacadeEncode for Rejected {
            fn write_facade_wire(
                &self,
                _: &mut impl buffa::EncodeSink,
            ) -> Result<(), SizeComputationOverflow> {
                Err(SizeComputationOverflow)
            }
        }

        let mut destination = vec![1, 2, 3];
        let before = destination.clone();
        assert!(encode_facade_into(&Rejected, &mut destination).is_err());
        assert_eq!(destination, before);

        struct FailsDuringEmission {
            calls: Cell<usize>,
        }

        impl FacadeEncode for FailsDuringEmission {
            fn write_facade_wire(
                &self,
                destination: &mut impl buffa::EncodeSink,
            ) -> Result<(), SizeComputationOverflow> {
                destination.put_slice(&[4, 5, 6]);
                let call = self.calls.get();
                self.calls.set(call + 1);
                if call == 0 {
                    Ok(())
                } else {
                    Err(SizeComputationOverflow)
                }
            }
        }

        let error = encode_facade_into(
            &FailsDuringEmission {
                calls: Cell::new(0),
            },
            &mut destination,
        )
        .unwrap_err();
        assert_eq!(error.kind(), EncodeErrorKind::MessageTooLarge);
        assert_eq!(destination, before);

        let mut destination = before.clone();
        let error = encode_facade_into_with_resource_limits(
            &FailsDuringEmission {
                calls: Cell::new(0),
            },
            &mut destination,
            &ArtifactResourceLimits::unbounded(),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), EncodeErrorKind::Other);
        assert_eq!(destination, before);
    }

    #[test]
    fn synthetic_raw_sizes_preserve_resource_then_format_precedence() {
        let raw_size = u64::from(buffa::MAX_MESSAGE_BYTES) + 1;
        let resource_error = resource_raw_outer_size_preflight(raw_size, &finite(1)).unwrap_err();
        assert_eq!(
            resource_error.kind(),
            crate::ArtifactResourceErrorKind::OutputArtifactTooLarge
        );
        assert_eq!(
            resource_error.observed_or_projected_artifact_bytes(),
            usize::try_from(raw_size).ok()
        );

        let inner =
            resource_raw_outer_size_preflight(raw_size, &ArtifactResourceLimits::unbounded())
                .unwrap()
                .unwrap_err();
        assert_eq!(inner.kind(), EncodeErrorKind::MessageTooLarge);
    }

    #[test]
    fn public_format_size_check_is_exact_at_the_ceiling() {
        let maximum = usize::try_from(buffa::MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(check_encoded_message_size(maximum), Ok(maximum));
        assert_eq!(
            check_encoded_message_size(maximum + 1).unwrap_err().kind(),
            EncodeErrorKind::MessageTooLarge
        );
    }

    #[test]
    fn counting_sink_detects_u64_accumulation_overflow() {
        let mut counter = CheckedSizeSink {
            size: u64::MAX,
            overflowed: false,
        };
        buffa::EncodeSink::put_u8(&mut counter, 0);
        assert_eq!(counter.finish(), Err(SizeComputationOverflow));
    }

    #[test]
    fn resource_preflight_detects_synthetic_platform_size_overflow() {
        let error = resource_protobuf_size_preflight_for_platform(
            17,
            16,
            &ArtifactResourceLimits::unbounded(),
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            crate::ArtifactResourceErrorKind::SizeComputationOverflow
        );
    }

    #[test]
    fn private_decode_options_exercise_runtime_safeguards() {
        #[derive(Clone, Debug, Default, PartialEq)]
        struct ElementChargedMessage;

        buffa::impl_default_instance!(ElementChargedMessage);

        impl buffa::Message for ElementChargedMessage {
            fn compute_size(&self, _: &mut buffa::SizeCache) -> u32 {
                0
            }

            fn write_to(&self, _: &mut buffa::SizeCache, _: &mut impl buffa::EncodeSink) {}

            fn merge_field(
                &mut self,
                tag: buffa::encoding::Tag,
                buffer: &mut impl buffa::bytes::Buf,
                context: buffa::DecodeContext<'_>,
            ) -> Result<(), buffa::DecodeError> {
                buffa::encoding::check_wire_type(tag, buffa::encoding::WireType::Varint)?;
                context.register_element_memory(1)?;
                let _ = buffa::types::decode_int32(buffer)?;
                Ok(())
            }

            fn clear(&mut self) {}
        }

        let carrier = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1])
            .encode_to_vec()
            .unwrap();
        let wire = compose_raw_outer(b"payload", &carrier);

        let recursion = buffa::DecodeOptions::new().with_recursion_limit(0);
        assert_eq!(
            decode_generated_artifact(&wire, &recursion)
                .unwrap_err()
                .kind(),
            DecodeErrorKind::RecursionLimitExceeded
        );

        let size = buffa::DecodeOptions::new().with_max_message_size(wire.len() - 1);
        assert_eq!(
            decode_generated_artifact_ref(&wire, &size)
                .unwrap_err()
                .kind(),
            DecodeErrorKind::MessageTooLarge
        );

        let mut unknown_wire = wire;
        push_tag(&mut unknown_wire, 10, 0);
        push_varint(&mut unknown_wire, 1);
        let unknown = buffa::DecodeOptions::new().with_unknown_field_limit(0);
        assert_eq!(
            decode_generated_artifact(&unknown_wire, &unknown)
                .unwrap_err()
                .kind(),
            DecodeErrorKind::UnknownFieldLimitExceeded
        );

        let element = buffa::DecodeOptions::new().with_element_memory_limit(0);
        let error = element
            .decode_from_slice::<ElementChargedMessage>(&[0x08, 0x01])
            .unwrap_err();
        assert_eq!(
            DecodeError::from_buffa(error).kind(),
            DecodeErrorKind::ElementMemoryLimitExceeded
        );
    }

    #[test]
    fn redacted_errors_contain_categories_only() {
        let error = DecodeError::from_buffa(buffa::DecodeError::WireTypeMismatch {
            field_number: 99,
            expected: 2,
            actual: 0,
        });
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(debug.contains("UnexpectedWireType"));
        assert!(!debug.contains("99"));
        assert!(!display.contains("99"));

        let error = EncodeError::message_too_large();
        assert_eq!(
            format!("{error:?}"),
            "EncodeError { kind: MessageTooLarge, .. }"
        );
        assert_eq!(
            error.to_string(),
            "protobuf encode failed: message exceeds the protobuf size ceiling"
        );
    }
}
