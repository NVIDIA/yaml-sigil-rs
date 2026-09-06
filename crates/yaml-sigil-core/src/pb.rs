// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Stable protobuf messages and zero-copy borrowed views.
//!
//! The generated protobuf implementation is private to `yaml-sigil-core`.
//! Consumers exchange protobuf bytes through these types, so their Buffa
//! dependency version does not become part of this crate's public contract.
//!
//! YamlSigil `v1alpha1` defines no maximum complete artifact size. These
//! entry points add no deployment-specific limit. The protobuf format's own
//! size ceiling and the decoder's implementation safeguards still apply.
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
//! Applications accepting potentially untrusted complete artifacts should
//! select a deployment-appropriate input bound before calling any YamlSigil
//! parser. `4 MiB` is an example and the intended default for future opt-in
//! bounded APIs, not a YamlSigil or gRPC protocol requirement. A deployment
//! can choose a lower value, a higher value, or no additional whole-artifact
//! byte limit.
//!
//! ```
//! use yaml_sigil_core::{
//!     AlgorithmId,
//!     pb::{
//!         DecodeError, SignedYamlArtifact, SignedYamlArtifactRef,
//!         YamlSigilSignature,
//!     },
//! };
//!
//! #[derive(Debug)]
//! enum InputError {
//!     ArtifactTooLarge,
//!     InvalidProtobuf,
//! }
//!
//! impl From<DecodeError> for InputError {
//!     fn from(error: DecodeError) -> Self {
//!         let _ = error;
//!         Self::InvalidProtobuf
//!     }
//! }
//!
//! fn check_artifact_size(
//!     artifact: &[u8],
//!     maximum: Option<usize>,
//! ) -> Result<(), InputError> {
//!     if maximum.is_some_and(|limit| artifact.len() > limit) {
//!         return Err(InputError::ArtifactTooLarge);
//!     }
//!
//!     Ok(())
//! }
//!
//! fn inspect(
//!     input: &[u8],
//!     deployment_limit: Option<usize>,
//! ) -> Result<usize, InputError> {
//!     check_artifact_size(input, deployment_limit)?;
//!     let artifact = SignedYamlArtifactRef::decode(input)?;
//!     Ok(artifact.payload().len())
//! }
//!
//! let signature =
//!     YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
//! let wire = SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature))
//!     .encode_to_vec()
//!     .unwrap();
//!
//! let deployment_limit = Some(4 * 1024 * 1024);
//! assert_eq!(inspect(&wire, deployment_limit).unwrap(), 8);
//!
//! let no_additional_limit = None;
//! assert_eq!(inspect(&wire, no_additional_limit).unwrap(), 8);
//! ```
//!
//! A local whole-artifact rejection does not make an artifact malformed or
//! non-conforming. The `v1alpha1` 16,384-octet YAML signature-carrier
//! constraint is independent of complete artifact size. Protobuf format
//! limits, address-space limits, allocator limits, and deployment controls
//! still apply when an application selects no additional limit.

use std::fmt;

use buffa::{MessageView as _, ViewEncode as _};

use crate::AlgorithmId;
use crate::generated_proto::yaml_sigil::v1alpha1::{
    SignedYamlArtifact as GeneratedSignedYamlArtifact,
    SignedYamlArtifactView as GeneratedSignedYamlArtifactView,
    YamlSigilSignature as GeneratedYamlSigilSignature,
    YamlSigilSignatureView as GeneratedYamlSigilSignatureView,
};

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

    fn from_buffa(error: buffa::EncodeError) -> Self {
        let kind = match error {
            buffa::EncodeError::MessageTooLarge => EncodeErrorKind::MessageTooLarge,
            _ => EncodeErrorKind::Other,
        };
        Self { kind }
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

fn varint_len(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn int32_len(value: i32) -> usize {
    if value < 0 {
        10
    } else {
        varint_len(value as u64)
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, EncodeError> {
    left.checked_add(right)
        .ok_or_else(EncodeError::message_too_large)
}

fn checked_len_field_size(value_len: usize) -> Result<usize, EncodeError> {
    checked_add(checked_add(1, varint_len(value_len as u64))?, value_len)
}

fn check_protobuf_size(size: usize) -> Result<usize, EncodeError> {
    if size > buffa::MAX_MESSAGE_BYTES as usize {
        Err(EncodeError::message_too_large())
    } else {
        Ok(size)
    }
}

fn push_varint(destination: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        destination.push((value as u8) | 0x80);
        value >>= 7;
    }
    destination.push(value as u8);
}

fn push_tag(destination: &mut Vec<u8>, field_number: u32, wire_type: u8) {
    push_varint(
        destination,
        (u64::from(field_number) << 3) | u64::from(wire_type),
    );
}

fn push_len_field(destination: &mut Vec<u8>, field_number: u32, value: &[u8]) {
    push_tag(destination, field_number, 2);
    push_varint(destination, value.len() as u64);
    destination.extend_from_slice(value);
}

trait FacadeEncode {
    fn facade_encoded_len(&self) -> Result<usize, EncodeError>;
    fn write_facade_wire(&self, destination: &mut Vec<u8>);
}

fn encode_facade_to_vec(value: &impl FacadeEncode) -> Result<Vec<u8>, EncodeError> {
    let encoded_len = value.facade_encoded_len()?;
    let mut destination = Vec::with_capacity(encoded_len);
    value.write_facade_wire(&mut destination);
    debug_assert_eq!(destination.len(), encoded_len);
    Ok(destination)
}

fn encode_facade_into(
    value: &impl FacadeEncode,
    destination: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let encoded_len = value.facade_encoded_len()?;
    destination.reserve(encoded_len);
    value.write_facade_wire(destination);
    Ok(())
}

fn encode_view_into(
    destination: &mut Vec<u8>,
    encode: impl FnOnce(&mut Vec<u8>) -> Result<(), buffa::EncodeError>,
) -> Result<(), EncodeError> {
    let original_len = destination.len();
    match encode(destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            destination.truncate(original_len);
            Err(EncodeError::from_buffa(error))
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
        self.facade_encoded_len()
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
    fn facade_encoded_len(&self) -> Result<usize, EncodeError> {
        let mut size = 0usize;
        if self.algorithm_wire_value != 0 {
            size = checked_add(size, checked_add(1, int32_len(self.algorithm_wire_value))?)?;
        }
        if let Some(keyid) = &self.keyid {
            size = checked_add(size, checked_len_field_size(keyid.len())?)?;
        }
        if !self.signature.is_empty() {
            size = checked_add(size, checked_len_field_size(self.signature.len())?)?;
        }
        size = checked_add(size, self.unknown_fields.encoded_len())?;
        check_protobuf_size(size)
    }

    fn write_facade_wire(&self, destination: &mut Vec<u8>) {
        if self.algorithm_wire_value != 0 {
            push_tag(destination, 1, 0);
            push_varint(destination, self.algorithm_wire_value as i64 as u64);
        }
        if let Some(keyid) = &self.keyid {
            push_len_field(destination, 2, keyid.as_bytes());
        }
        if !self.signature.is_empty() {
            push_len_field(destination, 3, &self.signature);
        }
        self.unknown_fields.write_to(destination);
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
        self.facade_encoded_len()
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
    fn facade_encoded_len(&self) -> Result<usize, EncodeError> {
        let mut size = 0usize;
        if !self.payload.is_empty() {
            size = checked_add(size, checked_len_field_size(self.payload.len())?)?;
        }
        if let Some(signature) = &self.signature {
            size = checked_add(size, checked_len_field_size(signature.encoded_len()?)?)?;
        }
        size = checked_add(size, self.unknown_fields.encoded_len())?;
        check_protobuf_size(size)
    }

    fn write_facade_wire(&self, destination: &mut Vec<u8>) {
        if !self.payload.is_empty() {
            push_len_field(destination, 1, &self.payload);
        }
        if let Some(signature) = &self.signature {
            push_tag(destination, 2, 2);
            let signature_len = signature
                .facade_encoded_len()
                .expect("artifact size validation already checked its signature");
            push_varint(destination, signature_len as u64);
            signature.write_facade_wire(destination);
        }
        self.unknown_fields.write_to(destination);
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
        self.inner
            .try_encoded_len()
            .map(|size| size as usize)
            .map_err(EncodeError::from_buffa)
    }

    /// Re-encode the borrowed view into a new byte vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        self.inner
            .try_encode_to_vec()
            .map_err(EncodeError::from_buffa)
    }

    /// Append the re-encoded view to a reusable destination.
    ///
    /// If this method returns an error, `destination` is unchanged.
    pub fn encode_into(&self, destination: &mut Vec<u8>) -> Result<(), EncodeError> {
        encode_view_into(destination, |destination| {
            self.inner.try_encode(destination)
        })
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
        self.generated()
            .try_encoded_len()
            .map(|size| size as usize)
            .map_err(EncodeError::from_buffa)
    }

    /// Re-encode the borrowed view into a new byte vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        self.generated()
            .try_encode_to_vec()
            .map_err(EncodeError::from_buffa)
    }

    /// Append the re-encoded view to a reusable destination.
    ///
    /// If this method returns an error, `destination` is unchanged.
    pub fn encode_into(&self, destination: &mut Vec<u8>) -> Result<(), EncodeError> {
        encode_view_into(destination, |destination| {
            self.generated().try_encode(destination)
        })
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

pub(crate) fn compose_raw_outer(payload: &[u8], signature_carrier: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    push_len_field(&mut output, 1, payload);
    push_len_field(&mut output, 2, signature_carrier);
    output
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

    fn assert_send_sync<T: Send + Sync>() {}

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
        struct Rejected;

        impl FacadeEncode for Rejected {
            fn facade_encoded_len(&self) -> Result<usize, EncodeError> {
                Err(EncodeError::message_too_large())
            }

            fn write_facade_wire(&self, _: &mut Vec<u8>) {
                panic!("failed size calculation must prevent a write");
            }
        }

        let mut destination = vec![1, 2, 3];
        let before = destination.clone();
        assert!(encode_facade_into(&Rejected, &mut destination).is_err());
        assert_eq!(destination, before);

        let error = encode_view_into(&mut destination, |destination| {
            destination.extend_from_slice(&[4, 5, 6]);
            Err(buffa::EncodeError::MessageTooLarge)
        })
        .unwrap_err();
        assert_eq!(error.kind(), EncodeErrorKind::MessageTooLarge);
        assert_eq!(destination, before);
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
