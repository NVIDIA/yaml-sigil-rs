// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign YamlSigil `v1alpha1` YAML and protobuf artifacts with Ed25519 or
//! ECDSA P-256 SHA-256.
//! Signed-artifact transcoding lives in [`transcription`].
//!
//! Request-shape failures are [`SignInvocationError`]; sign-time failures are
//! [`SignError`], plus the YAML serialization extension. Resource-aware
//! protobuf output preserves the core facade's [`yaml_sigil_core::pb::EncodeError`]
//! in a separate inner result layer.
//!
//! Use [`sign_yaml`] or [`sign_proto`] to call [`sign`] with a fixed
//! [`OutputForm`].
//!
//! Default P-256 signing samples a fresh nonce from the system CSPRNG for each
//! signature, using Web Crypto on browser and Node.js WebAssembly targets.
//! Entropy failure returns [`SignError::KeyOperationFailure`]. Ed25519 signing
//! remains deterministic.
//!
//! # Resource boundaries
//!
//! Existing signing entry points retain their unbounded complete-output
//! behavior. [`sign_with_resource_limits`], [`sign_yaml_with_resource_limits`],
//! and [`sign_proto_with_resource_limits`] apply an explicitly selected policy
//! before avoidable content processing, cryptography, and complete-output
//! allocation. This policy is operational hardening, not YamlSigil `v1alpha1`
//! conformance.
//!
//! # Local providers
//!
//! [`ProviderSigningKeyBuilder`] validates public-key bytes without storing a
//! signer. [`sign_with_provider`] accepts a callback for each operation and
//! independently verifies its output. [`sign_with_unqualified_provider`] names
//! the deliberate bypass. Message callbacks receive the final payload bytes;
//! [`sign_with_p256_digest_provider`] supplies their SHA-256 digest instead.
//! Callbacks may borrow mutable local state. [`signature_signing_callback`]
//! forwards existing `signature` 3.0 adapters. See [`provider`] for the public
//! contract and compiling local and shared examples.
//!
//! [`async_provider`] supplies an awaitable signing contract and provider-backed
//! implementations of [`AsyncSigner`]. Sync and async provider signing also
//! offer explicit `_and_resource_limits` operations with the same preflight
//! and final output checks as [`sign_with_resource_limits`]. The
//! [provider guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/crypto-providers.md)
//! compares qualified, unqualified, and direct trait integrations.

pub mod async_provider;
mod proto_carrier;
pub mod provider;
mod provider_crypto;
pub mod transcription;

#[cfg(test)]
mod callback_tests;

pub use async_provider::{
    AsyncProviderSignRequest, AsyncProviderSigner, AsyncProviderSigningKey,
    AsyncProviderSigningKeyBuilder, AsyncProviderSigningKeys, ProviderAsyncSigner,
    UnqualifiedAsyncProviderSignRequest, UnqualifiedAsyncProviderSigningKey,
    UnqualifiedAsyncProviderSigningKeys, UnqualifiedProviderAsyncSigner, sign_with_async_provider,
    sign_with_async_provider_and_resource_limits, sign_with_unqualified_async_provider,
    sign_with_unqualified_async_provider_and_resource_limits,
};

pub use provider::{
    ProviderSignRequest, ProviderSigningKey, ProviderSigningKeyBuilder, ProviderSigningKeyError,
    ProviderSigningKeyErrorKind, ProviderSigningKeys, UnqualifiedProviderSignRequest,
    UnqualifiedProviderSigningKey, UnqualifiedProviderSigningKeys, signature_signing_callback,
};
pub use transcription::{
    TranscodeError, proto_wire_to_signed_yaml_stream,
    proto_wire_to_signed_yaml_stream_with_resource_limits, signed_yaml_stream_to_proto_wire,
    signed_yaml_stream_to_proto_wire_with_resource_limits,
};

use sha2::{Digest, Sha256};
use tracing::instrument;
pub use yaml_sigil_core::p256_encoding::{
    P256EncodingError, p256_der_signature_to_raw, p256_public_key_to_uncompressed,
};
pub use yaml_sigil_core::pb::{EncodeError, EncodeErrorKind};
pub use yaml_sigil_core::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
use yaml_sigil_core::{SignatureDocument, pb::check_encoded_message_size, validate_payload_stream};
use yaml_sigil_traits::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};

// The portable traits and DTOs live in `yaml-sigil-traits`. This implementation
// binds the generic key-bearing DTOs to its RustCrypto key types while retaining
// the established `yaml_sigil_signing::{SigningKey, SignRequest}` paths.
pub use yaml_sigil_traits::signing::{
    AsyncSigner, OutputForm, SignError, SignInvocationError, SignOutcome, SignSuccess, Signer,
    SignerCapabilities,
};
use yaml_sigil_traits::signing::{
    SignRequest as GenericSignRequest, SigningKey as GenericSigningKey,
};

/// Signing keys supported by this RustCrypto implementation.
pub type SigningKey<'a> = GenericSigningKey<'a, ed25519_dalek::SigningKey, p256::ecdsa::SigningKey>;

/// Unified sign request specialized for this RustCrypto implementation.
pub type SignRequest<'a> =
    GenericSignRequest<'a, ed25519_dalek::SigningKey, p256::ecdsa::SigningKey>;

/// Return the capability set for this crate build.
pub fn signer_capabilities() -> SignerCapabilities {
    SignerCapabilities {
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        supported_output_forms: &[OutputForm::Yaml, OutputForm::Protobuf],
        supported_algorithms: &[AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256],
        best_effort_yaml_validation: false,
        implementation_name: env!("CARGO_PKG_NAME"),
        implementation_version: env!("CARGO_PKG_VERSION"),
    }
}

/// Parameters for producing a signed YAML artifact (convenience wrapper).
pub struct SignYamlParams<'a> {
    pub payload: &'a [u8],
    pub algorithm: AlgorithmId,
    pub key: SigningKey<'a>,
    pub keyid: Option<&'a str>,
    /// If true, a missing trailing `\\n` on a non-empty payload is fixed by appending `0x0A`.
    pub append_missing_final_newline: bool,
}

/// Parameters for producing protobuf `SignedYamlArtifact` wire bytes (convenience wrapper).
pub struct SignProtoParams<'a> {
    pub payload: &'a [u8],
    pub algorithm: AlgorithmId,
    pub key: SigningKey<'a>,
    pub keyid: Option<&'a str>,
    /// Ignored for protobuf output; payload bytes are always preserved exactly.
    pub append_missing_final_newline: bool,
}

fn validate_invocation_parameters<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
) -> Result<(), SignInvocationError> {
    let caps = signer_capabilities();
    if !caps.supported_output_forms.contains(&req.output_form) {
        return Err(SignInvocationError::InvalidOrUnsupportedOutputForm);
    }
    if !caps.supported_algorithms.contains(&req.algorithm) {
        return Err(SignInvocationError::InvalidOrUnsupportedAlgorithm);
    }
    if !req.algorithm_parameters.is_empty() {
        return Err(SignInvocationError::InvalidAlgorithmParameters);
    }
    if let Some(keyid) = req.keyid {
        let octets = keyid.len();
        if octets == 0 || octets > 1024 {
            return Err(SignInvocationError::InvalidKeyid);
        }
    }
    Ok(())
}

fn validate_key_algorithm<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
) -> Result<(), SignInvocationError> {
    match (&req.algorithm, &req.key) {
        (AlgorithmId::Ed25519, GenericSigningKey::Ed25519(_)) => Ok(()),
        (AlgorithmId::EcdsaP256Sha256, GenericSigningKey::EcdsaP256Sha256(_)) => Ok(()),
        _ => Err(SignInvocationError::InvalidOrUnsupportedAlgorithm),
    }
}

fn validate_invocation_shape<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
) -> Result<(), SignInvocationError> {
    validate_invocation_parameters(req)?;
    validate_key_algorithm(req)
}

fn validate_keyid_content<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
) -> Result<(), SignInvocationError> {
    if req.keyid.is_some_and(|keyid| keyid.contains(['\r', '\n'])) {
        Err(SignInvocationError::InvalidKeyid)
    } else {
        Ok(())
    }
}

fn validate_invocation<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
) -> Result<(), SignInvocationError> {
    validate_invocation_parameters(req)?;
    validate_keyid_content(req)?;
    validate_key_algorithm(req)
}

fn normalize_yaml_payload(
    payload: &[u8],
    append_missing_final_newline: bool,
) -> Result<Vec<u8>, SignError> {
    if std::str::from_utf8(payload).is_err() {
        return Err(SignError::InvalidPayloadBytes);
    }
    if payload.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(SignError::InvalidPayloadBytes);
    }
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if payload.ends_with(b"\n") {
        return Ok(payload.to_vec());
    }
    if append_missing_final_newline {
        let mut v = payload.to_vec();
        v.push(b'\n');
        return Ok(v);
    }
    Err(SignError::PayloadLineTerminatorRefusal)
}

const FIXED_SIGNATURE_BYTES: u64 = 64;

fn varint_len(mut value: u64) -> u64 {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn checked_yaml_signing_lower_bound<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<usize> {
    let overflow = || limits.size_computation_overflow(ArtifactResourceForm::Yaml);
    let projected_lf = usize::from(
        !req.payload.is_empty()
            && !req.payload.ends_with(b"\n")
            && req.append_missing_final_newline,
    );
    let minimum_signature_text_len = usize::try_from(FIXED_SIGNATURE_BYTES)
        .ok()
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bits| bits.checked_add(2))
        .map(|rounded| rounded / 3)
        .ok_or_else(overflow)?;
    let mut minimum_carrier_len = "schema: "
        .len()
        .checked_add(yaml_sigil_core::SCHEMA_V1ALPHA1.len())
        .and_then(|size| size.checked_add(1))
        .and_then(|size| size.checked_add("alg: ".len()))
        .and_then(|size| size.checked_add(req.algorithm.as_yaml_str().len()))
        .and_then(|size| size.checked_add(1))
        .ok_or_else(overflow)?;
    if let Some(keyid) = req.keyid {
        minimum_carrier_len = minimum_carrier_len
            .checked_add("keyid: ".len())
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(keyid.len()))
            .and_then(|size| size.checked_add(1))
            .ok_or_else(overflow)?;
    }
    minimum_carrier_len = minimum_carrier_len
        .checked_add("signature: ".len())
        .and_then(|size| size.checked_add(minimum_signature_text_len))
        .and_then(|size| size.checked_add(1))
        .ok_or_else(overflow)?;

    let minimum_artifact_len = req
        .payload
        .len()
        .checked_add(projected_lf)
        .and_then(|size| size.checked_add(4))
        .and_then(|size| size.checked_add(minimum_carrier_len))
        .ok_or_else(overflow)?;
    limits.check_output_size_lower_bound(ArtifactResourceForm::Yaml, minimum_artifact_len)
}

fn checked_len_field_size(value_len: u64) -> Option<u64> {
    1u64.checked_add(varint_len(value_len))
        .and_then(|size| size.checked_add(value_len))
}

fn checked_proto_signing_size<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    let overflow = || limits.size_computation_overflow(ArtifactResourceForm::Protobuf);
    let payload_len = u64::try_from(req.payload.len()).map_err(|_| overflow())?;
    let keyid_len = req
        .keyid
        .map(str::len)
        .map(u64::try_from)
        .transpose()
        .map_err(|_| overflow())?;
    checked_proto_signing_size_from_lengths(payload_len, keyid_len, limits)
}

fn checked_proto_signing_size_from_lengths(
    payload_len: u64,
    keyid_len: Option<u64>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    let overflow = || limits.size_computation_overflow(ArtifactResourceForm::Protobuf);
    let mut carrier_len = 2u64;
    if let Some(keyid_len) = keyid_len {
        carrier_len = carrier_len
            .checked_add(checked_len_field_size(keyid_len).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
    }
    carrier_len = carrier_len
        .checked_add(checked_len_field_size(FIXED_SIGNATURE_BYTES).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;

    let raw_size = checked_len_field_size(payload_len)
        .and_then(|payload_size| {
            checked_len_field_size(carrier_len)
                .and_then(|carrier_size| payload_size.checked_add(carrier_size))
        })
        .ok_or_else(overflow)?;
    let encoded_size = usize::try_from(raw_size).map_err(|_| overflow())?;
    limits.check_output_size(ArtifactResourceForm::Protobuf, encoded_size)?;
    Ok(check_encoded_message_size(encoded_size))
}

fn preflight_signing_output<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    match req.output_form {
        OutputForm::Yaml => Ok(Ok(checked_yaml_signing_lower_bound(req, limits)?)),
        OutputForm::Protobuf => checked_proto_signing_size(req, limits),
    }
}

/// Unified signing entry point corresponding to the IDL `Sign` operation.
///
/// For protobuf output, `append_missing_final_newline` is
/// ignored and the payload bytes are signed and emitted without modification.
///
/// This method does not enforce an implementation-local complete-artifact
/// limit. Use [`sign_with_resource_limits`] to select the shared output policy.
#[instrument(level = "info", skip(req), fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign(req: &SignRequest<'_>) -> SignOutcome {
    sign_inner(req)
}

/// Sign after applying an explicit complete-output resource policy.
///
/// Request-shape validation performs work bounded independently of payload
/// length. Protobuf output is sized exactly before content validation or
/// cryptography. YAML output first applies a conclusive lower bound and then
/// checks the exact serialized result before complete-artifact allocation.
/// The outer result reports resource rejection. The inner result preserves a
/// protobuf format error after resource admission; YAML output always reaches
/// the existing [`SignOutcome`] layer.
#[instrument(level = "info", skip(req, limits), fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_resource_limits(
    req: &SignRequest<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    if let Err(error) = validate_invocation_shape(req) {
        return Ok(Ok(SignOutcome::Invocation(error)));
    }
    if let Err(error) = preflight_signing_output(req, limits)? {
        return Ok(Err(error));
    }
    if let Err(error) = validate_keyid_content(req) {
        return Ok(Ok(SignOutcome::Invocation(error)));
    }
    Ok(Ok(sign_after_invocation_validation(
        req,
        Some(limits),
        |payload| sign_digest(payload, req.algorithm, &req.key),
    )?))
}

/// Sign through a callback and independently verify its output.
///
/// The callback receives the final payload bytes after any authorized YAML
/// final-newline handling. Protobuf payloads are unchanged. Return 64 canonical
/// Ed25519 `R || S` octets or P-256 big-endian `r || s` octets. P-256 callbacks
/// hash the message with SHA-256 once and own the profile's nonce sampling.
///
/// The callback may borrow mutable local state. It runs on the calling thread,
/// may block, and is invoked exactly once if validation reaches signing. No
/// probe or retry is performed. Callback errors become [`SignOutcome::Signer`];
/// malformed or incorrectly bound output becomes [`SignError::KeyOperationFailure`].
/// This entry point has the resource behavior documented on [`sign`].
/// See [`provider`] for compiling local and shared provider examples.
#[instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_provider(
    req: &ProviderSignRequest<'_>,
    callback: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
) -> SignOutcome {
    sign_with_provider_inner(req, None, None, callback)
        .expect("the unbounded signing path cannot return a resource error")
        .expect("the unbounded signing path cannot return a preflight encoding error")
}

/// Sign through the explicitly unqualified provider path.
///
/// This path validates the bound public key and provider signature structure,
/// but it does not cryptographically confirm that a produced signature
/// corresponds to the bound public key and payload. The callback input,
/// encoding, error, blocking, and call-count contracts match [`sign_with_provider`].
#[instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_unqualified_provider(
    req: &UnqualifiedProviderSignRequest<'_>,
    callback: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
) -> SignOutcome {
    sign_with_provider_inner(req, None, None, callback)
        .expect("the unbounded signing path cannot return a resource error")
        .expect("the unbounded signing path cannot return a preflight encoding error")
}

/// Sign with qualified provider output checks and an explicit output policy.
///
/// Uses the request-shape, projected-size, and final exact-size checks of
/// [`sign_with_resource_limits`]. A conclusive size rejection avoids signing.
/// YAML's final check runs after signing but before complete-artifact allocation.
/// All callback contracts match [`sign_with_provider`].
#[instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_provider_and_resource_limits(
    req: &ProviderSignRequest<'_>,
    limits: &ArtifactResourceLimits,
    callback: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    sign_with_provider_inner(req, Some(limits), None, callback)
}

/// Sign without output self-verification and enforce the selected output policy.
///
/// Retains key and signature-structure checks and the resource behavior of
/// [`sign_with_provider_and_resource_limits`].
#[instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_unqualified_provider_and_resource_limits(
    req: &UnqualifiedProviderSignRequest<'_>,
    limits: &ArtifactResourceLimits,
    callback: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    sign_with_provider_inner(req, Some(limits), None, callback)
}

/// Sign the SHA-256 digest of the final payload through a P-256 callback.
///
/// Supply the complete payload in `req`. YamlSigil prepares it exactly as in
/// [`sign_with_provider`], then hashes it once for the callback's `&[u8; 32]`
/// input. The callback must sign those digest bytes without hashing them again
/// and return 64 big-endian `r || s` octets. It owns CSPRNG nonce sampling and
/// provider error mapping. Independent output verification checks the bound
/// public key and final payload, which may hash that payload again.
///
/// Only [`AlgorithmId::EcdsaP256Sha256`] requests are admitted. An Ed25519
/// request returns [`SignInvocationError::InvalidOrUnsupportedAlgorithm`]
/// without invoking the callback. The callback's thread, blocking, error, and
/// call-count contracts match [`sign_with_provider`]. This API does not accept
/// a caller-computed digest in place of the payload.
///
/// # Example
///
/// Wrap your initialized device's digest operation in `device_sign_digest`.
/// Map an SDK failure to [`SignError::KeyOperationFailure`]. The operation must
/// return fixed-width signature bytes and satisfy the profile's nonce rules.
///
/// ```
/// use yaml_sigil_core::AlgorithmId;
/// use yaml_sigil_signing::{
///     OutputForm, ProviderSignRequest, ProviderSigningKeyBuilder,
///     ProviderSigningKeyError, ProviderSigningKeys, SignError, SignOutcome,
///     sign_with_p256_digest_provider,
/// };
///
/// fn sign_document(
///     public_key: &[u8],
///     payload: &[u8],
///     device_sign_digest: impl FnOnce(&[u8; 32]) -> Result<[u8; 64], SignError>,
/// ) -> Result<SignOutcome, ProviderSigningKeyError> {
///     let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public_key).build()?;
///     let request = ProviderSignRequest {
///         payload,
///         algorithm: AlgorithmId::EcdsaP256Sha256,
///         key: ProviderSigningKeys::EcdsaP256Sha256(&key),
///         keyid: None,
///         append_missing_final_newline: true,
///         output_form: OutputForm::Yaml,
///         algorithm_parameters: &[],
///     };
///     // The callback receives SHA-256(payload with its final newline).
///     Ok(sign_with_p256_digest_provider(&request, device_sign_digest))
/// }
/// # // Deterministic signing is only a test fixture for this callback example.
/// # use signature::hazmat::PrehashSigner;
/// # let native_key = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
/// # let public_key = native_key.verifying_key().to_sec1_point(false);
/// # let outcome = sign_document(public_key.as_bytes(), b"device: signed", |digest| {
/// #     let signature: p256::ecdsa::Signature = native_key.sign_prehash(digest)
/// #         .map_err(|_| SignError::KeyOperationFailure)?;
/// #     Ok(signature.to_bytes().into())
/// # }).unwrap();
/// # assert!(matches!(outcome, SignOutcome::Success(_)));
/// ```
#[instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_p256_digest_provider(
    req: &ProviderSignRequest<'_>,
    callback: impl FnOnce(&[u8; 32]) -> Result<[u8; 64], SignError>,
) -> SignOutcome {
    sign_with_provider_inner(
        req,
        None,
        Some(AlgorithmId::EcdsaP256Sha256),
        p256_digest_callback(callback),
    )
    .expect("the unbounded signing path cannot return a resource error")
    .expect("the unbounded signing path cannot return a preflight encoding error")
}

/// Sign a P-256 digest with qualified output checks and an output policy.
///
/// Uses the callback contract of [`sign_with_p256_digest_provider`] and the
/// resource checks of [`sign_with_provider_and_resource_limits`]. A conclusive
/// preflight rejection performs neither digest preparation nor a callback call.
/// YAML's final exact-size rejection may occur after the single callback call.
#[instrument(level = "info", skip_all, fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_p256_digest_provider_and_resource_limits(
    req: &ProviderSignRequest<'_>,
    limits: &ArtifactResourceLimits,
    callback: impl FnOnce(&[u8; 32]) -> Result<[u8; 64], SignError>,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    sign_with_provider_inner(
        req,
        Some(limits),
        Some(AlgorithmId::EcdsaP256Sha256),
        p256_digest_callback(callback),
    )
}

fn p256_digest_callback(
    callback: impl FnOnce(&[u8; 32]) -> Result<[u8; 64], SignError>,
) -> impl FnOnce(&[u8]) -> Result<[u8; 64], SignError> {
    // This adapter changes only the callback input. Preparation, validation,
    // and output verification continue to use the final complete payload.
    |payload| callback(&Sha256::digest(payload).into())
}

fn sign_with_provider_inner<K: provider::BoundKey>(
    req: &GenericSignRequest<'_, K, K>,
    limits: Option<&ArtifactResourceLimits>,
    required_algorithm: Option<AlgorithmId>,
    callback: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    // Bounded operations preserve shape -> size -> content validation order.
    // Unbounded operations retain their existing invocation error precedence.
    let validation = if limits.is_some() {
        validate_invocation_shape(req)
    } else {
        validate_invocation(req)
    };
    if let Err(error) = validation {
        return Ok(Ok(SignOutcome::Invocation(error)));
    }
    let key = match &req.key {
        GenericSigningKey::Ed25519(key) | GenericSigningKey::EcdsaP256Sha256(key) => *key,
    };
    if key.algorithm() != req.algorithm
        || required_algorithm.is_some_and(|algorithm| algorithm != req.algorithm)
    {
        return Ok(Ok(SignOutcome::Invocation(
            SignInvocationError::InvalidOrUnsupportedAlgorithm,
        )));
    }
    if let Some(limits) = limits {
        if let Err(error) = preflight_signing_output(req, limits)? {
            return Ok(Err(error));
        }
        if let Err(error) = validate_keyid_content(req) {
            return Ok(Ok(SignOutcome::Invocation(error)));
        }
    }
    Ok(Ok(sign_after_invocation_validation(
        req,
        limits,
        |payload| key.try_sign(payload, callback),
    )?))
}

fn sign_inner(req: &SignRequest<'_>) -> SignOutcome {
    if let Err(e) = validate_invocation(req) {
        return SignOutcome::Invocation(e);
    }
    sign_after_invocation_validation(req, None, |payload| {
        sign_digest(payload, req.algorithm, &req.key)
    })
    .expect("the unbounded signing path cannot return a resource error")
}

fn sign_after_invocation_validation<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
    limits: Option<&ArtifactResourceLimits>,
    sign_payload: impl FnOnce(&[u8]) -> Result<[u8; 64], SignError>,
) -> ArtifactResourceResult<SignOutcome> {
    let prepared = match prepare_signing_payload(req) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(SignOutcome::Signer(error)),
    };
    let signature = match sign_payload(&prepared.payload) {
        Ok(signature) => signature,
        Err(error) => return Ok(SignOutcome::Signer(error)),
    };
    finish_signing(req, prepared, &signature, limits)
}

struct PreparedSigningPayload {
    payload: Vec<u8>,
    modified_payload: Vec<u8>,
}

// Sync and async operations keep exactly the same prepared bytes through
// signing and framing. An async caller owns this value across its await.
fn prepare_signing_payload<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
) -> Result<PreparedSigningPayload, SignError> {
    // Only YAML output applies the YAML envelope rules: valid UTF-8, no BOM,
    // and a final line terminator. Protobuf payloads are opaque bytes and must
    // bypass both normalization and validation.
    let payload = match req.output_form {
        OutputForm::Yaml => {
            let payload = normalize_yaml_payload(req.payload, req.append_missing_final_newline)?;
            if validate_payload_stream(&payload).is_err() {
                return Err(SignError::InvalidPayloadBytes);
            }
            payload
        }
        OutputForm::Protobuf => req.payload.to_vec(),
    };

    let modified_payload = if req.payload == payload.as_slice() {
        Vec::new()
    } else {
        payload.clone()
    };

    Ok(PreparedSigningPayload {
        payload,
        modified_payload,
    })
}

fn finish_signing<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
    prepared: PreparedSigningPayload,
    sig_bytes: &[u8; 64],
    limits: Option<&ArtifactResourceLimits>,
) -> ArtifactResourceResult<SignOutcome> {
    let PreparedSigningPayload {
        payload,
        modified_payload,
    } = prepared;

    let artifact = match req.output_form {
        OutputForm::Yaml => {
            let emitted = if let Some(limits) = limits {
                emit_yaml_artifact_with_resource_limits(&payload, req, sig_bytes, limits)?
            } else {
                emit_yaml_artifact(&payload, req, sig_bytes)
            };
            match emitted {
                Ok(artifact) => artifact,
                Err(error) => return Ok(SignOutcome::Signer(error)),
            }
        }
        OutputForm::Protobuf => match emit_proto_artifact(&payload, req, sig_bytes) {
            Ok(a) => a,
            Err(e) => return Ok(SignOutcome::Signer(e)),
        },
    };

    Ok(SignOutcome::Success(SignSuccess {
        artifact,
        modified_payload,
    }))
}

fn emit_yaml_artifact<Ed25519: ?Sized, P256: ?Sized>(
    payload: &[u8],
    req: &GenericSignRequest<'_, Ed25519, P256>,
    sig_bytes: &[u8],
) -> Result<Vec<u8>, SignError> {
    let body = serialize_yaml_signature_carrier(req, sig_bytes)?;

    match yaml_sigil_transcription::compose(&yaml_sigil_transcription::ComposeRequest {
        payload,
        signature_carrier: body.as_bytes(),
        form: yaml_sigil_transcription::TranscriptionForm::Yaml,
    }) {
        yaml_sigil_transcription::ComposeOutcome::Success(s) => Ok(s.artifact),
        yaml_sigil_transcription::ComposeOutcome::Invocation(_)
        | yaml_sigil_transcription::ComposeOutcome::Error(_) => {
            Err(SignError::YamlSerialize("compose failed".into()))
        }
    }
}

fn serialize_yaml_signature_carrier<Ed25519: ?Sized, P256: ?Sized>(
    req: &GenericSignRequest<'_, Ed25519, P256>,
    sig_bytes: &[u8],
) -> Result<String, SignError> {
    let doc = SignatureDocument {
        schema: yaml_sigil_core::SCHEMA_V1ALPHA1.to_string(),
        alg: req.algorithm.as_yaml_str().to_string(),
        keyid: req.keyid.map(|s| s.to_string()),
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sig_bytes,
        ),
    };

    let mut body = yaml_sigil_core::serialize_signature_document(&doc)
        .map_err(|e| SignError::YamlSerialize(e.to_string()))?;
    if !body.ends_with('\n') {
        body.push('\n');
    }
    Ok(body)
}

fn emit_yaml_artifact_with_resource_limits<Ed25519: ?Sized, P256: ?Sized>(
    payload: &[u8],
    req: &GenericSignRequest<'_, Ed25519, P256>,
    sig_bytes: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, SignError>> {
    let body = match serialize_yaml_signature_carrier(req, sig_bytes) {
        Ok(body) => body,
        Err(error) => return Ok(Err(error)),
    };

    let encoded_size = payload
        .len()
        .checked_add(4)
        .and_then(|size| size.checked_add(body.len()))
        .ok_or_else(|| limits.size_computation_overflow(ArtifactResourceForm::Yaml))?;
    limits.check_output_size(ArtifactResourceForm::Yaml, encoded_size)?;

    let outcome = yaml_sigil_transcription::compose(&yaml_sigil_transcription::ComposeRequest {
        payload,
        signature_carrier: body.as_bytes(),
        form: yaml_sigil_transcription::TranscriptionForm::Yaml,
    });
    match outcome {
        yaml_sigil_transcription::ComposeOutcome::Success(s) => {
            debug_assert_eq!(s.artifact.len(), encoded_size);
            Ok(Ok(s.artifact))
        }
        yaml_sigil_transcription::ComposeOutcome::Invocation(_)
        | yaml_sigil_transcription::ComposeOutcome::Error(_) => {
            Ok(Err(SignError::YamlSerialize("compose failed".into())))
        }
    }
}

fn emit_proto_artifact<Ed25519: ?Sized, P256: ?Sized>(
    payload: &[u8],
    req: &GenericSignRequest<'_, Ed25519, P256>,
    sig_bytes: &[u8],
) -> Result<Vec<u8>, SignError> {
    let carrier = proto_carrier::encode_inner_signature_carrier(
        req.algorithm,
        sig_bytes.to_vec(),
        req.keyid.map(|s| s.to_string()),
    );
    Ok(yaml_sigil_core::compose_proto_outer(payload, &carrier))
}

/// Sign with YAML output through [`sign`].
///
/// This wrapper has the resource behavior documented on [`sign`].
#[instrument(level = "info", skip(params), fields(alg = ?params.algorithm))]
pub fn sign_yaml(params: &SignYamlParams<'_>) -> Result<Vec<u8>, SignError> {
    let req = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    match sign_inner(&req) {
        SignOutcome::Success(s) => Ok(s.artifact),
        SignOutcome::Invocation(e) => Err(map_invocation_to_sign_error(e)),
        SignOutcome::Signer(e) => Err(e),
    }
}

/// Sign with YAML output after applying an explicit output policy.
pub fn sign_yaml_with_resource_limits(
    params: &SignYamlParams<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, SignError>> {
    let request = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    if let Err(error) = validate_invocation_shape(&request) {
        return Ok(Err(map_invocation_to_sign_error(error)));
    }
    checked_yaml_signing_lower_bound(&request, limits)?;
    if let Err(error) = validate_keyid_content(&request) {
        return Ok(Err(map_invocation_to_sign_error(error)));
    }
    let outcome = sign_after_invocation_validation(&request, Some(limits), |payload| {
        sign_digest(payload, request.algorithm, &request.key)
    })?;
    Ok(match outcome {
        SignOutcome::Success(success) => Ok(success.artifact),
        SignOutcome::Invocation(error) => Err(map_invocation_to_sign_error(error)),
        SignOutcome::Signer(error) => Err(error),
    })
}

/// Sign with protobuf output through [`sign`].
///
/// This wrapper has the resource behavior documented on [`sign`].
#[instrument(level = "info", skip(params), fields(alg = ?params.algorithm))]
pub fn sign_proto(params: &SignProtoParams<'_>) -> Result<Vec<u8>, SignError> {
    let req = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    match sign(&req) {
        SignOutcome::Success(s) => Ok(s.artifact),
        SignOutcome::Invocation(e) => Err(map_invocation_to_sign_error(e)),
        SignOutcome::Signer(e) => Err(e),
    }
}

/// Sign with protobuf output after applying an explicit output policy.
///
/// The outer result reports resource rejection, the next result preserves a
/// protobuf format error, and the innermost result preserves [`SignError`].
pub fn sign_proto_with_resource_limits(
    params: &SignProtoParams<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Result<Vec<u8>, SignError>, EncodeError>> {
    let request = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    let outcome = match sign_with_resource_limits(&request, limits)? {
        Ok(outcome) => outcome,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok(match outcome {
        SignOutcome::Success(success) => Ok(success.artifact),
        SignOutcome::Invocation(error) => Err(map_invocation_to_sign_error(error)),
        SignOutcome::Signer(error) => Err(error),
    }))
}

fn map_invocation_to_sign_error(e: SignInvocationError) -> SignError {
    match e {
        SignInvocationError::InvalidOrUnsupportedAlgorithm => {
            SignError::InvalidOrUnsupportedAlgorithm
        }
        SignInvocationError::InvalidAlgorithmParameters => SignError::InvalidAlgorithmParameters,
        SignInvocationError::InvalidOrUnsupportedOutputForm => {
            SignError::InvalidOrUnsupportedOutputForm
        }
        SignInvocationError::InvalidKeyid => SignError::InvalidKeyid,
    }
}

fn sign_digest(
    payload: &[u8],
    algorithm: AlgorithmId,
    key: &SigningKey<'_>,
) -> Result<[u8; 64], SignError> {
    match (algorithm, key) {
        (AlgorithmId::Ed25519, SigningKey::Ed25519(sk)) => {
            use ed25519_dalek::Signer;
            Ok(sk.sign(payload).to_bytes())
        }
        (AlgorithmId::EcdsaP256Sha256, SigningKey::EcdsaP256Sha256(sk)) => {
            sign_p256_with_rng(payload, sk, &mut getrandom::SysRng)
        }
        _ => Err(SignError::InvalidOrUnsupportedAlgorithm),
    }
}

fn sign_p256_with_rng<R: getrandom::rand_core::TryCryptoRng + ?Sized>(
    payload: &[u8],
    key: &p256::ecdsa::SigningKey,
    rng: &mut R,
) -> Result<[u8; 64], SignError> {
    use p256::elliptic_curve::Generate;
    use sha2::Digest;
    use zeroize::Zeroizing;

    // The v1alpha1 P-256 profile requires a CSPRNG-sampled nonce. RustCrypto's
    // message-signing APIs use RFC 6979, including the randomized variant.
    // Keep the supplied nonce independent of the key and SHA-256 payload hash.
    let digest = sha2::Sha256::digest(payload);
    loop {
        // RustCrypto rejection-samples uniformly in 1..n; entropy failure must
        // abort rather than panic or fall back to deterministic signing.
        let nonce = Zeroizing::new(
            p256::NonZeroScalar::try_generate_from_rng(rng)
                .map_err(|_| SignError::KeyOperationFailure)?,
        );
        // The primitive rejects zero R or S. The profile requires a fresh
        // nonce in that case. It consumes the prehash without hashing again.
        if let Ok((signature, _)) =
            ecdsa::hazmat::sign_prehashed(key.as_nonzero_scalar(), &nonce, &digest)
        {
            return Ok(signature.to_bytes().into());
        }
    }
}

/// In-process default signer that delegates to the crate's free functions.
///
/// This unit type retains the unbounded resource behavior of [`sign`]. Use the
/// resource-aware free functions when you need the shared policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultSigner;

impl Signer for DefaultSigner {
    type Ed25519SigningKey = ed25519_dalek::SigningKey;
    type P256SigningKey = p256::ecdsa::SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }
    fn sign(&self, req: &SignRequest<'_>) -> SignOutcome {
        sign(req)
    }
}

/// In-process default async signer that delegates to the crate's free functions.
///
/// The body is `async { sign(req) }`. It runs cryptography and P-256 system
/// entropy acquisition on the polling thread without selecting an executor or
/// a blocking pool. Entropy failure returns [`SignError::KeyOperationFailure`].
///
/// This unit type retains the unconfigured resource behavior of [`sign`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAsyncSigner;

impl AsyncSigner for DefaultAsyncSigner {
    type Ed25519SigningKey = ed25519_dalek::SigningKey;
    type P256SigningKey = p256::ecdsa::SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }
    async fn sign(&self, req: &SignRequest<'_>) -> SignOutcome {
        sign(req)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use ed25519_dalek::SigningKey as EdSk;

    struct CapturingEd25519Signer {
        key: EdSk,
        calls: AtomicUsize,
        messages: Mutex<Vec<Vec<u8>>>,
    }

    impl CapturingEd25519Signer {
        fn new(seed: u8) -> Self {
            Self {
                key: EdSk::from_bytes(&[seed; 32]),
                calls: AtomicUsize::new(0),
                messages: Mutex::new(Vec::new()),
            }
        }
    }

    impl signature::Signer<[u8; 64]> for CapturingEd25519Signer {
        fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.messages.lock().unwrap().push(message.to_vec());
            let signature: ed25519_dalek::Signature =
                signature::Signer::try_sign(&self.key, message)?;
            Ok(signature.to_bytes())
        }
    }

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(maximum).unwrap())
    }

    fn p256_request<'a>(
        key: &'a p256::ecdsa::SigningKey,
        output_form: OutputForm,
        payload: &'a [u8],
    ) -> SignRequest<'a> {
        SignRequest {
            payload,
            algorithm: AlgorithmId::EcdsaP256Sha256,
            key: SigningKey::EcdsaP256Sha256(key),
            keyid: Some("p256-nonce-test"),
            append_missing_final_newline: true,
            output_form,
            algorithm_parameters: &[],
        }
    }

    fn verify_p256_success(
        outcome: SignOutcome,
        request: &SignRequest<'_>,
        key: &p256::ecdsa::SigningKey,
        expected_payload: &[u8],
    ) -> [u8; 64] {
        use signature::Verifier;
        use yaml_sigil_core::pb::SignedYamlArtifact;

        let SignOutcome::Success(success) = outcome else {
            panic!("expected a signed artifact, got {outcome:?}");
        };
        let wire = match request.output_form {
            OutputForm::Yaml => signed_yaml_stream_to_proto_wire(&success.artifact).unwrap(),
            OutputForm::Protobuf => success.artifact,
        };
        let artifact = SignedYamlArtifact::decode(&wire).unwrap();
        assert_eq!(artifact.payload(), expected_payload);
        let carrier = artifact.signature().unwrap();
        assert_eq!(carrier.algorithm(), Some(AlgorithmId::EcdsaP256Sha256));
        assert_eq!(carrier.keyid(), request.keyid);
        let signature = p256::ecdsa::Signature::from_slice(carrier.signature()).unwrap();
        key.verifying_key()
            .verify(expected_payload, &signature)
            .expect("signature must hash the final payload exactly once");
        signature.to_bytes().into()
    }

    fn p256_payload_cases() -> [(OutputForm, &'static [u8], &'static [u8]); 4] {
        [
            (OutputForm::Yaml, b"", b""),
            (OutputForm::Yaml, b"a: b", b"a: b\n"),
            (OutputForm::Protobuf, b"", b""),
            (OutputForm::Protobuf, &[0xff, 0, 0x80], &[0xff, 0, 0x80]),
        ]
    }

    // Test-only entropy source. Exhaustion models an unavailable system CSPRNG.
    struct ScriptedRng {
        candidates: std::vec::IntoIter<[u8; 32]>,
        calls: usize,
    }

    impl ScriptedRng {
        fn new(candidates: impl IntoIterator<Item = [u8; 32]>) -> Self {
            Self {
                candidates: candidates.into_iter().collect::<Vec<_>>().into_iter(),
                calls: 0,
            }
        }
    }

    impl getrandom::rand_core::TryRng for ScriptedRng {
        type Error = getrandom::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("nonce sampling must request scalar bytes");
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("nonce sampling must request scalar bytes");
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            let candidate = self
                .candidates
                .next()
                .ok_or(getrandom::Error::UNSUPPORTED)?;
            dest.copy_from_slice(&candidate);
            Ok(())
        }
    }

    impl getrandom::rand_core::TryCryptoRng for ScriptedRng {}

    #[test]
    fn p256_uses_sampled_nonce_without_rfc6979() {
        use p256::elliptic_curve::point::AffineCoordinates;
        use signature::Verifier;

        let key = p256::ecdsa::SigningKey::from_slice(&[15; 32]).unwrap();
        // A test-only nonce of one must produce R = x(G), independently of the
        // message. RFC 6979 with added entropy would not preserve that R.
        let expected_r = p256::AffinePoint::GENERATOR.x();
        for payload in [b"first payload".as_slice(), b"second payload"] {
            let mut rng = ScriptedRng::new([p256::Scalar::ONE.to_bytes().into()]);
            let bytes = sign_p256_with_rng(payload, &key, &mut rng).unwrap();
            assert_eq!(rng.calls, 1);
            assert_eq!(&bytes[..32], expected_r.as_slice());
            key.verifying_key()
                .verify(
                    payload,
                    &p256::ecdsa::Signature::from_slice(&bytes).unwrap(),
                )
                .unwrap();
        }
    }

    #[test]
    fn p256_rejects_zero_and_out_of_range_nonces() {
        use p256::elliptic_curve::{Curve, point::AffineCoordinates};
        use signature::Verifier;

        let key = p256::ecdsa::SigningKey::from_slice(&[16; 32]).unwrap();
        let mut rng = ScriptedRng::new([
            [0; 32],
            p256::NistP256::ORDER.to_be_bytes().into(),
            [0xff; 32],
            (-p256::Scalar::ONE).to_bytes().into(),
        ]);
        let payload = b"nonce range rejection\n";
        let bytes = sign_p256_with_rng(payload, &key, &mut rng).unwrap();
        assert_eq!(rng.calls, 4);
        // n - 1 is admissible and produces the same x coordinate as G.
        assert_eq!(&bytes[..32], p256::AffinePoint::GENERATOR.x().as_slice());
        key.verifying_key()
            .verify(
                payload,
                &p256::ecdsa::Signature::from_slice(&bytes).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn p256_entropy_failure_returns_no_artifact() {
        let key = p256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
        for form in [OutputForm::Yaml, OutputForm::Protobuf] {
            for candidates in [vec![], vec![[0; 32]]] {
                let expected_calls = candidates.len() + 1;
                let mut rng = ScriptedRng::new(candidates);
                let request = p256_request(&key, form, b"a: b\n");
                let outcome = sign_after_invocation_validation(&request, None, |payload| {
                    sign_p256_with_rng(payload, &key, &mut rng)
                })
                .unwrap();
                assert!(matches!(
                    outcome,
                    SignOutcome::Signer(SignError::KeyOperationFailure)
                ));
                assert_eq!(rng.calls, expected_calls);
            }
        }
    }

    #[test]
    fn p256_retries_zero_s_with_a_fresh_nonce() {
        use p256::elliptic_curve::{ops::Reduce, point::AffineCoordinates};
        use sha2::Digest;
        use signature::Verifier;

        let payload = b"zero-s retry\n";
        let digest = sha2::Sha256::digest(payload);
        let z = <p256::Scalar as Reduce<p256::U256>>::reduce(&p256::U256::from_be_slice(&digest));
        let r = <p256::Scalar as Reduce<p256::U256>>::reduce(&p256::U256::from_be_slice(
            &p256::AffinePoint::GENERATOR.x(),
        ));
        // Construct a synthetic test key for which nonce one gives S = 0.
        let secret = -(z * r.invert().unwrap());
        let key = p256::ecdsa::SigningKey::from_bytes(&secret.to_bytes()).unwrap();
        let one: [u8; 32] = p256::Scalar::ONE.to_bytes().into();
        let nonce = p256::NonZeroScalar::from_repr(one.into()).unwrap();
        assert!(ecdsa::hazmat::sign_prehashed(key.as_nonzero_scalar(), &nonce, &digest).is_err());

        let mut rng = ScriptedRng::new([one, p256::Scalar::from(2u64).to_bytes().into()]);
        let bytes = sign_p256_with_rng(payload, &key, &mut rng).unwrap();
        assert_eq!(rng.calls, 2);
        key.verifying_key()
            .verify(
                payload,
                &p256::ecdsa::Signature::from_slice(&bytes).unwrap(),
            )
            .unwrap();

        let mut exhausted = ScriptedRng::new([one]);
        assert!(matches!(
            sign_p256_with_rng(payload, &key, &mut exhausted),
            Err(SignError::KeyOperationFailure)
        ));
        assert_eq!(exhausted.calls, 2);
    }

    #[test]
    fn default_p256_signer_uses_fresh_nonces() {
        let key = p256::ecdsa::SigningKey::from_slice(&[13; 32]).unwrap();
        for (form, payload, expected) in p256_payload_cases() {
            let request = p256_request(&key, form, payload);
            let first = verify_p256_success(
                Signer::sign(&DefaultSigner, &request),
                &request,
                &key,
                expected,
            );
            let second = verify_p256_success(
                Signer::sign(&DefaultSigner, &request),
                &request,
                &key,
                expected,
            );
            assert_ne!(&first[..32], &second[..32], "P-256 must use a fresh nonce");
            let bounded = verify_p256_success(
                sign_with_resource_limits(&request, &ArtifactResourceLimits::unbounded())
                    .unwrap()
                    .unwrap(),
                &request,
                &key,
                expected,
            );
            assert_ne!(&first[..32], &bounded[..32]);
        }
    }

    #[tokio::test]
    async fn default_async_p256_signer_uses_fresh_nonces() {
        let key = p256::ecdsa::SigningKey::from_slice(&[14; 32]).unwrap();
        for (form, payload, expected) in p256_payload_cases() {
            let request = p256_request(&key, form, payload);
            let first = verify_p256_success(
                AsyncSigner::sign(&DefaultAsyncSigner, &request).await,
                &request,
                &key,
                expected,
            );
            let second = verify_p256_success(
                AsyncSigner::sign(&DefaultAsyncSigner, &request).await,
                &request,
                &key,
                expected,
            );
            assert_ne!(&first[..32], &second[..32], "P-256 must use a fresh nonce");
        }
    }

    #[test]
    fn signer_capabilities_lists_two_algorithms() {
        let c = signer_capabilities();
        assert_eq!(c.supported_algorithms.len(), 2);
        assert_eq!(c.supported_output_forms.len(), 2);
        assert!(!c.best_effort_yaml_validation);
        assert_eq!(
            c.protobuf_wire_decode,
            yaml_sigil_core::ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder
        );
        assert_eq!(
            c.yaml_signature_duplicate_key_policy,
            yaml_sigil_core::YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse
        );
        assert_eq!(
            c.yaml_signature_unknown_field_policy,
            yaml_sigil_core::YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse
        );
    }

    // The concrete RustCrypto bindings must remain expressible on a
    // synchronous trait object.
    #[test]
    fn default_signer_supports_a_trait_object_with_explicit_bindings() {
        let signer: &dyn Signer<
            Ed25519SigningKey = ed25519_dalek::SigningKey,
            P256SigningKey = p256::ecdsa::SigningKey,
        > = &DefaultSigner;
        assert_eq!(signer.capabilities(), signer_capabilities());
    }

    #[test]
    fn signer_rejects_line_break_in_keyid() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        for keyid in ["kid\nsuffix", "kid\rsuffix"] {
            let req = SignRequest {
                payload: b"a: b\n",
                algorithm: AlgorithmId::Ed25519,
                key: SigningKey::Ed25519(&sk),
                keyid: Some(keyid),
                append_missing_final_newline: false,
                output_form: OutputForm::Yaml,
                algorithm_parameters: &[],
            };
            assert!(matches!(
                sign(&req),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid)
            ));
        }
    }

    #[test]
    fn existing_signing_preserves_keyid_error_before_key_mismatch() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        for output_form in [OutputForm::Yaml, OutputForm::Protobuf] {
            for keyid in ["kid\nsuffix", "kid\rsuffix"] {
                let request = SignRequest {
                    payload: b"a: b\n",
                    algorithm: AlgorithmId::EcdsaP256Sha256,
                    key: SigningKey::Ed25519(&sk),
                    keyid: Some(keyid),
                    append_missing_final_newline: false,
                    output_form,
                    algorithm_parameters: &[],
                };
                assert!(matches!(
                    sign(&request),
                    SignOutcome::Invocation(SignInvocationError::InvalidKeyid)
                ));
                // The opt-in path rejects an invalid key shape without scanning
                // key-id content, while the existing API retains its ordering.
                assert!(matches!(
                    sign_with_resource_limits(&request, &finite(1))
                        .unwrap()
                        .unwrap(),
                    SignOutcome::Invocation(SignInvocationError::InvalidOrUnsupportedAlgorithm)
                ));
            }
        }
    }

    #[test]
    fn bounded_signing_preserves_request_shape_precedence() {
        let sk = EdSk::from_bytes(&[8u8; 32]);
        let request = SignRequest {
            payload: &[0xff; 16],
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[1],
        };
        assert!(matches!(
            sign_with_resource_limits(&request, &finite(1))
                .unwrap()
                .unwrap(),
            SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters)
        ));
    }

    #[test]
    fn bounded_signing_defers_keyid_content_and_payload_validation() {
        let sk = EdSk::from_bytes(&[9u8; 32]);
        for output_form in [OutputForm::Yaml, OutputForm::Protobuf] {
            let request = SignRequest {
                payload: &[0xff; 16],
                algorithm: AlgorithmId::Ed25519,
                key: SigningKey::Ed25519(&sk),
                keyid: Some("line\nbreak"),
                append_missing_final_newline: false,
                output_form,
                algorithm_parameters: &[],
            };
            let error = sign_with_resource_limits(&request, &finite(1)).unwrap_err();
            assert_eq!(
                error.kind(),
                ArtifactResourceErrorKind::OutputArtifactTooLarge
            );
            assert_eq!(
                error.artifact_form(),
                Some(match output_form {
                    OutputForm::Yaml => ArtifactResourceForm::Yaml,
                    OutputForm::Protobuf => ArtifactResourceForm::Protobuf,
                })
            );
            assert_eq!(
                error.observed_or_projected_artifact_bytes(),
                match output_form {
                    OutputForm::Yaml => None,
                    OutputForm::Protobuf => Some(
                        checked_proto_signing_size(&request, &ArtifactResourceLimits::unbounded(),)
                            .unwrap()
                            .unwrap(),
                    ),
                }
            );

            assert!(matches!(
                sign_with_resource_limits(&request, &ArtifactResourceLimits::unbounded())
                    .unwrap()
                    .unwrap(),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid)
            ));
        }
    }

    #[test]
    fn protobuf_signing_projection_matches_emission_at_varint_boundaries() {
        let sk = EdSk::from_bytes(&[10u8; 32]);
        for payload_len in [0, 1, 127, 128, 16_383, 16_384] {
            let payload = vec![0xa5; payload_len];
            for keyid in [None, Some("key")] {
                let request = SignRequest {
                    payload: &payload,
                    algorithm: AlgorithmId::Ed25519,
                    key: SigningKey::Ed25519(&sk),
                    keyid,
                    append_missing_final_newline: false,
                    output_form: OutputForm::Protobuf,
                    algorithm_parameters: &[],
                };
                let projected =
                    checked_proto_signing_size(&request, &ArtifactResourceLimits::unbounded())
                        .unwrap()
                        .unwrap();
                let outcome = sign_with_resource_limits(&request, &finite(projected))
                    .unwrap()
                    .unwrap();
                let artifact = match outcome {
                    SignOutcome::Success(success) => success.artifact,
                    other => panic!("{other:?}"),
                };
                assert_eq!(artifact.len(), projected);
            }
        }

        let p256_key = p256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        for payload_len in [0, 127, 128] {
            let payload = vec![0x5a; payload_len];
            let request = SignRequest {
                payload: &payload,
                algorithm: AlgorithmId::EcdsaP256Sha256,
                key: SigningKey::EcdsaP256Sha256(&p256_key),
                keyid: Some("p256-key"),
                append_missing_final_newline: false,
                output_form: OutputForm::Protobuf,
                algorithm_parameters: &[],
            };
            let projected =
                checked_proto_signing_size(&request, &ArtifactResourceLimits::unbounded())
                    .unwrap()
                    .unwrap();
            let outcome = sign_with_resource_limits(&request, &finite(projected))
                .unwrap()
                .unwrap();
            let artifact = match outcome {
                SignOutcome::Success(success) => success.artifact,
                other => panic!("{other:?}"),
            };
            assert_eq!(artifact.len(), projected);
        }
    }

    #[test]
    fn protobuf_signing_preserves_resource_then_format_precedence() {
        let payload_len = u64::try_from(i32::MAX).unwrap();
        let resource_error =
            checked_proto_signing_size_from_lengths(payload_len, None, &finite(1)).unwrap_err();
        assert_eq!(
            resource_error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );

        let format_error = checked_proto_signing_size_from_lengths(
            payload_len,
            None,
            &ArtifactResourceLimits::unbounded(),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(
            format_error.kind(),
            yaml_sigil_core::pb::EncodeErrorKind::MessageTooLarge
        );
    }

    #[test]
    fn protobuf_signing_reports_exact_output_rejection() {
        let sk = EdSk::from_bytes(&[11u8; 32]);
        let params = SignProtoParams {
            payload: b"opaque payload",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("key"),
            append_missing_final_newline: false,
        };
        let artifact = sign_proto(&params).unwrap();
        assert!(
            sign_proto_with_resource_limits(&params, &finite(artifact.len()))
                .unwrap()
                .unwrap()
                .is_ok()
        );
        let error =
            sign_proto_with_resource_limits(&params, &finite(artifact.len() - 1)).unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );
        assert_eq!(
            error.observed_or_projected_artifact_bytes(),
            Some(artifact.len())
        );
    }

    #[test]
    fn yaml_signing_uses_lower_bound_then_final_exact_size() {
        let sk = EdSk::from_bytes(&[12u8; 32]);
        let request = SignRequest {
            payload: b"key: value",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("quoted\"key"),
            append_missing_final_newline: true,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let minimum =
            checked_yaml_signing_lower_bound(&request, &ArtifactResourceLimits::unbounded())
                .unwrap();
        let artifact = match sign(&request) {
            SignOutcome::Success(success) => success.artifact,
            other => panic!("{other:?}"),
        };
        assert!(minimum < artifact.len());
        assert!(artifact.starts_with(b"key: value\n---\n"));

        let early = sign_with_resource_limits(&request, &finite(minimum - 1)).unwrap_err();
        assert_eq!(early.observed_or_projected_artifact_bytes(), None);

        let exact = sign_with_resource_limits(&request, &finite(artifact.len() - 1)).unwrap_err();
        assert_eq!(
            exact.observed_or_projected_artifact_bytes(),
            Some(artifact.len())
        );
        assert!(matches!(
            sign_with_resource_limits(&request, &finite(artifact.len()))
                .unwrap()
                .unwrap(),
            SignOutcome::Success(_)
        ));

        let params = SignYamlParams {
            payload: request.payload,
            algorithm: request.algorithm,
            key: request.key,
            keyid: request.keyid,
            append_missing_final_newline: request.append_missing_final_newline,
        };
        assert_eq!(
            sign_yaml_with_resource_limits(&params, &finite(artifact.len()))
                .unwrap()
                .unwrap(),
            artifact
        );
    }

    #[test]
    fn qualified_provider_receives_exact_final_yaml_and_protobuf_payloads() {
        let signer = CapturingEd25519Signer::new(20);
        let public_key = signer.key.verifying_key().to_bytes();
        let key = ProviderSigningKeyBuilder::ed25519(&public_key)
            .build()
            .unwrap();
        let yaml_request = ProviderSignRequest {
            payload: b"provider: yaml",
            algorithm: AlgorithmId::Ed25519,
            key: ProviderSigningKeys::Ed25519(&key),
            keyid: None,
            append_missing_final_newline: true,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let SignOutcome::Success(yaml_success) =
            sign_with_provider(&yaml_request, signature_signing_callback(&signer))
        else {
            panic!("qualified YAML provider signing failed");
        };
        assert_eq!(yaml_success.modified_payload, b"provider: yaml\n");
        assert!(yaml_success.artifact.starts_with(b"provider: yaml\n---\n"));
        assert_eq!(signer.messages.lock().unwrap()[0], b"provider: yaml\n");

        let protobuf_payload = [0xff, 0x00, 0x80, 0x0a];
        let protobuf_request = ProviderSignRequest {
            payload: &protobuf_payload,
            algorithm: AlgorithmId::Ed25519,
            key: ProviderSigningKeys::Ed25519(&key),
            keyid: Some("provider-key"),
            append_missing_final_newline: true,
            output_form: OutputForm::Protobuf,
            algorithm_parameters: &[],
        };
        assert!(matches!(
            sign_with_provider(&protobuf_request, signature_signing_callback(&signer)),
            SignOutcome::Success(_)
        ));
        assert_eq!(signer.messages.lock().unwrap()[1], protobuf_payload);
    }

    #[test]
    fn provider_output_self_verification_is_mandatory_on_qualified_path() {
        let signer = CapturingEd25519Signer::new(21);
        let other_key = EdSk::from_bytes(&[22; 32]);
        let qualified = ProviderSigningKeyBuilder::ed25519(other_key.verifying_key().as_bytes())
            .build()
            .unwrap();
        let request = ProviderSignRequest {
            payload: b"provider: mismatch\n",
            algorithm: AlgorithmId::Ed25519,
            key: ProviderSigningKeys::Ed25519(&qualified),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        assert!(matches!(
            sign_with_provider(&request, signature_signing_callback(&signer)),
            SignOutcome::Signer(SignError::KeyOperationFailure)
        ));

        let unqualified = ProviderSigningKeyBuilder::ed25519(other_key.verifying_key().as_bytes())
            .build_unqualified()
            .unwrap();
        let request = UnqualifiedProviderSignRequest {
            payload: b"provider: mismatch\n",
            algorithm: AlgorithmId::Ed25519,
            key: UnqualifiedProviderSigningKeys::Ed25519(&unqualified),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        assert!(matches!(
            sign_with_unqualified_provider(&request, signature_signing_callback(&signer)),
            SignOutcome::Success(_)
        ));
    }

    #[test]
    fn provider_invocation_validation_precedes_payload_scan_and_signing() {
        let signer = CapturingEd25519Signer::new(23);
        let public_key = signer.key.verifying_key().to_bytes();
        let key = ProviderSigningKeyBuilder::ed25519(&public_key)
            .build()
            .unwrap();
        let invalid_shape = ProviderSignRequest {
            payload: &[0xff; 32],
            algorithm: AlgorithmId::Ed25519,
            key: ProviderSigningKeys::Ed25519(&key),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[1],
        };
        assert!(matches!(
            sign_with_provider(&invalid_shape, signature_signing_callback(&signer)),
            SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters)
        ));

        for output_form in [OutputForm::Yaml, OutputForm::Protobuf] {
            let request = ProviderSignRequest {
                payload: &[0xff; 32],
                algorithm: AlgorithmId::Ed25519,
                key: ProviderSigningKeys::Ed25519(&key),
                keyid: Some("line\nbreak"),
                append_missing_final_newline: false,
                output_form,
                algorithm_parameters: &[],
            };
            assert!(matches!(
                sign_with_provider(&request, signature_signing_callback(&signer)),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid)
            ));
        }
        assert_eq!(signer.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn default_signer_matches_free_function() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        let payload = b"a: b\n";
        let req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("kid-d"),
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let direct = match sign(&req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via free fn"),
        };
        let via_trait = match Signer::sign(&DefaultSigner, &req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via trait"),
        };
        assert_eq!(direct, via_trait);
        assert_eq!(
            DefaultSigner.capabilities().supported_algorithms.len(),
            signer_capabilities().supported_algorithms.len()
        );
    }

    #[test]
    fn unified_sign_matches_wrappers() {
        let sk = EdSk::from_bytes(&[3u8; 32]);
        let payload = b"x: y\n";
        let yaml_req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let proto_req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Protobuf,
            algorithm_parameters: &[],
        };
        let y1 = sign_yaml(&SignYamlParams {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap();
        let y2 = match sign(&yaml_req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success"),
        };
        assert_eq!(y1, y2);
        let p1 = sign_proto(&SignProtoParams {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap();
        let p2 = match sign(&proto_req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success"),
        };
        assert_eq!(p1, p2);
    }

    #[tokio::test]
    async fn default_async_signer_matches_free_function() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        let payload = b"a: b\n";
        let req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("kid-d"),
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let direct = match sign(&req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via free fn"),
        };
        let via_async_trait = match AsyncSigner::sign(&DefaultAsyncSigner, &req).await {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via async trait"),
        };
        assert_eq!(direct, via_async_trait);
        assert_eq!(
            AsyncSigner::capabilities(&DefaultAsyncSigner)
                .supported_algorithms
                .len(),
            signer_capabilities().supported_algorithms.len()
        );
    }
}
