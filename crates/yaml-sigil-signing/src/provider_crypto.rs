// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-key and signature checks used by provider-backed signing.
//!
//! The Ed25519 point-encoding, scalar, challenge, and verification rules below
//! are third-party RFC material. They are not relicensed under this file's
//! Apache-2.0 declaration. See the crate's `THIRD_PARTY_NOTICES.md` for
//! attribution and applicable terms.
//! The P-256 public-key check uses the uncompressed point encoding from
//! *Standards for Efficient Cryptography 1 (SEC 1)* under the terms in the
//! same notice.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha512};
use signature::Verifier as _;
use yaml_sigil_traits::AlgorithmId;

pub(crate) enum ProviderPublicKey {
    Ed25519 {
        bytes: [u8; 32],
        point: EdwardsPoint,
    },
    EcdsaP256Sha256(P256VerifyingKey),
}

impl ProviderPublicKey {
    pub(crate) fn algorithm(&self) -> AlgorithmId {
        match self {
            Self::Ed25519 { .. } => AlgorithmId::Ed25519,
            Self::EcdsaP256Sha256(_) => AlgorithmId::EcdsaP256Sha256,
        }
    }
}

pub(crate) fn resolve_provider_public_key(
    algorithm: AlgorithmId,
    bytes: &[u8],
) -> Option<ProviderPublicKey> {
    match algorithm {
        AlgorithmId::Ed25519 => {
            let bytes: [u8; 32] = bytes.try_into().ok()?;
            let point = CompressedEdwardsY(bytes).decompress()?;
            if point.compress().to_bytes() != bytes || point.is_small_order() {
                return None;
            }
            Some(ProviderPublicKey::Ed25519 { bytes, point })
        }
        AlgorithmId::EcdsaP256Sha256 => {
            // SEC 1 section 2.3.3 supplies the uncompressed point encoding.
            if bytes.len() != 65 || bytes.first() != Some(&0x04) {
                return None;
            }
            P256VerifyingKey::from_sec1_bytes(bytes)
                .ok()
                .map(ProviderPublicKey::EcdsaP256Sha256)
        }
    }
}

fn parse_ed25519_signature(signature: &[u8; 64]) -> Option<([u8; 32], EdwardsPoint, Scalar)> {
    let r_bytes: [u8; 32] = signature[..32].try_into().ok()?;
    let r = CompressedEdwardsY(r_bytes).decompress()?;
    if r.compress().to_bytes() != r_bytes {
        return None;
    }
    let s_bytes: [u8; 32] = signature[32..].try_into().ok()?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))?;
    Some((r_bytes, r, s))
}

pub(crate) fn provider_signature_is_structurally_valid(
    algorithm: AlgorithmId,
    signature: &[u8; 64],
) -> bool {
    match algorithm {
        AlgorithmId::Ed25519 => parse_ed25519_signature(signature).is_some(),
        AlgorithmId::EcdsaP256Sha256 => P256Signature::from_slice(signature).is_ok(),
    }
}

pub(crate) fn verify_provider_signature(
    public_key: &ProviderPublicKey,
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    match public_key {
        ProviderPublicKey::Ed25519 { bytes, point } => {
            let Some((r_bytes, r, s)) = parse_ed25519_signature(signature) else {
                return false;
            };
            let mut hasher = Sha512::new();
            hasher.update(r_bytes);
            hasher.update(bytes);
            hasher.update(message);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hasher.finalize());
            let challenge = Scalar::from_bytes_mod_order_wide(&wide);
            (s * ED25519_BASEPOINT_POINT - r - challenge * point)
                .mul_by_cofactor()
                .is_identity()
        }
        ProviderPublicKey::EcdsaP256Sha256(key) => P256Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
    }
}
