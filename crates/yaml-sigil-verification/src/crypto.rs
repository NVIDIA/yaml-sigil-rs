// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared cryptographic verification.
//!
//! The Ed25519 point-encoding, scalar, and verification rules below, together
//! with the test-only RFC 8032 section 7.1 signature, are third-party RFC
//! material. They are not relicensed under this file's Apache-2.0 declaration.
//! See the crate's `THIRD_PARTY_NOTICES.md` for attribution and applicable
//! terms.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::VerifyingKey as EdVk;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Vk};
use sha2::{Digest, Sha512};
use signature::Verifier as P256VerifierTrait;

use crate::InvocationError;

struct ParsedEd25519Signature {
    r_bytes: [u8; 32],
    r: EdwardsPoint,
    s: Scalar,
}

/// edwards25519 prime-order subgroup order
/// `L = 2^252 + 27742317777372353535851937790883648493`, little-endian.
#[cfg(test)]
const ED25519_L_LE: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Decode the exact canonical compressed Edwards-y representation of a point.
fn decode_canonical_edwards_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().to_bytes() == *bytes).then_some(point)
}

/// Parse the required canonical 64-octet Ed25519 `R || S` representation.
fn parse_ed25519_signature(sig_bytes: &[u8]) -> Option<ParsedEd25519Signature> {
    if sig_bytes.len() != 64 {
        return None;
    }

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    let r = decode_canonical_edwards_point(&r_bytes)?;

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_bytes[32..]);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))?;

    Some(ParsedEd25519Signature { r_bytes, r, s })
}

/// Reduce the RFC 8032 challenge `SHA-512(R || A || M)` modulo `L`.
fn ed25519_challenge(r_bytes: &[u8; 32], a_bytes: &[u8; 32], payload: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(a_bytes);
    hasher.update(payload);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Verify the RFC 8032 cofactored equation required by the YamlSigil slot.
pub(crate) fn verify_ed25519(vk: &EdVk, payload: &[u8], sig_bytes: &[u8]) -> Result<(), ()> {
    let signature = parse_ed25519_signature(sig_bytes).ok_or(())?;
    let a = decode_canonical_edwards_point(vk.as_bytes()).ok_or(())?;
    if a.is_small_order() {
        return Err(());
    }

    let k = ed25519_challenge(&signature.r_bytes, vk.as_bytes(), payload);
    let equation = signature.s * ED25519_BASEPOINT_POINT - signature.r - k * a;
    equation
        .mul_by_cofactor()
        .is_identity()
        .then_some(())
        .ok_or(())
}

/// Returns whether a typed Ed25519 key is suitable for verification.
///
/// This check is deliberately repeated at the point of use because callers may
/// construct a RustCrypto key without using this crate's byte-oriented resolver.
pub(crate) fn ed25519_verifying_key_is_admissible(vk: &EdVk) -> bool {
    decode_canonical_edwards_point(vk.as_bytes()).is_some_and(|point| !point.is_small_order())
}

/// Resolve raw Ed25519 public-key bytes into an admissible typed key.
pub(crate) fn resolve_ed25519_verifying_key(bytes: &[u8]) -> Result<EdVk, InvocationError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| InvocationError::KeyResolutionFailure)?;
    let point =
        decode_canonical_edwards_point(&bytes).ok_or(InvocationError::KeyResolutionFailure)?;
    if point.is_small_order() {
        return Err(InvocationError::KeyResolutionFailure);
    }
    let vk = EdVk::from_bytes(&bytes).map_err(|_| InvocationError::KeyResolutionFailure)?;
    Ok(vk)
}

/// Resolve P-256 public-key bytes encoded according to
/// *Standards for Efficient Cryptography 1 (SEC 1)* into a typed key.
///
/// See this crate's `THIRD_PARTY_NOTICES.md` for the source notice and patent/IP
/// caveat.
pub(crate) fn resolve_p256_verifying_key(bytes: &[u8]) -> Result<P256Vk, InvocationError> {
    if bytes == [0u8].as_slice() {
        return Err(InvocationError::KeyResolutionFailure);
    }
    if bytes.len() == 65 && bytes.iter().all(|&byte| byte == 0) {
        return Err(InvocationError::KeyResolutionFailure);
    }
    P256Vk::from_sec1_bytes(bytes).map_err(|_| InvocationError::KeyResolutionFailure)
}

/// Returns whether `sig_bytes` is the canonical Ed25519 signature form the
/// YamlSigil algorithm slot requires.
///
/// Splits the 64-octet `R || S` wire form into the two 32-byte halves and
/// requires `R` to decode from its exact canonical compressed Edwards-y form
/// and `S` to be the canonical scalar in `0 <= S < L`. A failure is structural
/// and maps to `VerifierState::MalformedAttemptedSigned` before equation
/// verification.
pub(crate) fn ed25519_signature_is_canonical(sig_bytes: &[u8]) -> bool {
    parse_ed25519_signature(sig_bytes).is_some()
}

/// The stage at which ECDSA verification rejected a signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EcdsaVerifyError {
    MalformedSignature,
    EquationFailure,
}

/// Verify ECDSA P-256 SHA-256 against a raw `R || S` 64-octet signature.
///
/// The wire format is fixed 64-octet raw `R || S`. ASN.1 DER signatures are not
/// accepted at this layer.
pub(crate) fn verify_ecdsa_p256_sha256(
    vk: &P256Vk,
    payload: &[u8],
    sig_bytes: &[u8],
) -> Result<(), EcdsaVerifyError> {
    let sig =
        P256Signature::from_slice(sig_bytes).map_err(|_| EcdsaVerifyError::MalformedSignature)?;
    P256VerifierTrait::verify(vk, payload, &sig).map_err(|_| EcdsaVerifyError::EquationFailure)
}

#[cfg(test)]
mod tests {
    use super::{
        EcdsaVerifyError, ed25519_challenge, ed25519_signature_is_canonical,
        ed25519_verifying_key_is_admissible, resolve_ed25519_verifying_key,
        verify_ecdsa_p256_sha256, verify_ed25519,
    };
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

    fn signature_with_permitted_non_prime_order_r(
        payload: &[u8],
    ) -> (ed25519_dalek::VerifyingKey, [u8; 64]) {
        let secret = Scalar::from(7u64);
        let public_point = secret * ED25519_BASEPOINT_POINT;
        let public_bytes = public_point.compress().to_bytes();
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&public_bytes).expect("canonical public key");

        let nonce = Scalar::from(11u64);
        let r_point = nonce * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(!r_point.is_torsion_free());
        let r_bytes = r_point.compress().to_bytes();
        let challenge = ed25519_challenge(&r_bytes, &public_bytes, payload);
        let s_bytes = (nonce + challenge * secret).to_bytes();

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&s_bytes);
        (verifying_key, signature)
    }

    fn assert_malformed_signature_state(signature: &[u8]) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let keys = crate::PublicKeys {
            ed25519: Some(&verifying_key),
            p256: None,
        };
        assert_eq!(
            crate::verify_extracted_signature(
                b"payload\n",
                1,
                signature,
                &keys,
                &crate::VerifierOptions::default(),
            ),
            Ok(crate::VerifierState::MalformedAttemptedSigned)
        );
    }

    #[test]
    fn ed25519_accepts_permitted_non_prime_order_r() {
        let payload = b"cofactored equation\n";
        let (verifying_key, signature) = signature_with_permitted_non_prime_order_r(payload);

        assert!(ed25519_signature_is_canonical(&signature));
        assert!(verify_ed25519(&verifying_key, payload, &signature).is_ok());
        assert!(verify_ed25519(&verifying_key, b"different payload\n", &signature).is_err());

        let keys = crate::PublicKeys {
            ed25519: Some(&verifying_key),
            p256: None,
        };
        assert!(matches!(
            crate::verify_extracted_signature(
                payload,
                1,
                &signature,
                &keys,
                &crate::VerifierOptions::default(),
            ),
            Ok(crate::VerifierState::Verified { .. })
        ));
        assert_eq!(
            crate::verify_extracted_signature(
                b"different payload\n",
                1,
                &signature,
                &keys,
                &crate::VerifierOptions::default(),
            ),
            Ok(crate::VerifierState::SignedButFailedVerification)
        );
    }

    // Resolution applies the implementation's complete point-encoding policy,
    // including cases the underlying key constructor accepts.
    #[test]
    fn ed25519_key_resolution_enforces_canonical_field_encoding() {
        // y = p + 3 is not a canonical field encoding.
        let mut noncanonical = [0xFF; 32];
        noncanonical[0] = 0xF0;
        noncanonical[31] = 0x7F;
        let typed_key =
            ed25519_dalek::VerifyingKey::from_bytes(&noncanonical).expect("typed key construction");
        assert!(!typed_key.is_weak());
        assert!(!ed25519_verifying_key_is_admissible(&typed_key));
        assert!(resolve_ed25519_verifying_key(&noncanonical).is_err());

        let mut canonical = [0u8; 32];
        canonical[0] = 3;
        assert!(resolve_ed25519_verifying_key(&canonical).is_ok());
    }

    // Callers may supply an already typed key, so point-of-use verification
    // must apply the same admissibility policy as byte-oriented resolution.
    #[test]
    fn ed25519_key_resolution_accepts_non_small_mixed_order_point() {
        let point = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(!point.is_small_order());
        assert!(!point.is_torsion_free());
        let bytes = point.compress().to_bytes();
        let typed_key =
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).expect("canonical mixed-order key");

        assert!(ed25519_verifying_key_is_admissible(&typed_key));
        assert_eq!(resolve_ed25519_verifying_key(&bytes), Ok(typed_key));
    }

    #[test]
    fn ed25519_verification_rechecks_typed_key_admissibility() {
        let mut noncanonical = [0xFF; 32];
        noncanonical[0] = 0xF0;
        noncanonical[31] = 0x7F;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&noncanonical).expect("typed key construction");
        let keys = crate::PublicKeys {
            ed25519: Some(&key),
            p256: None,
        };

        assert_eq!(
            crate::verify_extracted_signature(
                b"payload\n",
                1,
                &[0u8; 64],
                &keys,
                &crate::VerifierOptions::default(),
            ),
            Err(crate::InvocationError::KeyResolutionFailure)
        );
    }

    #[test]
    fn ecdsa_accepts_raw_rs64_and_classifies_failures() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let msg = b"payload line\n";
        let sig: p256::ecdsa::Signature = sk.sign(msg);
        assert!(verify_ecdsa_p256_sha256(&vk, msg, &sig.to_bytes()[..]).is_ok());
        assert_eq!(
            verify_ecdsa_p256_sha256(&vk, msg, sig.to_der().as_bytes()),
            Err(EcdsaVerifyError::MalformedSignature),
            "DER must be malformed at the wire layer"
        );
        assert_eq!(
            verify_ecdsa_p256_sha256(&vk, b"altered payload\n", &sig.to_bytes()[..]),
            Err(EcdsaVerifyError::EquationFailure),
            "a structurally valid signature over another payload must fail the equation"
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2), "odd-length hex");
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// RFC 8032 §7.1 Test 1 signature (`Sign(seed=9d61..7f60, message=())`).
    ///
    /// This is an attributed RFC test-vector value under the applicable
    /// IETF Trust and BCP 78 framework, not a Revised-BSD Code Component.
    /// See this crate's `THIRD_PARTY_NOTICES.md`.
    /// `R || S`, exactly 64 octets, both components canonical.
    const RFC8032_T1_SIG_HEX: &str = "e5564300c360ac729086e2cc806e828a\
                                      84877f1eb8e5d974d873e065224901555f\
                                      b8821590a33bacc61e39701cf9b46bd25b\
                                      f5f0595bbe24655141438e7a100b";

    #[test]
    fn ed25519_canonical_accepts_rfc8032_test1_signature() {
        let sig = hex(RFC8032_T1_SIG_HEX);
        assert_eq!(sig.len(), 64);
        assert!(ed25519_signature_is_canonical(&sig));
    }

    #[test]
    fn ed25519_canonical_rejects_wrong_length_inputs() {
        assert!(!ed25519_signature_is_canonical(&[]));
        assert!(!ed25519_signature_is_canonical(&[0u8; 63]));
        assert!(!ed25519_signature_is_canonical(&[0u8; 65]));
    }

    #[test]
    fn ed25519_canonical_rejects_noncanonical_r() {
        // R = all-0xFF (masks to 0x7F..FF = 2^255 - 1, which is > p = 2^255 - 19).
        // S = valid (last half of the RFC 8032 Test 1 signature).
        let mut sig = vec![0xFFu8; 32];
        sig.extend_from_slice(&hex(RFC8032_T1_SIG_HEX)[32..]);
        assert_eq!(sig.len(), 64);
        assert!(!ed25519_signature_is_canonical(&sig));
    }

    #[test]
    fn ed25519_canonical_rejects_undecodable_r() {
        let undecodable_r = (0u8..=u8::MAX)
            .find_map(|low_byte| {
                let mut candidate = [0u8; 32];
                candidate[0] = low_byte;
                CompressedEdwardsY(candidate)
                    .decompress()
                    .is_none()
                    .then_some(candidate)
            })
            .expect("an undecodable canonical-field candidate");
        let mut sig = undecodable_r.to_vec();
        sig.extend_from_slice(&[0u8; 32]);

        assert!(!ed25519_signature_is_canonical(&sig));
        assert_malformed_signature_state(&sig);
    }

    #[test]
    fn ed25519_canonical_rejects_negative_zero_r() {
        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        let mut sig = negative_zero.to_vec();
        sig.extend_from_slice(&[0u8; 32]);

        assert!(!ed25519_signature_is_canonical(&sig));
        assert_malformed_signature_state(&sig);
    }

    #[test]
    fn ed25519_canonical_rejects_s_equals_l() {
        // S = L exactly (canonical lower bound for non-canonical S).
        let mut sig = hex(RFC8032_T1_SIG_HEX)[..32].to_vec();
        sig.extend_from_slice(&super::ED25519_L_LE);
        assert_eq!(sig.len(), 64);
        assert!(!ed25519_signature_is_canonical(&sig));
        assert_malformed_signature_state(&sig);
    }

    #[test]
    fn ed25519_canonical_rejects_s_equals_l_plus_one() {
        // S = L + 1.
        let mut s_plus_one = super::ED25519_L_LE;
        // LSB increment: L's byte 0 is 0xED, +1 = 0xEE, no carry.
        s_plus_one[0] = s_plus_one[0].wrapping_add(1);
        assert_ne!(s_plus_one[0], 0x00, "L+1 should not carry into byte 1");
        let mut sig = hex(RFC8032_T1_SIG_HEX)[..32].to_vec();
        sig.extend_from_slice(&s_plus_one);
        assert_eq!(sig.len(), 64);
        assert!(!ed25519_signature_is_canonical(&sig));
        assert_malformed_signature_state(&sig);
    }

    #[test]
    fn ed25519_canonical_accepts_s_equals_l_minus_one() {
        // S = L - 1 is the largest canonical S value.
        let mut s_minus_one = super::ED25519_L_LE;
        s_minus_one[0] = s_minus_one[0].wrapping_sub(1);
        let mut sig = hex(RFC8032_T1_SIG_HEX)[..32].to_vec();
        sig.extend_from_slice(&s_minus_one);
        assert_eq!(sig.len(), 64);
        assert!(ed25519_signature_is_canonical(&sig));
    }
}
