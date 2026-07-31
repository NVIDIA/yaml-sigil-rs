// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared cryptographic verification.
//!
//! The Ed25519 canonicality constants and rules below, together with the
//! test-only RFC 8032 section 7.1 signature, are third-party RFC material.
//! They are not relicensed under this file's Apache-2.0 declaration. See the
//! crate's `THIRD_PARTY_NOTICES.md` for attribution and applicable terms.

use ed25519_dalek::{Signature as EdSignature, Verifier as EdVerifier, VerifyingKey as EdVk};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Vk};
use signature::Verifier as P256VerifierTrait;

pub(crate) fn verify_ed25519(vk: &EdVk, payload: &[u8], sig_bytes: &[u8]) -> Result<(), ()> {
    let sig = EdSignature::try_from(sig_bytes).map_err(|_| ())?;
    EdVerifier::verify(vk, payload, &sig).map_err(|_| ())
}

/// edwards25519 field prime `p = 2^255 - 19`, little-endian.
///
/// Used to validate that the `R` component of an Ed25519 signature is the
/// canonical encoding of an Edwards-form point (per RFC 8032 §5.1.2: clear the
/// x-sign bit at byte 31 then require the resulting integer to be `< p`).
const ED25519_P_LE: [u8; 32] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// edwards25519 prime-order subgroup order
/// `L = 2^252 + 27742317777372353535851937790883648493`, little-endian.
///
/// Used to validate that the `S` component of an Ed25519 signature is a
/// canonical scalar (per RFC 8032 §5.1.7 / §7: `S < L`).
const ED25519_L_LE: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `a < b` for two little-endian 32-byte unsigned integers.
///
/// Compared most-significant byte first. Not constant-time; both operands are
/// signature bytes / public curve constants, never key material.
fn lt_le_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Returns `true` iff `sig_bytes` is a canonical-encoded Ed25519 signature
/// per the strict-variant rule the YamlSigil spec mandates.
///
/// Splits the 64-octet `R || S` wire form into the two 32-byte halves and
/// checks (per RFC 8032 §5.1.2 / §5.1.7):
///
/// - `R`'s y-coordinate is `< p` after masking the x-sign bit at byte 31.
/// - `S` is `< L`.
///
/// Both checks are spec-mandated structural pre-validation of the artifact
/// bytes; failing either is a *malformed-artifact* signal
/// (`VerifierState::MalformedAttemptedSigned`), not a signature-equation
/// failure. `ed25519-dalek`'s `VerifyingKey::verify` collapses canonical
/// rejection and equation-failure into one `SignatureError`, so this helper
/// runs *before* the crypto round-trip to preserve the verifier-state
/// distinction (which YamlSigil consumers treat as load-bearing: malformed
/// vs. failed-verification surface different audit lenses).
///
/// See `docs/conformance-validation.md` for the fixture coverage around this
/// structural pre-validation.
pub(crate) fn ed25519_signature_is_canonical(sig_bytes: &[u8]) -> bool {
    if sig_bytes.len() != 64 {
        return false;
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    r[31] &= 0x7F;
    if !lt_le_32(&r, &ED25519_P_LE) {
        return false;
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig_bytes[32..]);
    lt_le_32(&s, &ED25519_L_LE)
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
    use super::{EcdsaVerifyError, ed25519_signature_is_canonical, verify_ecdsa_p256_sha256};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

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
    fn ed25519_canonical_rejects_s_equals_l() {
        // S = L exactly (canonical lower bound for non-canonical S).
        let mut sig = hex(RFC8032_T1_SIG_HEX)[..32].to_vec();
        sig.extend_from_slice(&super::ED25519_L_LE);
        assert_eq!(sig.len(), 64);
        assert!(!ed25519_signature_is_canonical(&sig));
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
