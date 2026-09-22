// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Convert provider encodings before entering the P-256 algorithm boundary.
//!
//! These helpers use RustCrypto's parsers and return canonical fixed-width
//! bytes. They do not verify a signature against a message or widen the
//! algorithm's accepted signature and public-key encodings.
//!
//! The point-encoding selection follows
//! *Standards for Efficient Cryptography 1 (SEC 1)*, Version 2.0, section 2.3.3.
//! Those encoding rules are not relicensed under this file's Apache-2.0
//! declaration. See this crate's `THIRD_PARTY_NOTICES.md` for applicable terms.

use thiserror::Error;

/// A provider encoding could not be converted to the P-256 profile's byte form.
///
/// Errors retain no input bytes or implementation-specific parser errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum P256EncodingError {
    /// The input is not a DER signature with nonzero components below the order.
    #[error("invalid P-256 DER signature")]
    InvalidSignature,
    /// The input is not an admissible compressed or uncompressed public point.
    #[error("invalid P-256 public-key encoding")]
    InvalidPublicKey,
}

/// Convert a strict ASN.1 DER P-256 signature to 64 big-endian `r || s` octets.
///
/// Both components must satisfy `1 <= r, s < n`. Valid leading sign padding
/// is removed, and each component is left-padded to 32 octets. High-S and
/// low-S signatures retain their original scalar values. This conversion
/// checks encoding and ranges, not the signature equation.
///
/// # Errors
///
/// Returns [`P256EncodingError::InvalidSignature`] for malformed, truncated,
/// non-minimal, trailing, negative, zero, or out-of-range input. DER signatures
/// for this curve have at most 72 octets; larger inputs are rejected before
/// parsing. Raw signatures, PEM, and other wrappers are not accepted.
///
/// # Example
///
/// ```
/// use yaml_sigil_core::p256_der_signature_to_raw;
///
/// // Synthetic r = s = 1 demonstrates conversion, not message verification.
/// let raw = p256_der_signature_to_raw(&[0x30, 6, 2, 1, 1, 2, 1, 1])?;
/// assert_eq!(raw.len(), 64);
/// assert_eq!((raw[31], raw[63]), (1, 1));
/// # Ok::<(), yaml_sigil_core::P256EncodingError>(())
/// ```
pub fn p256_der_signature_to_raw(bytes: &[u8]) -> Result<[u8; 64], P256EncodingError> {
    // Two INTEGERs, each with at most 32 value octets and one sign-padding
    // octet, plus their tags/lengths and the SEQUENCE tag/length, fit in 72.
    if !(8..=72).contains(&bytes.len()) {
        return Err(P256EncodingError::InvalidSignature);
    }
    p256::ecdsa::Signature::from_der(bytes)
        .map(|signature| signature.to_bytes().into())
        .map_err(|_| P256EncodingError::InvalidSignature)
}

/// Convert a P-256 public point to 65 uncompressed SEC 1 octets.
///
/// Accepts exactly 33 compressed octets starting with `0x02` or `0x03`, or
/// exactly 65 uncompressed octets starting with `0x04`. The point must be a
/// valid, nonidentity P-256 point. An already uncompressed key is validated
/// and returned unchanged. Private keys and signatures are never needed.
///
/// # Errors
///
/// Returns [`P256EncodingError::InvalidPublicKey`] for an invalid length, tag,
/// coordinate, or point. Infinity, compact, hybrid, x-only, DER, and PEM
/// encodings are not accepted. Existing algorithm-slot validators still
/// require the uncompressed output; they do not perform this conversion.
///
/// # Example
///
/// ```
/// use yaml_sigil_core::p256_public_key_to_uncompressed;
///
/// // The fixed private key is only an example fixture. Providers expose their
/// // public bytes without exporting a private key.
/// let key = p256::ecdsa::SigningKey::from_slice(&[7; 32])?;
/// let compressed = key.verifying_key().to_sec1_point(true);
/// let canonical = p256_public_key_to_uncompressed(compressed.as_bytes())?;
/// assert_eq!(canonical[0], 0x04);
/// assert_eq!(canonical.as_slice(), key.verifying_key().to_sec1_point(false).as_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn p256_public_key_to_uncompressed(bytes: &[u8]) -> Result<[u8; 65], P256EncodingError> {
    // SEC 1 section 2.3.3 defines these compressed/uncompressed point tags.
    match (bytes.len(), bytes.first().copied()) {
        (33, Some(0x02 | 0x03)) | (65, Some(0x04)) => {}
        _ => return Err(P256EncodingError::InvalidPublicKey),
    }
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|_| P256EncodingError::InvalidPublicKey)?;
    let point = key.to_sec1_point(false);
    // A validated nonidentity point encoded without compression has 65 octets.
    let mut output = [0; 65];
    output.copy_from_slice(point.as_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use p256::elliptic_curve::Curve;

    use super::*;

    // Test-only encoder for deliberately invalid component values. Production
    // parsing is entirely delegated to RustCrypto.
    fn der_pair(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut der = vec![0x30, u8::try_from(4 + r.len() + s.len()).unwrap(), 2];
        der.push(u8::try_from(r.len()).unwrap());
        der.extend_from_slice(r);
        der.extend_from_slice(&[2, u8::try_from(s.len()).unwrap()]);
        der.extend_from_slice(s);
        der
    }

    #[test]
    fn der_padding_and_high_s_are_preserved_as_scalar_values() {
        let largest = -p256::Scalar::ONE;
        for (r, s) in [
            (p256::Scalar::ONE, p256::Scalar::ONE),
            (p256::Scalar::from(127u64), p256::Scalar::from(128u64)),
            (p256::Scalar::from(128u64), p256::Scalar::ONE),
            (largest, largest),
        ] {
            let signature =
                p256::ecdsa::Signature::from_scalars(r.to_bytes(), s.to_bytes()).unwrap();
            let der = signature.to_der();
            let raw = p256_der_signature_to_raw(der.as_bytes()).unwrap();
            assert_eq!(raw.as_slice(), signature.to_bytes().as_slice());
        }
        let high =
            p256::ecdsa::Signature::from_scalars(largest.to_bytes(), largest.to_bytes()).unwrap();
        assert_eq!(high.to_der().as_bytes().len(), 72);
        assert_ne!(high, high.normalize_s());
        let raw = p256_der_signature_to_raw(high.to_der().as_bytes()).unwrap();
        assert_eq!(&raw[32..], largest.to_bytes().as_slice());
    }

    #[test]
    fn der_rejects_zero_and_out_of_range_components() {
        let mut order = vec![0];
        order.extend_from_slice(&p256::NistP256::ORDER.to_be_bytes());
        let mut oversized = vec![0];
        oversized.extend_from_slice(&[0xff; 32]);
        for invalid in [vec![0], order, oversized, vec![1; 33]] {
            for der in [der_pair(&invalid, &[1]), der_pair(&[1], &invalid)] {
                assert_eq!(
                    p256_der_signature_to_raw(&der),
                    Err(P256EncodingError::InvalidSignature),
                );
            }
        }
    }

    #[test]
    fn der_rejects_noncanonical_malformed_and_trailing_data() {
        let valid = der_pair(&[1], &[1]);
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut wrong_tag = valid.clone();
        wrong_tag[2] = 4;
        for invalid in [
            Vec::new(),
            vec![0; 73],
            valid[..valid.len() - 1].to_vec(),
            trailing,
            wrong_tag,
            der_pair(&[], &[1]),
            der_pair(&[0x80], &[1]),
            der_pair(&[1], &[0x80]),
            der_pair(&[0, 1], &[1]),
            der_pair(&[1], &[0, 1]),
            vec![0x30, 0x81, 6, 2, 1, 1, 2, 1, 1],
            vec![0x30, 0x80, 2, 1, 1, 2, 1, 1, 0, 0],
            vec![1; 64],
        ] {
            assert_eq!(
                p256_der_signature_to_raw(&invalid),
                Err(P256EncodingError::InvalidSignature),
            );
        }
    }

    #[test]
    fn both_compressed_parities_and_uncompressed_points_round_trip() {
        let key = p256::ecdsa::SigningKey::from_slice(&[11; 32]).unwrap();
        let mut compressed = key.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        let mut outputs = Vec::new();
        for tag in [2, 3] {
            compressed[0] = tag;
            let output = p256_public_key_to_uncompressed(&compressed).unwrap();
            assert_eq!(output[0], 4);
            assert_eq!(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&output)
                    .unwrap()
                    .to_sec1_point(true)
                    .as_bytes(),
                compressed,
            );
            assert_eq!(p256_public_key_to_uncompressed(&output).unwrap(), output);
            outputs.push(output);
        }
        assert_eq!(&outputs[0][1..33], &outputs[1][1..33]);
        assert_ne!(&outputs[0][33..], &outputs[1][33..]);
    }

    #[test]
    fn points_reject_invalid_shapes_coordinates_and_infinity() {
        let key = p256::ecdsa::SigningKey::from_slice(&[12; 32]).unwrap();
        let valid = key.verifying_key().to_sec1_point(false);
        let mut trailing = valid.as_bytes().to_vec();
        trailing.push(0);
        let mut hybrid = valid.as_bytes().to_vec();
        hybrid[0] = 6;
        let mut hybrid_odd = hybrid.clone();
        hybrid_odd[0] = 7;
        let mut invalid_compressed = vec![0xff; 33];
        invalid_compressed[0] = 2;
        let mut invalid_uncompressed = vec![0xff; 65];
        invalid_uncompressed[0] = 4;
        let mut off_curve = vec![0; 65];
        off_curve[0] = 4;
        for invalid in [
            Vec::new(),
            vec![0],
            vec![0; 32],
            vec![5; 33],
            vec![2; 65],
            vec![4; 33],
            valid.as_bytes()[..64].to_vec(),
            trailing,
            hybrid,
            hybrid_odd,
            invalid_compressed,
            invalid_uncompressed,
            off_curve,
        ] {
            assert_eq!(
                p256_public_key_to_uncompressed(&invalid),
                Err(P256EncodingError::InvalidPublicKey),
            );
        }
    }
}
