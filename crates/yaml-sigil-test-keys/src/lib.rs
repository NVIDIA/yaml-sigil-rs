// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Build-time key pairs for integration tests.
//!
//! Add this unpublished crate only under [`dev-dependencies`]. Its keys are for
//! tests and must not be used in production. Building or checking
//! `yaml-sigil-verification` or `yaml-sigil-signing` without test targets does
//! not compile this crate. Building their tests, or running
//! `cargo test -p yaml-sigil-test-keys`, compiles it.
//!
//! [`dev-dependencies`]: https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies

#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/buildtime_test_keys.rs"));

use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};

#[inline]
pub fn ed25519_signing_key(idx: u8) -> EdSigningKey {
    match idx {
        0 => EdSigningKey::from_bytes(&ED25519_SIGNING_KEY_BYTES_0),
        1 => EdSigningKey::from_bytes(&ED25519_SIGNING_KEY_BYTES_1),
        _ => panic!("ed25519_signing_key: idx must be 0 or 1"),
    }
}

#[inline]
pub fn ed25519_verifying_key(idx: u8) -> EdVerifyingKey {
    EdVerifyingKey::from(&ed25519_signing_key(idx))
}

#[inline]
pub fn p256_signing_key(idx: u8) -> P256SigningKey {
    let s: &[u8] = match idx {
        0 => &P256_SIGNING_KEY_BYTES_0[..],
        1 => &P256_SIGNING_KEY_BYTES_1[..],
        _ => panic!("p256_signing_key: idx must be 0 or 1"),
    };
    P256SigningKey::try_from(s).expect("build-time P-256 signing key")
}

#[inline]
pub fn p256_verifying_key(idx: u8) -> P256VerifyingKey {
    *p256_signing_key(idx).verifying_key()
}
