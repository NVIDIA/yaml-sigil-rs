// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Conformance suites that exercise local `fixtures/` through the workspace's
//! public `Transcriber`, `Verifier`, and `Signer` traits and selected
//! `yaml-sigil-core` helpers.
//!
//! Keep the [validation record](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/conformance-validation.md)
//! updated in the same commit as every conformance-related change, as required
//! by the [conformance guidance](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/AGENTS.md#conformance).

pub mod alg_ecdsa;
pub mod alg_ed25519;
pub mod base64;
pub mod decomposition;
pub mod fixtures;
pub mod key_id;
pub mod proto_outer;
pub mod schema_alignment;
pub mod transcoding;
pub mod verification_runtime;
pub mod yaml_signature;

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use yaml_sigil_signing::{AsyncSigner, Signer};
use yaml_sigil_verification::{AsyncVerifier, Verifier};

/// RustCrypto verification-key binding used by the conformance suites.
#[doc(hidden)]
pub trait ConformanceVerifier:
    Verifier<Ed25519VerifyingKey = Ed25519VerifyingKey, P256VerifyingKey = P256VerifyingKey>
{
}

impl<T> ConformanceVerifier for T where
    T: Verifier<Ed25519VerifyingKey = Ed25519VerifyingKey, P256VerifyingKey = P256VerifyingKey>
{
}

/// RustCrypto verification-key binding used by the async conformance suites.
#[doc(hidden)]
pub trait ConformanceAsyncVerifier:
    AsyncVerifier<Ed25519VerifyingKey = Ed25519VerifyingKey, P256VerifyingKey = P256VerifyingKey>
{
}

impl<T> ConformanceAsyncVerifier for T where
    T: AsyncVerifier<
            Ed25519VerifyingKey = Ed25519VerifyingKey,
            P256VerifyingKey = P256VerifyingKey,
        >
{
}

/// RustCrypto signing-key binding used by the conformance suites.
#[doc(hidden)]
pub trait ConformanceSigner:
    Signer<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}

impl<T> ConformanceSigner for T where
    T: Signer<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}

/// RustCrypto signing-key binding used by the async conformance suites.
#[doc(hidden)]
pub trait ConformanceAsyncSigner:
    AsyncSigner<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}

impl<T> ConformanceAsyncSigner for T where
    T: AsyncSigner<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}
