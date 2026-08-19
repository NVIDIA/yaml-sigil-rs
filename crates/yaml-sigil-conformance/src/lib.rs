// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Test harness that drives local `fixtures/` through the workspace's public
//! trait surfaces (`Transcriber`, `Verifier`, `Signer`) and a small set of
//! `yaml-sigil-core` helpers.
//!
//! Audit trail: [`docs/conformance-validation.md`](../../docs/conformance-validation.md).
//! Every conformance-related change to this crate MUST update that document in
//! the same commit (see also [`AGENTS.md`](../../AGENTS.md) § *Conformance
//! testing*).

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

/// Verifier binding exercised by this implementation's conformance harness.
#[doc(hidden)]
pub trait ConformanceVerifier:
    Verifier<Ed25519VerifyingKey = Ed25519VerifyingKey, P256VerifyingKey = P256VerifyingKey>
{
}

impl<T> ConformanceVerifier for T where
    T: Verifier<Ed25519VerifyingKey = Ed25519VerifyingKey, P256VerifyingKey = P256VerifyingKey>
{
}

/// Async verifier binding exercised by this implementation's conformance harness.
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

/// Signer binding exercised by this implementation's conformance harness.
#[doc(hidden)]
pub trait ConformanceSigner:
    Signer<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}

impl<T> ConformanceSigner for T where
    T: Signer<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}

/// Async signer binding exercised by this implementation's conformance harness.
#[doc(hidden)]
pub trait ConformanceAsyncSigner:
    AsyncSigner<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}

impl<T> ConformanceAsyncSigner for T where
    T: AsyncSigner<Ed25519SigningKey = Ed25519SigningKey, P256SigningKey = P256SigningKey>
{
}
