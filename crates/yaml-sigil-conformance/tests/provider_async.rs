// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Focused existing P-256 fixtures through downstream async provider APIs.
//!
//! Fixture bytes and public values remain in fixtures/alg-ecdsa with their
//! existing provenance and source terms in THIRD_PARTY_NOTICES.md. This test
//! adds no copied constants or new cryptographic validation rules.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

use p256::ecdsa::{Signature, VerifyingKey};
use signature::Verifier as _;
use yaml_sigil_conformance::fixtures::{load_bytes, load_string, require_hex_field};
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_verification::{
    ArtifactForm, AsyncProviderPublicKeys, AsyncProviderVerifier, AsyncProviderVerifierFactory,
    AsyncVerificationProviderBuilder, AsyncVerifier as _, ProviderAsyncVerifier,
    ProviderVerificationOutcome, UnqualifiedAsyncProviderPublicKeys,
    UnqualifiedProviderAsyncVerifier, VerifierOptions, VerifierState, resolve_p256_verifying_key,
};

struct Factory<'client>(&'client AtomicUsize);
struct Handle<'client> {
    calls: &'client AtomicUsize,
    key: VerifyingKey,
}

impl AsyncProviderVerifierFactory for Factory<'_> {
    type Verifier<'factory>
        = Handle<'factory>
    where
        Self: 'factory;

    async fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        public_key: &[u8],
    ) -> Result<Self::Verifier<'factory>, signature::Error> {
        tokio::task::yield_now().await;
        if algorithm != AlgorithmId::EcdsaP256Sha256 {
            return Err(signature::Error::new());
        }
        Ok(Handle {
            calls: self.0,
            key: resolve_p256_verifying_key(public_key).map_err(|_| signature::Error::new())?,
        })
    }
}

impl AsyncProviderVerifier for Handle<'_> {
    async fn verify_provider<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a [u8; 64],
    ) -> ProviderVerificationOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        match Signature::from_slice(signature) {
            Ok(sig) if self.key.verify(message, &sig).is_ok() => {
                ProviderVerificationOutcome::Verified
            }
            _ => ProviderVerificationOutcome::SignatureMismatch,
        }
    }
}

// Prove the public future is Send with a non-static factory, outside the
// implementation crate. Do not add a synchronous adapter just for this test.
async fn send_future<F: Future + Send>(future: F) -> F::Output {
    future.await
}

#[tokio::test]
async fn p256_fixtures_preserve_provider_outcomes() {
    let calls = AtomicUsize::new(0);
    let qualified =
        send_future(AsyncVerificationProviderBuilder::new(Factory(&calls)).qualify()).await;
    assert!(
        qualified
            .status(AlgorithmId::EcdsaP256Sha256)
            .is_qualified()
    );
    let unqualified = AsyncVerificationProviderBuilder::new(Factory(&calls)).build_unqualified();
    let (key, unqualified_key) = {
        let expected = load_string("alg-ecdsa", "verify-happy-path.expected.txt");
        let temporary_public = require_hex_field(&expected, "public key Q (uncompressed)");
        (
            send_future(qualified.bind_ecdsa_p256_sha256(&temporary_public))
                .await
                .unwrap(),
            send_future(unqualified.bind_ecdsa_p256_sha256(&temporary_public))
                .await
                .unwrap(),
        )
    };
    let keys = AsyncProviderPublicKeys {
        ed25519: None,
        p256: Some(&key),
    };
    let unqualified_keys = UnqualifiedAsyncProviderPublicKeys {
        ed25519: None,
        p256: Some(&unqualified_key),
    };
    for (file, form, verified) in [
        ("high-s.yaml", ArtifactForm::Yaml, true),
        ("low-s.yaml", ArtifactForm::Yaml, true),
        ("high-s.binpb", ArtifactForm::Proto, true),
        ("low-s.binpb", ArtifactForm::Proto, true),
        ("invalid-r-zero.binpb", ArtifactForm::Proto, false),
        ("invalid-s-equals-n.binpb", ArtifactForm::Proto, false),
        ("signature-63-bytes.binpb", ArtifactForm::Proto, false),
        ("signature-65-bytes.binpb", ArtifactForm::Proto, false),
    ] {
        let artifact = load_bytes("alg-ecdsa", file);
        let before = calls.load(Ordering::SeqCst);
        let result = send_future(ProviderAsyncVerifier::default().verify(
            &artifact,
            form,
            &keys,
            VerifierOptions::default(),
        ))
        .await
        .unwrap();
        let unqualified_result = send_future(UnqualifiedProviderAsyncVerifier::default().verify(
            &artifact,
            form,
            &unqualified_keys,
            VerifierOptions::default(),
        ))
        .await
        .unwrap();
        assert_eq!(result, unqualified_result, "{file}");
        if verified {
            assert!(matches!(result, VerifierState::Verified { .. }), "{file}");
        } else {
            assert_eq!(result, VerifierState::MalformedAttemptedSigned, "{file}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst) - before,
            if verified { 2 } else { 0 },
            "{file}"
        );
    }
}
