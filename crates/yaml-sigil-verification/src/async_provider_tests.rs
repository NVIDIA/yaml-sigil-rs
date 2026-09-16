// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Tests of our orchestration with controllable, borrowed provider adapters.
//! The adapters reuse the existing crypto helpers and attributed qualification
//! inputs; they do not certify any third-party SDK's scheduling or randomness.

use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use yaml_sigil_signing as signing;
use yaml_sigil_traits::signing::{SignRequest, SigningKey};
use yaml_sigil_traits::verification::PublicKeys;

use super::*;
use signing::{AsyncProviderSigner, AsyncSigner, OutputForm, SignError, SignOutcome};

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, Option<Waker>)>,
    cancelled: AtomicUsize,
}

impl Gate {
    fn pause(&self) {
        self.state.lock().unwrap().0 = true;
    }
    fn release(&self) {
        let waker = {
            let mut state = self.state.lock().unwrap();
            state.0 = false;
            state.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    fn wait(&self) -> GateWait<'_> {
        GateWait {
            gate: self,
            completed: false,
        }
    }
}

struct GateWait<'a> {
    gate: &'a Gate,
    completed: bool,
}
impl Future for GateWait<'_> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.gate.state.lock().unwrap();
        if state.0 {
            state.1 = Some(cx.waker().clone());
            Poll::Pending
        } else {
            drop(state);
            self.completed = true;
            Poll::Ready(())
        }
    }
}
impl Drop for GateWait<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.gate.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn assert_pending<F: Future>(future: Pin<&mut F>) -> Arc<WakeCount> {
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    assert!(future.poll(&mut Context::from_waker(&waker)).is_pending());
    counter
}
fn assert_send<T: Send>(_: &T) {}
fn assert_send_sync<T: Send + Sync>() {}

#[derive(Default)]
struct Control {
    signing: Gate,
    binding: Gate,
    verification: Gate,
    sign_calls: AtomicUsize,
    bind_calls: AtomicUsize,
    verify_calls: AtomicUsize,
    sign_fault: AtomicUsize,
    verify_fault: AtomicUsize,
    messages: Mutex<Vec<Vec<u8>>>,
}

enum SecretKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}
struct TestSigner<'a> {
    control: &'a Control,
    key: SecretKey,
}
impl<'a> TestSigner<'a> {
    fn new(control: &'a Control, algorithm: AlgorithmId) -> Self {
        let key = match algorithm {
            AlgorithmId::Ed25519 => {
                SecretKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[12; 32]))
            }
            AlgorithmId::EcdsaP256Sha256 => {
                SecretKey::P256(p256::ecdsa::SigningKey::from_slice(&[12; 32]).unwrap())
            }
        };
        Self { control, key }
    }
    fn public_key(&self) -> Vec<u8> {
        match &self.key {
            SecretKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
            SecretKey::P256(key) => key.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
        }
    }
    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        match self.control.sign_fault.load(Ordering::SeqCst) {
            1 => return Err(signature::Error::new()),
            2 => return Ok([0xff; 64]),
            _ => (),
        }
        let message = if self.control.sign_fault.load(Ordering::SeqCst) == 3 {
            b"wrong message"
        } else {
            message
        };
        match &self.key {
            SecretKey::Ed25519(key) => {
                let signature: ed25519_dalek::Signature =
                    signature::Signer::try_sign(key, message)?;
                Ok(signature.to_bytes())
            }
            SecretKey::P256(key) => {
                let signature: p256::ecdsa::Signature = signature::Signer::try_sign(key, message)?;
                Ok(signature.to_bytes().into())
            }
        }
    }
}
impl AsyncProviderSigner for TestSigner<'_> {
    async fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        self.control.sign_calls.fetch_add(1, Ordering::SeqCst);
        self.control.messages.lock().unwrap().push(message.to_vec());
        self.control.signing.wait().await;
        self.sign_message(message)
    }
}
// The async-only adapter above does not implement a synchronous operation.
// This separate wrapper compares bounded sync and async orchestration.
struct SyncSigner<'a>(&'a TestSigner<'a>);
impl signature::Signer<[u8; 64]> for SyncSigner<'_> {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        self.0.control.sign_calls.fetch_add(1, Ordering::SeqCst);
        self.0.sign_message(message)
    }
}

#[derive(Clone)]
enum TestPublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}
impl TestPublicKey {
    fn slot(&self) -> usize {
        match self {
            Self::Ed25519(_) => 0,
            Self::P256(_) => 1,
        }
    }

    fn verifies(&self, message: &[u8], signature: &[u8; 64], strict_ed25519: bool) -> bool {
        match self {
            Self::Ed25519(key) if strict_ed25519 => key
                .verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok(),
            Self::Ed25519(key) => crypto::verify_ed25519(key, message, signature).is_ok(),
            Self::P256(key) => crypto::verify_ecdsa_p256_sha256(key, message, signature).is_ok(),
        }
    }
}
#[derive(Clone, Copy)]
enum Behavior {
    Honest,
    StrictEd25519,
    BindingFailure,
    Failure,
    AcceptAll,
    CacheFirst,
    Retarget,
    AcceptAnyKey,
    InvalidateAlternate,
}
struct TestFactory<'a> {
    control: &'a Control,
    behavior: Behavior,
    cached: Mutex<[Vec<TestPublicKey>; 2]>,
}
impl<'a> TestFactory<'a> {
    fn new(control: &'a Control) -> Self {
        Self::with_behavior(control, Behavior::Honest)
    }
    fn with_behavior(control: &'a Control, behavior: Behavior) -> Self {
        Self {
            control,
            behavior,
            cached: Mutex::new([Vec::new(), Vec::new()]),
        }
    }
    fn bind_key(
        &self,
        algorithm: AlgorithmId,
        bytes: &[u8],
    ) -> Result<TestVerifier<'_>, signature::Error> {
        if matches!(self.behavior, Behavior::BindingFailure) {
            return Err(signature::Error::new());
        }
        let mut key = match algorithm {
            AlgorithmId::Ed25519 => TestPublicKey::Ed25519(
                resolve_ed25519_verifying_key(bytes).map_err(|_| signature::Error::new())?,
            ),
            AlgorithmId::EcdsaP256Sha256 => TestPublicKey::P256(
                resolve_p256_verifying_key(bytes).map_err(|_| signature::Error::new())?,
            ),
        };
        // Model the same accidental shared-state mistakes independently for
        // each algorithm. Qualification must reject them in either slot.
        let mut cached = self.cached.lock().unwrap();
        let keys = &mut cached[key.slot()];
        let key_index = keys.len();
        match self.behavior {
            Behavior::CacheFirst if !keys.is_empty() => key = keys[0].clone(),
            Behavior::Retarget => {
                keys.clear();
                keys.push(key.clone());
            }
            Behavior::CacheFirst | Behavior::AcceptAnyKey | Behavior::InvalidateAlternate => {
                keys.push(key.clone());
            }
            _ => (),
        }
        Ok(TestVerifier {
            factory: self,
            key,
            key_index,
        })
    }
}
struct TestVerifier<'a> {
    factory: &'a TestFactory<'a>,
    key: TestPublicKey,
    key_index: usize,
}
impl TestVerifier<'_> {
    fn verify_message(&self, message: &[u8], signature: &[u8; 64]) -> ProviderVerificationOutcome {
        match self.factory.control.verify_fault.load(Ordering::SeqCst) {
            1 => return ProviderVerificationOutcome::SignatureMismatch,
            2 => return ProviderVerificationOutcome::ProviderFailure,
            _ => (),
        }
        match self.factory.behavior {
            Behavior::Failure => return ProviderVerificationOutcome::ProviderFailure,
            Behavior::AcceptAll => return ProviderVerificationOutcome::Verified,
            _ => (),
        }
        let verifies = |key: &TestPublicKey| {
            key.verifies(
                message,
                signature,
                matches!(self.factory.behavior, Behavior::StrictEd25519),
            )
        };
        let valid = match self.factory.behavior {
            Behavior::Retarget | Behavior::AcceptAnyKey | Behavior::InvalidateAlternate => {
                let mut cached = self.factory.cached.lock().unwrap();
                let keys = &mut cached[self.key.slot()];
                match self.factory.behavior {
                    Behavior::Retarget => keys.last().is_some_and(verifies),
                    Behavior::AcceptAnyKey => keys.iter().any(verifies),
                    _ => {
                        let valid = keys.get(self.key_index).is_some_and(verifies);
                        if self.key_index == 0 {
                            keys.truncate(1);
                        }
                        valid
                    }
                }
            }
            _ => verifies(&self.key),
        };
        if valid {
            ProviderVerificationOutcome::Verified
        } else {
            ProviderVerificationOutcome::SignatureMismatch
        }
    }
}
impl AsyncProviderVerifierFactory for TestFactory<'_> {
    type Verifier<'factory>
        = TestVerifier<'factory>
    where
        Self: 'factory;
    async fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        bytes: &[u8],
    ) -> Result<TestVerifier<'factory>, signature::Error> {
        self.control.bind_calls.fetch_add(1, Ordering::SeqCst);
        self.control.binding.wait().await;
        self.bind_key(algorithm, bytes)
    }
}
impl AsyncProviderVerifier for TestVerifier<'_> {
    async fn verify_provider(
        &self,
        message: &[u8],
        signature: &[u8; 64],
    ) -> ProviderVerificationOutcome {
        self.factory
            .control
            .verify_calls
            .fetch_add(1, Ordering::SeqCst);
        self.factory
            .control
            .messages
            .lock()
            .unwrap()
            .push(message.to_vec());
        self.factory.control.verification.wait().await;
        self.verify_message(message, signature)
    }
}
struct SyncFactory<'a>(TestFactory<'a>);
struct SyncVerifier<'a>(TestVerifier<'a>);
impl signature::Verifier<[u8; 64]> for SyncVerifier<'_> {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        (self.0.verify_message(message, signature) == ProviderVerificationOutcome::Verified)
            .then_some(())
            .ok_or_else(signature::Error::new)
    }
}
impl ProviderVerifier for SyncVerifier<'_> {
    fn verify_provider(&self, message: &[u8], signature: &[u8; 64]) -> ProviderVerificationOutcome {
        self.0
            .factory
            .control
            .verify_calls
            .fetch_add(1, Ordering::SeqCst);
        self.0.verify_message(message, signature)
    }
}
impl ProviderVerifierFactory for SyncFactory<'_> {
    fn bind<'a>(
        &'a self,
        algorithm: AlgorithmId,
        bytes: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'a>, signature::Error> {
        self.0.control.bind_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(SyncVerifier(self.0.bind_key(algorithm, bytes)?)))
    }
}

fn request<'a, K>(
    payload: &'a [u8],
    algorithm: AlgorithmId,
    form: OutputForm,
    key: &'a K,
) -> SignRequest<'a, K, K> {
    SignRequest {
        payload,
        algorithm,
        key: match algorithm {
            AlgorithmId::Ed25519 => SigningKey::Ed25519(key),
            AlgorithmId::EcdsaP256Sha256 => SigningKey::EcdsaP256Sha256(key),
        },
        keyid: Some("quoted\"key"),
        append_missing_final_newline: true,
        output_form: form,
        algorithm_parameters: &[],
    }
}
fn public_keys<K>(algorithm: AlgorithmId, key: &K) -> PublicKeys<'_, K, K> {
    PublicKeys {
        ed25519: (algorithm == AlgorithmId::Ed25519).then_some(key),
        p256: (algorithm == AlgorithmId::EcdsaP256Sha256).then_some(key),
    }
}
fn builder<'a>(
    signer: &'a TestSigner<'a>,
    algorithm: AlgorithmId,
) -> signing::AsyncProviderSigningKeyBuilder<'a> {
    let public_key = signer.public_key();
    match algorithm {
        AlgorithmId::Ed25519 => {
            signing::AsyncProviderSigningKeyBuilder::ed25519(signer, &public_key)
        }
        AlgorithmId::EcdsaP256Sha256 => {
            signing::AsyncProviderSigningKeyBuilder::ecdsa_p256_sha256(signer, &public_key)
        }
    }
}
fn success(outcome: SignOutcome) -> signing::SignSuccess {
    match outcome {
        SignOutcome::Success(success) => success,
        other => panic!("{other:?}"),
    }
}
fn finite(maximum: usize) -> ArtifactResourceLimits {
    ArtifactResourceLimits::unbounded().with_max_artifact_bytes(NonZeroUsize::new(maximum).unwrap())
}

#[tokio::test]
async fn async_trait_round_trips_preserve_both_algorithms_forms_and_metadata() {
    assert_send_sync::<signing::AsyncProviderSigningKey<'_>>();
    assert_send_sync::<signing::UnqualifiedAsyncProviderSigningKey<'_>>();
    assert_send_sync::<AsyncProviderVerifyingKey<'_>>();
    assert_send_sync::<UnqualifiedAsyncProviderVerifyingKey<'_>>();
    for algorithm in [AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256] {
        for (output_form, form, payload, expected) in [
            (
                OutputForm::Yaml,
                ArtifactForm::Yaml,
                b"async: true".as_slice(),
                b"async: true\n".as_slice(),
            ),
            (
                OutputForm::Protobuf,
                ArtifactForm::Proto,
                &[0xff, 0, 0x81],
                &[0xff, 0, 0x81],
            ),
        ] {
            for qualified in [true, false] {
                let control = Control::default();
                let signer = TestSigner::new(&control, algorithm);
                let signed = if qualified {
                    let key = builder(&signer, algorithm).build().unwrap();
                    let req = request(payload, algorithm, output_form, &key);
                    let facade = signing::ProviderAsyncSigner::default();
                    assert_eq!(facade.capabilities(), signing::signer_capabilities());
                    let future = facade.sign(&req);
                    assert_send(&future);
                    success(future.await)
                } else {
                    let key = builder(&signer, algorithm).build_unqualified().unwrap();
                    let req = request(payload, algorithm, output_form, &key);
                    success(
                        signing::UnqualifiedProviderAsyncSigner::default()
                            .sign(&req)
                            .await,
                    )
                };
                assert_eq!(control.sign_calls.load(Ordering::SeqCst), 1);
                assert_eq!(control.messages.lock().unwrap()[0], expected);
                assert_eq!(
                    signed.modified_payload,
                    if payload == expected {
                        vec![]
                    } else {
                        expected.to_vec()
                    }
                );
                if qualified {
                    let provider =
                        AsyncVerificationProviderBuilder::new(TestFactory::new(&control))
                            .qualify()
                            .await;
                    assert!(provider.status(AlgorithmId::Ed25519).is_qualified());
                    assert!(provider.status(AlgorithmId::EcdsaP256Sha256).is_qualified());
                    // The caller's temporary public-key buffer goes away while
                    // this handle continues borrowing the provider/client.
                    let key = {
                        let temporary_key = signer.public_key();
                        match algorithm {
                            AlgorithmId::Ed25519 => {
                                provider.bind_ed25519(&temporary_key).await.unwrap()
                            }
                            AlgorithmId::EcdsaP256Sha256 => provider
                                .bind_ecdsa_p256_sha256(&temporary_key)
                                .await
                                .unwrap(),
                        }
                    };
                    let keys = public_keys(algorithm, &key);
                    let facade = ProviderAsyncVerifier::default();
                    assert_eq!(facade.capabilities(), verifier_capabilities());
                    let before = control.verify_calls.load(Ordering::SeqCst);
                    let future =
                        facade.verify(&signed.artifact, form, &keys, VerifierOptions::default());
                    assert_send(&future);
                    assert_eq!(
                        future.await.unwrap(),
                        VerifierState::Verified {
                            payload: expected.to_vec(),
                            algorithm
                        }
                    );
                    assert_eq!(control.verify_calls.load(Ordering::SeqCst), before + 1);
                    let pre = facade.pre_verify(&signed.artifact, form, false, true).await;
                    let metadata = facade
                        .verify_with_metadata(
                            &signed.artifact,
                            form,
                            &keys,
                            VerifierOptions::default(),
                            true,
                        )
                        .await
                        .unwrap();
                    assert_eq!(metadata.parser_observations, pre.parser_observations);
                    assert_eq!(
                        facade
                            .verify_from_pre_verify(&pre, &keys, VerifierOptions::default())
                            .await
                            .unwrap(),
                        metadata.state
                    );
                    assert_eq!(
                        verify_with_async_provider(
                            &signed.artifact,
                            form,
                            &keys,
                            VerifierOptions::default()
                        )
                        .await
                        .unwrap(),
                        metadata.state
                    );
                    assert_eq!(
                        verify_with_async_provider_and_metadata(
                            &signed.artifact,
                            form,
                            &keys,
                            VerifierOptions::default(),
                            true
                        )
                        .await
                        .unwrap(),
                        metadata
                    );
                    assert_eq!(
                        verify_from_pre_verify_with_async_provider(
                            &pre,
                            &keys,
                            VerifierOptions::default()
                        )
                        .await
                        .unwrap(),
                        metadata.state
                    );
                } else {
                    let provider =
                        AsyncVerificationProviderBuilder::new(TestFactory::new(&control))
                            .build_unqualified();
                    assert_eq!(control.bind_calls.load(Ordering::SeqCst), 0);
                    let bytes = signer.public_key();
                    let key = match algorithm {
                        AlgorithmId::Ed25519 => provider.bind_ed25519(&bytes).await.unwrap(),
                        AlgorithmId::EcdsaP256Sha256 => {
                            provider.bind_ecdsa_p256_sha256(&bytes).await.unwrap()
                        }
                    };
                    let keys = public_keys(algorithm, &key);
                    let facade = UnqualifiedProviderAsyncVerifier::default();
                    let expected_state = VerifierState::Verified {
                        payload: expected.to_vec(),
                        algorithm,
                    };
                    assert_eq!(
                        facade
                            .verify(&signed.artifact, form, &keys, VerifierOptions::default())
                            .await
                            .unwrap(),
                        expected_state
                    );
                    let pre = facade.pre_verify(&signed.artifact, form, false, true).await;
                    let metadata = facade
                        .verify_with_metadata(
                            &signed.artifact,
                            form,
                            &keys,
                            VerifierOptions::default(),
                            true,
                        )
                        .await
                        .unwrap();
                    assert_eq!(metadata.parser_observations, pre.parser_observations);
                    assert_eq!(
                        facade
                            .verify_from_pre_verify(&pre, &keys, VerifierOptions::default())
                            .await
                            .unwrap(),
                        expected_state
                    );
                    assert_eq!(
                        verify_with_unqualified_async_provider(
                            &signed.artifact,
                            form,
                            &keys,
                            VerifierOptions::default()
                        )
                        .await
                        .unwrap(),
                        expected_state
                    );
                    assert_eq!(
                        verify_with_unqualified_async_provider_and_metadata(
                            &signed.artifact,
                            form,
                            &keys,
                            VerifierOptions::default(),
                            true
                        )
                        .await
                        .unwrap(),
                        metadata
                    );
                    assert_eq!(
                        verify_from_pre_verify_with_unqualified_async_provider(
                            &pre,
                            &keys,
                            VerifierOptions::default()
                        )
                        .await
                        .unwrap(),
                        expected_state
                    );
                }
                assert_eq!(control.messages.lock().unwrap().last().unwrap(), expected);
            }
        }
    }
}

#[tokio::test]
async fn signing_suspends_wakes_and_drops_the_borrowed_operation() {
    let control = Control::default();
    let signer = TestSigner::new(&control, AlgorithmId::Ed25519);
    let key = builder(&signer, AlgorithmId::Ed25519).build().unwrap();
    let req = request(b"ready: true", AlgorithmId::Ed25519, OutputForm::Yaml, &key);
    control.signing.pause();
    let mut future = Box::pin(signing::sign_with_async_provider(&req));
    assert_send(&future);
    let wake = assert_pending(future.as_mut());
    assert_eq!(control.sign_calls.load(Ordering::SeqCst), 1);
    control.signing.release();
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert!(success(future.await).artifact.starts_with(b"ready: true\n"));
    control.signing.pause();
    let mut unfinished = Box::pin(signing::sign_with_async_provider(&req));
    assert_pending(unfinished.as_mut());
    drop(unfinished);
    assert_eq!(control.signing.cancelled.load(Ordering::SeqCst), 1);
    control.signing.release();
    assert_eq!(control.sign_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn qualification_and_binding_suspend_without_publishing_partial_state() {
    let control = Control::default();
    control.binding.pause();
    let mut unfinished =
        Box::pin(AsyncVerificationProviderBuilder::new(TestFactory::new(&control)).qualify());
    assert_send(&unfinished);
    assert_pending(unfinished.as_mut());
    assert_eq!(control.verify_calls.load(Ordering::SeqCst), 0);
    drop(unfinished);
    assert_eq!(control.binding.cancelled.load(Ordering::SeqCst), 1);
    control.binding.release();
    control.verification.pause();
    let mut unfinished =
        Box::pin(AsyncVerificationProviderBuilder::new(TestFactory::new(&control)).qualify());
    assert_send(&unfinished);
    assert_pending(unfinished.as_mut());
    drop(unfinished);
    assert_eq!(control.verification.cancelled.load(Ordering::SeqCst), 1);
    control.verify_calls.store(0, Ordering::SeqCst);
    let mut qualification =
        Box::pin(AsyncVerificationProviderBuilder::new(TestFactory::new(&control)).qualify());
    let wake = assert_pending(qualification.as_mut());
    assert_eq!(control.verify_calls.load(Ordering::SeqCst), 1);
    control.verification.release();
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    let provider = qualification.await;
    assert!(provider.status(AlgorithmId::EcdsaP256Sha256).is_qualified());
    let before = control.bind_calls.load(Ordering::SeqCst);
    assert_eq!(
        provider.bind_ed25519(&[0; 31]).await.unwrap_err().kind(),
        ProviderKeyBindingErrorKind::InvalidPublicKey
    );
    assert_eq!(control.bind_calls.load(Ordering::SeqCst), before);
    control.binding.pause();
    let signer = TestSigner::new(&control, AlgorithmId::Ed25519);
    let bytes = signer.public_key();
    let mut binding = Box::pin(provider.bind_ed25519(&bytes));
    assert_send(&binding);
    let wake = assert_pending(binding.as_mut());
    control.binding.release();
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    let _bound = binding.await.unwrap();
}

#[tokio::test]
async fn async_qualification_matches_sync_cases_and_rejects_faulty_bindings() {
    for behavior in [
        Behavior::Honest,
        Behavior::StrictEd25519,
        Behavior::BindingFailure,
        Behavior::Failure,
        Behavior::AcceptAll,
        Behavior::CacheFirst,
        Behavior::Retarget,
        Behavior::AcceptAnyKey,
        Behavior::InvalidateAlternate,
    ] {
        let async_control = Control::default();
        let sync_control = Control::default();
        let asynchronous = AsyncVerificationProviderBuilder::new(TestFactory::with_behavior(
            &async_control,
            behavior,
        ))
        .qualify()
        .await;
        let synchronous = VerificationProviderBuilder::new(SyncFactory(
            TestFactory::with_behavior(&sync_control, behavior),
        ))
        .qualify();
        for algorithm in [AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256] {
            let classify = |status: &ProviderQualificationStatus| match status {
                ProviderQualificationStatus::Qualified => None,
                ProviderQualificationStatus::Rejected(error) => Some(error.kind()),
            };
            assert_eq!(
                classify(asynchronous.status(algorithm)),
                classify(synchronous.status(algorithm))
            );
            let expected = match behavior {
                Behavior::Honest => None,
                Behavior::StrictEd25519 if algorithm == AlgorithmId::EcdsaP256Sha256 => None,
                Behavior::BindingFailure => Some(ProviderQualificationErrorKind::KeyBindingFailed),
                Behavior::Failure => Some(ProviderQualificationErrorKind::ProviderFailure),
                Behavior::AcceptAll | Behavior::AcceptAnyKey => {
                    Some(ProviderQualificationErrorKind::InvalidSignatureAccepted)
                }
                Behavior::StrictEd25519
                | Behavior::CacheFirst
                | Behavior::Retarget
                | Behavior::InvalidateAlternate => {
                    Some(ProviderQualificationErrorKind::ValidSignatureRejected)
                }
            };
            assert_eq!(classify(asynchronous.status(algorithm)), expected);
        }
        assert_eq!(
            async_control.bind_calls.load(Ordering::SeqCst),
            sync_control.bind_calls.load(Ordering::SeqCst)
        );
        assert_eq!(
            async_control.verify_calls.load(Ordering::SeqCst),
            sync_control.verify_calls.load(Ordering::SeqCst)
        );
        if matches!(behavior, Behavior::StrictEd25519) {
            assert!(!asynchronous.status(AlgorithmId::Ed25519).is_qualified());
            assert!(
                asynchronous
                    .status(AlgorithmId::EcdsaP256Sha256)
                    .is_qualified()
            );
            let before = async_control.bind_calls.load(Ordering::SeqCst);
            assert_eq!(
                asynchronous
                    .bind_ed25519(&provider::RFC8032_TEST_1_PUBLIC_KEY)
                    .await
                    .unwrap_err()
                    .kind(),
                ProviderKeyBindingErrorKind::AlgorithmNotQualified
            );
            assert_eq!(async_control.bind_calls.load(Ordering::SeqCst), before);
        }
    }
}

#[tokio::test]
async fn verification_suspends_and_preserves_authoritative_failure_categories() {
    let control = Control::default();
    let signer = TestSigner::new(&control, AlgorithmId::Ed25519);
    let key = builder(&signer, AlgorithmId::Ed25519).build().unwrap();
    let req = request(
        b"verified: true\n",
        AlgorithmId::Ed25519,
        OutputForm::Yaml,
        &key,
    );
    let signed = success(signing::sign_with_async_provider(&req).await);
    let provider = AsyncVerificationProviderBuilder::new(TestFactory::new(&control))
        .qualify()
        .await;
    let bytes = signer.public_key();
    let key = provider.bind_ed25519(&bytes).await.unwrap();
    let keys = public_keys(AlgorithmId::Ed25519, &key);
    control.verification.pause();
    let mut operation = Box::pin(verify_with_async_provider(
        &signed.artifact,
        ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    ));
    assert_send(&operation);
    let wake = assert_pending(operation.as_mut());
    control.verification.release();
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        operation.await.unwrap(),
        VerifierState::Verified { .. }
    ));
    for (fault, expected) in [
        (1, Ok(VerifierState::SignedButFailedVerification)),
        (2, Err(InvocationError::KeyResolutionFailure)),
    ] {
        control.verify_fault.store(fault, Ordering::SeqCst);
        let before = control.verify_calls.load(Ordering::SeqCst);
        assert_eq!(
            verify_with_async_provider(
                &signed.artifact,
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions::default()
            )
            .await,
            expected
        );
        assert_eq!(control.verify_calls.load(Ordering::SeqCst), before + 1);
    }
    control.verification.pause();
    let mut unfinished = Box::pin(verify_with_async_provider(
        &signed.artifact,
        ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
    ));
    assert_pending(unfinished.as_mut());
    drop(unfinished);
    assert_eq!(control.verification.cancelled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unqualified_signing_skips_only_self_verification() {
    for algorithm in [AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256] {
        let control = Control::default();
        let signer = TestSigner::new(&control, algorithm);
        let qualified = builder(&signer, algorithm).build().unwrap();
        let unqualified = builder(&signer, algorithm).build_unqualified().unwrap();
        assert_eq!(control.sign_calls.load(Ordering::SeqCst), 0);
        for fault in [1, 2, 3] {
            control.sign_fault.store(fault, Ordering::SeqCst);
            let req = request(b"test: true\n", algorithm, OutputForm::Yaml, &qualified);
            assert!(matches!(
                signing::sign_with_async_provider(&req).await,
                SignOutcome::Signer(SignError::KeyOperationFailure)
            ));
            let req = request(b"test: true\n", algorithm, OutputForm::Yaml, &unqualified);
            let outcome = signing::sign_with_unqualified_async_provider(&req).await;
            if fault == 3 {
                assert!(matches!(outcome, SignOutcome::Success(_)));
            } else {
                assert!(matches!(
                    outcome,
                    SignOutcome::Signer(SignError::KeyOperationFailure)
                ));
            }
        }
    }
}

#[tokio::test]
async fn invalid_inputs_and_resource_prechecks_never_poll_verification() {
    for algorithm in [AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256] {
        let control = Control::default();
        let signer = TestSigner::new(&control, algorithm);
        let provider =
            AsyncVerificationProviderBuilder::new(TestFactory::new(&control)).build_unqualified();
        assert_eq!(
            provider.bind_ed25519(&[0; 32]).await.unwrap_err().kind(),
            ProviderKeyBindingErrorKind::InvalidPublicKey
        );
        assert_eq!(
            provider
                .bind_ecdsa_p256_sha256(&[0; 65])
                .await
                .unwrap_err()
                .kind(),
            ProviderKeyBindingErrorKind::InvalidPublicKey
        );
        assert_eq!(control.bind_calls.load(Ordering::SeqCst), 0);
        let bytes = signer.public_key();
        let key = match algorithm {
            AlgorithmId::Ed25519 => provider.bind_ed25519(&bytes).await.unwrap(),
            AlgorithmId::EcdsaP256Sha256 => provider.bind_ecdsa_p256_sha256(&bytes).await.unwrap(),
        };
        let keys = public_keys(algorithm, &key);
        for signature in [vec![], vec![0; 63], vec![0xff; 64]] {
            let pre = PreVerifyResponse {
                outcome: PreVerifyOutcome::Ok,
                form: ArtifactForm::Proto,
                unverified_payload_bytes: Some(b"payload".to_vec()),
                unverified_signature: Some(UnverifiedSignature {
                    algorithm,
                    keyid: None,
                    signature_octets: signature,
                }),
                parser_observations: vec![],
            };
            assert_eq!(
                verify_from_pre_verify_with_unqualified_async_provider(
                    &pre,
                    &keys,
                    VerifierOptions::default()
                )
                .await
                .unwrap(),
                VerifierState::MalformedAttemptedSigned
            );
        }
        assert_eq!(
            verify_with_unqualified_async_provider(
                b"unsigned: true\n",
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions::default()
            )
            .await
            .unwrap(),
            VerifierState::MalformedAttemptedSigned
        );
        let options = VerifierOptions {
            algorithm_parameters: vec![1],
            ..VerifierOptions::default()
        };
        assert_eq!(
            verify_with_unqualified_async_provider(b"bad", ArtifactForm::Yaml, &keys, options)
                .await,
            Err(InvocationError::InvalidAlgorithmParameters)
        );
        for form in [ArtifactForm::Yaml, ArtifactForm::Proto] {
            let rejected = async {
                let admitted = finite(1).check_input_size(resource_form(form), b"too large")?;
                Ok::<_, ArtifactResourceError>(
                    verify_with_unqualified_async_provider(
                        admitted,
                        form,
                        &keys,
                        VerifierOptions::default(),
                    )
                    .await,
                )
            }
            .await
            .unwrap_err();
            assert_eq!(
                rejected.kind(),
                ArtifactResourceErrorKind::InputArtifactTooLarge
            );
        }
        assert_eq!(control.verify_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bounded_signing_matches_sync_early_and_final_output_checks() {
    for algorithm in [AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256] {
        for form in [OutputForm::Yaml, OutputForm::Protobuf] {
            for qualified in [true, false] {
                let control = Control::default();
                let signer = TestSigner::new(&control, algorithm);
                let sync_signer = SyncSigner(&signer);
                let bytes = signer.public_key();
                let sync_builder = match algorithm {
                    AlgorithmId::Ed25519 => {
                        signing::ProviderSigningKeyBuilder::ed25519(&sync_signer, &bytes)
                    }
                    AlgorithmId::EcdsaP256Sha256 => {
                        signing::ProviderSigningKeyBuilder::ecdsa_p256_sha256(&sync_signer, &bytes)
                    }
                };
                macro_rules! compare_limits {
                    ($build:ident, $async_sign:ident, $async_bounded:ident, $sync_bounded:ident) => {{
                        let key = builder(&signer, algorithm).$build().unwrap();
                        let req = request(b"key: value", algorithm, form, &key);
                        let native_key = sync_builder.$build().unwrap();
                        let native_req = request(b"key: value", algorithm, form, &native_key);
                        let output = success(signing::$async_sign(&req).await);
                        for maximum in [1, output.artifact.len() - 1, output.artifact.len()] {
                            let policy = finite(maximum);
                            let before = control.sign_calls.load(Ordering::SeqCst);
                            let actual = signing::$async_bounded(&req, &policy).await;
                            let async_calls = control.sign_calls.load(Ordering::SeqCst) - before;
                            let before = control.sign_calls.load(Ordering::SeqCst);
                            let expected = signing::$sync_bounded(&native_req, &policy);
                            assert_eq!(
                                control.sign_calls.load(Ordering::SeqCst) - before,
                                async_calls
                            );
                            if maximum < output.artifact.len() {
                                assert_eq!(actual.unwrap_err(), expected.unwrap_err());
                                if maximum == 1 || form == OutputForm::Protobuf {
                                    assert_eq!(async_calls, 0);
                                } else {
                                    assert_eq!(async_calls, 1);
                                }
                            } else {
                                assert_eq!(
                                    success(actual.unwrap().unwrap()).artifact,
                                    success(expected.unwrap().unwrap()).artifact
                                );
                                assert_eq!(async_calls, 1);
                            }
                        }
                    }};
                }
                if qualified {
                    compare_limits!(
                        build,
                        sign_with_async_provider,
                        sign_with_async_provider_and_resource_limits,
                        sign_with_provider_and_resource_limits
                    );
                } else {
                    compare_limits!(
                        build_unqualified,
                        sign_with_unqualified_async_provider,
                        sign_with_unqualified_async_provider_and_resource_limits,
                        sign_with_unqualified_provider_and_resource_limits
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn signing_validation_precedes_the_await_and_retains_error_order() {
    let control = Control::default();
    let signer = TestSigner::new(&control, AlgorithmId::Ed25519);
    assert!(
        signing::AsyncProviderSigningKeyBuilder::ed25519(&signer, &[0; 31])
            .build()
            .is_err()
    );
    assert!(
        signing::AsyncProviderSigningKeyBuilder::ecdsa_p256_sha256(&signer, &[0; 65])
            .build_unqualified()
            .is_err()
    );
    let key = builder(&signer, AlgorithmId::Ed25519).build().unwrap();
    let mut req = request(
        b"key: value\n",
        AlgorithmId::Ed25519,
        OutputForm::Yaml,
        &key,
    );
    req.keyid = Some("invalid\nkey");
    req.algorithm = AlgorithmId::EcdsaP256Sha256;
    assert!(matches!(
        signing::sign_with_async_provider(&req).await,
        SignOutcome::Invocation(signing::SignInvocationError::InvalidKeyid)
    ));
    assert!(matches!(
        signing::sign_with_async_provider_and_resource_limits(&req, &finite(1))
            .await
            .unwrap()
            .unwrap(),
        SignOutcome::Invocation(signing::SignInvocationError::InvalidOrUnsupportedAlgorithm)
    ));
    req.algorithm = AlgorithmId::Ed25519;
    assert!(
        signing::sign_with_async_provider_and_resource_limits(&req, &finite(1))
            .await
            .is_err()
    );
    req.keyid = None;
    req.payload = &[0xff];
    assert!(matches!(
        signing::sign_with_async_provider(&req).await,
        SignOutcome::Signer(SignError::InvalidPayloadBytes)
    ));
    req.payload = b"missing newline";
    req.append_missing_final_newline = false;
    assert!(matches!(
        signing::sign_with_async_provider(&req).await,
        SignOutcome::Signer(SignError::PayloadLineTerminatorRefusal)
    ));
    req.algorithm_parameters = &[1];
    assert!(matches!(
        signing::sign_with_async_provider(&req).await,
        SignOutcome::Invocation(signing::SignInvocationError::InvalidAlgorithmParameters)
    ));
    assert_eq!(control.sign_calls.load(Ordering::SeqCst), 0);
}
