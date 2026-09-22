// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Integration coverage for provider-neutral signing and verification.
//!
//! The Ed25519 equation in this test adapter implements RFC 8032-derived
//! behavior and is not relicensed under this file's Apache-2.0 declaration.
//! See `../THIRD_PARTY_NOTICES.md` for attribution and applicable terms.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs as aws;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ring::signature::KeyPair as _;
use sha2::{Digest, Sha256, Sha512};
use signature::Signer as _;
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{
    OutputForm, ProviderSignRequest, ProviderSigningKeyBuilder, ProviderSigningKeys, SignOutcome,
    SignProtoParams, SignYamlParams, SigningKey, UnqualifiedProviderSignRequest,
    UnqualifiedProviderSigningKeys, sign_proto, sign_with_provider, sign_with_unqualified_provider,
    sign_yaml, signature_signing_callback,
};
use yaml_sigil_verification::{
    ArtifactForm, InvocationError, PreVerifyOutcome, PreVerifyResponse, ProviderPublicKeys,
    ProviderQualificationErrorKind, ProviderQualificationStatus, ProviderVerificationOutcome,
    ProviderVerifier, ProviderVerifierFactory, QualifiedVerificationProvider,
    UnqualifiedProviderPublicKeys, UnverifiedSignature, VerificationProviderBuilder,
    VerifierOptions, VerifierState, pre_verify, verify_from_pre_verify_with_provider,
    verify_from_pre_verify_with_unqualified_provider, verify_with_provider,
    verify_with_provider_and_metadata, verify_with_unqualified_provider,
};

fn signature_error() -> signature::Error {
    signature::Error::new()
}

fn verify_ed25519_cofactored(public_key: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(public_key): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Some(public_point) = CompressedEdwardsY(public_key).decompress() else {
        return false;
    };
    if public_point.compress().to_bytes() != public_key || public_point.is_small_order() {
        return false;
    }

    let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();
    let Some(r) = CompressedEdwardsY(r_bytes).decompress() else {
        return false;
    };
    if r.compress().to_bytes() != r_bytes {
        return false;
    }
    let s_bytes: [u8; 32] = signature[32..].try_into().unwrap();
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };

    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let mut wide = [0; 64];
    wide.copy_from_slice(&hasher.finalize());
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);
    (s * ED25519_BASEPOINT_POINT - r - challenge * public_point)
        .mul_by_cofactor()
        .is_identity()
}

#[derive(Clone, Copy)]
struct ReferenceFactory;

enum ReferenceVerifier {
    Ed25519([u8; 32]),
    EcdsaP256Sha256(p256::ecdsa::VerifyingKey),
}

impl signature::Verifier<[u8; 64]> for ReferenceVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        let verified = match self {
            Self::Ed25519(public_key) => verify_ed25519_cofactored(public_key, message, signature),
            Self::EcdsaP256Sha256(public_key) => {
                let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
                    return Err(signature_error());
                };
                public_key.verify(message, &signature).is_ok()
            }
        };
        verified.then_some(()).ok_or_else(signature_error)
    }
}

impl ProviderVerifier for ReferenceVerifier {}

impl ProviderVerifierFactory for ReferenceFactory {
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
        let verifier = match algorithm {
            AlgorithmId::Ed25519 => {
                let public_key = canonical_public_key
                    .try_into()
                    .map_err(|_| signature_error())?;
                ReferenceVerifier::Ed25519(public_key)
            }
            AlgorithmId::EcdsaP256Sha256 => ReferenceVerifier::EcdsaP256Sha256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(canonical_public_key)
                    .map_err(|_| signature_error())?,
            ),
        };
        Ok(Box::new(verifier))
    }
}

#[derive(Clone, Copy)]
struct RingFactory;

struct RingVerifier {
    algorithm: AlgorithmId,
    public_key: Vec<u8>,
}

impl signature::Verifier<[u8; 64]> for RingVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        let result = match self.algorithm {
            AlgorithmId::Ed25519 => {
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.public_key)
                    .verify(message, signature)
            }
            AlgorithmId::EcdsaP256Sha256 => ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                &self.public_key,
            )
            .verify(message, signature),
        };
        result.map_err(|_| signature_error())
    }
}

impl ProviderVerifier for RingVerifier {}

impl ProviderVerifierFactory for RingFactory {
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
        Ok(Box::new(RingVerifier {
            algorithm,
            public_key: canonical_public_key.to_vec(),
        }))
    }
}

#[derive(Clone, Copy)]
struct AwsFactory;

struct AwsVerifier {
    algorithm: AlgorithmId,
    public_key: Vec<u8>,
}

impl signature::Verifier<[u8; 64]> for AwsVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        let result = match self.algorithm {
            AlgorithmId::Ed25519 => {
                aws::signature::UnparsedPublicKey::new(&aws::signature::ED25519, &self.public_key)
                    .verify(message, signature)
            }
            AlgorithmId::EcdsaP256Sha256 => aws::signature::UnparsedPublicKey::new(
                &aws::signature::ECDSA_P256_SHA256_FIXED,
                &self.public_key,
            )
            .verify(message, signature),
        };
        result.map_err(|_| signature_error())
    }
}

impl ProviderVerifier for AwsVerifier {}

impl ProviderVerifierFactory for AwsFactory {
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
        Ok(Box::new(AwsVerifier {
            algorithm,
            public_key: canonical_public_key.to_vec(),
        }))
    }
}

struct RustCryptoEd25519Signer(ed25519_dalek::SigningKey);

impl signature::Signer<[u8; 64]> for RustCryptoEd25519Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        let signature: ed25519_dalek::Signature = self.0.try_sign(message)?;
        Ok(signature.to_bytes())
    }
}

struct RustCryptoP256Signer(p256::ecdsa::SigningKey);

impl signature::Signer<[u8; 64]> for RustCryptoP256Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        let signature: p256::ecdsa::Signature = self.0.try_sign(message)?;
        Ok(signature.to_bytes().into())
    }
}

struct DoubleHashP256Signer(p256::ecdsa::SigningKey);

impl signature::Signer<[u8; 64]> for DoubleHashP256Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        let digest = Sha256::digest(message);
        let signature: p256::ecdsa::Signature = self.0.try_sign(&digest)?;
        Ok(signature.to_bytes().into())
    }
}

struct RingEd25519Signer(ring::signature::Ed25519KeyPair);

impl signature::Signer<[u8; 64]> for RingEd25519Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        self.0
            .sign(message)
            .as_ref()
            .try_into()
            .map_err(|_| signature_error())
    }
}

struct RingP256Signer {
    key: ring::signature::EcdsaKeyPair,
    random: ring::rand::SystemRandom,
}

impl signature::Signer<[u8; 64]> for RingP256Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        self.key
            .sign(&self.random, message)
            .map_err(|_| signature_error())?
            .as_ref()
            .try_into()
            .map_err(|_| signature_error())
    }
}

struct AwsEd25519Signer(aws::signature::Ed25519KeyPair);

impl signature::Signer<[u8; 64]> for AwsEd25519Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        self.0
            .try_sign(message)
            .map_err(|_| signature_error())?
            .as_ref()
            .try_into()
            .map_err(|_| signature_error())
    }
}

struct AwsP256Signer {
    key: aws::signature::EcdsaKeyPair,
    random: aws::rand::SystemRandom,
}

impl signature::Signer<[u8; 64]> for AwsP256Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        self.key
            .sign(&self.random, message)
            .map_err(|_| signature_error())?
            .as_ref()
            .try_into()
            .map_err(|_| signature_error())
    }
}

fn ring_ed25519_signer() -> (RingEd25519Signer, Vec<u8>) {
    let random = ring::rand::SystemRandom::new();
    let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let public_key = key.public_key().as_ref().to_vec();
    (RingEd25519Signer(key), public_key)
}

fn ring_p256_signer() -> (RingP256Signer, Vec<u8>) {
    let random = ring::rand::SystemRandom::new();
    let document = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &random,
    )
    .unwrap();
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        document.as_ref(),
        &random,
    )
    .unwrap();
    let public_key = key.public_key().as_ref().to_vec();
    (RingP256Signer { key, random }, public_key)
}

fn aws_ed25519_signer() -> (AwsEd25519Signer, Vec<u8>) {
    use aws::signature::KeyPair as _;

    let key = aws::signature::Ed25519KeyPair::generate().unwrap();
    let public_key = key.public_key().as_ref().to_vec();
    (AwsEd25519Signer(key), public_key)
}

fn aws_p256_signer() -> (AwsP256Signer, Vec<u8>) {
    use aws::signature::KeyPair as _;

    let key =
        aws::signature::EcdsaKeyPair::generate(&aws::signature::ECDSA_P256_SHA256_FIXED_SIGNING)
            .unwrap();
    let public_key = key.public_key().as_ref().to_vec();
    (
        AwsP256Signer {
            key,
            random: aws::rand::SystemRandom::new(),
        },
        public_key,
    )
}

fn assert_rejected_as_cofactored_incompatible(status: &ProviderQualificationStatus) {
    let ProviderQualificationStatus::Rejected(error) = status else {
        panic!("the strict Ed25519 slot unexpectedly qualified");
    };
    assert_eq!(
        error.kind(),
        ProviderQualificationErrorKind::ValidSignatureRejected
    );
    assert_eq!(error.algorithm(), AlgorithmId::Ed25519);
}

fn exercise_qualified_pair<F: ProviderVerifierFactory>(
    signer: &(dyn signature::Signer<[u8; 64]> + Sync),
    public_key: &[u8],
    algorithm: AlgorithmId,
    provider: &QualifiedVerificationProvider<F>,
    output_form: OutputForm,
) {
    let signing_key = match algorithm {
        AlgorithmId::Ed25519 => ProviderSigningKeyBuilder::ed25519(public_key),
        AlgorithmId::EcdsaP256Sha256 => ProviderSigningKeyBuilder::ecdsa_p256_sha256(public_key),
    }
    .build()
    .unwrap();
    let request = ProviderSignRequest {
        payload: b"provider-matrix: signed\n",
        algorithm,
        key: match algorithm {
            AlgorithmId::Ed25519 => ProviderSigningKeys::Ed25519(&signing_key),
            AlgorithmId::EcdsaP256Sha256 => ProviderSigningKeys::EcdsaP256Sha256(&signing_key),
        },
        keyid: Some("provider-matrix"),
        append_missing_final_newline: false,
        output_form,
        algorithm_parameters: &[],
    };
    let SignOutcome::Success(success) =
        sign_with_provider(&request, signature_signing_callback(signer))
    else {
        panic!("qualified provider signing failed for {algorithm:?}");
    };

    let verifying_key = match algorithm {
        AlgorithmId::Ed25519 => provider.bind_ed25519(public_key),
        AlgorithmId::EcdsaP256Sha256 => provider.bind_ecdsa_p256_sha256(public_key),
    }
    .unwrap();
    let keys = ProviderPublicKeys {
        ed25519: (algorithm == AlgorithmId::Ed25519).then_some(&verifying_key),
        p256: (algorithm == AlgorithmId::EcdsaP256Sha256).then_some(&verifying_key),
    };
    let form = match output_form {
        OutputForm::Yaml => ArtifactForm::Yaml,
        OutputForm::Protobuf => ArtifactForm::Proto,
    };
    let state =
        verify_with_provider(&success.artifact, form, &keys, VerifierOptions::default()).unwrap();
    assert_eq!(
        state,
        VerifierState::Verified {
            payload: b"provider-matrix: signed\n".to_vec(),
            algorithm,
        }
    );
}

#[test]
fn real_provider_qualification_and_cross_provider_matrix() {
    let reference = VerificationProviderBuilder::new(ReferenceFactory).qualify();
    let ring = VerificationProviderBuilder::new(RingFactory).qualify();
    let aws = VerificationProviderBuilder::new(AwsFactory).qualify();

    assert!(reference.status(AlgorithmId::Ed25519).is_qualified());
    assert!(
        reference
            .status(AlgorithmId::EcdsaP256Sha256)
            .is_qualified()
    );
    assert_rejected_as_cofactored_incompatible(ring.status(AlgorithmId::Ed25519));
    assert_rejected_as_cofactored_incompatible(aws.status(AlgorithmId::Ed25519));
    assert!(ring.status(AlgorithmId::EcdsaP256Sha256).is_qualified());
    assert!(aws.status(AlgorithmId::EcdsaP256Sha256).is_qualified());

    let rustcrypto_ed = RustCryptoEd25519Signer(ed25519_dalek::SigningKey::from_bytes(&[31; 32]));
    let rustcrypto_ed_public = rustcrypto_ed.0.verifying_key().to_bytes();
    let rustcrypto_p =
        RustCryptoP256Signer(p256::ecdsa::SigningKey::from_slice(&[32; 32]).unwrap());
    let rustcrypto_p_public = rustcrypto_p.0.verifying_key().to_sec1_point(false);
    let (ring_ed, ring_ed_public) = ring_ed25519_signer();
    let (ring_p, ring_p_public) = ring_p256_signer();
    let (aws_ed, aws_ed_public) = aws_ed25519_signer();
    let (aws_p, aws_p_public) = aws_p256_signer();

    let ed25519_signers: [(&(dyn signature::Signer<[u8; 64]> + Sync), &[u8]); 3] = [
        (&rustcrypto_ed, &rustcrypto_ed_public),
        (&ring_ed, &ring_ed_public),
        (&aws_ed, &aws_ed_public),
    ];
    let p256_signers: [(&(dyn signature::Signer<[u8; 64]> + Sync), &[u8]); 3] = [
        (&rustcrypto_p, rustcrypto_p_public.as_bytes()),
        (&ring_p, &ring_p_public),
        (&aws_p, &aws_p_public),
    ];

    for output_form in [OutputForm::Yaml, OutputForm::Protobuf] {
        for (signer, public_key) in ed25519_signers {
            exercise_qualified_pair(
                signer,
                public_key,
                AlgorithmId::Ed25519,
                &reference,
                output_form,
            );
        }
        for (signer, public_key) in p256_signers {
            exercise_qualified_pair(
                signer,
                public_key,
                AlgorithmId::EcdsaP256Sha256,
                &reference,
                output_form,
            );
            exercise_qualified_pair(
                signer,
                public_key,
                AlgorithmId::EcdsaP256Sha256,
                &ring,
                output_form,
            );
            exercise_qualified_pair(
                signer,
                public_key,
                AlgorithmId::EcdsaP256Sha256,
                &aws,
                output_form,
            );
        }
    }
}

#[test]
fn provider_keys_can_be_shared_across_workers() {
    let signer = RustCryptoEd25519Signer(ed25519_dalek::SigningKey::from_bytes(&[74; 32]));
    let public_key = signer.0.verifying_key().to_bytes();
    let signing_key = ProviderSigningKeyBuilder::ed25519(&public_key)
        .build()
        .unwrap();
    let provider = VerificationProviderBuilder::new(ReferenceFactory).qualify();
    let verifying_key = provider.bind_ed25519(&public_key).unwrap();
    let request = ProviderSignRequest {
        payload: b"provider: shared workers\n",
        algorithm: AlgorithmId::Ed25519,
        key: ProviderSigningKeys::Ed25519(&signing_key),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    let keys = ProviderPublicKeys {
        ed25519: Some(&verifying_key),
        p256: None,
    };

    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                let SignOutcome::Success(success) =
                    sign_with_provider(&request, signature_signing_callback(&signer))
                else {
                    panic!("shared provider signing failed");
                };
                assert_eq!(
                    verify_with_provider(
                        &success.artifact,
                        ArtifactForm::Proto,
                        &keys,
                        VerifierOptions::default(),
                    )
                    .unwrap(),
                    VerifierState::Verified {
                        payload: request.payload.to_vec(),
                        algorithm: AlgorithmId::Ed25519,
                    },
                );
            });
        }
    });
}

struct ScriptedVerifier {
    outcome: ProviderVerificationOutcome,
    calls: Arc<AtomicUsize>,
    messages: RecordedMessages,
}

impl signature::Verifier<[u8; 64]> for ScriptedVerifier {
    fn verify(&self, _message: &[u8], _signature: &[u8; 64]) -> Result<(), signature::Error> {
        match self.outcome {
            ProviderVerificationOutcome::Verified => Ok(()),
            ProviderVerificationOutcome::SignatureMismatch
            | ProviderVerificationOutcome::ProviderFailure => Err(signature_error()),
            _ => Err(signature_error()),
        }
    }
}

impl ProviderVerifier for ScriptedVerifier {
    fn verify_provider(
        &self,
        message: &[u8],
        _signature: &[u8; 64],
    ) -> ProviderVerificationOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.messages.lock().unwrap().push(message.to_vec());
        self.outcome
    }
}

struct ScriptedFactory {
    outcome: ProviderVerificationOutcome,
    calls: Arc<AtomicUsize>,
    messages: RecordedMessages,
}

impl ProviderVerifierFactory for ScriptedFactory {
    fn bind<'factory>(
        &'factory self,
        _algorithm: AlgorithmId,
        _canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
        Ok(Box::new(ScriptedVerifier {
            outcome: self.outcome,
            calls: Arc::clone(&self.calls),
            messages: Arc::clone(&self.messages),
        }))
    }
}

type RecordedMessages = Arc<Mutex<Vec<Vec<u8>>>>;
type ScriptedFactoryFixture = (ScriptedFactory, Arc<AtomicUsize>, RecordedMessages);

fn scripted_factory(outcome: ProviderVerificationOutcome) -> ScriptedFactoryFixture {
    let calls = Arc::new(AtomicUsize::new(0));
    let messages = Arc::new(Mutex::new(Vec::new()));
    (
        ScriptedFactory {
            outcome,
            calls: Arc::clone(&calls),
            messages: Arc::clone(&messages),
        },
        calls,
        messages,
    )
}

fn signed_ed25519_artifact(form: ArtifactForm) -> (Vec<u8>, ed25519_dalek::VerifyingKey) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[40; 32]);
    let verifying_key = signing_key.verifying_key();
    let artifact = match form {
        ArtifactForm::Yaml => sign_yaml(&SignYamlParams {
            payload: b"scripted-provider: test\n",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&signing_key),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap(),
        ArtifactForm::Proto => sign_proto(&SignProtoParams {
            payload: b"scripted-provider: test\n",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&signing_key),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap(),
    };
    (artifact, verifying_key)
}

#[test]
fn verification_preserves_mismatch_and_provider_failure_categories() {
    let (artifact, public_key) = signed_ed25519_artifact(ArtifactForm::Yaml);
    for (outcome, expected) in [
        (
            ProviderVerificationOutcome::SignatureMismatch,
            Ok(VerifierState::SignedButFailedVerification),
        ),
        (
            ProviderVerificationOutcome::ProviderFailure,
            Err(InvocationError::KeyResolutionFailure),
        ),
    ] {
        let (factory, calls, _) = scripted_factory(outcome);
        let provider = VerificationProviderBuilder::new(factory).build_unqualified();
        let key = provider.bind_ed25519(public_key.as_bytes()).unwrap();
        let keys = UnqualifiedProviderPublicKeys {
            ed25519: Some(&key),
            p256: None,
        };
        assert_eq!(
            verify_with_unqualified_provider(
                &artifact,
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions::default(),
            ),
            expected
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn malformed_signature_octets_never_reach_a_provider() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    let (factory, calls, _) = scripted_factory(ProviderVerificationOutcome::Verified);
    let provider = VerificationProviderBuilder::new(factory).build_unqualified();
    let key = provider
        .bind_ed25519(signing_key.verifying_key().as_bytes())
        .unwrap();
    let keys = UnqualifiedProviderPublicKeys {
        ed25519: Some(&key),
        p256: None,
    };

    for signature_octets in [vec![0xff; 64], vec![0; 63], vec![0x30; 70]] {
        let pre = PreVerifyResponse {
            outcome: PreVerifyOutcome::Ok,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: Some(b"payload\n".to_vec()),
            unverified_signature: Some(UnverifiedSignature {
                algorithm: AlgorithmId::Ed25519,
                keyid: None,
                signature_octets,
            }),
            parser_observations: Vec::new(),
        };
        assert_eq!(
            verify_from_pre_verify_with_unqualified_provider(
                &pre,
                &keys,
                VerifierOptions::default(),
            ),
            Ok(VerifierState::MalformedAttemptedSigned)
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let p256_signing_key = p256::ecdsa::SigningKey::from_slice(&[42; 32]).unwrap();
    let p256_key = provider
        .bind_ecdsa_p256_sha256(
            p256_signing_key
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes(),
        )
        .unwrap();
    let p256_keys = UnqualifiedProviderPublicKeys {
        ed25519: None,
        p256: Some(&p256_key),
    };
    let valid_signature: p256::ecdsa::Signature = p256_signing_key.sign(b"payload\n");
    for signature_octets in [vec![0; 64], valid_signature.to_der().as_bytes().to_vec()] {
        let pre = PreVerifyResponse {
            outcome: PreVerifyOutcome::Ok,
            form: ArtifactForm::Proto,
            unverified_payload_bytes: Some(b"payload\n".to_vec()),
            unverified_signature: Some(UnverifiedSignature {
                algorithm: AlgorithmId::EcdsaP256Sha256,
                keyid: None,
                signature_octets,
            }),
            parser_observations: Vec::new(),
        };
        assert_eq!(
            verify_from_pre_verify_with_unqualified_provider(
                &pre,
                &p256_keys,
                VerifierOptions::default(),
            ),
            Ok(VerifierState::MalformedAttemptedSigned)
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn pre_verification_handoff_runs_provider_verification_once() {
    let (artifact, public_key) = signed_ed25519_artifact(ArtifactForm::Proto);
    let (factory, calls, _) = scripted_factory(ProviderVerificationOutcome::Verified);
    let unqualified = VerificationProviderBuilder::new(factory).build_unqualified();
    let unqualified_key = unqualified.bind_ed25519(public_key.as_bytes()).unwrap();
    let unqualified_keys = UnqualifiedProviderPublicKeys {
        ed25519: Some(&unqualified_key),
        p256: None,
    };
    let provider = VerificationProviderBuilder::new(ReferenceFactory).qualify();
    let key = provider.bind_ed25519(public_key.as_bytes()).unwrap();
    let keys = ProviderPublicKeys {
        ed25519: Some(&key),
        p256: None,
    };

    let pre = pre_verify(&artifact, ArtifactForm::Proto, false, false);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(matches!(
        verify_from_pre_verify_with_unqualified_provider(
            &pre,
            &unqualified_keys,
            VerifierOptions::default(),
        ),
        Ok(VerifierState::Verified { .. })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        verify_from_pre_verify_with_provider(&pre, &keys, VerifierOptions::default()),
        Ok(VerifierState::Verified { .. })
    ));
}

struct ExpectedP256Signer {
    key: p256::ecdsa::SigningKey,
    expected_message: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl signature::Signer<[u8; 64]> for ExpectedP256Signer {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        assert_eq!(message, self.expected_message);
        self.calls.fetch_add(1, Ordering::Relaxed);
        let signature: p256::ecdsa::Signature = self.key.try_sign(message)?;
        Ok(signature.to_bytes().into())
    }
}

#[test]
fn p256_providers_receive_message_bytes_without_a_yaml_sigil_prehash() {
    for (output_form, payload, expected_message) in [
        (
            OutputForm::Yaml,
            b"p256-provider: exact".as_slice(),
            b"p256-provider: exact\n".as_slice(),
        ),
        (
            OutputForm::Protobuf,
            b"\xff\x00opaque\x80".as_slice(),
            b"\xff\x00opaque\x80".as_slice(),
        ),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = ExpectedP256Signer {
            key: p256::ecdsa::SigningKey::from_slice(&[43; 32]).unwrap(),
            expected_message: expected_message.to_vec(),
            calls: Arc::clone(&calls),
        };
        let public_key = signer.key.verifying_key().to_sec1_point(false);
        let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public_key.as_bytes())
            .build()
            .unwrap();
        let request = ProviderSignRequest {
            payload,
            algorithm: AlgorithmId::EcdsaP256Sha256,
            key: ProviderSigningKeys::EcdsaP256Sha256(&key),
            keyid: None,
            append_missing_final_newline: true,
            output_form,
            algorithm_parameters: &[],
        };
        let SignOutcome::Success(success) =
            sign_with_provider(&request, signature_signing_callback(&signer))
        else {
            panic!("qualified P-256 signing failed");
        };
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        let (factory, verify_calls, messages) =
            scripted_factory(ProviderVerificationOutcome::Verified);
        let provider = VerificationProviderBuilder::new(factory).build_unqualified();
        let verifying_key = provider
            .bind_ecdsa_p256_sha256(public_key.as_bytes())
            .unwrap();
        let keys = UnqualifiedProviderPublicKeys {
            ed25519: None,
            p256: Some(&verifying_key),
        };
        let form = match output_form {
            OutputForm::Yaml => ArtifactForm::Yaml,
            OutputForm::Protobuf => ArtifactForm::Proto,
        };
        assert!(matches!(
            verify_with_unqualified_provider(
                &success.artifact,
                form,
                &keys,
                VerifierOptions::default(),
            ),
            Ok(VerifierState::Verified { .. })
        ));
        assert_eq!(verify_calls.load(Ordering::Relaxed), 1);
        assert_eq!(messages.lock().unwrap().as_slice(), [expected_message]);
    }
}

#[test]
fn qualified_p256_signing_rejects_an_adapter_that_hashes_twice() {
    let signer = DoubleHashP256Signer(p256::ecdsa::SigningKey::from_slice(&[44; 32]).unwrap());
    let public_key = signer.0.verifying_key().to_sec1_point(false);
    let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public_key.as_bytes())
        .build()
        .unwrap();
    let request = ProviderSignRequest {
        payload: b"p256-provider: one hash\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: ProviderSigningKeys::EcdsaP256Sha256(&key),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };

    assert!(matches!(
        sign_with_provider(&request, signature_signing_callback(&signer)),
        SignOutcome::Signer(yaml_sigil_signing::SignError::KeyOperationFailure)
    ));
}

#[test]
fn provider_metadata_and_exact_message_paths_remain_available() {
    let (artifact, public_key) = signed_ed25519_artifact(ArtifactForm::Yaml);
    let (factory, calls, messages) = scripted_factory(ProviderVerificationOutcome::Verified);
    let provider = VerificationProviderBuilder::new(factory).build_unqualified();
    let key = provider.bind_ed25519(public_key.as_bytes()).unwrap();
    let keys = UnqualifiedProviderPublicKeys {
        ed25519: Some(&key),
        p256: None,
    };

    let result = yaml_sigil_verification::verify_with_unqualified_provider_and_metadata(
        &artifact,
        ArtifactForm::Yaml,
        &keys,
        VerifierOptions::default(),
        true,
    )
    .unwrap();
    assert!(matches!(result.state, VerifierState::Verified { .. }));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        messages.lock().unwrap().as_slice(),
        [b"scripted-provider: test\n"]
    );

    let qualified = VerificationProviderBuilder::new(ReferenceFactory).qualify();
    let qualified_key = qualified.bind_ed25519(public_key.as_bytes()).unwrap();
    let qualified_keys = ProviderPublicKeys {
        ed25519: Some(&qualified_key),
        p256: None,
    };
    let result = verify_with_provider_and_metadata(
        &artifact,
        ArtifactForm::Yaml,
        &qualified_keys,
        VerifierOptions::default(),
        true,
    )
    .unwrap();
    assert!(matches!(result.state, VerifierState::Verified { .. }));
}

#[test]
fn p256_digest_callbacks_preserve_payloads_through_both_artifact_verifiers() {
    use signature::hazmat::PrehashSigner as _;
    use yaml_sigil_signing::{
        ArtifactResourceLimits, SignError, sign_with_p256_digest_provider,
        sign_with_p256_digest_provider_and_resource_limits,
    };
    use yaml_sigil_verification::{PublicKeys, verify};

    // Deterministic signatures isolate payload/encoding equivalence in this
    // regression; production callbacks own the profile's nonce sampling.
    let native = p256::ecdsa::SigningKey::from_slice(&[46; 32]).unwrap();
    let public = native.verifying_key().to_sec1_point(false);
    let key = ProviderSigningKeyBuilder::ecdsa_p256_sha256(public.as_bytes())
        .build()
        .unwrap();
    let keys = PublicKeys {
        ed25519: None,
        p256: Some(native.verifying_key()),
    };
    for (form, payload, expected) in [
        (
            OutputForm::Yaml,
            b"digest: value".as_slice(),
            b"digest: value\n".as_slice(),
        ),
        (
            OutputForm::Yaml,
            b"key: value\r\n".as_slice(),
            b"key: value\r\n".as_slice(),
        ),
        (OutputForm::Yaml, b"".as_slice(), b"".as_slice()),
        (
            OutputForm::Protobuf,
            b"\xff\0\x80".as_slice(),
            b"\xff\0\x80".as_slice(),
        ),
        (OutputForm::Protobuf, b"".as_slice(), b"".as_slice()),
    ] {
        let req = ProviderSignRequest {
            payload,
            algorithm: AlgorithmId::EcdsaP256Sha256,
            key: ProviderSigningKeys::EcdsaP256Sha256(&key),
            keyid: Some("digest-provider"),
            append_missing_final_newline: true,
            output_form: form,
            algorithm_parameters: &[],
        };
        for bounded in [false, true] {
            let mut calls = 0;
            let callback = |digest: &[u8; 32]| {
                calls += 1;
                let expected_digest: [u8; 32] = Sha256::digest(expected).into();
                assert_eq!(digest, &expected_digest);
                let signature: p256::ecdsa::Signature = native
                    .sign_prehash(digest)
                    .map_err(|_| SignError::KeyOperationFailure)?;
                Ok(signature.to_bytes().into())
            };
            let outcome = if bounded {
                sign_with_p256_digest_provider_and_resource_limits(
                    &req,
                    &ArtifactResourceLimits::default(),
                    callback,
                )
                .unwrap()
                .unwrap()
            } else {
                sign_with_p256_digest_provider(&req, callback)
            };
            let SignOutcome::Success(signed) = outcome else {
                panic!("digest signing failed");
            };
            assert_eq!(calls, 1);
            let artifact_form = match form {
                OutputForm::Yaml => ArtifactForm::Yaml,
                OutputForm::Protobuf => ArtifactForm::Proto,
            };
            assert_eq!(
                verify(
                    &signed.artifact,
                    artifact_form,
                    &keys,
                    VerifierOptions::default()
                ),
                Ok(VerifierState::Verified {
                    payload: expected.to_vec(),
                    algorithm: AlgorithmId::EcdsaP256Sha256,
                }),
            );
        }
    }
}

#[test]
fn unqualified_provider_signing_accepts_protobuf_output() {
    let signer = RustCryptoEd25519Signer(ed25519_dalek::SigningKey::from_bytes(&[45; 32]));
    let signer_public_key = signer.0.verifying_key().to_bytes();
    let signing_key = ProviderSigningKeyBuilder::ed25519(&signer_public_key)
        .build_unqualified()
        .unwrap();
    let request = UnqualifiedProviderSignRequest {
        payload: b"provider: output\n",
        algorithm: AlgorithmId::Ed25519,
        key: UnqualifiedProviderSigningKeys::Ed25519(&signing_key),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    assert!(matches!(
        sign_with_unqualified_provider(&request, signature_signing_callback(&signer)),
        SignOutcome::Success(_)
    ));
}
