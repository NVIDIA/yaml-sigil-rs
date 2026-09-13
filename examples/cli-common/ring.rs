// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Native ring keys and adapters shared by the two ring CLI examples.
//!
//! These implement public library contracts. Each CLI selects its own
//! qualified or unqualified operations; this module makes no such choice.

use anyhow::{Result, anyhow};
use ring::signature::KeyPair as _;
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_verification::{ProviderVerifier, ProviderVerifierFactory};

// This wrapper owns native provider keys. An application could instead borrow
// a key handle. YamlSigil needs the operation trait and corresponding public
// bytes; it never needs a private-key export.
pub(crate) enum RingSigner {
    Ed25519(ring::signature::Ed25519KeyPair),
    P256 {
        key: ring::signature::EcdsaKeyPair,
        random: ring::rand::SystemRandom,
    },
}

impl RingSigner {
    pub(crate) fn generate(algorithm: AlgorithmId) -> Result<Self> {
        // Generate fresh random keys on each invocation. Do not use fixed test
        // seeds or print the provider's private key or initialization document.

        let random = ring::rand::SystemRandom::new();
        match algorithm {
            AlgorithmId::Ed25519 => {
                let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&random)
                    .map_err(|_| anyhow!("ring Ed25519 key generation failed"))?;
                let key = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref())
                    .map_err(|_| anyhow!("ring Ed25519 key initialization failed"))?;
                Ok(Self::Ed25519(key))
            }
            AlgorithmId::EcdsaP256Sha256 => {
                let document = ring::signature::EcdsaKeyPair::generate_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    &random,
                )
                .map_err(|_| anyhow!("ring P-256 key generation failed"))?;
                let key = ring::signature::EcdsaKeyPair::from_pkcs8(
                    &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    document.as_ref(),
                    &random,
                )
                .map_err(|_| anyhow!("ring P-256 key initialization failed"))?;
                Ok(Self::P256 { key, random })
            }
        }
    }

    pub(crate) fn public_key(&self) -> &[u8] {
        // Canonical public bytes: 32 for Ed25519, or the 65-byte uncompressed
        // P-256 point. Printing these public bytes does not expose the key pair.
        match self {
            Self::Ed25519(key) => key.public_key().as_ref(),
            Self::P256 { key, .. } => key.public_key().as_ref(),
        }
    }
}

impl signature::Signer<[u8; 64]> for RingSigner {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        // Pass final payload bytes unchanged. Ed25519 signs the message
        // directly; P-256 FIXED_SIGNING applies SHA-256 once and returns raw
        // r || s. DER output or an additional prehash would violate the trait.
        let signature = match self {
            Self::Ed25519(key) => key.sign(message),
            Self::P256 { key, random } => key
                .sign(random, message)
                .map_err(|_| signature::Error::new())?,
        };
        signature
            .as_ref()
            .try_into()
            .map_err(|_| signature::Error::new())
    }
}

#[derive(Default)]
pub(crate) struct RingFactory;

struct RingVerifier {
    algorithm: AlgorithmId,
    public_key: Vec<u8>,
}

impl signature::Verifier<[u8; 64]> for RingVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        // Match the signing operation's message and signature conventions.
        // YamlSigil checks public-key and signature structure before this call.
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
        result.map_err(|_| signature::Error::new())
    }
}

// The default classifies a local verification error as signature mismatch.
// Adapters with fallible key access or remote operations must distinguish
// those provider failures by overriding verify_provider.
impl ProviderVerifier for RingVerifier {}

impl ProviderVerifierFactory for RingFactory {
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
        // Own exactly the supplied key. A later bind must never retarget a
        // handle that the factory has already returned.
        Ok(Box::new(RingVerifier {
            algorithm,
            public_key: canonical_public_key.to_vec(),
        }))
    }
}
