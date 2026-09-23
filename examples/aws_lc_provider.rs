// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Native aws-lc-rs adapters for the shared YAML signing and verification example.
//!
//! The shared flow in cli-common/mod.rs handles clap, input, YamlSigil key
//! binding and operations, and output. This file shows the provider-specific
//! key generation and implementations of the public adapter contracts.
//!
//! We choose `non-fips` for this interoperability example to avoid the
//! FIPS-specific build-tool and platform requirements. The example exercises
//! the adapter contracts and makes no FIPS validation claim.

#[path = "cli-common/mod.rs"]
mod cli_common;

use anyhow::{Result, anyhow};
use aws::signature::KeyPair as _;
use aws_lc_rs as aws;
use cli_common::{KeyType, ProviderExample};
use yaml_sigil_core::v1alpha1::AlgorithmId;
use yaml_sigil_verification::v1alpha1::{ProviderVerifier, ProviderVerifierFactory};

// This wrapper owns native provider keys. An application could instead borrow
// a key handle. YamlSigil needs the operation trait and corresponding public
// bytes; it never needs a private-key export.
enum AwsSigner {
    Ed25519(aws::signature::Ed25519KeyPair),
    P256 {
        key: aws::signature::EcdsaKeyPair,
        random: aws::rand::SystemRandom,
    },
}

impl AwsSigner {
    fn generate(key_type: KeyType) -> Result<Self> {
        // Generate fresh random keys on each invocation. Do not use fixed test
        // seeds or print the provider's private key or initialization document.

        match key_type {
            KeyType::Ed25519 => {
                let key = aws::signature::Ed25519KeyPair::generate()
                    .map_err(|_| anyhow!("aws-lc-rs Ed25519 key generation failed"))?;
                Ok(Self::Ed25519(key))
            }
            KeyType::P256 => {
                let key = aws::signature::EcdsaKeyPair::generate(
                    &aws::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                )
                .map_err(|_| anyhow!("aws-lc-rs P-256 key generation failed"))?;
                Ok(Self::P256 {
                    key,
                    random: aws::rand::SystemRandom::new(),
                })
            }
        }
    }

    fn public_key(&self) -> &[u8] {
        // Canonical public bytes: 32 for Ed25519, or the 65-byte uncompressed
        // P-256 point. Printing these public bytes does not expose the key pair.
        match self {
            Self::Ed25519(key) => key.public_key().as_ref(),
            Self::P256 { key, .. } => key.public_key().as_ref(),
        }
    }
}

impl signature::Signer<[u8; 64]> for AwsSigner {
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], signature::Error> {
        // Pass final payload bytes unchanged. Ed25519 signs the message
        // directly; P-256 FIXED_SIGNING applies SHA-256 once and returns raw
        // r || s. DER output or an additional prehash would violate the trait.
        let signature = match self {
            Self::Ed25519(key) => key.try_sign(message).map_err(|_| signature::Error::new())?,
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
struct AwsFactory;

struct AwsVerifier {
    algorithm: AlgorithmId,
    public_key: Vec<u8>,
}

impl signature::Verifier<[u8; 64]> for AwsVerifier {
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        // Match the signing operation's message and signature conventions.
        // YamlSigil checks public-key and signature structure before this call.
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
        result.map_err(|_| signature::Error::new())
    }
}

// The default classifies a local verification error as signature mismatch.
// Adapters with fallible key access or remote operations must distinguish
// those provider failures by overriding verify_provider.
impl ProviderVerifier for AwsVerifier {}

impl ProviderVerifierFactory for AwsFactory {
    fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Box<dyn ProviderVerifier + 'factory>, signature::Error> {
        // Own exactly the supplied key. A later bind must never retarget a
        // handle that the factory has already returned.
        Ok(Box::new(AwsVerifier {
            algorithm,
            public_key: canonical_public_key.to_vec(),
        }))
    }
}

// Connect the native adapters to the examples' shared CLI driver. This trait
// is example scaffolding; the implementations above are the library contracts.
impl ProviderExample for AwsFactory {
    type Key = AwsSigner;
    const NAME: &'static str = "aws-lc-rs";
    const COMMAND: &'static str = "aws-lc-provider";

    fn generate_key(key_type: KeyType) -> Result<Self::Key> {
        AwsSigner::generate(key_type)
    }

    fn public_key(key: &Self::Key) -> &[u8] {
        key.public_key()
    }
}

fn main() -> Result<()> {
    cli_common::run_cli::<AwsFactory>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_builds() {
        cli_common::tests::cli_builds::<AwsFactory>();
    }

    #[test]
    fn default_p256_document() -> Result<()> {
        cli_common::tests::default_p256_document::<AwsFactory>()
    }

    #[test]
    fn default_ed25519_document() -> Result<()> {
        cli_common::tests::default_ed25519_document::<AwsFactory>()
    }

    #[test]
    fn yaml_file_for_both_key_types() -> Result<()> {
        cli_common::tests::yaml_file_for_both_key_types::<AwsFactory>()
    }

    #[test]
    fn standard_input_for_both_key_types() -> Result<()> {
        cli_common::tests::standard_input_for_both_key_types::<AwsFactory>()
    }
}
