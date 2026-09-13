// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign and verify YAML through an awaitable, simulated P-256 service.
//!
//! The blocking worker stands in for an HSM or KMS. It owns the private key;
//! adapters send requests and await replies. There is no network, SDK, or
//! credential setup. This is a scheduling and integration example, not an HSM
//! implementation or a claim about any service's security boundary.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, ValueEnum};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use signature::{RandomizedSigner as _, Verifier as _};
use tokio::sync::{mpsc, oneshot};
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{
    AsyncProviderSignRequest, AsyncProviderSigner, AsyncProviderSigningKeyBuilder,
    AsyncProviderSigningKeys, AsyncSigner as _, OutputForm, ProviderAsyncSigner, SignOutcome,
    SignSuccess, UnqualifiedAsyncProviderSignRequest, UnqualifiedAsyncProviderSigningKeys,
    UnqualifiedProviderAsyncSigner,
};
use yaml_sigil_verification::{
    ArtifactForm, AsyncProviderPublicKeys, AsyncProviderVerifier, AsyncProviderVerifierFactory,
    AsyncVerificationProviderBuilder, AsyncVerifier as _, ProviderAsyncVerifier,
    ProviderVerificationOutcome, UnqualifiedAsyncProviderPublicKeys,
    UnqualifiedProviderAsyncVerifier, VerifierOptions, VerifierState,
};

// Reuse only the applicable CLI support. The synchronous provider driver in
// cli-common/mod.rs has different options and an algorithm-specific policy.
#[path = "cli-common/yaml_io.rs"]
mod yaml_io;

#[derive(Parser)]
#[command(version, about = "Sign and verify YAML using an async P-256 service")]
struct Args {
    /// Select provider checks explicitly. No automatic fallback occurs.
    #[arg(long, value_enum, default_value_t = ProviderMode::Qualified)]
    provider_mode: ProviderMode,
    #[command(flatten)]
    input: yaml_io::PayloadArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderMode {
    Qualified,
    Unqualified,
}

impl ProviderMode {
    fn label(self) -> &'static str {
        match self {
            Self::Qualified => "qualified",
            Self::Unqualified => "unqualified",
        }
    }
}

// Everything below this request enum, through start_service, is simulated
// service plumbing. A real integration would use its SDK and opaque key IDs.
// The bounded queue limits queued requests, not payload size or remote cost.
enum Operation {
    PublicKey(oneshot::Sender<Vec<u8>>),
    Sign(Vec<u8>, oneshot::Sender<Result<[u8; 64], signature::Error>>),
    Bind(Vec<u8>, oneshot::Sender<Result<usize, signature::Error>>),
    Verify {
        key: usize,
        message: Vec<u8>,
        signature: [u8; 64],
        reply: oneshot::Sender<ProviderVerificationOutcome>,
    },
}

struct Client {
    requests: mpsc::Sender<Operation>,
}

impl Client {
    async fn request<T: Send>(
        &self,
        operation: impl FnOnce(oneshot::Sender<T>) -> Operation + Send,
    ) -> Result<T, signature::Error> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(operation(reply))
            .await
            .map_err(|_| signature::Error::new())?;
        // This await can suspend independently of the worker's progress.
        // Dropping response does not undo work already accepted by the worker.
        response.await.map_err(|_| signature::Error::new())
    }
}

fn start_service() -> (Client, tokio::task::JoinHandle<()>) {
    let (requests, mut operations) = mpsc::channel(8);
    let worker = tokio::task::spawn_blocking(move || {
        // Generate a fresh random private key inside the worker. Only its
        // public bytes and actual requested signatures leave this scope.
        let key = SigningKey::random(&mut OsRng);
        let public_key = key.verifying_key().to_encoded_point(false);
        let mut verification_keys = Vec::<VerifyingKey>::new();
        while let Some(operation) = operations.blocking_recv() {
            match operation {
                Operation::PublicKey(reply) => {
                    let _ = reply.send(public_key.as_bytes().to_vec());
                }
                Operation::Sign(message, reply) => {
                    // Randomized message signing hashes with SHA-256 exactly
                    // once. Return fixed-width big-endian r || s, not DER.
                    let signed: Result<Signature, _> = key.try_sign_with_rng(&mut OsRng, &message);
                    let _ = reply.send(signed.map(|sig| sig.to_bytes().into()));
                }
                Operation::Bind(bytes, reply) => {
                    let bound = VerifyingKey::from_sec1_bytes(&bytes)
                        .map_err(|_| signature::Error::new())
                        .map(|key| {
                            // Each handle keeps its own immutable binding.
                            // Creating another handle never retargets this one.
                            let id = verification_keys.len();
                            verification_keys.push(key);
                            id
                        });
                    let _ = reply.send(bound);
                }
                Operation::Verify {
                    key,
                    message,
                    signature,
                    reply,
                } => {
                    let outcome = match verification_keys.get(key) {
                        None => ProviderVerificationOutcome::ProviderFailure,
                        Some(key) => match Signature::from_slice(&signature) {
                            // The ordinary message verifier hashes once and
                            // accepts both high-S and low-S representations.
                            Ok(sig) if key.verify(&message, &sig).is_ok() => {
                                ProviderVerificationOutcome::Verified
                            }
                            _ => ProviderVerificationOutcome::SignatureMismatch,
                        },
                    };
                    let _ = reply.send(outcome);
                }
            }
        }
    });
    (Client { requests }, worker)
}

// This is the public signing extension point. Initialization/public-key
// retrieval is separate, so binding never triggers a synthetic signing call.
impl AsyncProviderSigner for Client {
    async fn try_sign<'a>(&'a self, message: &'a [u8]) -> Result<[u8; 64], signature::Error> {
        self.request(|reply| Operation::Sign(message.to_vec(), reply))
            .await?
    }
}

struct Factory<'client> {
    client: &'client Client,
}

struct BoundVerifier<'client> {
    client: &'client Client,
    key: usize,
}

// The public factory GAT allows the returned handle to borrow a client.
// The public-key slice can be temporary: only its bytes reach the service,
// and the completed handle retains a service key ID, never that slice.
impl AsyncProviderVerifierFactory for Factory<'_> {
    type Verifier<'factory>
        = BoundVerifier<'factory>
    where
        Self: 'factory;

    async fn bind<'factory>(
        &'factory self,
        algorithm: AlgorithmId,
        canonical_public_key: &[u8],
    ) -> Result<Self::Verifier<'factory>, signature::Error> {
        // This service supports only P-256. Qualification tracks the two
        // algorithm slots separately, so Ed25519 failure does not disable it.
        if algorithm != AlgorithmId::EcdsaP256Sha256 {
            return Err(signature::Error::new());
        }
        let key = self
            .client
            .request(|reply| Operation::Bind(canonical_public_key.to_vec(), reply))
            .await??;
        Ok(BoundVerifier {
            client: self.client,
            key,
        })
    }
}

// Async verification has no synchronous trait requirement. Preserve mismatch
// versus operational failure; neither outcome causes a retry through another
// provider. A service unable to import public test keys may choose the
// explicitly unqualified route instead of this qualification protocol.
impl AsyncProviderVerifier for BoundVerifier<'_> {
    async fn verify_provider<'a>(
        &'a self,
        message: &'a [u8],
        signature: &'a [u8; 64],
    ) -> ProviderVerificationOutcome {
        self.client
            .request(|reply| Operation::Verify {
                key: self.key,
                message: message.to_vec(),
                signature: *signature,
                reply,
            })
            .await
            .unwrap_or(ProviderVerificationOutcome::ProviderFailure)
    }
}

async fn sign_and_verify(
    mode: ProviderMode,
    payload: &str,
    client: &Client,
    output: &mut impl Write,
) -> Result<()> {
    let public_key = client.request(Operation::PublicKey).await?;
    yaml_io::print_public_key(
        output,
        "simulated async service",
        "ECDSA P-256 (SHA-256)",
        &public_key,
    )?;

    // The provider-backed facades implement the existing AsyncSigner trait.
    // Select the key type and facade deliberately; the unqualified route
    // retains structural checks but skips cryptographic output self-checking.
    let builder = AsyncProviderSigningKeyBuilder::ecdsa_p256_sha256(client, &public_key);
    let outcome = match mode {
        ProviderMode::Qualified => {
            let key = builder.build()?;
            ProviderAsyncSigner::default()
                .sign(&AsyncProviderSignRequest {
                    payload: payload.as_bytes(),
                    algorithm: AlgorithmId::EcdsaP256Sha256,
                    key: AsyncProviderSigningKeys::EcdsaP256Sha256(&key),
                    keyid: None,
                    append_missing_final_newline: true,
                    output_form: OutputForm::Yaml,
                    algorithm_parameters: &[],
                })
                .await
        }
        ProviderMode::Unqualified => {
            let key = builder.build_unqualified()?;
            UnqualifiedProviderAsyncSigner::default()
                .sign(&UnqualifiedAsyncProviderSignRequest {
                    payload: payload.as_bytes(),
                    algorithm: AlgorithmId::EcdsaP256Sha256,
                    key: UnqualifiedAsyncProviderSigningKeys::EcdsaP256Sha256(&key),
                    keyid: None,
                    append_missing_final_newline: true,
                    output_form: OutputForm::Yaml,
                    algorithm_parameters: &[],
                })
                .await
        }
    };
    let SignOutcome::Success(signed) = outcome else {
        return match outcome {
            SignOutcome::Invocation(error) => Err(error).context("invalid signing request"),
            SignOutcome::Signer(error) => Err(error).context("signing failed"),
            SignOutcome::Success(_) => unreachable!(),
        };
    };

    // Qualification awaits a finite suite of public test operations on this
    // exact factory. It is narrower evidence than complete conformance. The
    // unqualified branch is an explicit choice, never a fallback on failure.
    let builder = AsyncVerificationProviderBuilder::new(Factory { client });
    let options = VerifierOptions {
        verify_ed25519: false,
        ..VerifierOptions::default()
    };
    let state = match mode {
        ProviderMode::Qualified => {
            let provider = builder.qualify().await;
            ensure!(
                provider.status(AlgorithmId::EcdsaP256Sha256).is_qualified(),
                "P-256 provider did not qualify"
            );
            let key = provider.bind_ecdsa_p256_sha256(&public_key).await?;
            ProviderAsyncVerifier::default()
                .verify(
                    &signed.artifact,
                    ArtifactForm::Yaml,
                    &AsyncProviderPublicKeys {
                        ed25519: None,
                        p256: Some(&key),
                    },
                    options,
                )
                .await?
        }
        ProviderMode::Unqualified => {
            let provider = builder.build_unqualified();
            let key = provider.bind_ecdsa_p256_sha256(&public_key).await?;
            UnqualifiedProviderAsyncVerifier::default()
                .verify(
                    &signed.artifact,
                    ArtifactForm::Yaml,
                    &UnqualifiedAsyncProviderPublicKeys {
                        ed25519: None,
                        p256: Some(&key),
                    },
                    options,
                )
                .await?
        }
    };
    check_verified(&signed, payload, state)?;
    yaml_io::print_verification(output, mode.label(), None)?;
    // Both operations use the selected mode. Label signing explicitly so
    // an unqualified transcript cannot suggest its output was self-checked.
    writeln!(output, "provider_signing: {}", mode.label())?;
    yaml_io::print_signed(output, &signed.artifact)
}

fn check_verified(signed: &SignSuccess, payload: &str, state: VerifierState) -> Result<()> {
    // Only Verified authenticates payload bytes. Also check the algorithm and
    // the exact authorized newline normalization before printing success.
    let VerifierState::Verified {
        payload: verified,
        algorithm,
    } = state
    else {
        bail!("artifact did not verify");
    };
    ensure!(
        algorithm == AlgorithmId::EcdsaP256Sha256,
        "unexpected algorithm"
    );
    let expected = if signed.modified_payload.is_empty() {
        payload.as_bytes()
    } else {
        &signed.modified_payload
    };
    ensure!(
        verified == expected,
        "verified payload differs from signed payload"
    );
    Ok(())
}

async fn run(args: &Args, stdin: impl Read, mut output: impl Write) -> Result<()> {
    // This CLI performs its finite file/terminal I/O outside provider work.
    // A server would choose its own async I/O and artifact admission policy.
    let payload = args.input.read_and_print(stdin, &mut output)?;
    let (client, worker) = start_service();
    let result = sign_and_verify(args.provider_mode, &payload, &client, &mut output).await;
    // Close the queue and join even when the operation failed. Production
    // adapters must define their own deadlines and remote cancellation policy.
    drop(client);
    worker.await.context("simulated service worker failed")?;
    result
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    run(&Args::parse(), io::stdin().lock(), io::stdout().lock()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use clap::CommandFactory;
    use yaml_sigil_verification::{PublicKeys, resolve_p256_verifying_key, verify_yaml};

    #[test]
    fn cli_builds() {
        Args::command().debug_assert();
        assert!(Args::try_parse_from(["async-provider", "--payload"]).is_err());
    }

    async fn check_output(args: &Args, input: &[u8], expected: &[u8]) -> Result<()> {
        let mut output = Vec::new();
        run(args, input, &mut output).await?;
        let output = String::from_utf8(output)?;
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("====== "))
                .count(),
            4
        );
        assert!(output.contains("key_type: ECDSA P-256 (SHA-256)\n"));
        assert!(output.contains(&format!(
            "provider_verification: {}\n",
            args.provider_mode.label()
        )));
        assert!(output.contains(&format!(
            "provider_signing: {}\n",
            args.provider_mode.label()
        )));
        let encoded = output
            .split_once("public_key: \"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        let key = resolve_p256_verifying_key(&BASE64.decode(encoded)?)?;
        let artifact = output
            .split_once("====== Signed YAML artifact ======\n")
            .unwrap()
            .1;
        // Independently verify the actual transcript with its printed key.
        let state = verify_yaml(
            artifact.as_bytes(),
            &PublicKeys {
                ed25519: None,
                p256: Some(&key),
            },
            VerifierOptions::default(),
        )?;
        let VerifierState::Verified { payload, .. } = state else {
            panic!("printed artifact did not verify");
        };
        assert_eq!(payload, expected);
        Ok(())
    }

    #[tokio::test]
    async fn default_document_for_both_modes() -> Result<()> {
        for mode in ["qualified", "unqualified"] {
            let args = Args::try_parse_from(["async-provider", "--provider-mode", mode])?;
            check_output(&args, &[], yaml_io::DEFAULT_PAYLOAD.as_bytes()).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn file_and_stdin_for_both_modes() -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"example: YAML from a file")?;
        for mode in ["qualified", "unqualified"] {
            let args = Args::try_parse_from([
                std::ffi::OsStr::new("async-provider"),
                std::ffi::OsStr::new("--provider-mode"),
                std::ffi::OsStr::new(mode),
                std::ffi::OsStr::new("--payload"),
                file.path().as_os_str(),
            ])?;
            check_output(&args, &[], b"example: YAML from a file\n").await?;
            let args = Args::try_parse_from([
                "async-provider",
                "--provider-mode",
                mode,
                "--payload",
                "stdin",
            ])?;
            check_output(
                &args,
                b"example: YAML from stdin",
                b"example: YAML from stdin\n",
            )
            .await?;
        }
        Ok(())
    }
}
