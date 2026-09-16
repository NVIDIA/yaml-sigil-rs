// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign YAML and verify it with SSH-agent keys, optionally discovered on GitHub.
//!
//! The caller uses agent identities, selects an account, or supplies a public
//! key. The artifact's optional, unsigned keyid is a hint and does not constrain that
//! choice. A signature match says nothing about the payload's truth, safety,
//! or application validity.
//!
//! HTTP and SSH-agent access are example scaffolding. The qualified signing
//! builder, bounded provider operation, and verification calls below are public
//! library APIs. The SSH agent keeps the private key outside this process.

mod agent;
mod github;
mod input;
mod keys;

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use russh::keys::ssh_key::Fingerprint;
use yaml_sigil_core::{AlgorithmId, ArtifactResourceLimits};
use yaml_sigil_signing::{
    AsyncProviderSignRequest, AsyncProviderSigningKeyBuilder, AsyncProviderSigningKeys, OutputForm,
    SignOutcome, sign_with_async_provider_and_resource_limits,
};
use yaml_sigil_verification::{
    PreVerifyOutcome, PublicKeys, VerifierOptions, VerifierState,
    pre_verify_yaml_with_resource_limits, verify_from_pre_verify_yaml,
};

use github::GitHubAccount;
use input::Input;
use keys::Candidate;

#[derive(Parser)]
#[command(
    about = "Sign or verify YAML with Ed25519 SSH-agent keys, a GitHub username, or an SSH public key",
    after_help = "Progress goes to stderr. Signing writes the exact artifact to stdout unless --output is set. A signature match does not validate the payload's contents or authorize its use."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign YAML using an Ed25519 key already loaded in your SSH agent.
    Sign {
        /// Restrict keys to a GitHub username or quoted ssh-ed25519 public key; defaults to agent keys.
        #[arg(long, value_name = "USERNAME|PUBLIC_KEY")]
        signer: Option<Signer>,
        /// Restrict to this fingerprint; signing requires exactly one matching agent key.
        #[arg(long, value_name = "SHA256:FINGERPRINT", value_parser = parse_fingerprint)]
        key_fingerprint: Option<Fingerprint>,
        /// Unsigned YAML from a file, HTTP(S) URL, or 'stdin'; maximum 4 MiB.
        #[arg(long, value_name = "FILE|URL|stdin")]
        input: Input,
        /// Write signed YAML to a new file; omit for stdout. Never overwrites a file.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Verify locally using agent public identities, account keys, or an explicit key.
    Verify {
        /// Restrict keys to a GitHub username or quoted ssh-ed25519 public key; defaults to agent keys.
        #[arg(long, value_name = "USERNAME|PUBLIC_KEY")]
        signer: Option<Signer>,
        /// Restrict verification candidates to this SHA256 public-key fingerprint.
        #[arg(long, value_name = "SHA256:FINGERPRINT", value_parser = parse_fingerprint)]
        key_fingerprint: Option<Fingerprint>,
        /// Complete signed YAML from a file, HTTP(S) URL, or 'stdin'; maximum 4 MiB.
        #[arg(long, value_name = "FILE|URL|stdin")]
        input: Input,
    },
}

#[derive(Clone)]
enum Signer {
    GitHub(GitHubAccount),
    PublicKey(Box<Candidate>),
}

impl FromStr for Signer {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        // A username has no whitespace. A complete OpenSSH public key includes
        // an algorithm and base64 wire blob, with an optional comment.
        let line = value.trim();
        if line.chars().any(char::is_whitespace) {
            ensure!(
                line.lines().count() == 1,
                "supply exactly one SSH public key"
            );
            let mut keys = keys::parse_export(line)
                .context("direct signer must be one ordinary Ed25519 SSH public key")?;
            let candidate = keys.pop().context("missing public key")?;
            Ok(Self::PublicKey(Box::new(candidate)))
        } else {
            Ok(Self::GitHub(value.parse()?))
        }
    }
}

impl Signer {
    fn resolve(
        &self,
        fetch: impl Fn(&GitHubAccount) -> Result<Vec<Candidate>>,
        progress: &mut impl Write,
    ) -> Result<Vec<Candidate>> {
        match self {
            Self::GitHub(account) => {
                for url in account.key_urls() {
                    writeln!(progress, "Account key URL: {url}")?;
                }
                fetch(account)
            }
            Self::PublicKey(candidate) => {
                writeln!(
                    progress,
                    "Using the supplied public key; no GitHub key lookup."
                )?;
                Ok(vec![candidate.as_ref().clone()])
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(
        cli.command,
        github::fetch,
        input::fetch,
        agent::connect,
        io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
    .await
}

// Inject only the environment boundaries so offline tests exercise the same
// operations as the CLI. These closures are not public extension contracts.
async fn run(
    command: Command,
    fetch: impl Fn(&GitHubAccount) -> Result<Vec<Candidate>>,
    fetch_input: impl FnOnce(&ureq::http::Uri) -> Result<Vec<u8>>,
    connect_agent: impl AsyncFnOnce() -> Result<agent::Connection>,
    stdin: impl Read,
    output: &mut impl Write,
    progress: &mut impl Write,
) -> Result<()> {
    match command {
        Command::Sign {
            signer,
            key_fingerprint,
            input,
            output: destination,
        } => {
            writeln!(
                progress,
                "REMINDER: Signing a document does not validate its contents."
            )?;
            print_step(progress, 1, 6, "Check SSH agent")?;
            let session = agent::Session::open(connect_agent().await?).await?;
            print_step(progress, 2, 6, "Read unsigned YAML")?;
            let payload = input.read(stdin, fetch_input)?;
            writeln!(progress, "Read {} input bytes.", payload.len())?;

            print_step(progress, 3, 6, "Resolve public keys")?;
            let candidates = signer
                .as_ref()
                .map(|signer| signer.resolve(fetch, progress))
                .transpose()?;
            if candidates.is_none() {
                writeln!(
                    progress,
                    "Using SSH-agent public identities; no GitHub key lookup."
                )?;
            }
            print_step(progress, 4, 6, "Select SSH-agent key")?;
            let (adapter, matched) =
                agent::AgentSigner::select(session, candidates.as_deref(), key_fingerprint)?;
            print_match(progress, matched.source.as_deref(), &matched.fingerprint)?;

            print_step(progress, 5, 6, "Sign YAML through the SSH agent")?;
            // Binding checks the public key locally without a signing challenge.
            // Qualified signing self-verifies every real agent response.
            let key = AsyncProviderSigningKeyBuilder::ed25519(&adapter, matched.key.as_bytes())
                .build()
                .context("could not bind the SSH-agent public key")?;
            let signed = sign_with_async_provider_and_resource_limits(
                &AsyncProviderSignRequest {
                    payload: &payload,
                    algorithm: AlgorithmId::Ed25519,
                    key: AsyncProviderSigningKeys::Ed25519(&key),
                    // Agent identities and directly supplied keys have no account source.
                    keyid: matched.source.as_deref(),
                    append_missing_final_newline: true,
                    output_form: OutputForm::Yaml,
                    algorithm_parameters: &[],
                },
                &resource_limits(),
            )
            .await
            .context("signed document exceeds the example limit")?
            .context("could not encode signed YAML")?;
            let artifact = match signed {
                SignOutcome::Success(signed) => signed.artifact,
                SignOutcome::Invocation(error) => bail!("signing invocation failed: {error}"),
                SignOutcome::Signer(error) => bail!(
                    "SSH-agent signing failed: {error}; check that the agent permits the request and still holds the selected key"
                ),
            };

            print_step(progress, 6, 6, "Write signed YAML")?;
            // Keep the transcript on stderr and preserve every returned artifact
            // byte on stdout or in the new file. No headings enter signed output.
            if let Some(destination) = destination {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .with_context(|| {
                        format!("could not create new output {}", destination.display())
                    })?;
                file.write_all(&artifact)
                    .context("could not write signed YAML")?;
                writeln!(progress, "====== STATUS ======")?;
                writeln!(
                    progress,
                    "Signed YAML written to {}.",
                    destination.display()
                )?;
            } else {
                output
                    .write_all(&artifact)
                    .context("could not write signed YAML to stdout")?;
                output
                    .flush()
                    .context("could not flush signed YAML to stdout")?;
                writeln!(progress, "====== STATUS ======")?;
                writeln!(progress, "Signed YAML written to stdout.")?;
            }
            print_match(progress, matched.source.as_deref(), &matched.fingerprint)?;
        }
        Command::Verify {
            signer,
            key_fingerprint,
            input,
        } => {
            writeln!(
                progress,
                "REMINDER: We are validating the document's signature, not the document itself."
            )?;
            print_step(progress, 1, 5, "Check key source")?;
            let agent_candidates = if signer.is_none() {
                // Listing public identities never creates a signing adapter or
                // asks the agent to sign. All verification happens locally.
                let session = agent::Session::open(connect_agent().await?).await?;
                writeln!(
                    progress,
                    "Using SSH-agent public identities; no GitHub key lookup."
                )?;
                session.candidates()
            } else {
                writeln!(progress, "Explicit signer selected; no SSH agent needed.")?;
                Vec::new()
            };
            print_step(progress, 2, 5, "Read signed YAML")?;
            let artifact = input.read(stdin, fetch_input)?;
            writeln!(progress, "Read {} input bytes.", artifact.len())?;
            let verified = verify_artifact(
                &artifact,
                |progress| match signer {
                    Some(signer) => signer.resolve(fetch, progress),
                    None => Ok(agent_candidates),
                },
                key_fingerprint,
                progress,
            )?;
            writeln!(progress, "====== STATUS ======")?;
            print_match(progress, verified.source.as_deref(), &verified.fingerprint)?;
            writeln!(
                progress,
                "Signature verified ({} payload bytes).",
                verified.payload.len()
            )?;
        }
    }
    Ok(())
}

fn print_step(output: &mut impl Write, step: usize, total: usize, title: &str) -> Result<()> {
    // Match the provider examples' '=' headings, distinct from YAML's '---'
    // and '...' markers. Flush before each operation so blocked I/O is visible.
    writeln!(output, "====== {step}/{total} {title} ======")?;
    output.flush()?;
    Ok(())
}

fn print_match(
    output: &mut impl Write,
    source: Option<&str>,
    fingerprint: &Fingerprint,
) -> Result<()> {
    if let Some(source) = source {
        writeln!(output, "Account key URL: {source}")?;
    }
    writeln!(output, "Public-key fingerprint: {fingerprint}")?;
    Ok(())
}

fn parse_fingerprint(value: &str) -> Result<Fingerprint> {
    let fingerprint: Fingerprint = value.parse().context("invalid SSH fingerprint")?;
    ensure!(
        matches!(fingerprint, Fingerprint::Sha256(_)),
        "use a SHA256 fingerprint"
    );
    Ok(fingerprint)
}

fn resource_limits() -> ArtifactResourceLimits {
    ArtifactResourceLimits::unbounded().with_max_artifact_bytes(
        NonZeroUsize::new(input::MAX_DOCUMENT_BYTES).expect("positive example limit"),
    )
}

struct Verified {
    payload: Vec<u8>,
    fingerprint: Fingerprint,
    source: Option<String>,
}

fn verify_artifact<W: Write>(
    artifact: &[u8],
    resolve: impl FnOnce(&mut W) -> Result<Vec<Candidate>>,
    fingerprint: Option<Fingerprint>,
    progress: &mut W,
) -> Result<Verified> {
    print_step(progress, 3, 5, "Check signature metadata")?;
    // Pre-verification extracts untrusted metadata; it is not signature success.
    let pre = pre_verify_yaml_with_resource_limits(artifact, false, &resource_limits())
        .context("signed document exceeds the example limit")?;
    ensure!(
        pre.outcome == PreVerifyOutcome::Ok,
        "artifact cannot be verified: {:?}",
        pre.outcome
    );
    let metadata = pre
        .unverified_signature
        .as_ref()
        .context("missing signature metadata")?;
    ensure!(
        metadata.algorithm == AlgorithmId::Ed25519,
        "this example verifies Ed25519 only"
    );

    // keyid is an optional, unsigned hint. Resolve only the caller-selected
    // signer, regardless of whether that hint is present or what it contains.
    print_step(progress, 4, 5, "Resolve public keys")?;
    let candidates = keys::filter_fingerprint(resolve(progress)?, fingerprint)?;
    writeln!(progress, "Supported Ed25519 keys: {}.", candidates.len())?;
    print_step(progress, 5, 5, "Verify the signature")?;
    for candidate in candidates {
        let state = verify_from_pre_verify_yaml(
            &pre,
            &PublicKeys {
                ed25519: Some(&candidate.key),
                p256: None,
            },
            VerifierOptions {
                verify_ecdsa_p256_sha256: false,
                ..Default::default()
            },
        )
        .context("verification invocation failed")?;
        match state {
            VerifierState::Verified { payload, .. } => {
                // Only bytes returned by Verified have passed the signature check.
                // The application still owns every decision about their contents.
                return Ok(Verified {
                    payload,
                    fingerprint: candidate.fingerprint,
                    source: candidate.source,
                });
            }
            VerifierState::SignedButFailedVerification => continue,
            other => bail!("artifact cannot be verified: {other}"),
        }
    }
    bail!("signature does not match any Ed25519 key for the selected signer")
}

#[cfg(test)]
mod tests;
