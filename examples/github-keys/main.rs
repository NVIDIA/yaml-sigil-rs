// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign YAML and verify it using public GitHub account keys.
//!
//! The caller selects the expected account or supplies one public key. The
//! artifact's optional, unsigned keyid is a hint and does not constrain that
//! choice. A signature match says nothing about the payload's truth, safety,
//! or application validity.
//!
//! The HTTP and OpenSSH helpers are example code. The sign_yaml, pre_verify_yaml,
//! and verify_from_pre_verify_yaml calls below are the public library operations.
//! Version 0.6.0 is intended to replace private-key-file loading with an
//! SSH-agent-backed signing provider; discovery and verification stay separate.

mod github;
mod input;

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ssh_key::{Fingerprint, PrivateKey};
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{SignYamlParams, SigningKey, sign_yaml};
use yaml_sigil_verification::{
    PreVerifyOutcome, PublicKeys, VerifierOptions, VerifierState, pre_verify_yaml,
    verify_from_pre_verify_yaml,
};
use zeroize::Zeroizing;

use github::{Candidate, GitHubAccount};
use input::Input;

#[derive(Parser)]
#[command(
    about = "Sign YAML or verify an Ed25519 signature using a GitHub username or an SSH public key",
    after_help = "Progress goes to stderr. Signing writes the exact artifact to stdout unless --output is set. A signature match does not validate the payload's contents or authorize its use."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign YAML using an OpenSSH Ed25519 private-key file.
    Sign {
        /// GitHub username or quoted ssh-ed25519 public key for offline use.
        #[arg(long, value_name = "USERNAME|PUBLIC_KEY")]
        signer: Signer,
        /// OpenSSH private-key file; encrypted keys prompt on the terminal.
        #[arg(long, value_name = "FILE")]
        private_key: PathBuf,
        /// Unsigned YAML from a file, HTTP(S) URL, or 'stdin'; maximum 4 MiB.
        #[arg(long, value_name = "FILE|URL|stdin")]
        input: Input,
        /// Write signed YAML to a new file; omit for stdout. Never overwrites a file.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Require a signature matching the selected account's public keys or the supplied key.
    Verify {
        /// Expected GitHub username or quoted ssh-ed25519 public key.
        #[arg(long, value_name = "USERNAME|PUBLIC_KEY")]
        signer: Signer,
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
            let mut keys = github::parse_export(line)
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    run(
        cli.command,
        github::fetch,
        input::fetch,
        || {
            rpassword::prompt_password("OpenSSH key passphrase: ")
                .map(Zeroizing::new)
                .context("could not read passphrase from the terminal")
        },
        io::stdin().lock(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

// Inject only the environment boundaries so offline tests exercise the same
// operations as the CLI. These closures are not public extension contracts.
fn run(
    command: Command,
    fetch: impl Fn(&GitHubAccount) -> Result<Vec<Candidate>>,
    fetch_input: impl FnOnce(&ureq::http::Uri) -> Result<Vec<u8>>,
    prompt: impl FnOnce() -> Result<Zeroizing<String>>,
    stdin: impl Read,
    output: &mut impl Write,
    progress: &mut impl Write,
) -> Result<()> {
    match command {
        Command::Sign {
            signer,
            private_key,
            input,
            output: destination,
        } => {
            writeln!(
                progress,
                "REMINDER: Signing a document does not validate its contents."
            )?;
            print_step(progress, 1, 5, "Read unsigned YAML")?;
            let payload = input.read(stdin, fetch_input)?;
            writeln!(progress, "Read {} input bytes.", payload.len())?;

            print_step(progress, 2, 5, "Load private key")?;
            writeln!(
                progress,
                "This example takes ownership of the private key in process memory."
            )?;
            progress.flush()?;
            let key = load_signing_key(&private_key, prompt)?;

            print_step(progress, 3, 5, "Resolve signer and match the public key")?;
            let candidates = signer.resolve(fetch, progress)?;
            let matched = require_matching_key(&key, &candidates)?;

            print_step(progress, 4, 5, "Sign YAML")?;
            // The library signs payload bytes and composes the YAML artifact.
            // OpenSSH's SSHSIG envelope signs different bytes and is not used.
            let artifact = sign_yaml(&SignYamlParams {
                payload: &payload,
                algorithm: AlgorithmId::Ed25519,
                key: SigningKey::Ed25519(&key),
                // Emit the resource containing the matching key. A directly
                // supplied public key has no account source and omits keyid.
                keyid: matched.source.as_deref(),
                append_missing_final_newline: true,
            })
            .context("could not sign YAML")?;
            // Keep the signed artifact within the same limit used when reading it.
            ensure!(
                artifact.len() <= input::MAX_DOCUMENT_BYTES,
                "signed document exceeds the {}-byte example limit",
                input::MAX_DOCUMENT_BYTES
            );

            print_step(progress, 5, 5, "Write signed YAML")?;
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
        Command::Verify { signer, input } => {
            writeln!(
                progress,
                "REMINDER: We are validating the document's signature, not the document itself."
            )?;
            print_step(progress, 1, 4, "Read signed YAML")?;
            let artifact = input.read(stdin, fetch_input)?;
            writeln!(progress, "Read {} input bytes.", artifact.len())?;
            let verified = verify_artifact(&artifact, &signer, fetch, progress)?;
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

fn load_signing_key(
    path: &Path,
    prompt: impl FnOnce() -> Result<Zeroizing<String>>,
) -> Result<Ed25519SigningKey> {
    // Keep file I/O here so ssh-key needs no std feature or unrelated backends.
    // File bytes, decoded private keys, the passphrase, and the native signing
    // key clear their secret buffers on drop.
    let mut key = {
        let encoded =
            Zeroizing::new(fs::read(path).context("could not read an OpenSSH private key")?);
        PrivateKey::from_openssh(&*encoded)
            .map_err(|error| anyhow::anyhow!("could not decode OpenSSH private key: {error}"))?
    };
    if key.is_encrypted() {
        let passphrase = prompt()?;
        key = key
            .decrypt(passphrase.as_bytes())
            .map_err(|error| anyhow::anyhow!("could not decrypt OpenSSH key: {error}"))?;
    }
    let pair = key.key_data().ed25519().context(
        "this example signs with ordinary Ed25519 keys only; P-256, RSA, and security keys are unsupported",
    )?;
    Ed25519SigningKey::try_from(pair)
        .map_err(|error| anyhow::anyhow!("inconsistent Ed25519 private/public key pair: {error}"))
}

fn require_matching_key<'a>(
    key: &Ed25519SigningKey,
    candidates: &'a [Candidate],
) -> Result<&'a Candidate> {
    candidates
        .iter()
        .find(|candidate| candidate.key == key.verifying_key())
        .context("the private key's public key does not match the selected signer")
}

struct Verified {
    payload: Vec<u8>,
    fingerprint: Fingerprint,
    source: Option<String>,
}

fn verify_artifact(
    artifact: &[u8],
    signer: &Signer,
    fetch: impl Fn(&GitHubAccount) -> Result<Vec<Candidate>>,
    progress: &mut impl Write,
) -> Result<Verified> {
    print_step(progress, 2, 4, "Check signature metadata")?;
    // Pre-verification extracts untrusted metadata; it is not signature success.
    let pre = pre_verify_yaml(artifact, false);
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
    print_step(progress, 3, 4, "Resolve public keys")?;
    let candidates = signer.resolve(fetch, progress)?;
    writeln!(progress, "Supported Ed25519 keys: {}.", candidates.len())?;
    print_step(progress, 4, 4, "Verify the signature")?;
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
