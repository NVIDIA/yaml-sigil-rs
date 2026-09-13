// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI and YamlSigil flow for the local cryptographic-provider examples.
//!
//! The two entry points supply native adapters; this module owns their common
//! options, input handling, key binding, signing, verification, and transcript.
//! Other CLI examples can reuse applicable helpers without adopting this
//! provider-specific command contract.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail, ensure};
use clap::{CommandFactory, FromArgMatches, Parser};
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{
    OutputForm, ProviderSignRequest, ProviderSigningKeyBuilder, ProviderSigningKeys, SignOutcome,
    sign_with_provider,
};
use yaml_sigil_verification::{
    ArtifactForm, ProviderPublicKeys, ProviderVerifierFactory, UnqualifiedProviderPublicKeys,
    VerificationProviderBuilder, VerifierOptions, VerifierState, verify_with_provider,
    verify_with_unqualified_provider,
};

mod key_type;
pub(crate) use key_type::KeyType;
mod yaml_io;
use yaml_io::{PayloadArgs, print_public_key, print_signed, print_verification};

#[derive(Parser)]
#[command(version, about = "Sign and verify YAML using a local provider")]
struct Args {
    /// Type of the fresh key to generate. Ed25519 verification is unqualified.
    #[arg(long, value_enum, default_value_t = KeyType::P256)]
    key_type: KeyType,
    #[command(flatten)]
    input: PayloadArgs,
}

// This trait is only the examples' shared driver, not a yaml-sigil-rs API.
// Each native adapter implements the public signature operation traits
// and ProviderVerifierFactory directly. The driver associates those adapters
// with key generation and the command's identity.
pub(crate) trait ProviderExample: ProviderVerifierFactory + Default {
    type Key: signature::Signer<[u8; 64]> + Sync;
    const NAME: &'static str;
    const COMMAND: &'static str;

    fn generate_key(key_type: KeyType) -> Result<Self::Key>;
    fn public_key(key: &Self::Key) -> &[u8];
}

fn command<P: ProviderExample>() -> clap::Command {
    Args::command().name(P::COMMAND)
}
fn verify_artifact<P: ProviderExample>(
    algorithm: AlgorithmId,
    public_key: &[u8],
    artifact: &[u8],
) -> Result<VerifierState> {
    match algorithm {
        AlgorithmId::EcdsaP256Sha256 => {
            // Qualification tests this exact factory with public vectors.
            // Reuse the qualified instance for application keys. A failed
            // qualification is an error, never a reason to bypass the suite.
            let provider = VerificationProviderBuilder::new(P::default()).qualify();
            ensure!(
                provider.status(algorithm).is_qualified(),
                "P-256 provider did not qualify"
            );
            let key = provider.bind_ecdsa_p256_sha256(public_key)?;
            let keys = ProviderPublicKeys {
                ed25519: None,
                p256: Some(&key),
            };
            Ok(verify_with_provider(
                artifact,
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions {
                    verify_ed25519: false,
                    ..VerifierOptions::default()
                },
            )?)
        }
        AlgorithmId::Ed25519 => {
            // The native verifier rejects some mixed-order signatures that
            // YamlSigil accepts, so its Ed25519 slot cannot qualify. This
            // generated-key demonstration explicitly selects the unqualified
            // path, which still checks signatures and retains structural checks.
            // Success here does not establish full YamlSigil compatibility.
            // This is selected by key type, never as a retry after failure.
            let provider = VerificationProviderBuilder::new(P::default()).build_unqualified();
            let key = provider.bind_ed25519(public_key)?;
            let keys = UnqualifiedProviderPublicKeys {
                ed25519: Some(&key),
                p256: None,
            };
            Ok(verify_with_unqualified_provider(
                artifact,
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions {
                    verify_ecdsa_p256_sha256: false,
                    ..VerifierOptions::default()
                },
            )?)
        }
    }
}

fn run<P: ProviderExample>(args: &Args, stdin: impl Read, mut output: impl Write) -> Result<()> {
    let payload = args.input.read_and_print(stdin, &mut output)?;

    let signer = P::generate_key(args.key_type)?;
    let public_key = P::public_key(&signer);
    let algorithm = args.key_type.algorithm();
    print_public_key(&mut output, P::NAME, args.key_type.label(), public_key)?;

    // Both algorithms use the normal signing builder. It validates the public
    // key and self-verifies each real signature before returning an artifact.
    // The provider keeps the native private key behind the operation trait.
    let signing_key = match algorithm {
        AlgorithmId::Ed25519 => ProviderSigningKeyBuilder::ed25519(&signer, public_key),
        AlgorithmId::EcdsaP256Sha256 => {
            ProviderSigningKeyBuilder::ecdsa_p256_sha256(&signer, public_key)
        }
    }
    .build()?;
    let key = match algorithm {
        AlgorithmId::Ed25519 => ProviderSigningKeys::Ed25519(&signing_key),
        AlgorithmId::EcdsaP256Sha256 => ProviderSigningKeys::EcdsaP256Sha256(&signing_key),
    };
    let signed = match sign_with_provider(&ProviderSignRequest {
        payload: payload.as_bytes(),
        algorithm,
        key,
        keyid: None,
        // Allow a missing final newline to be appended before YAML signing.
        // Compare the verified payload with those normalized bytes below.
        append_missing_final_newline: true,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    }) {
        SignOutcome::Success(signed) => signed,
        SignOutcome::Invocation(error) => bail!("signing invocation failed: {error}"),
        SignOutcome::Signer(error) => bail!("signing failed: {error}"),
    };

    // Only Verified permits the final artifact output. Invocation errors and
    // other verifier states propagate as errors without a success transcript.
    let state = verify_artifact::<P>(algorithm, public_key, &signed.artifact)
        .context("verification failed")?;
    let VerifierState::Verified {
        payload: verified_payload,
        algorithm: verified_algorithm,
    } = state
    else {
        bail!("artifact did not verify");
    };
    let expected_payload = if signed.modified_payload.is_empty() {
        payload.as_bytes()
    } else {
        &signed.modified_payload
    };
    ensure!(verified_algorithm == algorithm, "unexpected algorithm");
    ensure!(
        verified_payload == expected_payload,
        "verified payload differs from signed payload"
    );
    let mode = match args.key_type {
        KeyType::P256 => "qualified",
        KeyType::Ed25519 => "unqualified",
    };
    let note = matches!(args.key_type, KeyType::Ed25519)
        .then_some("This provider rejects some mixed-order signatures accepted by YamlSigil.");
    print_verification(&mut output, mode, note)?;
    print_signed(&mut output, &signed.artifact)
}

pub(crate) fn run_cli<P: ProviderExample>() -> Result<()> {
    // Both binaries use the same parser and operation. Only their command
    // names and native adapters differ.
    let args = Args::from_arg_matches(&command::<P>().get_matches())?;
    run::<P>(&args, io::stdin().lock(), io::stdout().lock())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use yaml_io::DEFAULT_PAYLOAD;

    pub(crate) fn cli_builds<P: ProviderExample>() {
        command::<P>().debug_assert();
        assert!(Args::try_parse_from([P::COMMAND, "--payload"]).is_err());
    }

    // Verify the printed artifact with the printed public key. This exercises
    // the CLI operation and catches output corruption or a mislabeled key.
    fn check_output<P: ProviderExample>(args: &Args, input: &[u8], expected: &[u8]) -> Result<()> {
        let mut output = Vec::new();
        run::<P>(args, input, &mut output)?;
        let output = String::from_utf8(output)?;
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("====== "))
                .count(),
            4
        );
        assert!(output.contains(&format!("key_type: {}\n", args.key_type.label())));
        let encoded = output
            .split_once("public_key: \"")
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        let public_key = BASE64.decode(encoded)?;
        let artifact = output
            .split_once("====== Signed YAML artifact ======\n")
            .unwrap()
            .1;
        let state =
            verify_artifact::<P>(args.key_type.algorithm(), &public_key, artifact.as_bytes())?;
        let VerifierState::Verified { payload, .. } = state else {
            panic!("printed artifact did not verify with the printed public key");
        };
        assert_eq!(payload, expected);
        assert!(artifact.starts_with(std::str::from_utf8(expected)?));
        let mode = match args.key_type {
            KeyType::P256 => "qualified",
            KeyType::Ed25519 => "unqualified",
        };
        assert!(output.contains(&format!("provider_verification: {mode}\n")));
        Ok(())
    }

    pub(crate) fn default_p256_document<P: ProviderExample>() -> Result<()> {
        let args = Args::try_parse_from([P::COMMAND])?;
        check_output::<P>(&args, &[], DEFAULT_PAYLOAD.as_bytes())
    }

    pub(crate) fn default_ed25519_document<P: ProviderExample>() -> Result<()> {
        let args = Args::try_parse_from([P::COMMAND, "--key-type", "ed25519"])?;
        check_output::<P>(&args, &[], DEFAULT_PAYLOAD.as_bytes())
    }

    pub(crate) fn yaml_file_for_both_key_types<P: ProviderExample>() -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"example: YAML from a file")?;
        for key_type in ["p256", "ed25519"] {
            let args = Args::try_parse_from([
                std::ffi::OsStr::new(P::COMMAND),
                std::ffi::OsStr::new("--key-type"),
                std::ffi::OsStr::new(key_type),
                std::ffi::OsStr::new("--payload"),
                file.path().as_os_str(),
            ])?;
            check_output::<P>(&args, &[], b"example: YAML from a file\n")?;
        }
        Ok(())
    }

    pub(crate) fn standard_input_for_both_key_types<P: ProviderExample>() -> Result<()> {
        for key_type in ["p256", "ed25519"] {
            let args =
                Args::try_parse_from([P::COMMAND, "--key-type", key_type, "--payload", "stdin"])?;
            check_output::<P>(
                &args,
                b"example: YAML from stdin",
                b"example: YAML from stdin\n",
            )?;
        }
        Ok(())
    }
}
