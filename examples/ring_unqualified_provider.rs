// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! WARNING: Both signing and verification are explicitly unqualified.
//! The integration implementer owns the additional risk and compatibility
//! assessment. Signing skips independent output self-verification, and the
//! verifier never runs the fixed qualification suite. A native round trip
//! does not establish YamlSigil compatibility. In particular, ring rejects
//! some mixed-order Ed25519 signatures that YamlSigil accepts.
//!
//! Public-key admissibility, signature structure, and artifact checks remain.
//! A structurally valid signature for the wrong key or message can leave the
//! signing operation undetected. Verification below uses ring's verdict;
//! it supplies no independent check of ring's cryptographic behavior.
//!
//! cli-common/ring.rs implements the native adapters. Shared key selection and
//! YAML I/O are example scaffolding. The unqualified integration calls stay
//! here so you can see the choices required for both operations.

#[path = "cli-common/key_type.rs"]
mod key_type;
#[path = "cli-common/ring.rs"]
mod ring_adapter;
#[path = "cli-common/yaml_io.rs"]
mod yaml_io;

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use key_type::KeyType;
use ring_adapter::{RingFactory, RingSigner};
use yaml_io::{PayloadArgs, print_public_key, print_section, print_signed, print_verification};
use yaml_sigil_core::v1alpha1::AlgorithmId;
use yaml_sigil_signing::v1alpha1::{
    OutputForm, ProviderSigningKeyBuilder, SignOutcome, UnqualifiedProviderSignRequest,
    UnqualifiedProviderSigningKeys, sign_with_unqualified_provider, signature_signing_callback,
};
use yaml_sigil_verification::v1alpha1::{
    ArtifactForm, UnqualifiedProviderPublicKeys, VerificationProviderBuilder, VerifierOptions,
    VerifierState, verify_with_unqualified_provider,
};

#[derive(Parser)]
#[command(
    version,
    about = "Sign and verify YAML with ring. WARNING: Both operations are unqualified; the implementer owns the additional risk.",
    long_about = "Sign and verify YAML with a fresh random ring key.\n\nWARNING: Both operations are unqualified; the implementer owns the additional risk and compatibility assessment. Signing skips independent output self-verification. Verification skips the fixed qualification suite. Public-key admissibility, signature structure, and artifact checks remain. A native round trip is not proof of YamlSigil compatibility. ring rejects some mixed-order Ed25519 signatures that YamlSigil accepts."
)]
struct Args {
    /// Type of the fresh key to generate. Both choices use unqualified operations.
    #[arg(long, value_enum, default_value_t = KeyType::P256)]
    key_type: KeyType,
    #[command(flatten)]
    input: PayloadArgs,
}

fn run(args: &Args, stdin: impl Read, mut output: impl Write) -> Result<()> {
    // Print this before signing work, including for the default P-256 choice.
    // These fields describe the selected policy, not a qualification result.
    print_section(
        &mut output,
        "Unqualified operation warning",
        "provider_signing: unqualified\n\
         provider_verification: unqualified\n\
         skipped_checks:\n\
           - Independent signing output self-verification.\n\
           - Fixed verification-provider qualification suite.\n\
         responsibility: The integration implementer owns the additional risk and compatibility assessment.\n\
         limitation: A native round trip does not prove YamlSigil compatibility.\n\
         ed25519_note: ring rejects some mixed-order signatures that YamlSigil accepts.\n",
    )?;
    let payload = args.input.read_and_print(stdin, &mut output)?;

    // The shared native adapter generates a fresh key and keeps private bytes
    // inside ring. Only the canonical public key appears in the transcript.
    let algorithm = args.key_type.algorithm();
    let signer = RingSigner::generate(algorithm)?;
    let public_key = signer.public_key();
    print_public_key(&mut output, "ring", args.key_type.label(), public_key)?;

    let builder = match algorithm {
        AlgorithmId::Ed25519 => ProviderSigningKeyBuilder::ed25519(public_key),
        AlgorithmId::EcdsaP256Sha256 => ProviderSigningKeyBuilder::ecdsa_p256_sha256(public_key),
    };
    // WARNING: This deliberately skips independent verification of each real
    // signature. Canonical admissible keys and signature structure are still
    // checked, but those checks cannot detect a wrong-message/key signature.
    // The implementer owns the binding and cryptographic compatibility risk.
    let signing_key = builder.build_unqualified()?;
    let key = match algorithm {
        AlgorithmId::Ed25519 => UnqualifiedProviderSigningKeys::Ed25519(&signing_key),
        AlgorithmId::EcdsaP256Sha256 => {
            UnqualifiedProviderSigningKeys::EcdsaP256Sha256(&signing_key)
        }
    };
    // The forwarding callback borrows the adapter for this operation. The
    // public-key binding does not store the provider's private-key handle.
    let signed = match sign_with_unqualified_provider(
        &UnqualifiedProviderSignRequest {
            payload: payload.as_bytes(),
            algorithm,
            key,
            keyid: None,
            // YAML needs a final newline. The library appends it when missing,
            // then signs those final message bytes through the native adapter.
            append_missing_final_newline: true,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        },
        signature_signing_callback(&signer),
    ) {
        SignOutcome::Success(signed) => signed,
        SignOutcome::Invocation(error) => bail!("signing invocation failed: {error}"),
        SignOutcome::Signer(error) => bail!("signing failed: {error}"),
    };

    // WARNING: This factory never runs the fixed qualification suite. The
    // implementer owns evidence for its verification behavior, including
    // ring's known mixed-order Ed25519 difference. Both algorithms use this
    // path explicitly. Neither retries after a qualification failure.
    let provider = VerificationProviderBuilder::new(RingFactory).build_unqualified();
    let bound_key = match algorithm {
        AlgorithmId::Ed25519 => provider.bind_ed25519(public_key)?,
        AlgorithmId::EcdsaP256Sha256 => provider.bind_ecdsa_p256_sha256(public_key)?,
    };
    let keys = match algorithm {
        AlgorithmId::Ed25519 => UnqualifiedProviderPublicKeys {
            ed25519: Some(&bound_key),
            p256: None,
        },
        AlgorithmId::EcdsaP256Sha256 => UnqualifiedProviderPublicKeys {
            ed25519: None,
            p256: Some(&bound_key),
        },
    };
    // The library parses the artifact and checks its structure, then ring
    // verifies with this bound key. There is no second provider or RustCrypto
    // fallback. Disable the algorithm for which this run supplies no key.
    let state = verify_with_unqualified_provider(
        &signed.artifact,
        ArtifactForm::Yaml,
        &keys,
        VerifierOptions {
            verify_ed25519: algorithm == AlgorithmId::Ed25519,
            verify_ecdsa_p256_sha256: algorithm == AlgorithmId::EcdsaP256Sha256,
            ..VerifierOptions::default()
        },
    )
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

    // Only a successful native verification reaches this stage. The output
    // remains explicitly unqualified even though this sample round trip works.
    print_verification(
        &mut output,
        "unqualified",
        Some("This round trip does not establish YamlSigil compatibility."),
    )?;
    writeln!(output, "provider_signing: unqualified")?;
    // Preserve the returned signed YAML bytes and leave this as the last stage.
    print_signed(&mut output, &signed.artifact)
}

fn main() -> Result<()> {
    run(&Args::parse(), io::stdin().lock(), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use clap::CommandFactory as _;
    use yaml_sigil_verification::v1alpha1::{
        PublicKeys, resolve_ed25519_verifying_key, resolve_p256_verifying_key, verify_yaml,
    };

    #[test]
    fn cli_builds_and_warns() {
        Args::command().debug_assert();
        assert!(Args::try_parse_from(["ring-unqualified-provider", "--payload"]).is_err());
        for help in [
            Args::command().render_help(),
            Args::command().render_long_help(),
        ] {
            let help = help.to_string();
            assert!(help.contains("WARNING: Both operations are unqualified"));
            assert!(help.contains("the implementer owns the additional risk"));
        }
    }

    fn check_output(args: &Args, input: &[u8], expected: &[u8]) -> Result<()> {
        let mut output = Vec::new();
        run(args, input, &mut output)?;
        let output = String::from_utf8(output)?;
        assert!(output.starts_with("====== Unqualified operation warning ======\n"));
        assert!(output.contains("implementer owns the additional risk"));
        assert!(output.contains("Independent signing output self-verification."));
        assert!(output.contains("Fixed verification-provider qualification suite."));
        assert!(output.contains("native round trip does not prove YamlSigil compatibility"));
        assert!(output.contains("ring rejects some mixed-order signatures"));
        assert_eq!(output.matches("provider_signing: unqualified\n").count(), 2);
        assert_eq!(
            output
                .matches("provider_verification: unqualified\n")
                .count(),
            2
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.starts_with("====== "))
                .count(),
            5
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

        // Independently check the generated sample with the convenience API.
        // This test catches adapter/output mistakes; it runs no qualification
        // suite and does not establish compatibility for all possible inputs.
        let ed25519 = match args.key_type {
            KeyType::Ed25519 => Some(resolve_ed25519_verifying_key(&public_key)?),
            KeyType::P256 => None,
        };
        let p256 = match args.key_type {
            KeyType::P256 => Some(resolve_p256_verifying_key(&public_key)?),
            KeyType::Ed25519 => None,
        };
        let state = verify_yaml(
            artifact.as_bytes(),
            &PublicKeys {
                ed25519: ed25519.as_ref(),
                p256: p256.as_ref(),
            },
            VerifierOptions::default(),
        )?;
        let VerifierState::Verified { payload, algorithm } = state else {
            panic!("printed artifact did not verify with the printed public key");
        };
        assert_eq!(payload, expected);
        assert_eq!(algorithm, args.key_type.algorithm());
        assert!(artifact.starts_with(std::str::from_utf8(expected)?));
        Ok(())
    }

    #[test]
    fn default_p256_document() -> Result<()> {
        let args = Args::try_parse_from(["ring-unqualified-provider"])?;
        check_output(&args, &[], yaml_io::DEFAULT_PAYLOAD.as_bytes())
    }

    #[test]
    fn default_ed25519_document() -> Result<()> {
        let args = Args::try_parse_from(["ring-unqualified-provider", "--key-type", "ed25519"])?;
        check_output(&args, &[], yaml_io::DEFAULT_PAYLOAD.as_bytes())
    }

    #[test]
    fn yaml_file_for_both_key_types() -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"example: YAML from a file")?;
        for key_type in ["p256", "ed25519"] {
            let args = Args::try_parse_from([
                std::ffi::OsStr::new("ring-unqualified-provider"),
                std::ffi::OsStr::new("--key-type"),
                std::ffi::OsStr::new(key_type),
                std::ffi::OsStr::new("--payload"),
                file.path().as_os_str(),
            ])?;
            check_output(&args, &[], b"example: YAML from a file\n")?;
        }
        Ok(())
    }

    #[test]
    fn standard_input_for_both_key_types() -> Result<()> {
        for key_type in ["p256", "ed25519"] {
            let args = Args::try_parse_from([
                "ring-unqualified-provider",
                "--key-type",
                key_type,
                "--payload",
                "stdin",
            ])?;
            check_output(
                &args,
                b"example: YAML from stdin",
                b"example: YAML from stdin\n",
            )?;
        }
        Ok(())
    }
}
