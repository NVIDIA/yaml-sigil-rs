// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::CommandFactory;
use rand_core::OsRng;
use ssh_key::private::KeypairData;
use ssh_key::{HashAlg, LineEnding, PublicKey as SshPublicKey};
use tempfile::tempdir;

const SIGNER: &str = "ddurst-nvidia";
const KEY_ID: &str = "https://api.github.com/users/ddurst-nvidia/ssh_signing_keys";
const PAYLOAD: &[u8] = b"example: synthetic test\nport: 8080\n";

fn endpoint() -> Signer {
    SIGNER.parse().unwrap()
}

// These seeds are invented test data, never personal signing keys.
fn private(seed: u8) -> PrivateKey {
    PrivateKey::new(
        KeypairData::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32])),
        "synthetic example test",
    )
    .unwrap()
}

fn native(key: &PrivateKey) -> Ed25519SigningKey {
    Ed25519SigningKey::try_from(key.key_data().ed25519().unwrap()).unwrap()
}

fn export(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}

fn candidates(key: &PrivateKey) -> Vec<Candidate> {
    let mut candidates = github::parse_export(&export(key)).unwrap();
    for candidate in &mut candidates {
        candidate.source = Some(KEY_ID.to_owned());
    }
    candidates
}

fn write_private(key: &PrivateKey, path: &Path) {
    // Only synthetic keys are written under a fresh temporary directory.
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    fs::write(path, pem.as_bytes()).unwrap();
}

fn sign(payload: &[u8], key: &PrivateKey, keyid: Option<&str>) -> Vec<u8> {
    sign_yaml(&SignYamlParams {
        payload,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&native(key)),
        keyid,
        append_missing_final_newline: true,
    })
    .unwrap()
}

fn no_prompt() -> Result<Zeroizing<String>> {
    panic!("unencrypted keys and verification must not prompt")
}

fn run_file_command(
    command: Command,
    fetch: impl Fn(&GitHubAccount) -> Result<Vec<Candidate>>,
    prompt: impl FnOnce() -> Result<Zeroizing<String>>,
    progress: &mut impl Write,
) -> Result<()> {
    let mut stdout = Vec::new();
    let result = run(
        command,
        fetch,
        |_| panic!("file input must not fetch a document"),
        prompt,
        io::empty(),
        &mut stdout,
        progress,
    );
    assert!(stdout.is_empty());
    result
}

fn verify_offline(
    artifact: &[u8],
    signer: &Signer,
    fetch: impl Fn(&GitHubAccount) -> Result<Vec<Candidate>>,
) -> Result<Verified> {
    verify_artifact(artifact, signer, fetch, &mut io::sink())
}

#[test]
fn cli_parser_and_required_arguments() {
    Cli::command().debug_assert();
    assert!(Cli::try_parse_from(["github-keys", "verify", "--input", "signed.yaml"]).is_err());
    assert!(Cli::try_parse_from(["github-keys", "verify", "--signer", SIGNER]).is_err());
    for (command, extra) in [("verify", vec![]), ("sign", vec!["--private-key", "key"])] {
        let args = [
            "github-keys",
            command,
            "--signer",
            SIGNER,
            "--input",
            "signed.yaml",
        ];
        let cli = Cli::try_parse_from(args.into_iter().chain(extra.iter().copied())).unwrap();
        let (Command::Sign { signer, .. } | Command::Verify { signer, .. }) = cli.command;
        let Signer::GitHub(account) = signer else {
            panic!("username must select a GitHub account");
        };
        assert_eq!(
            account.key_urls(),
            ["https://api.github.com/users/ddurst-nvidia/keys", KEY_ID,]
        );

        let mut url_args = args;
        url_args[3] = KEY_ID;
        assert!(Cli::try_parse_from(url_args.into_iter().chain(extra)).is_err());
    }
}

const RAW_URL: &str = "https://raw.githubusercontent.com/NVIDIA/yaml-sigil-rs/main/examples/github-keys/fixtures/unsigned.yaml";

fn input_response(status: u16, bytes: Vec<u8>) -> ureq::http::Response<ureq::Body> {
    ureq::http::Response::builder()
        .status(status)
        .body(ureq::Body::builder().data(bytes))
        .unwrap()
}

#[test]
fn input_parser_accepts_files_stdin_and_http_urls() {
    assert!(matches!("stdin".parse::<Input>().unwrap(), Input::Stdin));
    assert!(matches!(
        "./stdin".parse::<Input>().unwrap(),
        Input::File(_)
    ));
    assert!(matches!(RAW_URL.parse::<Input>().unwrap(), Input::Url(_)));
    assert!(matches!(
        "http://example.com/input.yaml".parse::<Input>().unwrap(),
        Input::Url(_)
    ));
    for invalid in [
        "ftp://example.com/input.yaml",
        "file:///input.yaml",
        "https://",
        "https://user:secret@example.com/input.yaml",
        "https://example.com/input.yaml#fragment",
    ] {
        assert!(invalid.parse::<Input>().is_err(), "{invalid}");
    }
}

#[test]
fn stdin_and_url_commands_preserve_stdout_artifacts_and_report_each_step() {
    let directory = tempdir().unwrap();
    let key = private(7);
    let key_path = directory.path().join("key");
    write_private(&key, &key_path);
    let payload = &PAYLOAD[..PAYLOAD.len() - 1];

    for source in ["stdin", RAW_URL] {
        let cli = Cli::try_parse_from([
            "github-keys",
            "sign",
            "--signer",
            SIGNER,
            "--private-key",
            key_path.to_str().unwrap(),
            "--input",
            source,
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut progress = Vec::new();
        run(
            cli.command,
            |_| Ok(candidates(&key)),
            |uri| {
                assert_eq!(source, RAW_URL);
                assert_eq!(uri.to_string(), RAW_URL);
                input::read_response(input_response(200, payload.to_vec()))
            },
            no_prompt,
            payload,
            &mut stdout,
            &mut progress,
        )
        .unwrap();
        assert_eq!(stdout, sign(payload, &key, Some(KEY_ID)));
        let progress = String::from_utf8(progress).unwrap();
        let steps: Vec<_> = progress
            .lines()
            .filter(|line| line.starts_with("====== "))
            .collect();
        assert_eq!(steps.len(), 6);
        for (index, heading) in steps[..5].iter().enumerate() {
            assert!(heading.starts_with(&format!("====== {}/5 ", index + 1)));
        }
        assert!(!progress.contains("---"));
        assert!(!progress.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(progress.contains("private key in process memory"));
        assert!(progress.contains("====== STATUS ======\nSigned YAML written to stdout.\n"));

        let cli = Cli::try_parse_from([
            "github-keys",
            "verify",
            "--signer",
            SIGNER,
            "--input",
            source,
        ])
        .unwrap();
        let mut verify_stdout = Vec::new();
        let mut progress = Vec::new();
        run(
            cli.command,
            |_| Ok(candidates(&key)),
            |uri| {
                assert_eq!(source, RAW_URL);
                assert_eq!(uri.to_string(), RAW_URL);
                input::read_response(input_response(200, stdout.clone()))
            },
            no_prompt,
            stdout.as_slice(),
            &mut verify_stdout,
            &mut progress,
        )
        .unwrap();
        assert!(verify_stdout.is_empty());
        let progress = String::from_utf8(progress).unwrap();
        let steps: Vec<_> = progress
            .lines()
            .filter(|line| line.starts_with("====== "))
            .collect();
        assert_eq!(steps.len(), 4);
        for (index, heading) in steps.iter().enumerate() {
            assert!(heading.starts_with(&format!("====== {}/4 ", index + 1)));
        }
        assert_eq!(
            progress.lines().next(),
            Some("REMINDER: We are validating the document's signature, not the document itself.")
        );
        assert!(progress.ends_with(&format!(
            "Signature verified ({} payload bytes).\n",
            PAYLOAD.len()
        )));
        assert!(progress.contains("Public-key fingerprint: SHA256:"));
        assert!(!progress.contains("Payload contents are not validated"));
    }
}

struct FailedRead;
impl Read for FailedRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::TimedOut))
    }
}

#[test]
fn input_failures_stop_before_signing_or_key_lookup() {
    for source in ["stdin", RAW_URL] {
        let cli = Cli::try_parse_from([
            "github-keys",
            "sign",
            "--signer",
            SIGNER,
            "--private-key",
            "unused-key",
            "--input",
            source,
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut progress = Vec::new();
        let error = run(
            cli.command,
            |_| panic!("must not fetch keys after an input error"),
            |_| bail!("input request failed"),
            no_prompt,
            FailedRead,
            &mut stdout,
            &mut progress,
        )
        .unwrap_err();
        assert!(error.to_string().contains(if source == "stdin" {
            "stdin"
        } else {
            "input request"
        }));
        assert!(stdout.is_empty());
        let progress = String::from_utf8(progress).unwrap();
        assert!(progress.contains("1/5 Read unsigned YAML"));
        assert!(!progress.contains("2/5"));
    }
}

#[test]
fn document_http_reads_preserve_bytes_and_reject_failed_responses() {
    let bytes = b"example: exact bytes\r\nvalue: \xff".to_vec();
    assert_eq!(
        input::read_response(input_response(200, bytes.clone())).unwrap(),
        bytes
    );
    for status in [204, 206, 301, 302, 401, 403, 404, 429, 500] {
        let error = input::read_response(input_response(status, PAYLOAD.to_vec())).unwrap_err();
        assert!(error.to_string().contains(&status.to_string()));
    }
    let response = ureq::http::Response::builder()
        .body(ureq::Body::builder().reader(FailedRead))
        .unwrap();
    assert!(input::read_response(response).is_err());
}

#[test]
fn document_input_size_boundaries_apply_to_every_source() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("input.yaml");
    let limit = input::MAX_DOCUMENT_BYTES;
    for length in [0, limit - 1, limit, limit + 1] {
        let bytes = vec![b'x'; length];
        fs::write(&path, &bytes).unwrap();
        for source in [
            Input::File(path.clone()),
            Input::Stdin,
            RAW_URL.parse().unwrap(),
        ] {
            let result = source.read(bytes.as_slice(), |_| {
                input::read_response(input_response(200, bytes.clone()))
            });
            if length <= limit {
                assert_eq!(result.unwrap(), bytes);
            } else {
                assert!(format!("{:#}", result.unwrap_err()).contains("example limit"));
            }
        }
    }
}

#[test]
fn document_readers_stop_after_one_overflow_byte() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counted(Arc<AtomicUsize>);
    impl Read for Counted {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let total = self.0.fetch_add(buffer.len(), Ordering::Relaxed) + buffer.len();
            // Fail promptly if a regression tries to consume this endless source.
            assert!(total <= input::MAX_DOCUMENT_BYTES + 1);
            buffer.fill(b'x');
            Ok(buffer.len())
        }
    }
    for http in [false, true] {
        let count = Arc::new(AtomicUsize::new(0));
        let reader = Counted(count.clone());
        let result = if http {
            let response = ureq::http::Response::builder()
                .body(ureq::Body::builder().reader(reader))
                .unwrap();
            input::read_response(response)
        } else {
            Input::Stdin.read(reader, |_| panic!("stdin must not fetch"))
        };
        assert!(format!("{:#}", result.unwrap_err()).contains("example limit"));
        assert_eq!(count.load(Ordering::Relaxed), input::MAX_DOCUMENT_BYTES + 1);
    }
}

#[test]
fn oversized_documents_stop_both_commands_before_key_access() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("large.yaml");
    let bytes = vec![b'x'; input::MAX_DOCUMENT_BYTES + 1];
    fs::write(&path, &bytes).unwrap();
    for source in [Input::File(path), Input::Stdin, RAW_URL.parse().unwrap()] {
        for command in [
            Command::Sign {
                signer: endpoint(),
                private_key: directory.path().join("absent-key"),
                input: source.clone(),
                output: None,
            },
            Command::Verify {
                signer: endpoint(),
                input: source.clone(),
            },
        ] {
            let mut output = Vec::new();
            let mut progress = Vec::new();
            let error = run(
                command,
                |_| panic!("oversized input must not fetch keys"),
                |_| input::read_response(input_response(200, bytes.clone())),
                no_prompt,
                bytes.as_slice(),
                &mut output,
                &mut progress,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("example limit"));
            assert!(output.is_empty());
            assert!(!String::from_utf8(progress).unwrap().contains("====== 2/"));
        }
    }
}

#[test]
fn signing_keeps_the_complete_artifact_within_the_document_limit() {
    let directory = tempdir().unwrap();
    let key = private(31);
    let key_path = directory.path().join("key");
    write_private(&key, &key_path);
    let signer: Signer = export(&key).parse().unwrap();
    let overhead = sign(b"x\n", &key, None).len() - 2;
    let mut payload = vec![b'x'; input::MAX_DOCUMENT_BYTES - overhead];
    *payload.last_mut().unwrap() = b'\n';
    let mut artifact = Vec::new();
    run(
        Command::Sign {
            signer: signer.clone(),
            private_key: key_path.clone(),
            input: Input::Stdin,
            output: None,
        },
        |_| panic!("direct key must not fetch"),
        |_| panic!("stdin must not fetch"),
        no_prompt,
        payload.as_slice(),
        &mut artifact,
        &mut io::sink(),
    )
    .unwrap();
    assert_eq!(artifact.len(), input::MAX_DOCUMENT_BYTES);
    let mut verify_output = Vec::new();
    run(
        Command::Verify {
            signer: signer.clone(),
            input: Input::Stdin,
        },
        |_| panic!("direct key must not fetch"),
        |_| panic!("stdin must not fetch"),
        no_prompt,
        artifact.as_slice(),
        &mut verify_output,
        &mut io::sink(),
    )
    .unwrap();
    assert!(verify_output.is_empty());

    payload.push(b'\n');
    let destination = directory.path().join("refused.yaml");
    for output in [None, Some(destination.clone())] {
        let mut stdout = Vec::new();
        let error = run(
            Command::Sign {
                signer: signer.clone(),
                private_key: key_path.clone(),
                input: Input::Stdin,
                output,
            },
            |_| panic!("direct key must not fetch"),
            |_| panic!("stdin must not fetch"),
            no_prompt,
            payload.as_slice(),
            &mut stdout,
            &mut io::sink(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("signed document exceeds"));
        assert!(stdout.is_empty());
        assert!(!destination.exists());
    }
}

#[test]
fn signed_output_preserves_terminal_control_bytes() {
    let directory = tempdir().unwrap();
    let key = private(32);
    let key_path = directory.path().join("key");
    write_private(&key, &key_path);
    let signer: Signer = export(&key).parse().unwrap();
    let payload = b"message: \x1b]0;synthetic title\x07\n";
    let mut artifact = Vec::new();
    run(
        Command::Sign {
            signer: signer.clone(),
            private_key: key_path,
            input: Input::Stdin,
            output: None,
        },
        |_| panic!("direct key must not fetch"),
        |_| panic!("stdin must not fetch"),
        no_prompt,
        payload.as_slice(),
        &mut artifact,
        &mut io::sink(),
    )
    .unwrap();
    assert!(artifact.starts_with(payload));
    let verified =
        verify_offline(&artifact, &signer, |_| panic!("direct key must not fetch")).unwrap();
    assert_eq!(verified.payload, payload);
}

#[test]
fn file_signing_and_verification_use_the_cli_operations() {
    let directory = tempdir().unwrap();
    let key = private(7);
    let key_path = directory.path().join("key");
    write_private(&key, &key_path);
    let input = directory.path().join("payload.yaml");
    let destination = directory.path().join("signed.yaml");
    fs::write(&input, b"port: 8080").unwrap();
    let mut output = Vec::new();
    run_file_command(
        Command::Sign {
            signer: endpoint(),
            private_key: key_path.clone(),
            input: Input::File(input.clone()),
            output: Some(destination.clone()),
        },
        |signer| {
            assert_eq!(signer.key_urls()[1], KEY_ID);
            Ok(candidates(&key))
        },
        no_prompt,
        &mut output,
    )
    .unwrap();
    let artifact = fs::read(&destination).unwrap();
    assert_eq!(
        pre_verify_yaml(&artifact, false)
            .unverified_signature
            .unwrap()
            .keyid
            .as_deref(),
        Some(KEY_ID)
    );
    assert_eq!(
        verify_offline(&artifact, &endpoint(), |_| Ok(candidates(&key)))
            .unwrap()
            .payload,
        b"port: 8080\n"
    );
    assert!(
        String::from_utf8(output)
            .unwrap()
            .starts_with("REMINDER: Signing a document does not validate its contents.\n")
    );

    let mut output = Vec::new();
    run_file_command(
        Command::Verify {
            signer: endpoint(),
            input: Input::File(destination.clone()),
        },
        |_| Ok(candidates(&key)),
        no_prompt,
        &mut output,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(
        output.lines().next(),
        Some("REMINDER: We are validating the document's signature, not the document itself.")
    );
    assert!(output.ends_with("Signature verified (11 payload bytes).\n"));
    assert!(!output.contains("Payload contents are not validated"));
    assert!(output.contains(&key.fingerprint(HashAlg::Sha256).to_string()));
    assert!(!output.contains("BEGIN OPENSSH PRIVATE KEY"));

    let error = run_file_command(
        Command::Sign {
            signer: endpoint(),
            private_key: key_path,
            input: Input::File(input),
            output: Some(destination.clone()),
        },
        |_| Ok(candidates(&key)),
        no_prompt,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("could not create new output"));
    assert_eq!(fs::read(destination).unwrap(), artifact);
}

#[test]
fn encrypted_key_unlock_and_bad_passphrase() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("encrypted-key");
    let key = private(8);
    write_private(&key.encrypt(&mut OsRng, "test passphrase").unwrap(), &path);
    let loaded = load_signing_key(&path, || Ok(Zeroizing::new("test passphrase".into()))).unwrap();
    assert_eq!(loaded.verifying_key(), native(&key).verifying_key());
    let error = load_signing_key(&path, || Ok(Zeroizing::new("wrong".into())))
        .err()
        .unwrap();
    assert!(error.to_string().contains("could not decrypt"));
    assert!(load_signing_key(&path, || bail!("terminal unavailable")).is_err());
}

#[test]
fn signing_refuses_an_unpublished_key_and_preserves_missing_input_errors() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("key");
    let key = private(7);
    write_private(&key, &path);
    let input = directory.path().join("payload.yaml");
    let output = directory.path().join("signed.yaml");
    fs::write(&input, PAYLOAD).unwrap();
    let command = || Command::Sign {
        signer: endpoint(),
        private_key: path.clone(),
        input: Input::File(input.clone()),
        output: Some(output.clone()),
    };
    let error = run_file_command(
        command(),
        |_| Ok(candidates(&private(8))),
        no_prompt,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the selected signer")
    );
    assert!(!output.exists());
    fs::remove_file(&input).unwrap();
    assert!(
        run_file_command(
            command(),
            |_| panic!("must not fetch after input failure"),
            no_prompt,
            &mut Vec::new()
        )
        .is_err()
    );
    assert!(!output.exists());
}

#[test]
fn multiple_keys_comments_and_unsupported_algorithms() {
    let key = private(7);
    let other = private(8);
    let another = private(10);
    let p256_key = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
    let p256_public = SshPublicKey::new(
        ssh_key::public::EcdsaPublicKey::NistP256(p256_key.verifying_key().to_encoded_point(false))
            .into(),
        "unsupported by this CLI",
    )
    .to_openssh()
    .unwrap();
    let keys = format!(
        "# comment\n\n{}\n{p256_public}\n{}\n{}\n{}\n",
        export(&other),
        export(&another),
        export(&key),
        export(&key)
    );
    let mut parsed = github::parse_export(&keys).unwrap();
    assert_eq!(parsed.len(), 3);
    let artifact = sign(PAYLOAD, &key, Some(KEY_ID));
    // Rotate the export so the matching key is last, first, and in the middle.
    // Wrong supported keys, unsupported algorithms, and duplicates coexist.
    for _ in 0..parsed.len() {
        let mut progress = Vec::new();
        let verified = verify_artifact(
            &artifact,
            &endpoint(),
            |_| Ok(parsed.clone()),
            &mut progress,
        )
        .unwrap();
        assert_eq!(verified.payload, PAYLOAD);
        assert_eq!(verified.fingerprint, key.fingerprint(HashAlg::Sha256));
        assert!(
            String::from_utf8(progress)
                .unwrap()
                .contains("Supported Ed25519 keys: 3.")
        );
        parsed.rotate_right(1);
    }
    parsed.retain(|candidate| candidate.key != native(&key).verifying_key());
    assert!(verify_offline(&artifact, &endpoint(), |_| Ok(parsed.clone())).is_err());
    assert!(
        github::parse_export(&p256_public)
            .err()
            .unwrap()
            .to_string()
            .contains("no supported")
    );
    assert!(
        github::parse_export("# empty\n")
            .err()
            .unwrap()
            .to_string()
            .contains("no supported Ed25519 public keys")
    );
    assert!(github::parse_export("ssh-ed25519 not-base64").is_err());
    assert!(github::parse_export(&format!("{}\n<html>login</html>", export(&key))).is_err());

    // The real SSH parser validates the blob's algorithm, not only its label.
    assert!(github::parse_export(&export(&key).replacen("ssh-ed25519", "ssh-rsa", 1)).is_err());
    let identity = SshPublicKey::new(ssh_key::public::Ed25519PublicKey([0; 32]).into(), "")
        .to_openssh()
        .unwrap();
    assert!(github::parse_export(&identity).is_err());
}

#[test]
fn authentication_and_signing_registrations_both_sign_and_verify() {
    let directory = tempdir().unwrap();
    let key = private(29);
    let key_path = directory.path().join("key");
    write_private(&key, &key_path);
    let public = export(&key);
    let account: GitHubAccount = SIGNER.parse().unwrap();
    let urls = account.key_urls();

    for registered in 0..2 {
        let calls = std::cell::Cell::new(0);
        let fetch = |selected: &GitHubAccount| {
            assert_eq!(selected.key_urls(), urls);
            github::fetch_pages(selected, |url| {
                calls.set(calls.get() + 1);
                assert!(
                    urls.iter()
                        .any(|base| url == format!("{base}?per_page=100&page=1"))
                );
                let records = if url.starts_with(&urls[registered]) {
                    serde_json::json!([{"id": 1, "key": public}])
                } else {
                    serde_json::json!([])
                };
                Ok(ureq::http::Response::builder()
                    .header("content-type", "application/json")
                    .body(ureq::Body::builder().data(serde_json::to_vec(&records).unwrap()))
                    .unwrap())
            })
        };
        let mut artifact = Vec::new();
        run(
            Command::Sign {
                signer: endpoint(),
                private_key: key_path.clone(),
                input: Input::Stdin,
                output: None,
            },
            fetch,
            |_| panic!("stdin must not fetch input"),
            no_prompt,
            PAYLOAD,
            &mut artifact,
            &mut io::sink(),
        )
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            pre_verify_yaml(&artifact, false)
                .unverified_signature
                .unwrap()
                .keyid
                .as_deref(),
            Some(urls[registered].as_str())
        );
        let verified = verify_offline(&artifact, &endpoint(), fetch).unwrap();
        assert_eq!(calls.get(), 4);
        assert_eq!(verified.payload, PAYLOAD);
        assert_eq!(verified.fingerprint, key.fingerprint(HashAlg::Sha256));
        assert_eq!(verified.source.as_deref(), Some(urls[registered].as_str()));
    }
}

#[test]
fn unsigned_and_malformed_fail_before_discovery() {
    let key = private(7);
    for artifact in [
        PAYLOAD.to_vec(),
        sign(PAYLOAD, &key, Some(KEY_ID))[..12].to_vec(),
    ] {
        assert!(verify_offline(&artifact, &endpoint(), |_| panic!("must not fetch")).is_err());
    }
}

#[test]
fn keyid_hints_do_not_constrain_or_redirect_the_selected_signer() {
    let key = private(7);
    for keyid in [
        None,
        Some(KEY_ID),
        Some("https://api.github.com/users/someone-else/ssh_signing_keys"),
        Some("https://untrusted.example/key"),
        Some(SIGNER),
    ] {
        let artifact = sign(PAYLOAD, &key, keyid);
        let calls = std::cell::Cell::new(0);
        let mut stdout = Vec::new();
        let mut progress = Vec::new();
        run(
            Command::Verify {
                signer: endpoint(),
                input: Input::Stdin,
            },
            |selected| {
                assert_eq!(selected.key_urls()[1], KEY_ID);
                calls.set(calls.get() + 1);
                Ok(candidates(&key))
            },
            |_| panic!("stdin must not fetch input"),
            no_prompt,
            artifact.as_slice(),
            &mut stdout,
            &mut progress,
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(stdout.is_empty());
        assert!(String::from_utf8(progress).unwrap().ends_with(&format!(
            "Signature verified ({} payload bytes).\n",
            PAYLOAD.len()
        )));
        assert!(verify_offline(&artifact, &endpoint(), |_| Ok(candidates(&private(8)))).is_err());
    }
}

#[test]
fn tampering_wrong_keys_and_lookup_failures_do_not_verify() {
    let key = private(7);
    let artifact = sign(PAYLOAD, &key, Some(KEY_ID));
    let changed = String::from_utf8(artifact.clone())
        .unwrap()
        .replace("8080", "8081");
    assert!(verify_offline(changed.as_bytes(), &endpoint(), |_| Ok(candidates(&key))).is_err());
    assert!(verify_offline(&artifact, &endpoint(), |_| Ok(candidates(&private(8)))).is_err());
    assert!(verify_offline(&artifact, &endpoint(), |_| bail!("network unavailable")).is_err());
    assert!(verify_offline(&artifact, &endpoint(), |_| Ok(vec![])).is_err());

    let mut signature = pre_verify_yaml(&artifact, false)
        .unverified_signature
        .unwrap()
        .signature_octets;
    let original = URL_SAFE_NO_PAD.encode(&signature);
    signature[32] ^= 1; // Change a low scalar bit while retaining a complete signature.
    let changed = String::from_utf8(artifact.clone())
        .unwrap()
        .replace(&original, &URL_SAFE_NO_PAD.encode(signature));
    assert!(verify_offline(changed.as_bytes(), &endpoint(), |_| Ok(candidates(&key))).is_err());
    let malformed = String::from_utf8(artifact)
        .unwrap()
        .replace(&original, "AA");
    assert!(verify_offline(malformed.as_bytes(), &endpoint(), |_| Ok(candidates(&key))).is_err());
}

// Keep the README recipe compiling with the example's selected features.
fn resolve_ssh_p256(line: &str) -> Result<p256::ecdsa::VerifyingKey> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use ssh_key::{PublicKey, public::EcdsaPublicKey};
    use yaml_sigil_verification::resolve_p256_verifying_key;

    let parsed = PublicKey::from_openssh(line)
        .map_err(|error| anyhow::anyhow!("invalid OpenSSH key: {error}"))?;
    let Some(EcdsaPublicKey::NistP256(point)) = parsed.key_data().ecdsa() else {
        bail!("expected an ordinary P-256 SSH public key");
    };
    let native = p256::PublicKey::from_sec1_bytes(point.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid P-256 point"))?;
    let uncompressed = native.to_encoded_point(false);
    Ok(resolve_p256_verifying_key(uncompressed.as_bytes())?)
}

#[test]
fn p256_adaptation_uses_existing_library_apis_but_is_not_a_cli_mode() {
    // This is the README's adaptation recipe, exercised independently of the
    // Ed25519 CLI. It calls dependencies rather than copying encoding rules.
    let signing = p256::ecdsa::SigningKey::from_slice(&[11; 32]).unwrap();
    let ssh_public = SshPublicKey::new(
        ssh_key::public::EcdsaPublicKey::NistP256(signing.verifying_key().to_encoded_point(false))
            .into(),
        "",
    )
    .to_openssh()
    .unwrap();
    let verifying = resolve_ssh_p256(&ssh_public).unwrap();
    assert!(resolve_ssh_p256(&export(&private(7))).is_err());
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&signing),
        keyid: Some(KEY_ID),
        append_missing_final_newline: true,
    })
    .unwrap();
    assert!(matches!(
        yaml_sigil_verification::verify_yaml(
            &artifact,
            &PublicKeys {
                ed25519: None,
                p256: Some(&verifying)
            },
            VerifierOptions::default()
        )
        .unwrap(),
        VerifierState::Verified { .. }
    ));
    assert!(
        verify_offline(&artifact, &endpoint(), |_| panic!(
            "CLI must reject P-256 before fetching"
        ))
        .is_err()
    );
}

#[test]
fn published_yaml_fixtures_have_the_documented_outcomes() {
    // The snapshot tests cryptographic reproducibility, not current GitHub
    // account association. A live lookup remains an explicit manual check.
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("github-keys/fixtures");
    let keys = fs::read_to_string(directory.join("ddurst-nvidia.pub-key")).unwrap();
    let direct: Signer = keys.parse().unwrap();
    let fetch = |_: &GitHubAccount| github::parse_export(&keys);
    for (signed, unsigned) in [
        ("signed.yaml", "unsigned.yaml"),
        ("changed-keyid.yaml", "unsigned.yaml"),
        (
            "signed-application-invalid.yaml",
            "application-invalid.yaml",
        ),
    ] {
        let artifact = fs::read(directory.join(signed)).unwrap();
        let result = verify_offline(&artifact, &endpoint(), fetch).unwrap();
        assert_eq!(result.payload, fs::read(directory.join(unsigned)).unwrap());
        assert_eq!(
            verify_offline(&artifact, &direct, |_| panic!("offline fixture lookup"))
                .unwrap()
                .payload,
            result.payload
        );
    }
    for file in [
        "unsigned.yaml",
        "tampered-payload.yaml",
        "tampered-signature.yaml",
    ] {
        let artifact = fs::read(directory.join(file)).unwrap();
        assert!(
            verify_offline(&artifact, &endpoint(), fetch).is_err(),
            "{file}"
        );
        let direct_result =
            verify_offline(&artifact, &direct, |_| panic!("offline fixture lookup"));
        assert!(direct_result.is_err(), "{file}");
    }
}

#[test]
fn direct_public_key_signing_and_verification_never_fetch_github_keys() {
    let directory = tempdir().unwrap();
    let key = private(17);
    let path = directory.path().join("private-key");
    write_private(&key, &path);
    let public = export(&key);
    let command = Cli::try_parse_from([
        "github-keys",
        "sign",
        "--signer",
        &public,
        "--private-key",
        path.to_str().unwrap(),
        "--input",
        "stdin",
    ])
    .unwrap()
    .command;
    let mut artifact = Vec::new();
    let mut progress = Vec::new();
    run(
        command,
        |_| panic!("direct public key must not query GitHub"),
        |_| panic!("stdin must not fetch input"),
        no_prompt,
        PAYLOAD,
        &mut artifact,
        &mut progress,
    )
    .unwrap();
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    assert_eq!(
        pre_verify_yaml(&artifact, false)
            .unverified_signature
            .unwrap()
            .keyid
            .as_deref(),
        None
    );
    let command = Cli::try_parse_from([
        "github-keys",
        "verify",
        "--signer",
        &public,
        "--input",
        "stdin",
    ])
    .unwrap()
    .command;
    let mut output = Vec::new();
    progress.clear();
    run(
        command,
        |_| panic!("direct public key must not query GitHub"),
        |_| panic!("stdin must not fetch input"),
        no_prompt,
        artifact.as_slice(),
        &mut output,
        &mut progress,
    )
    .unwrap();
    assert!(output.is_empty());
    let progress = String::from_utf8(progress).unwrap();
    assert!(progress.contains("Using the supplied public key; no GitHub key lookup."));
    assert!(!progress.contains("Account key URL:"));
    assert!(progress.contains(&fingerprint));
    assert!(progress.ends_with(&format!(
        "Signature verified ({} payload bytes).\n",
        PAYLOAD.len()
    )));

    // Direct mode pins the cryptographic key. The unsigned hint need not name
    // GitHub or be present, and cannot cause any network request.
    let signer: Signer = public.parse().unwrap();
    for keyid in [Some(KEY_ID), Some("https://untrusted.example/key"), None] {
        let artifact = sign(PAYLOAD, &key, keyid);
        let verified =
            verify_offline(&artifact, &signer, |_| panic!("must not resolve keyid")).unwrap();
        assert_eq!(verified.payload, PAYLOAD);
        let wrong: Signer = export(&private(18)).parse().unwrap();
        assert!(
            verify_offline(&artifact, &wrong, |_| panic!(
                "must not fetch for wrong key"
            ))
            .is_err()
        );
    }
    let destination = directory.path().join("refused.yaml");
    let input = directory.path().join("input.yaml");
    fs::write(&input, PAYLOAD).unwrap();
    let error = run_file_command(
        Command::Sign {
            signer: export(&private(18)).parse().unwrap(),
            private_key: path,
            input: Input::File(input),
            output: Some(destination.clone()),
        },
        |_| panic!("must not query GitHub"),
        no_prompt,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(!destination.exists());
    assert!(
        error
            .to_string()
            .contains("does not match the selected signer")
    );
}

#[test]
fn direct_signer_requires_one_admissible_ed25519_public_key() {
    let public = export(&private(17));
    for text in [
        &public,
        &format!("{public}\n"),
        &format!("{public} optional comment"),
    ] {
        assert!(matches!(
            text.parse::<Signer>().unwrap(),
            Signer::PublicKey(_)
        ));
    }
    for text in [
        format!("{public}\n{public}"),
        "ssh-ed25519 not-base64".into(),
        "SHA256:not-an-ssh-key".into(),
        "./fixtures/key.pub".into(),
    ] {
        assert!(text.parse::<Signer>().is_err());
    }
    let p256 = p256::ecdsa::SigningKey::from_slice(&[19; 32]).unwrap();
    let public = SshPublicKey::new(
        ssh_key::public::EcdsaPublicKey::NistP256(p256.verifying_key().to_encoded_point(false))
            .into(),
        "unsupported",
    )
    .to_openssh()
    .unwrap();
    assert!(public.parse::<Signer>().is_err());
}
