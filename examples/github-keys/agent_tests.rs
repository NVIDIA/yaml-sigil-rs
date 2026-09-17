// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Synthetic agent exchanges exercise russh's real client without a live
//! socket, account, or personal key. Only this test peer encodes replies.

use super::*;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_encoding::{Decode, Encode};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[derive(Clone, Copy, Default)]
enum Reply {
    #[default]
    Valid,
    Refused,
    WrongKey,
    WrongAlgorithm,
    Oversized,
    Truncated,
    Pending,
}

#[derive(Default)]
struct Observed {
    messages: Vec<Vec<u8>>,
    requests: usize,
}

pub(super) fn test_agent(key: &PrivateKey) -> impl AsyncFnOnce() -> Result<agent::Connection> {
    let key = key.clone();
    async move || Ok(mock_agent(&[key], Reply::Valid).0)
}

fn mock_agent(keys: &[PrivateKey], reply: Reply) -> (agent::Connection, Arc<Mutex<Observed>>) {
    let (client, server) = tokio::io::duplex(4096);
    let observed = Arc::new(Mutex::new(Observed::default()));
    let recorded = observed.clone();
    let keys = keys.to_vec();
    tokio::spawn(async move {
        serve(server, keys, reply, recorded).await.unwrap();
    });
    (AgentClient::connect(client).dynamic(), observed)
}

async fn serve(
    mut stream: DuplexStream,
    keys: Vec<PrivateKey>,
    reply: Reply,
    observed: Arc<Mutex<Observed>>,
) -> Result<()> {
    loop {
        let size = match stream.read_u32().await {
            Ok(size) => size as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            size <= input::MAX_DOCUMENT_BYTES + 1024,
            "unexpected test request size"
        );
        let mut request = vec![0; size];
        stream.read_exact(&mut request).await?;
        let mut fields = &request[1..];
        let mut response = Vec::new();
        // OpenSSH agent message tags identify key listing (11/12) and signing
        // (13/14). ssh-encoding owns the length-prefixed fields on this test peer.
        match request[0] {
            11 => {
                response.push(12);
                (keys.len() as u32).encode(&mut response)?;
                for key in &keys {
                    key.public_key().to_bytes()?.encode(&mut response)?;
                    "synthetic test key".encode(&mut response)?;
                }
            }
            13 => {
                let key_bytes = Vec::<u8>::decode(&mut fields)?;
                // The test peer admits the example's full document bound;
                // ssh-encoding's generic Vec decoder has a smaller limit.
                let message_len = u32::decode(&mut fields)? as usize;
                let (message, remaining) = fields
                    .split_at_checked(message_len)
                    .context("truncated test signing request")?;
                let message = message.to_vec();
                fields = remaining;
                ensure!(u32::decode(&mut fields)? == 0, "unexpected signing flags");
                ensure!(fields.is_empty(), "unexpected request suffix");
                let key = keys
                    .iter()
                    .find(|key| key.public_key().to_bytes().unwrap() == key_bytes)
                    .context("unexpected signing key")?;
                {
                    let mut observed = observed.lock().unwrap();
                    observed.requests += 1;
                    observed.messages.push(message.clone());
                }
                match reply {
                    Reply::Refused => response.push(5),
                    Reply::Oversized => {
                        stream.write_u32(256 * 1024 + 1).await?;
                        return Ok(());
                    }
                    Reply::Truncated => {
                        stream.write_u32(100).await?;
                        stream.write_all(&[14]).await?;
                        return Ok(());
                    }
                    Reply::Pending => {
                        std::future::pending::<()>().await;
                        unreachable!();
                    }
                    Reply::Valid | Reply::WrongKey | Reply::WrongAlgorithm => {
                        let key = if matches!(reply, Reply::WrongKey) {
                            native(&private(99))
                        } else {
                            native(key)
                        };
                        let signature: ed25519_dalek::Signature =
                            signature::Signer::try_sign(&key, &message)
                                .map_err(|_| anyhow::anyhow!("synthetic signing failed"))?;
                        let mut blob = Vec::new();
                        if matches!(reply, Reply::WrongAlgorithm) {
                            "ssh-rsa".encode(&mut blob)?;
                            signature.to_bytes().as_slice().encode(&mut blob)?;
                        } else {
                            let signature = ssh_key::Signature::new(
                                ssh_key::Algorithm::Ed25519,
                                signature.to_bytes(),
                            )?;
                            signature.encode(&mut blob)?;
                        }
                        response.push(14);
                        blob.encode(&mut response)?;
                    }
                }
            }
            _ => bail!("unexpected agent operation"),
        }
        stream.write_u32(response.len() as u32).await?;
        if let Err(error) = stream.write_all(&response).await {
            if error.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error.into());
        }
    }
}

async fn run_agent(
    connection: agent::Connection,
    keys: Vec<Candidate>,
    fingerprint: Option<Fingerprint>,
    payload: &[u8],
) -> (Result<()>, Vec<u8>) {
    let mut output = Vec::new();
    let result = run(
        Command::Sign {
            signer: Some(endpoint()),
            key_fingerprint: fingerprint,
            input: Input::Stdin,
            output: None,
        },
        |_| Ok(keys.clone()),
        |_| panic!("stdin must not fetch a document"),
        async move || Ok(connection),
        payload,
        &mut output,
        &mut io::sink(),
    )
    .await;
    (result, output)
}

#[tokio::test]
async fn selection_and_qualification_do_not_request_a_signature() {
    let key = private(41);
    let (connection, observed) = mock_agent(&[private(42), key.clone()], Reply::Valid);
    let (adapter, matched) = agent::AgentSigner::select(
        agent::Session::open(connection).await.unwrap(),
        Some(&candidates(&key)),
        None,
    )
    .unwrap();
    let _qualified = AsyncProviderSigningKeyBuilder::ed25519(&adapter, matched.key.as_bytes())
        .build()
        .unwrap();
    assert_eq!(observed.lock().unwrap().requests, 0);
    assert_eq!(matched.key, native(&key).verifying_key());
}

#[tokio::test]
async fn signing_requests_the_final_message_once() {
    let key = private(41);
    let (connection, observed) = mock_agent(std::slice::from_ref(&key), Reply::Valid);
    let (result, artifact) = run_agent(connection, candidates(&key), None, b"message: demo").await;
    result.unwrap();
    let observed = observed.lock().unwrap();
    assert_eq!(observed.requests, 1);
    assert_eq!(observed.messages, [b"message: demo\n".to_vec()]);
    assert_eq!(artifact, sign(b"message: demo", &key, Some(KEY_ID)));
}

#[tokio::test]
async fn multiple_matching_keys_require_explicit_selection() {
    let first = private(43);
    let second = private(44);
    let keys = [first.clone(), second.clone()];
    let mut public = candidates(&first);
    public.extend(candidates(&second));
    let (connection, observed) = mock_agent(&keys, Reply::Valid);
    let error = agent::AgentSigner::select(
        agent::Session::open(connection).await.unwrap(),
        Some(&public),
        None,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("multiple SSH-agent keys"));
    assert_eq!(observed.lock().unwrap().requests, 0);

    let (connection, observed) = mock_agent(&keys, Reply::Valid);
    let (result, artifact) = run_agent(
        connection,
        public,
        Some(second.fingerprint(HashAlg::Sha256)),
        PAYLOAD,
    )
    .await;
    result.unwrap();
    assert_eq!(observed.lock().unwrap().requests, 1);
    assert_eq!(artifact, sign(PAYLOAD, &second, Some(KEY_ID)));
}

#[tokio::test]
async fn missing_keys_and_fingerprints_do_not_sign() {
    let key = private(45);
    for available in [vec![], vec![private(46)], vec![key.clone()]] {
        let (connection, observed) = mock_agent(&available, Reply::Valid);
        let (result, output) = run_agent(
            connection,
            candidates(&key),
            Some(private(47).fingerprint(HashAlg::Sha256)),
            PAYLOAD,
        )
        .await;
        let expected = if available.is_empty() {
            "SSH agent has no identities"
        } else {
            "no SSH-agent Ed25519 key matches"
        };
        assert!(result.unwrap_err().to_string().contains(expected));
        assert!(output.is_empty());
        assert_eq!(observed.lock().unwrap().requests, 0);
    }
}

#[tokio::test]
async fn failed_agent_responses_never_emit_an_artifact_or_retry() {
    let key = private(48);
    for reply in [
        Reply::Refused,
        Reply::WrongKey,
        Reply::WrongAlgorithm,
        Reply::Oversized,
        Reply::Truncated,
    ] {
        let (connection, observed) = mock_agent(std::slice::from_ref(&key), reply);
        let (result, output) = run_agent(connection, candidates(&key), None, PAYLOAD).await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("SSH-agent signing failed")
        );
        assert!(output.is_empty());
        assert_eq!(observed.lock().unwrap().requests, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn agent_timeout_does_not_emit_or_retry() {
    let key = private(49);
    let (connection, observed) = mock_agent(std::slice::from_ref(&key), Reply::Pending);
    let (result, output) = run_agent(connection, candidates(&key), None, PAYLOAD).await;
    assert!(result.is_err());
    assert!(output.is_empty());
    assert_eq!(observed.lock().unwrap().requests, 1);
}

#[tokio::test(start_paused = true)]
async fn cancelled_requests_close_the_connection() {
    use yaml_sigil_signing::AsyncProviderSigner;
    let key = private(50);
    let (connection, observed) = mock_agent(std::slice::from_ref(&key), Reply::Pending);
    let (adapter, _) = agent::AgentSigner::select(
        agent::Session::open(connection).await.unwrap(),
        Some(&candidates(&key)),
        None,
    )
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), adapter.try_sign(PAYLOAD))
            .await
            .is_err()
    );
    assert!(adapter.try_sign(PAYLOAD).await.is_err());
    assert_eq!(observed.lock().unwrap().requests, 1);
}

#[tokio::test]
async fn missing_agent_socket_is_an_operation_error() {
    let directory = tempdir().unwrap();
    assert!(
        agent::connect_path(&directory.path().join("missing-agent"))
            .await
            .is_err()
    );
}

#[test]
fn cli_does_not_accept_private_key_files_and_requires_sha256_fingerprints() {
    assert!(
        Cli::try_parse_from([
            "github-keys",
            "sign",
            "--signer",
            SIGNER,
            "--input",
            "stdin",
            "--private-key",
            "key",
        ])
        .is_err()
    );
    assert!(parse_fingerprint("not a fingerprint").is_err());
    assert!(parse_fingerprint("MD5:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00").is_err());
    assert!(parse_fingerprint(&private(51).fingerprint(HashAlg::Sha256).to_string()).is_ok());
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires OpenSSH ssh-agent and ssh-add; uses an isolated agent and synthetic key"]
async fn openssh_agent_round_trip() -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    use std::time::Duration;

    struct IsolatedAgent(Child);
    impl Drop for IsolatedAgent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let directory = tempdir()?;
    let socket = directory.path().join("agent.sock");
    let key_path = directory.path().join("synthetic-key");
    let key = private(52);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)?
        .write_all(key.to_openssh(ssh_key::LineEnding::LF)?.as_bytes())?;
    let _agent = IsolatedAgent(
        ProcessCommand::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("isolated SSH agent did not start")?;
    let loaded = ProcessCommand::new("ssh-add")
        .arg("-q")
        .arg(&key_path)
        .env("SSH_AUTH_SOCK", &socket)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        loaded.status.success(),
        "could not load synthetic key into isolated agent"
    );
    let connection = agent::connect_path(&socket).await?;
    let (result, artifact) = run_agent(connection, candidates(&key), None, PAYLOAD).await;
    result?;
    let verified = verify_offline(&artifact, &export(&key).parse()?, |_| {
        panic!("direct key must not fetch")
    })?;
    assert_eq!(verified.payload, PAYLOAD);
    Ok(())
}

#[tokio::test]
async fn agent_only_commands_are_offline_and_verification_never_signs() {
    let first = private(60);
    let selected = private(61);
    for fingerprint in [None, Some(selected.fingerprint(HashAlg::Sha256))] {
        let (connection, observed) = mock_agent(
            &[first.clone(), selected.clone(), selected.clone()],
            Reply::Refused,
        );
        let artifact = sign(PAYLOAD, &selected, Some("https://ignored.example/key"));
        let mut stdout = Vec::new();
        let mut progress = Vec::new();
        run(
            Command::Verify {
                signer: None,
                key_fingerprint: fingerprint,
                input: Input::Stdin,
            },
            |_| panic!("agent mode must not query GitHub"),
            |_| panic!("stdin must not fetch input"),
            async move || Ok(connection),
            artifact.as_slice(),
            &mut stdout,
            &mut progress,
        )
        .await
        .unwrap();
        assert!(stdout.is_empty());
        assert_eq!(observed.lock().unwrap().requests, 0);
        assert!(
            String::from_utf8(progress)
                .unwrap()
                .contains(&selected.fingerprint(HashAlg::Sha256).to_string())
        );
    }
    for available in [
        vec![selected.clone(), selected.clone()],
        vec![first, selected.clone()],
    ] {
        let (connection, observed) = mock_agent(&available, Reply::Valid);
        let mut artifact = Vec::new();
        run(
            Command::Sign {
                signer: None,
                key_fingerprint: (available.len() > 1)
                    .then(|| selected.fingerprint(HashAlg::Sha256)),
                input: Input::Stdin,
                output: None,
            },
            |_| panic!("agent mode must not query GitHub"),
            |_| panic!("stdin must not fetch input"),
            async move || Ok(connection),
            PAYLOAD,
            &mut artifact,
            &mut io::sink(),
        )
        .await
        .unwrap();
        assert_eq!(artifact, sign(PAYLOAD, &selected, None));
        assert_eq!(observed.lock().unwrap().requests, 1);
    }
}

#[tokio::test]
async fn agent_selection_rejects_ambiguity_but_deduplicates_identities() {
    let first = private(62);
    for (available, success) in [
        (vec![first.clone(), first.clone()], true),
        (vec![first.clone(), private(63)], false),
    ] {
        let (connection, observed) = mock_agent(&available, Reply::Valid);
        let session = agent::Session::open(connection).await.unwrap();
        assert_eq!(
            agent::AgentSigner::select(session, None, None).is_ok(),
            success
        );
        assert_eq!(observed.lock().unwrap().requests, 0);
    }
}

#[tokio::test]
async fn explicit_signers_and_fingerprints_intersect_without_agent_fallback() {
    let selected = private(64);
    let other = private(65);
    for signer in [endpoint(), export(&other).parse().unwrap()] {
        for signing in [false, true] {
            let (connection, observed) = mock_agent(std::slice::from_ref(&selected), Reply::Valid);
            let command = if signing {
                Command::Sign {
                    signer: Some(signer.clone()),
                    key_fingerprint: Some(selected.fingerprint(HashAlg::Sha256)),
                    input: Input::Stdin,
                    output: None,
                }
            } else {
                Command::Verify {
                    signer: Some(signer.clone()),
                    key_fingerprint: Some(selected.fingerprint(HashAlg::Sha256)),
                    input: Input::Stdin,
                }
            };
            let artifact = sign(PAYLOAD, &selected, None);
            let mut stdout = Vec::new();
            let error = run(
                command,
                |_| Ok(candidates(&other)),
                |_| panic!("stdin must not fetch input"),
                async move || {
                    assert!(signing, "explicit verification must not access the agent");
                    Ok(connection)
                },
                if signing {
                    PAYLOAD
                } else {
                    artifact.as_slice()
                },
                &mut stdout,
                &mut io::sink(),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("matches the selected signer"));
            assert!(stdout.is_empty());
            assert_eq!(observed.lock().unwrap().requests, 0);
        }
    }
}

#[tokio::test]
async fn fingerprint_verification_works_without_an_agent_for_explicit_signers() {
    let selected = private(66);
    for signer in [endpoint(), export(&selected).parse().unwrap()] {
        for fingerprint in [
            selected.fingerprint(HashAlg::Sha256),
            private(67).fingerprint(HashAlg::Sha256),
        ] {
            let mut stdout = Vec::new();
            let artifact = sign(PAYLOAD, &selected, None);
            let result = run(
                Command::Verify {
                    signer: Some(signer.clone()),
                    key_fingerprint: Some(fingerprint),
                    input: Input::Stdin,
                },
                |_| Ok(candidates(&selected)),
                |_| panic!("stdin must not fetch input"),
                no_agent,
                artifact.as_slice(),
                &mut stdout,
                &mut io::sink(),
            )
            .await;
            assert_eq!(
                result.is_ok(),
                fingerprint == selected.fingerprint(HashAlg::Sha256)
            );
            assert!(stdout.is_empty());
        }
    }
}

#[tokio::test]
async fn unavailable_agents_fail_before_reading_input_or_fetching_keys() {
    for command in [
        Command::Sign {
            signer: Some(endpoint()),
            key_fingerprint: None,
            input: RAW_URL.parse().unwrap(),
            output: None,
        },
        Command::Sign {
            signer: None,
            key_fingerprint: None,
            input: Input::Stdin,
            output: None,
        },
        Command::Verify {
            signer: None,
            key_fingerprint: None,
            input: RAW_URL.parse().unwrap(),
        },
    ] {
        let mut stdout = Vec::new();
        let error = run(
            command,
            |_| panic!("unavailable agent must precede GitHub lookup"),
            |_| panic!("unavailable agent must precede input fetch"),
            async || bail!("agent unavailable"),
            FailedRead,
            &mut stdout,
            &mut io::sink(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "agent unavailable");
        assert!(stdout.is_empty());
    }
}

#[tokio::test]
async fn empty_unsupported_and_mixed_agent_identity_lists() {
    let unsupported = PrivateKey::random(
        &mut rand::rng(),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    for (available, expected) in [
        (vec![], "no identities"),
        (vec![unsupported.clone()], "no supported ordinary Ed25519"),
    ] {
        let (connection, observed) = mock_agent(&available, Reply::Valid);
        let error = agent::Session::open(connection).await.err().unwrap();
        assert!(error.to_string().contains(expected));
        assert_eq!(observed.lock().unwrap().requests, 0);
    }
    let key = private(68);
    let (connection, observed) = mock_agent(&[unsupported, key.clone(), key], Reply::Valid);
    let session = agent::Session::open(connection).await.unwrap();
    assert_eq!(session.candidates().len(), 1);
    assert!(agent::AgentSigner::select(session, None, None).is_ok());
    assert_eq!(observed.lock().unwrap().requests, 0);
}

#[tokio::test(start_paused = true)]
async fn identity_listing_timeouts_and_malformed_replies_fail_before_selection() {
    let (client, mut peer) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        assert_eq!(peer.read_u32().await.unwrap(), 1);
        assert_eq!(peer.read_u8().await.unwrap(), 11);
        std::future::pending::<()>().await;
    });
    let error = agent::Session::open(AgentClient::connect(client).dynamic())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("key listing timed out"));
    server.abort();

    let (client, mut peer) = tokio::io::duplex(64);
    let server = tokio::spawn(async move {
        assert_eq!(peer.read_u32().await.unwrap(), 1);
        assert_eq!(peer.read_u8().await.unwrap(), 11);
        peer.write_u32(1).await.unwrap();
        peer.write_u8(12).await.unwrap(); // Identity answer missing its count.
    });
    let error = agent::Session::open(AgentClient::connect(client).dynamic())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("could not list SSH-agent keys"));
    server.await.unwrap();
}

#[tokio::test]
async fn agent_only_fingerprint_mismatches_never_sign_or_verify() {
    let key = private(69);
    let absent = private(70).fingerprint(HashAlg::Sha256);
    for signing in [false, true] {
        let (connection, observed) = mock_agent(std::slice::from_ref(&key), Reply::Valid);
        let command = if signing {
            Command::Sign {
                signer: None,
                key_fingerprint: Some(absent),
                input: Input::Stdin,
                output: None,
            }
        } else {
            Command::Verify {
                signer: None,
                key_fingerprint: Some(absent),
                input: Input::Stdin,
            }
        };
        let mut output = Vec::new();
        let artifact = sign(PAYLOAD, &key, None);
        let error = run(
            command,
            |_| panic!("agent mode must not query GitHub"),
            |_| panic!("stdin must not fetch input"),
            async move || Ok(connection),
            if signing {
                PAYLOAD
            } else {
                artifact.as_slice()
            },
            &mut output,
            &mut io::sink(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("fingerprint"));
        assert!(output.is_empty());
        assert_eq!(observed.lock().unwrap().requests, 0);
    }
}
