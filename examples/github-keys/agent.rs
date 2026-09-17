// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Example-owned SSH-agent access. `russh` handles the agent protocol; the
//! adapter implements YamlSigil's public asynchronous signing contract.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::ssh_key::{Algorithm, Fingerprint, PublicKey};
use tokio::sync::Mutex;
use tokio::time::timeout;
use yaml_sigil_signing::AsyncProviderSigner;

use super::keys::Candidate;

pub(super) type Connection = AgentClient<Box<dyn AgentStream + Send + Unpin>>;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn connect() -> Result<Connection> {
    let socket = std::env::var_os("SSH_AUTH_SOCK").filter(|value| !value.is_empty());
    #[cfg(windows)]
    let socket = socket.unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".into());
    #[cfg(not(windows))]
    let socket = socket.context(
        "SSH_AUTH_SOCK is not set; start an SSH agent and load your demo key with ssh-add",
    )?;
    connect_path(&PathBuf::from(socket)).await
}

pub(super) async fn connect_path(path: &Path) -> Result<Connection> {
    #[cfg(unix)]
    let connection = AgentClient::connect_uds(path);
    #[cfg(windows)]
    let connection = AgentClient::connect_named_pipe(path);
    timeout(REQUEST_TIMEOUT, connection)
        .await
        .context("SSH-agent connection timed out")?
        .map(AgentClient::dynamic)
        .context("could not connect to the SSH agent")
}

// List identities once, before reading input or fetching account keys. Holding
// the connection keeps signing tied to the agent whose identities we checked.
pub(super) struct Session {
    connection: Connection,
    identities: Vec<(PublicKey, Candidate)>,
}

impl Session {
    pub(super) async fn open(mut connection: Connection) -> Result<Self> {
        let identities = timeout(REQUEST_TIMEOUT, connection.request_identities())
            .await
            .context("SSH-agent key listing timed out")?
            .context("could not list SSH-agent keys")?;
        ensure!(
            !identities.is_empty(),
            "SSH agent has no identities; load your demo key with ssh-add"
        );
        let mut supported = Vec::new();
        for identity in identities {
            let AgentIdentity::PublicKey { key, .. } = identity else {
                continue;
            };
            if let Some(candidate) = Candidate::from_public(&key)?
                && !supported
                    .iter()
                    .any(|(_, known): &(PublicKey, Candidate)| known.key == candidate.key)
            {
                supported.push((key, candidate));
            }
        }
        ensure!(
            !supported.is_empty(),
            "SSH agent has no supported ordinary Ed25519 keys; load your demo key with ssh-add"
        );
        Ok(Self {
            connection,
            identities: supported,
        })
    }

    pub(super) fn candidates(&self) -> Vec<Candidate> {
        self.identities
            .iter()
            .map(|(_, candidate)| candidate.clone())
            .collect()
    }
}

// Each adapter owns one connection and one immutable public-key binding. It
// never imports, unlocks, adds, or removes private keys. Configure the agent
// outside the example; verification never creates this adapter.
pub(super) struct AgentSigner {
    connection: Mutex<Option<Connection>>,
    public_key: PublicKey,
}

impl AgentSigner {
    pub(super) fn select(
        session: Session,
        candidates: Option<&[Candidate]>,
        fingerprint: Option<Fingerprint>,
    ) -> Result<(Self, Candidate)> {
        let mut matched: Option<(PublicKey, Candidate)> = None;
        for (key, public) in session.identities {
            // An explicit signer restricts the set; it never supplies a fallback.
            let candidate = match candidates {
                Some(candidates) => candidates
                    .iter()
                    .find(|candidate| candidate.key == public.key),
                None => Some(&public),
            };
            let Some(candidate) = candidate
                .filter(|candidate| fingerprint.is_none_or(|value| candidate.fingerprint == value))
            else {
                continue;
            };
            if let Some((_, previous)) = &matched {
                ensure!(
                    previous.key == candidate.key,
                    "multiple SSH-agent keys match this signer; select one with --key-fingerprint SHA256:... or use --signer with an explicit public key"
                );
            } else {
                matched = Some((key, candidate.clone()));
            }
        }
        let Some((public_key, candidate)) = matched else {
            bail!(
                "no SSH-agent Ed25519 key matches the selected signer and fingerprint; load the matching demo key with ssh-add"
            );
        };
        Ok((
            Self {
                connection: Mutex::new(Some(session.connection)),
                public_key,
            },
            candidate,
        ))
    }
}

impl AsyncProviderSigner for AgentSigner {
    async fn try_sign<'a>(&'a self, message: &'a [u8]) -> Result<[u8; 64], signature::Error> {
        let mut slot = self.connection.lock().await;
        // Taking the connection closes it on failure or cancellation. A later
        // call cannot consume a late response as though it were its own.
        let mut connection = slot.take().ok_or_else(signature::Error::new)?;
        // Forward exactly the final message bytes supplied by YamlSigil. No
        // prehash or SSHSIG envelope is added. The agent owns any confirmation.
        let signature = timeout(
            REQUEST_TIMEOUT,
            connection.sign_request_signature(&self.public_key, None, message),
        )
        .await
        .map_err(|_| signature::Error::new())?
        .map_err(|_| signature::Error::new())?;
        if signature.algorithm() != Algorithm::Ed25519 {
            return Err(signature::Error::new());
        }
        let bytes = signature
            .as_bytes()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        *slot = Some(connection);
        // The qualified builder in main.rs independently checks these 64
        // bytes against the bound public key before an artifact is emitted.
        Ok(bytes)
    }
}
