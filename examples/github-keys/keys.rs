// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared public-key decoding and selection, independent of GitHub discovery.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use russh::keys::ssh_key::{Fingerprint, HashAlg, PublicKey};
use yaml_sigil_verification::resolve_ed25519_verifying_key;

#[derive(Clone)]
pub(super) struct Candidate {
    pub(super) key: VerifyingKey,
    pub(super) fingerprint: Fingerprint,
    // Set only by discovery, never from an artifact's untrusted keyid hint.
    pub(super) source: Option<String>,
}

impl Candidate {
    pub(super) fn from_public(public: &PublicKey) -> Result<Option<Self>> {
        let Some(ed25519) = public.key_data().ed25519() else {
            // Certificates and security-key forms are distinct SSH algorithms.
            return Ok(None);
        };
        // The SSH blob contains more than the point. Decode it before applying
        // the library's Ed25519 admissibility checks to the extracted bytes.
        Ok(Some(Self {
            key: resolve_ed25519_verifying_key(ed25519.as_ref())?,
            fingerprint: public.fingerprint(HashAlg::Sha256),
            source: None,
        }))
    }
}

pub(super) fn filter_fingerprint(
    mut candidates: Vec<Candidate>,
    fingerprint: Option<Fingerprint>,
) -> Result<Vec<Candidate>> {
    candidates.retain(|candidate| fingerprint.is_none_or(|value| candidate.fingerprint == value));
    ensure!(
        !candidates.is_empty(),
        "no Ed25519 key matches the selected signer and fingerprint"
    );
    Ok(candidates)
}

// This also reads the offline fixture's OpenSSH public-key snapshot. API key
// fields have already been checked to contain exactly one nonempty line each.
pub(super) fn parse_export(export: &str) -> Result<Vec<Candidate>> {
    let candidates = parse_candidates(export)?;
    ensure!(!candidates.is_empty(), "no supported Ed25519 public keys");
    Ok(candidates)
}

pub(super) fn parse_candidates(export: &str) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    for (index, line) in export.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let public = PublicKey::from_openssh(line).map_err(|error| {
            anyhow::anyhow!("malformed OpenSSH key on line {}: {error}", index + 1)
        })?;
        if let Some(candidate) = Candidate::from_public(&public)
            .with_context(|| format!("inadmissible Ed25519 key on line {}", index + 1))?
            && !candidates
                .iter()
                .any(|known: &Candidate| known.key == candidate.key)
        {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}
