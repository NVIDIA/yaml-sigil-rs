// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Example-owned byte input. Document URLs are separate from key discovery.

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use ureq::http::{Response, StatusCode, Uri};

// An example-level document cap.
pub(super) const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(super) enum Input {
    File(PathBuf),
    Stdin,
    Url(Uri),
}

impl FromStr for Input {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value == "stdin" {
            return Ok(Self::Stdin);
        }
        if value.contains("://") {
            let uri: Uri = value.parse().context("invalid input URL")?;
            ensure!(
                matches!(uri.scheme_str(), Some("http" | "https"))
                    && uri.host().is_some()
                    && uri
                        .authority()
                        .is_some_and(|part| !part.as_str().contains('@'))
                    && !value.contains('#'),
                "input URL must use HTTP or HTTPS without embedded credentials or a fragment"
            );
            return Ok(Self::Url(uri));
        }
        Ok(Self::File(value.into()))
    }
}

impl Input {
    pub(super) fn read(
        &self,
        stdin: impl Read,
        fetch: impl FnOnce(&Uri) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        match self {
            Self::File(path) => {
                let file = fs::File::open(path)
                    .with_context(|| format!("could not open {}", path.display()))?;
                read_limited(file).with_context(|| format!("could not read {}", path.display()))
            }
            Self::Stdin => read_limited(stdin).context("could not read stdin"),
            Self::Url(uri) => fetch(uri),
        }
    }
}

pub(super) fn fetch(uri: &Uri) -> Result<Vec<u8>> {
    // The caller selects this document URL. It never chooses the signer or
    // changes the fixed GitHub key endpoint. Read anonymously without redirects.
    let response = ureq::Agent::config_builder()
        .max_redirects(0)
        .max_redirects_will_error(true)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .new_agent()
        .get(uri.clone())
        .header("User-Agent", "yaml-sigil-github-keys-example")
        .call()
        .context("could not fetch input document")?;
    read_response(response)
}

pub(super) fn read_response(mut response: Response<ureq::Body>) -> Result<Vec<u8>> {
    ensure!(
        response.status() == StatusCode::OK,
        "input lookup returned HTTP {}",
        response.status()
    );
    read_limited(response.body_mut().as_reader()).context("could not read input document")
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>> {
    // Read one overflow byte to reject oversized input without truncating it.
    // Preserve bytes; parsing and final-newline policy belong to the library.
    let mut bytes = Vec::new();
    reader
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "input document exceeds the {MAX_DOCUMENT_BYTES}-byte example limit"
    );
    Ok(bytes)
}
