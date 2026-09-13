// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Input and transcript helpers for examples that sign YAML documents.
//!
//! These are example scaffolding, not library APIs. An unrelated CLI example
//! can keep its own format and options instead of adopting this transcript.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

pub(crate) const DEFAULT_PAYLOAD: &str =
    "example: default\nmessage: This is the default YAML document.\n";

#[derive(clap::Args)]
pub(crate) struct PayloadArgs {
    /// Read YAML from FILE, or use 'stdin' for standard input. Omit for the default document.
    #[arg(long, value_name = "FILE")]
    payload: Option<PathBuf>,
}

impl PayloadArgs {
    pub(crate) fn read_and_print(
        &self,
        mut stdin: impl Read,
        output: &mut impl Write,
    ) -> Result<String> {
        // --payload identifies a source, never inline YAML. 'stdin' reads to
        // EOF; './stdin' names a file with that basename. Require UTF-8 and
        // propagate input errors, so a typo never signs the default instead.
        let (payload, title) = match &self.payload {
            None => (
                DEFAULT_PAYLOAD.to_owned(),
                "Unsigned YAML document (default)",
            ),
            Some(path) if path.as_os_str() == "stdin" => {
                let mut payload = String::new();
                stdin
                    .read_to_string(&mut payload)
                    .context("could not read YAML from stdin")?;
                (payload, "Unsigned YAML document (stdin)")
            }
            Some(path) => (
                fs::read_to_string(path)
                    .with_context(|| format!("could not read YAML file {}", path.display()))?,
                "Unsigned YAML document (file)",
            ),
        };
        print_section(output, title, &payload)?;
        Ok(payload)
    }
}

// These headings delimit a terminal transcript, not a complete YAML stream.
// '=' distinguishes them from YAML document markers ('---', '...') and '#'
// comments. Copy the final section's body to obtain the signed artifact.
pub(crate) fn print_section(output: &mut impl Write, title: &str, yaml: &str) -> Result<()> {
    writeln!(output, "====== {title} ======")?;
    output.write_all(yaml.as_bytes())?;
    if !yaml.ends_with('\n') {
        writeln!(output)?;
    }
    Ok(())
}

pub(crate) fn print_public_key(
    output: &mut impl Write,
    provider: &str,
    key_type: &str,
    public_key: &[u8],
) -> Result<()> {
    // Provider and key labels are fixed strings in the calling examples.
    // Base64 is tidy for a terminal and preserves the exact public encoding.
    print_section(
        output,
        "Generated public key",
        &format!(
            "provider: {provider}\nkey_type: {key_type}\npublic_key_encoding: base64\npublic_key: \"{}\"\n",
            BASE64.encode(public_key),
        ),
    )
}

pub(crate) fn print_verification(
    output: &mut impl Write,
    mode: &str,
    qualification_note: Option<&str>,
) -> Result<()> {
    print_section(
        output,
        "Verification",
        &format!("signature: verified\nprovider_verification: {mode}\n"),
    )?;
    if let Some(note) = qualification_note {
        writeln!(output, "qualification_note: {note}")?;
    }
    Ok(())
}

pub(crate) fn print_signed(output: &mut impl Write, artifact: &[u8]) -> Result<()> {
    // Preserve the returned artifact instead of reserializing it. Its
    // signature document belongs in the output; no private key is printed.
    let artifact = std::str::from_utf8(artifact).context("signed YAML artifact was not UTF-8")?;
    print_section(output, "Signed YAML artifact", artifact)
}
