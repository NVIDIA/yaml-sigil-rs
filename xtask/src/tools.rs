// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Selected-operation tool discovery and launch diagnostics.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::bounded_process::{self, OutputLimits};

fn which_in_path(program: &str, path: &OsStr, executable_suffix: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !executable_suffix.is_empty() && !program.ends_with(executable_suffix) {
            let candidate = dir.join(format!("{program}{executable_suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn which(program: &str, guidance: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    which_in_path(program, &path, std::env::consts::EXE_SUFFIX)
        .with_context(|| format!("{program} is missing from PATH; install it with `{guidance}`"))
}

pub(crate) fn require_tool(program: &str, guidance: &str) -> Result<PathBuf> {
    let executable = which(program, guidance)?;
    probe(&executable, &["--version"], program, guidance)?;
    Ok(executable)
}

pub(crate) fn require_cargo_tool(subcommand: &str, guidance: &str) -> Result<()> {
    which(&format!("cargo-{subcommand}"), guidance)?;
    let cargo = which("cargo", "install Rust from https://rustup.rs/")?;
    probe(&cargo, &[subcommand, "--version"], subcommand, guidance)
}

pub(crate) fn probe(path: &Path, args: &[&str], label: &str, guidance: &str) -> Result<()> {
    let mut command = Command::new(path);
    command.args(args);
    let output = bounded_process::output(
        &mut command,
        OutputLimits {
            stdout: 16 * 1024,
            stderr: 16 * 1024,
        },
    )
    .with_context(|| {
        format!("{label} is installed but unusable; repair it or install with `{guidance}`")
    })?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        let diagnostic = diagnostic.trim();
        bail!(
            "{label} is installed but unusable ({}): {diagnostic}; repair it or install with `{guidance}`",
            output.status
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_names_its_install_command() {
        let message = require_tool(
            "yaml-sigil-deliberately-missing-tool",
            "cargo install example",
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("missing from PATH"));
        assert!(message.contains("cargo install example"));
    }

    #[test]
    fn lookup_honors_platform_executable_suffix() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("cargo-example.exe");
        std::fs::write(&executable, b"fixture").unwrap();
        let path = std::env::join_paths([root.path()]).unwrap();
        assert_eq!(
            which_in_path("cargo-example", &path, ".exe"),
            Some(executable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn failing_and_unlaunchable_tools_are_unusable_not_missing() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("tool");
        std::fs::write(
            &executable,
            b"#!/bin/sh\necho missing-runtime-library >&2\nexit 7\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let message = probe(&executable, &["--version"], "tool", "cargo install example")
            .unwrap_err()
            .to_string();
        assert!(message.contains("installed but unusable"));
        assert!(message.contains("missing-runtime-library"));
        assert!(message.contains("cargo install example"));

        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        let message = probe(&executable, &["--version"], "tool", "cargo install example")
            .unwrap_err()
            .to_string();
        assert!(message.contains("installed but unusable"));
    }
}
