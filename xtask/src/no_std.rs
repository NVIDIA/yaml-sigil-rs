// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Isolated consumer validation without workspace feature unification.

use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use clap::Args;

#[derive(Args, Debug)]
pub(crate) struct NoStdArgs {
    /// Bare-metal target, installed separately with rustup target add.
    #[arg(long, default_value = "thumbv7em-none-eabi")]
    target: String,
    /// Toolchains to validate, including the workspace MSRV.
    #[arg(long, value_delimiter = ',', default_value = "1.95.0,1.98.0")]
    toolchains: Vec<String>,
}

pub(crate) fn run(root: &Path, args: NoStdArgs) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let target_dir = temporary.path().join("target");
    for toolchain in &args.toolchains {
        for features in ["", "alloc", "yaml", "protobuf", "yaml,protobuf"] {
            let command = |operation: &str, target: Option<&str>| {
                let mut command = Command::new("cargo");
                command
                    .current_dir(root)
                    .arg(format!("+{toolchain}"))
                    .arg(operation)
                    .args([
                        "--manifest-path",
                        "tests/no-std/Cargo.toml",
                        "--no-default-features",
                        "--lib",
                        "--target-dir",
                    ])
                    .arg(&target_dir);
                if !features.is_empty() {
                    command.args(["--features", features]);
                }
                if let Some(target) = target {
                    command.args(["--target", target]);
                }
                command
            };
            crate::require_success(
                crate::run(command("check", Some(&args.target)))?,
                "no_std target check",
            )?;
            crate::require_success(crate::run(command("test", None))?, "no_std consumer tests")?;
            inspect_features(root, toolchain, features)?;
        }
        inspect_features(root, toolchain, "bare")?;
        let binary = |features: &str| {
            let mut command = Command::new("cargo");
            command
                .current_dir(root)
                .arg(format!("+{toolchain}"))
                .args([
                    "build",
                    "--manifest-path",
                    "tests/no-std/Cargo.toml",
                    "--no-default-features",
                    "--bin",
                    "allocator-free",
                    "--features",
                    features,
                    "--target",
                    &args.target,
                    "--target-dir",
                ])
                .arg(&target_dir);
            command
        };
        crate::require_success(crate::run(binary("bare"))?, "allocator-free link")?;
        let mut negative = binary("bare,alloc");
        let output = crate::bounded_process::output(
            &mut negative,
            crate::bounded_process::VALIDATION_OUTPUT_LIMITS,
        )?;
        ensure!(
            !output.status.success()
                && String::from_utf8_lossy(&output.stderr).contains("global memory allocator"),
            "allocator link negative control did not detect the missing allocator"
        );
    }
    Ok(())
}

fn inspect_features(root: &Path, toolchain: &str, features: &str) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(root)
        .arg(format!("+{toolchain}"))
        .args([
            "tree",
            "--manifest-path",
            "tests/no-std/Cargo.toml",
            "--no-default-features",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
        ]);
    if !features.is_empty() {
        command.args(["--features", features]);
    }
    let output = crate::bounded_process::output(
        &mut command,
        crate::bounded_process::VALIDATION_OUTPUT_LIMITS,
    )?;
    crate::require_success(output.status, "no_std dependency features")?;
    let graph = std::str::from_utf8(&output.stdout)?;
    for line in graph.lines() {
        let (_, enabled) = line.split_once('|').unwrap_or((line, ""));
        let enabled = enabled.trim_end_matches(" (*)").trim();
        ensure!(
            !enabled.split(',').any(|feature| feature == "std"),
            "normal dependency enables std: {line}"
        );
        if features.is_empty() || features == "bare" {
            ensure!(
                !enabled.split(',').any(|feature| feature == "alloc"),
                "allocator-free dependency enables alloc: {line}"
            );
        }
        if !features.contains("protobuf") {
            ensure!(
                !line.starts_with("buffa "),
                "YAML-only consumer includes Buffa"
            );
        }
        if !features.contains("yaml") {
            ensure!(
                !line.starts_with("noyalib "),
                "protobuf-only consumer includes the YAML parser"
            );
        }
        ensure!(
            !line.starts_with("getrandom ") && !line.starts_with("tracing "),
            "no_std consumer includes a hosted dependency: {line}"
        );
    }
    Ok(())
}
