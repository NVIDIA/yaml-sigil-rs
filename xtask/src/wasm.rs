// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use tempfile::{Builder, TempDir};

use super::{
    WASM_PACK_INSTALL, WASM_TARGET_INSTALL, require_success, require_tool, run as run_command,
};

const TOOLCHAIN: &str = "1.95.0";
const TARGET: &str = "wasm32-unknown-unknown";
const WASM_PACK_VERSION: &str = "0.15.0";
const WASM_CRATE: &str = "crates/yaml-sigil-wasm";
const RUNTIME_PACKAGES: &[&str] = &[
    "yaml-sigil-core",
    "yaml-sigil-transcription",
    "yaml-sigil-signing",
    "yaml-sigil-verification",
];

pub(super) fn run(root: &Path) -> Result<()> {
    require_prerequisites()?;
    ensure_no_workspace_wasm(root)?;

    let temp = Builder::new()
        .prefix("yaml-sigil-wasm-")
        .tempdir()
        .context("create temporary WASM validation directory")?;
    make_browser_accessible(&temp)?;
    prepare_firefox(&temp)?;

    for package in RUNTIME_PACKAGES {
        run_cargo(
            root,
            &temp,
            ["check", "--target", TARGET, "--package", package],
            &format!("check {package} for {TARGET}"),
        )?;
    }
    run_cargo(
        root,
        &temp,
        ["check", "--target", TARGET, "--package", "yaml-sigil-wasm"],
        "check yaml-sigil-wasm default features",
    )?;
    run_cargo(
        root,
        &temp,
        [
            "check",
            "--target",
            TARGET,
            "--package",
            "yaml-sigil-wasm",
            "--features",
            "json-schema-validate",
        ],
        "check yaml-sigil-wasm with embedded schema",
    )?;

    run_isolated(
        root,
        &temp,
        "wasm-pack",
        [
            "test",
            "--node",
            WASM_CRATE,
            "--features",
            "json-schema-validate",
        ],
        "run WASM tests in Node.js",
    )?;
    if let Err(first_error) = run_firefox_tests(root, &temp) {
        eprintln!("Headless Firefox failed once ({first_error:#}); retrying once.");
        run_firefox_tests(root, &temp)?;
    }

    let default_size = build_and_measure(root, &temp, "default", None)?;
    let schema_size = build_and_measure(
        root,
        &temp,
        "json-schema-validate",
        Some("json-schema-validate"),
    )?;
    eprintln!(
        "Optimized web WASM sizes (raw bytes; Rust {TOOLCHAIN}; wasm-pack {WASM_PACK_VERSION}):"
    );
    eprintln!("  default: {default_size}");
    eprintln!("  json-schema-validate: {schema_size}");

    drop(temp);
    ensure_no_workspace_wasm(root)
}

#[cfg(unix)]
fn make_browser_accessible(temp: &TempDir) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
        .context("make temporary WASM directory traversable by the browser sandbox")
}

#[cfg(not(unix))]
fn make_browser_accessible(_temp: &TempDir) -> Result<()> {
    Ok(())
}

fn require_prerequisites() -> Result<()> {
    let wasm_pack = require_tool("wasm-pack", WASM_PACK_INSTALL)?;
    let output = Command::new(&wasm_pack)
        .arg("--version")
        .output()
        .context("run wasm-pack --version")?;
    ensure!(output.status.success(), "wasm-pack --version failed");
    let version = String::from_utf8_lossy(&output.stdout);
    ensure!(
        version.trim() == format!("wasm-pack {WASM_PACK_VERSION}"),
        "wasm-pack {WASM_PACK_VERSION} is required; install it with `{WASM_PACK_INSTALL}`"
    );

    let node = require_tool("node", "install Node.js 20 or newer and put it on PATH")?;
    let output = Command::new(&node)
        .arg("--version")
        .output()
        .context("run node --version")?;
    ensure!(output.status.success(), "node --version failed");
    let version = String::from_utf8_lossy(&output.stdout);
    let major = version
        .trim()
        .strip_prefix('v')
        .and_then(|value| value.split('.').next())
        .and_then(|value| value.parse::<u32>().ok())
        .context("parse node --version output")?;
    ensure!(
        major >= 20,
        "Node.js 20 or newer is required; found {}",
        version.trim()
    );

    require_tool("firefox", "install Firefox and put it on PATH")?;
    let rustup = require_tool("rustup", WASM_TARGET_INSTALL)?;
    let output = Command::new(rustup)
        .args(["target", "list", "--toolchain", TOOLCHAIN, "--installed"])
        .output()
        .context("list installed Rust targets")?;
    ensure!(output.status.success(), "rustup target list failed");
    ensure!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim() == TARGET),
        "{TARGET} for Rust {TOOLCHAIN} is required; install it with `{WASM_TARGET_INSTALL}`"
    );
    Ok(())
}

fn prepare_firefox(temp: &TempDir) -> Result<()> {
    #[cfg(unix)]
    if tool_works(
        Path::new("/snap/firefox/current/usr/lib/firefox/firefox"),
        "--version",
    ) {
        return prepare_snap_firefox(temp);
    }

    let firefox = require_tool("firefox", "install Firefox and put it on PATH")?;
    if tool_works(&firefox, "--version") {
        return Ok(());
    }

    bail!(
        "{} is present but cannot start; install a working Firefox binary",
        firefox.display()
    )
}

#[cfg(unix)]
fn prepare_snap_firefox(temp: &TempDir) -> Result<()> {
    use std::os::unix::fs::symlink;

    let firefox = Path::new("/snap/firefox/current/usr/lib/firefox/firefox");
    ensure!(
        tool_works(firefox, "--version"),
        "the direct Snap Firefox binary is unavailable"
    );
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).context("create temporary browser shim directory")?;
    symlink(firefox, bin.join("firefox")).context("create temporary Firefox shim")
}

fn tool_works(path: &Path, argument: &str) -> bool {
    Command::new(path)
        .arg(argument)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn run_cargo(
    root: &Path,
    temp: &TempDir,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    context: &str,
) -> Result<()> {
    run_isolated(root, temp, "cargo", args, context)
}

fn run_firefox_tests(root: &Path, temp: &TempDir) -> Result<()> {
    run_isolated(
        root,
        temp,
        "wasm-pack",
        [
            "test",
            "--release",
            "--headless",
            "--firefox",
            WASM_CRATE,
            "--features",
            "json-schema-validate,browser-tests",
        ],
        "run WASM tests in headless Firefox",
    )
}

fn run_isolated(
    root: &Path,
    temp: &TempDir,
    program: &str,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    context: &str,
) -> Result<()> {
    let mut command = Command::new(program);
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", temp.path().join("target"))
        .env("RUSTUP_TOOLCHAIN", TOOLCHAIN)
        .args(args);
    prepend_temporary_bin(&mut command, temp)?;
    require_success(run_command(command)?, context)
}

fn prepend_temporary_bin(command: &mut Command, temp: &TempDir) -> Result<()> {
    let bin = temp.path().join("bin");
    if !bin.is_dir() {
        return Ok(());
    }
    let mut paths = vec![bin];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    let path = std::env::join_paths(paths).context("construct PATH with temporary browser shim")?;
    command.env("PATH", path);
    Ok(())
}

fn build_and_measure(
    root: &Path,
    temp: &TempDir,
    label: &str,
    feature: Option<&str>,
) -> Result<u64> {
    let out_dir = temp.path().join("web").join(label);
    let mut args = vec![
        "build".to_string(),
        "--target".to_string(),
        "web".to_string(),
        "--release".to_string(),
        "--no-pack".to_string(),
        "--out-dir".to_string(),
        out_dir.display().to_string(),
        WASM_CRATE.to_string(),
    ];
    if let Some(feature) = feature {
        args.extend(["--features".to_string(), feature.to_string()]);
    }
    run_isolated(
        root,
        temp,
        "wasm-pack",
        &args,
        &format!("build optimized {label} web WASM"),
    )?;
    wasm_file_size(&out_dir)
}

fn wasm_file_size(out_dir: &Path) -> Result<u64> {
    let mut matches = Vec::new();
    for entry in
        std::fs::read_dir(out_dir).with_context(|| format!("read {}", out_dir.display()))?
    {
        let path = entry?.path();
        if path.extension() == Some(OsStr::new("wasm")) {
            matches.push(path);
        }
    }
    ensure!(
        matches.len() == 1,
        "expected one .wasm file under {}, found {}",
        out_dir.display(),
        matches.len()
    );
    Ok(std::fs::metadata(&matches[0])?.len())
}

fn ensure_no_workspace_wasm(root: &Path) -> Result<()> {
    let mut matches = Vec::new();
    collect_wasm_files(root, &mut matches)?;
    if matches.is_empty() {
        Ok(())
    } else {
        let paths = matches
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("executable WebAssembly must not be retained in the workspace: {paths}")
    }
}

fn collect_wasm_files(dir: &Path, matches: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name() == Some(OsStr::new(".git")) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_wasm_files(&path, matches)?;
        } else if file_type.is_file() && path.extension() == Some(OsStr::new("wasm")) {
            matches.push(path);
        }
    }
    Ok(())
}
