// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local browser-boundary validation with ephemeral executable output.

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
const GENERATED_API_SMOKE: &str = "crates/yaml-sigil-wasm/tests/generated_api.cjs";
const GENERATED_NODE_MODULE: &str = "yaml_sigil_wasm.js";
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
        .context("create temporary WebAssembly validation directory")?;

    let validation = run_in_temporary_directory(root, &temp);
    let cleanup = temp
        .close()
        .context("remove temporary WebAssembly validation directory");
    let validation = preserve_primary_error(validation, cleanup, "temporary cleanup also failed");
    preserve_primary_error(
        validation,
        ensure_no_workspace_wasm(root),
        "workspace artifact check also failed",
    )
}

fn run_in_temporary_directory(root: &Path, temp: &TempDir) -> Result<()> {
    make_browser_accessible(temp)?;
    prepare_firefox(temp)?;

    for package in RUNTIME_PACKAGES {
        run_isolated(
            root,
            temp,
            "cargo",
            ["check", "--target", TARGET, "--package", package],
            &format!("check {package} for {TARGET}"),
        )?;
    }
    run_isolated(
        root,
        temp,
        "cargo",
        ["check", "--target", TARGET, "--package", "yaml-sigil-wasm"],
        "check yaml-sigil-wasm default features",
    )?;
    run_isolated(
        root,
        temp,
        "cargo",
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
        temp,
        "wasm-pack",
        [
            "test",
            "--node",
            WASM_CRATE,
            "--features",
            "json-schema-validate",
        ],
        "run WebAssembly tests in Node.js",
    )?;
    run_generated_api_smoke(root, temp)?;
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
        "run WebAssembly tests in headless Firefox",
    )
}

fn run_generated_api_smoke(root: &Path, temp: &TempDir) -> Result<()> {
    let out_dir = temp.path().join("node-generated-api");
    let out_dir_string = out_dir.display().to_string();
    run_isolated(
        root,
        temp,
        "wasm-pack",
        [
            "build",
            "--target",
            "nodejs",
            "--release",
            "--no-pack",
            "--out-dir",
            &out_dir_string,
            WASM_CRATE,
        ],
        "build generated Node.js API",
    )?;

    let module = out_dir.join(GENERATED_NODE_MODULE);
    ensure!(
        module.is_file(),
        "generated Node.js module is missing: {}",
        module.display()
    );
    let script = root.join(GENERATED_API_SMOKE);
    ensure!(
        script.is_file(),
        "generated API smoke test is missing: {}",
        script.display()
    );
    run_isolated(
        root,
        temp,
        "node",
        [script.as_os_str(), module.as_os_str()],
        "exercise generated JavaScript API",
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

#[cfg(unix)]
fn make_browser_accessible(temp: &TempDir) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
        .context("make temporary validation directory traversable by the browser sandbox")
}

#[cfg(not(unix))]
fn make_browser_accessible(_temp: &TempDir) -> Result<()> {
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

fn prepend_temporary_bin(command: &mut Command, temp: &TempDir) -> Result<()> {
    let bin = temp.path().join("bin");
    if !bin.is_dir() {
        return Ok(());
    }
    let mut paths = vec![bin];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    command.env(
        "PATH",
        std::env::join_paths(paths).context("construct temporary browser PATH")?,
    );
    Ok(())
}

fn ensure_no_workspace_wasm(root: &Path) -> Result<()> {
    let mut matches = Vec::new();
    collect_wasm_files(root, &mut matches)?;
    if matches.is_empty() {
        return Ok(());
    }
    let paths = matches
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("executable WebAssembly must not be retained in the workspace: {paths}")
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
        } else if path.extension() == Some(OsStr::new("wasm")) {
            matches.push(path);
        }
    }
    Ok(())
}

fn preserve_primary_error(
    primary: Result<()>,
    secondary: Result<()>,
    secondary_context: &str,
) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => {
            Err::<(), _>(primary).with_context(|| format!("{secondary_context}: {secondary:#}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::{ensure_no_workspace_wasm, preserve_primary_error};

    #[test]
    fn validation_and_cleanup_errors_are_both_reported() {
        let primary = preserve_primary_error(
            Err(anyhow!("validation failed")),
            Ok(()),
            "cleanup also failed",
        )
        .expect_err("validation error must be retained");
        assert_eq!(format!("{primary:#}"), "validation failed");

        let secondary = preserve_primary_error(
            Ok(()),
            Err(anyhow!("cleanup failed")),
            "cleanup also failed",
        )
        .expect_err("cleanup error must be reported");
        assert_eq!(format!("{secondary:#}"), "cleanup failed");

        let combined = preserve_primary_error(
            Err(anyhow!("validation failed")),
            Err(anyhow!("cleanup failed")),
            "cleanup also failed",
        )
        .expect_err("both errors must be reported");
        let combined = format!("{combined:#}");
        assert!(combined.contains("validation failed"));
        assert!(combined.contains("cleanup also failed: cleanup failed"));
    }

    #[test]
    fn retained_wasm_is_rejected_recursively() {
        let root = tempfile::tempdir().expect("create test directory");
        ensure_no_workspace_wasm(root.path()).expect("empty directory is allowed");

        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).expect("create nested directory");
        let artifact = nested.join("generated.wasm");
        std::fs::write(&artifact, b"fixture").expect("write test artifact");

        let error = ensure_no_workspace_wasm(root.path())
            .expect_err("retained WebAssembly must be rejected")
            .to_string();
        assert!(error.contains("generated.wasm"));
    }

    #[cfg(unix)]
    #[test]
    fn wasm_symlink_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create test directory");
        symlink("missing-target", root.path().join("generated.wasm")).expect("create test symlink");

        let error = ensure_no_workspace_wasm(root.path())
            .expect_err("WebAssembly-named symlinks must be rejected")
            .to_string();
        assert!(error.contains("generated.wasm"));
    }
}
