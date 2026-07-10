// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Workspace maintenance tasks. Invoke via `cargo xtask <COMMAND>` from the repo root.

mod spec_publish;
mod spec_update;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

const E2E_PACKAGE: &str = "yaml-sigil-conformance";
const E2E_TEST: &str = "e2e_buildtime_keys";
const COVERAGE_HTML_DIR: &str = "target/llvm-cov-html";
const COVERAGE_INDEX: &str = "target/llvm-cov-html/html/index.html";
const PERF_HTML_DIR: &str = "target/perf-html";
const PERF_PROFILE_JSON: &str = "target/perf-html/profile.json";

#[derive(Parser)]
#[command(name = "xtask", about = "yaml-sigil-rs workspace tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// `fmt`, `clippy`, `test`, and `audit`.
    /// Use `--no-test` in CI.
    Hygiene {
        /// Skip `cargo test --workspace --all-features`.
        #[arg(long)]
        no_test: bool,
    },
    /// Build the E2E test binary and run `perf record` (Linux).
    Perfreport,
    /// Record a CPU profile with samply into `target/perf-html/` (view with `perf-open`).
    RustPerfHtml,
    /// Open the samply profile UI for `target/perf-html/profile.json`.
    PerfOpen,
    /// `cargo llvm-cov` HTML report for the whole workspace (`--all-features`).
    Coverage {
        /// After a successful run, open `target/llvm-cov-html/html/index.html`
        /// in the default browser (equivalent to chaining `coverage-open`).
        #[arg(long)]
        open: bool,
    },
    /// Open `target/llvm-cov-html/html/index.html` in the default browser.
    CoverageOpen,
    /// Refresh local proto/schema/conformance artifacts from yaml-sigil-spec.
    UpdateSpec(UpdateSpecArgs),
    /// Align `[workspace.dependencies]` versions with `[workspace.package].version`.
    SyncWorkspaceVersions,
}

#[derive(Args)]
struct UpdateSpecArgs {
    /// Spec ref to import from. Defaults to origin/main in yaml-sigil-spec.
    #[arg(long = "ref", value_name = "REF")]
    spec_ref: Option<String>,
}

fn main() -> Result<()> {
    let root = workspace_root();
    let cli = Cli::parse();
    match cli.command {
        Task::Hygiene { no_test } => hygiene(&root, no_test),
        Task::Perfreport => perfreport(&root),
        Task::RustPerfHtml => rust_perf_html(&root),
        Task::PerfOpen => perf_open(&root),
        Task::Coverage { open } => coverage(&root, open),
        Task::CoverageOpen => coverage_open(&root),
        Task::UpdateSpec(args) => {
            let spec_ref = args
                .spec_ref
                .as_deref()
                .unwrap_or(spec_update::DEFAULT_SPEC_REF);
            spec_update::update_spec(&root, spec_ref, run)?;
            Ok(())
        }
        Task::SyncWorkspaceVersions => {
            spec_publish::sync_workspace_dependency_versions(&root)?;
            Ok(())
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest lives in xtask/")
        .to_path_buf()
}

fn run(mut cmd: Command) -> Result<ExitStatus> {
    eprintln!("+ {}", format_cmd(&cmd));
    let program = cmd.get_program().to_owned();
    cmd.status()
        .with_context(|| format!("failed to run {program:?}"))
}

fn format_cmd(cmd: &Command) -> String {
    let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy()).collect();
    let dir = cmd
        .get_current_dir()
        .map(|d| format!(" (cwd {})", d.display()))
        .unwrap_or_default();
    format!(
        "{} {}{dir}",
        cmd.get_program().to_string_lossy(),
        args.join(" ")
    )
}

fn require_success(status: ExitStatus, context: &str) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!("{context} (exit {})", status.code().unwrap_or(-1));
    }
}

fn cargo(root: &Path, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args(args);
    cmd
}

fn hygiene(root: &Path, no_test: bool) -> Result<()> {
    let mut steps: Vec<(&str, Vec<&str>)> = vec![
        ("cargo fmt", vec!["fmt", "--all"]),
        (
            "cargo clippy",
            vec![
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ];
    if !no_test {
        steps.push(("cargo test", vec!["test", "--workspace", "--all-features"]));
    }
    steps.push(("cargo audit", vec!["audit"]));
    for (label, args) in &steps {
        require_success(run(cargo(root, args))?, label)?;
    }
    Ok(())
}

fn build_e2e_release(root: &Path) -> Result<PathBuf> {
    require_success(
        run(cargo(
            root,
            [
                "test",
                "-p",
                E2E_PACKAGE,
                "--test",
                E2E_TEST,
                "--no-run",
                "--release",
            ],
        ))?,
        "build E2E test binary (release)",
    )?;
    find_e2e_binary(root, "release")
}

fn find_e2e_binary(root: &Path, profile: &str) -> Result<PathBuf> {
    let deps = root.join("target").join(profile).join("deps");
    let mut matches: Vec<PathBuf> = std::fs::read_dir(&deps)
        .with_context(|| format!("read {}", deps.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with(&format!("{E2E_TEST}-")) && !name.ends_with(".d") && p.is_file()
        })
        .collect();
    matches.sort();
    matches.pop().context(format!(
        "no {E2E_TEST} test binary under {} (run the release build first)",
        deps.display()
    ))
}

#[cfg(not(target_os = "linux"))]
fn perfreport(_root: &Path) -> Result<()> {
    bail!("perfreport requires Linux (`perf` is not used on this host)");
}

#[cfg(target_os = "linux")]
fn perfreport(root: &Path) -> Result<()> {
    let e2e = build_e2e_release(root)?;
    eprintln!("E2E binary: {}", e2e.display());
    let perf_data = root.join("perf.data");
    let mut record = Command::new("perf");
    record
        .current_dir(root)
        .arg("record")
        .arg("--call-graph")
        .arg("dwarf")
        .arg("-o")
        .arg(&perf_data)
        .arg("--")
        .arg(&e2e)
        .arg("--test-threads=1");
    require_success(run(record)?, "perf record")?;
    eprintln!("Wrote {}", perf_data.display());
    let mut report = Command::new("perf");
    report
        .current_dir(root)
        .arg("report")
        .arg("-i")
        .arg(&perf_data);
    require_success(run(report)?, "perf report")
}

fn rust_perf_html(root: &Path) -> Result<()> {
    let e2e = build_e2e_release(root)?;
    let out_dir = root.join(PERF_HTML_DIR);
    std::fs::create_dir_all(&out_dir)?;
    let profile_path = root.join(PERF_PROFILE_JSON);

    let samply = which("samply").context(
        "samply not found on PATH (install: cargo install samply, or see README profiling section)",
    )?;

    // samply: `record [opts] -- COMMAND [ARGS…]`. Do not pass a second `--` before
    // libtest flags — Rust treats everything after `--` as test-name filters (0 tests run).
    let mut samply_cmd = Command::new(&samply);
    samply_cmd
        .current_dir(root)
        .arg("record")
        .arg("--save-only")
        .arg("-n")
        .arg("-o")
        .arg(&profile_path)
        .arg("--")
        .arg(&e2e)
        .arg("--test-threads=1");
    require_success(run(samply_cmd)?, "samply record")?;

    let index = out_dir.join("index.html");
    std::fs::write(
        &index,
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>yaml-sigil-rs perf profile</title></head>
<body>
  <p>CPU profile for <code>{E2E_TEST}</code> (release).</p>
  <p>Data: <code>profile.json</code> (Firefox Profiler format).</p>
  <p>Open the interactive UI: <code>cargo xtask perf-open</code></p>
</body>
</html>
"#
        ),
    )?;
    eprintln!("Wrote {}", profile_path.display());
    eprintln!("Wrote {}", index.display());
    eprintln!("Run `cargo xtask perf-open` to view in the browser.");
    Ok(())
}

fn perf_open(root: &Path) -> Result<()> {
    let profile = root.join(PERF_PROFILE_JSON);
    if !profile.is_file() {
        bail!(
            "missing {} — run `cargo xtask rust-perf-html` first",
            profile.display()
        );
    }
    let samply = which("samply").context("samply not found on PATH")?;
    let mut load = Command::new(samply);
    load.current_dir(root).arg("load").arg(&profile);
    require_success(run(load)?, "samply load")
}

fn coverage(root: &Path, open: bool) -> Result<()> {
    require_success(
        run(cargo(root, ["llvm-cov", "clean", "--workspace"]))?,
        "cargo llvm-cov clean",
    )?;
    require_success(
        run(cargo(
            root,
            [
                "llvm-cov",
                "test",
                "--workspace",
                "--all-features",
                "--html",
                "--output-dir",
                COVERAGE_HTML_DIR,
            ],
        ))?,
        "cargo llvm-cov test",
    )?;
    // Reached only when `cargo llvm-cov test` exited 0 (the `?` above bails
    // otherwise), so `--open` never pops a browser over a failed test run.
    if open {
        coverage_open(root)?;
    }
    Ok(())
}

fn coverage_open(root: &Path) -> Result<()> {
    let index = root.join(COVERAGE_INDEX);
    if !index.is_file() {
        bail!(
            "missing {} — run `cargo xtask coverage` first",
            index.display()
        );
    }
    open_in_browser(&index)
}

fn open_in_browser(path: &Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| path.display().to_string())?;
    let status = if cfg!(target_os = "linux") {
        let mut cmd = Command::new("xdg-open");
        cmd.arg(&path);
        run(cmd)?
    } else if cfg!(target_os = "macos") {
        let mut cmd = Command::new("open");
        cmd.arg(&path);
        run(cmd)?
    } else if cfg!(target_os = "windows") {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "start", "", &path.display().to_string()]);
        run(cmd)?
    } else {
        bail!(
            "no default browser opener for this OS; open {}",
            path.display()
        );
    };
    require_success(status, "open browser")
}

fn which(program: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("{program} not found on PATH");
}
