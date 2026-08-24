// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Workspace maintenance tasks. Invoke via `cargo xtask <COMMAND>` from the repo root.

mod ci;
mod package_content;
mod spec_update;
mod versions;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

const E2E_PACKAGE: &str = "yaml-sigil-conformance";
const E2E_TEST: &str = "e2e_buildtime_keys";
const COVERAGE_HTML_DIR: &str = "target/llvm-cov-html";
const COVERAGE_INDEX: &str = "target/llvm-cov-html/html/index.html";
const PROFILE_BUILD_PROFILE: &str = "profiling";
const PROFILE_DIR: &str = "target/profile";
const PROFILE_JSON: &str = "target/profile/profile.json";
const DEFAULT_PROFILE_ITERATIONS: u32 = 100;
const CARGO_LLVM_COV_INSTALL: &str = "cargo install cargo-llvm-cov";
const SAMPLY_INSTALL: &str = "cargo install --locked samply";

#[derive(Parser)]
#[command(name = "xtask", about = "yaml-sigil-rs workspace tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Run the repository's provider-neutral non-release validation sequence.
    Ci {
        /// Validate another repository checkout with this xtask implementation.
        #[arg(long, value_name = "PATH")]
        candidate_root: Option<PathBuf>,
    },
    /// Compare modeled source-package paths with committed exact inventories.
    PackageContent,
    /// Record the E2E test with samply into `target/profile/profile.json`.
    Profile {
        /// Open the interactive Firefox Profiler UI after recording.
        #[arg(long)]
        open: bool,
        /// Number of times to run the short E2E test while recording.
        #[arg(long, default_value_t = DEFAULT_PROFILE_ITERATIONS, value_parser = clap::value_parser!(u32).range(1..))]
        iterations: u32,
    },
    /// Open the existing samply profile in the interactive Firefox Profiler UI.
    ProfileOpen,
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
    SyncWorkspaceVersions {
        /// Validate alignment without changing the manifest.
        #[arg(long)]
        check: bool,
    },
    /// Manage provider-neutral release version transactions.
    ReleaseVersion(versions::ReleaseVersionArgs),
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
        Task::Ci { candidate_root } => {
            let candidate = resolve_candidate_root(candidate_root.as_deref().unwrap_or(&root))?;
            ci::run(&candidate)
        }
        Task::PackageContent => {
            package_content::run(&root)?;
            Ok(())
        }
        Task::Profile { open, iterations } => profile(&root, open, iterations),
        Task::ProfileOpen => profile_open(&root),
        Task::Coverage { open } => coverage(&root, open),
        Task::CoverageOpen => coverage_open(&root),
        Task::UpdateSpec(args) => {
            let spec_ref = args
                .spec_ref
                .as_deref()
                .unwrap_or(spec_update::DEFAULT_SPEC_REF);
            spec_update::update_spec(&root, spec_ref)?;
            Ok(())
        }
        Task::SyncWorkspaceVersions { check } => {
            versions::sync_workspace_dependency_versions(&root, check)?;
            Ok(())
        }
        Task::ReleaseVersion(args) => versions::release_version(&root, args),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest lives in xtask/")
        .to_path_buf()
}

fn resolve_candidate_root(root: &Path) -> Result<PathBuf> {
    let candidate = root
        .canonicalize()
        .with_context(|| format!("resolve candidate root {}", root.display()))?;
    if !candidate.join("Cargo.toml").is_file() {
        bail!("candidate root {} lacks Cargo.toml", candidate.display());
    }
    Ok(candidate)
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

fn build_e2e_profile(root: &Path) -> Result<PathBuf> {
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
                "--profile",
                PROFILE_BUILD_PROFILE,
            ],
        ))?,
        "build E2E test binary (profiling)",
    )?;
    find_e2e_binary(root, PROFILE_BUILD_PROFILE)
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
        "no {E2E_TEST} test binary under {} (run the profiling build first)",
        deps.display()
    ))
}

fn profile(root: &Path, open: bool, iterations: u32) -> Result<()> {
    let samply = require_tool("samply", SAMPLY_INSTALL)?;
    let e2e = build_e2e_profile(root)?;
    let out_dir = root.join(PROFILE_DIR);
    std::fs::create_dir_all(&out_dir)?;
    let profile_path = root.join(PROFILE_JSON);

    // samply: `record [opts] -- COMMAND [ARGS...]`. Do not pass a second `--`
    // before libtest flags: Rust treats everything after it as test-name filters.
    let mut samply_cmd = Command::new(&samply);
    samply_cmd
        .current_dir(root)
        .arg("record")
        .arg("--save-only")
        .arg("--no-open")
        .arg("--iteration-count")
        .arg(iterations.to_string())
        .arg("--profile-name")
        .arg("yaml-sigil-rs E2E")
        .arg("--output")
        .arg(&profile_path)
        .arg("--")
        .arg(&e2e)
        .arg("--test-threads=1");
    require_success(run(samply_cmd)?, "samply record")?;

    eprintln!("Wrote {}", profile_path.display());
    if open {
        profile_open(root)?;
    } else {
        eprintln!("Run `cargo xtask profile-open` to view it in the browser.");
    }
    Ok(())
}

fn profile_open(root: &Path) -> Result<()> {
    let samply = require_tool("samply", SAMPLY_INSTALL)?;
    let profile = root.join(PROFILE_JSON);
    if !profile.is_file() {
        bail!(
            "missing {} — run `cargo xtask profile` first",
            profile.display()
        );
    }
    let mut load = Command::new(samply);
    load.current_dir(root).arg("load").arg(&profile);
    require_success(run(load)?, "samply load")
}

fn coverage(root: &Path, open: bool) -> Result<()> {
    require_tool("cargo-llvm-cov", CARGO_LLVM_COV_INSTALL)?;
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

fn require_tool(program: &str, install_command: &str) -> Result<PathBuf> {
    which(program)
        .with_context(|| format!("{program} is required; install it with `{install_command}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT_GUIDANCE: &str = include_str!("../../AGENTS.md");
    const README: &str = include_str!("../../README.md");

    #[test]
    fn ci_candidate_root_is_repository_scoped() {
        let root = workspace_root();
        assert_eq!(
            resolve_candidate_root(&root).unwrap(),
            root.canonicalize().unwrap()
        );
        assert!(resolve_candidate_root(&root.join("missing-candidate")).is_err());
    }

    #[test]
    fn report_tool_install_guidance_is_synchronized() {
        for install_command in [CARGO_LLVM_COV_INSTALL, SAMPLY_INSTALL] {
            assert!(AGENT_GUIDANCE.contains(install_command));
            assert!(README.contains(install_command));
        }
    }

    #[test]
    fn missing_report_tool_names_its_install_command() {
        let error = require_tool(
            "yaml-sigil-deliberately-missing-report-tool",
            CARGO_LLVM_COV_INSTALL,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(CARGO_LLVM_COV_INSTALL));
    }
}
