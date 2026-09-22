// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Typed development commands for the yaml-sigil-rs workspace.

mod bounded_process;
mod cargo_metadata_output;
mod ci;
mod features;
mod github;
mod package_content;
mod package_content_policy;
mod release;
mod release_base;
mod release_policy;
mod reports;
mod safe_file;
mod spec_update;
mod tools;
mod versions;
mod wasm;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use tools::require_tool;

const WASM_PACK_INSTALL: &str = "cargo install --locked wasm-pack --version 0.15.0";
const WASM_TARGET_INSTALL: &str = "rustup target add --toolchain 1.95.0 wasm32-unknown-unknown";

/// Arguments for a repository development task.
#[derive(Parser)]
#[command(name = "xtask", about = "yaml-sigil-rs workspace tasks")]
pub struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Run the repository's provider-neutral non-release checks.
    #[command(visible_alias = "ci")]
    Check(ci::CheckArgs),
    /// Compare modeled source-package paths with committed exact inventories.
    PackageContent,
    /// Record the E2E test with Samply into target/profile/profile.json.
    Profile(reports::ProfileArgs),
    /// Record a fresh E2E profile and open the interactive Profiler UI.
    ProfileOpen(reports::ProfileOptions),
    /// Open the existing Samply profile without recording again.
    ProfileView,
    /// Generate workspace coverage with LLVM or Tarpaulin.
    Coverage(reports::CoverageArgs),
    /// Generate a fresh coverage report and open its HTML index.
    CoverageOpen(reports::CoverageOptions),
    /// Open an existing coverage report without rerunning tests.
    CoverageView(reports::CoverageViewArgs),
    /// Refresh local proto/schema/conformance artifacts from yaml-sigil-spec.
    UpdateSpec(UpdateSpecArgs),
    /// Align `[workspace.dependencies]` versions with `[workspace.package].version`.
    SyncWorkspaceVersions {
        /// Validate alignment without changing the manifest.
        #[arg(long)]
        check: bool,
    },
    /// Run provider-neutral release preparation and verification.
    Release(release::ReleaseArgs),
    /// Run bounded GitHub release-automation operations.
    Github(github::GithubArgs),
    /// Validate browser WebAssembly locally without retaining build output.
    Wasm,
}

#[derive(Args, Debug)]
struct UpdateSpecArgs {
    /// Spec ref to import from. Defaults to origin/main in yaml-sigil-spec.
    #[arg(long = "ref", value_name = "REF")]
    spec_ref: Option<String>,
}

/// Execute a parsed development command from this repository's root.
///
/// # Errors
///
/// Returns an error when a prerequisite, selected check, report, or maintenance
/// operation fails. Mutating maintenance commands retain their own safeguards.
pub fn execute(cli: Cli) -> Result<()> {
    let root = workspace_root();
    match cli.command {
        Task::Check(args) => ci::run(&root, args)?,
        Task::PackageContent => {
            package_content::run(&root)?;
        }
        Task::Profile(args) => reports::profile(&root, args.open, args.options.iterations)?,
        Task::ProfileOpen(options) => reports::profile(&root, true, options.iterations)?,
        Task::ProfileView => reports::profile_view(&root)?,
        Task::Coverage(args) => reports::coverage(&root, args.open, &args.options)?,
        Task::CoverageOpen(options) => reports::coverage(&root, true, &options)?,
        Task::CoverageView(args) => reports::coverage_view(&root, args.engine)?,
        Task::UpdateSpec(args) => {
            let spec_ref = args
                .spec_ref
                .as_deref()
                .unwrap_or(spec_update::DEFAULT_SPEC_REF);
            spec_update::update_spec(&root, spec_ref)?;
        }
        Task::SyncWorkspaceVersions { check } => {
            versions::sync_workspace_dependency_versions(&root, check)?;
        }
        Task::Release(args) => release::run(&root, args)?,
        Task::Github(args) => github::run(&root, args).map_err(anyhow::Error::msg)?,
        Task::Wasm => wasm::run(&root)?,
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_command_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn report_tool_install_guidance_is_synchronized() {
        for command in [
            reports::CARGO_LLVM_COV_INSTALL,
            reports::CARGO_TARPAULIN_INSTALL,
            reports::SAMPLY_INSTALL,
            WASM_PACK_INSTALL,
            WASM_TARGET_INSTALL,
        ] {
            assert!(
                include_str!("../../AGENTS.md").contains(command),
                "{command}"
            );
            assert!(
                include_str!("../../README.md").contains(command),
                "{command}"
            );
        }
    }
}
