// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Workspace version synchronization helpers.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use semver::{Prerelease, Version, VersionReq};
#[cfg(test)]
use serde_json::Value;
use toml_edit::{DocumentMut, Item, Value as TomlValue};

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::cargo_metadata_output::parse_bounded;
use crate::release::exact_output_line;
use crate::release_policy::{RUST_POLICY, RUST_TOOLCHAIN, TRAITS_POLICY};
use crate::safe_file;

const TRAITS_PACKAGE: &str = TRAITS_POLICY.packages[0].package;

#[derive(Args)]
pub struct ReleaseVersionArgs {
    #[command(subcommand)]
    command: ReleaseVersionCommand,
}

#[derive(Subcommand)]
enum ReleaseVersionCommand {
    /// Print the workspace package version.
    Show,
    /// Validate the version and synchronized internal dependency requirements.
    Check,
    /// Derive the exact reviewed release intent from two release versions.
    Intent {
        /// Last official published version.
        #[arg(long)]
        published: Version,
    },
    /// Check every public crate against one detached official baseline.
    CheckCompatibility {
        /// Detached official workspace root manifest.
        #[arg(long)]
        baseline_manifest: PathBuf,
        /// Current workspace root manifest.
        #[arg(long)]
        current_manifest: PathBuf,
        /// Exact common version in the detached baseline.
        #[arg(long)]
        expected_baseline_version: Version,
        /// Exact common version in the current workspace.
        #[arg(long)]
        expected_current_version: Version,
        /// Explicit reviewed release-line intent.
        #[arg(long, value_enum)]
        intent: ReleaseIntent,
    },
    /// Set the next RC candidate after release-plz computes changelogs.
    Candidate {
        /// Version currently published for every release crate.
        #[arg(long)]
        published: Version,
        /// Explicit release-line advancement.
        #[arg(long, value_enum)]
        bump: ReleaseBump,
        /// UTC release date in YYYY-MM-DD form.
        #[arg(long)]
        date: String,
        /// Ensure every release crate has a changelog section.
        #[arg(long)]
        release_notes: bool,
    },
    /// Copy the current RC changelog sections to a stable release and strip RC data.
    PromoteStable {
        /// UTC release date in YYYY-MM-DD form.
        #[arg(long)]
        date: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReleaseBump {
    Patch,
    Minor,
    Major,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ReleaseIntent {
    Patch,
    Minor,
    Major,
}

impl ReleaseIntent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }
}

pub fn release_version(root: &Path, args: ReleaseVersionArgs) -> Result<()> {
    match args.command {
        ReleaseVersionCommand::Show => {
            println!("{}", read_workspace_version(root)?);
        }
        ReleaseVersionCommand::Check => {
            let version = read_workspace_version(root)?;
            sync_workspace_dependency_versions(root, true)?;
            validate_crates_io_traits_dependency(root)?;
            validate_stable_traits_dependency(root, &version)?;
            eprintln!("release-version: workspace version is {version}");
        }
        ReleaseVersionCommand::Intent { published } => {
            println!(
                "{}",
                release_intent(&published, &read_workspace_version(root)?)?.as_str()
            );
        }
        ReleaseVersionCommand::CheckCompatibility {
            baseline_manifest,
            current_manifest,
            expected_baseline_version,
            expected_current_version,
            intent,
        } => {
            check_api_compatibility(
                root,
                &baseline_manifest,
                &current_manifest,
                &expected_baseline_version,
                &expected_current_version,
                intent,
            )?;
        }
        ReleaseVersionCommand::Candidate {
            published,
            bump,
            date,
            release_notes,
        } => {
            validate_date(&date)?;
            validate_crates_io_traits_dependency(root)?;
            let current = read_workspace_version(root)?;
            let target = candidate_version(&published, &current, bump)?;
            write_workspace_version(root, &target)?;
            sync_workspace_dependency_versions(root, false)?;
            if release_notes {
                ensure_candidate_changelogs(root, &current, &target, &date)?;
            }
            println!("{target}");
        }
        ReleaseVersionCommand::PromoteStable { date } => {
            validate_date(&date)?;
            validate_crates_io_traits_dependency(root)?;
            let current = read_workspace_version(root)?;
            let stable = stable_version(&current)?;
            validate_promotable_traits_dependency(root)?;
            promote_changelogs(root, &current, &stable, &date)?;
            write_workspace_version(root, &stable)?;
            promote_traits_dependency_to_stable(root)?;
            sync_workspace_dependency_versions(root, false)?;
            println!("{stable}");
        }
    }
    Ok(())
}

/// Rewrite in-workspace `[workspace.dependencies]` `version = "..."` values from
/// `[workspace.package].version` because Cargo cannot inherit `version` into
/// that table.
pub fn sync_workspace_dependency_versions(root: &Path, check: bool) -> Result<bool> {
    let mut runner = SystemCargoRunner;
    sync_workspace_dependency_versions_with_runner(root, check, &mut runner)
}

fn sync_workspace_dependency_versions_with_runner(
    root: &Path,
    check: bool,
    runner: &mut impl CargoRunner,
) -> Result<bool> {
    let path = root.join("Cargo.toml");
    let cargo_toml = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for version sync")?;
    let mut document = cargo_toml
        .parse::<DocumentMut>()
        .context("parse workspace Cargo.toml for version sync")?;
    let package_version = document
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(Item::as_str)
        .ok_or_else(|| anyhow!("missing string [workspace.package] version in root Cargo.toml"))?
        .to_string();
    let changed = synchronize_internal_dependency_entries(&mut document, &package_version)?;

    if changed && check {
        bail!(
            "[workspace.dependencies] versions are not synchronized with {package_version}; run `cargo xtask sync-workspace-versions`"
        );
    } else if changed {
        fs::write(&path, document.to_string())
            .context("write workspace Cargo.toml after version sync")?;
        eprintln!(
            "sync-workspace-versions: set [workspace.dependencies] versions to {package_version}"
        );
    } else {
        eprintln!("sync-workspace-versions: [workspace.dependencies] already at {package_version}");
    }
    validate_internal_dependency_metadata(root, &package_version, runner)?;
    Ok(changed)
}

fn synchronize_internal_dependency_entries(
    document: &mut DocumentMut,
    package_version: &str,
) -> Result<bool> {
    let dependencies = document
        .get_mut("workspace")
        .and_then(Item::as_table_mut)
        .and_then(|workspace| workspace.get_mut("dependencies"))
        .and_then(Item::as_table_mut)
        .ok_or_else(|| anyhow!("missing [workspace.dependencies] table"))?;
    let mut changed = false;
    for policy in RUST_POLICY.packages {
        let package = policy.package;
        let entry = dependencies
            .get_mut(package)
            .ok_or_else(|| anyhow!("missing [workspace.dependencies] entry for {package}"))?;
        let inline = entry.as_inline_table_mut().ok_or_else(|| {
            anyhow!("[workspace.dependencies] {package} must use an inline table")
        })?;
        let current = inline
            .get("version")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| {
                anyhow!("[workspace.dependencies] {package} must contain one string version field")
            })?;
        if current == package_version {
            continue;
        }
        let version = inline
            .get_mut("version")
            .expect("the validated inline-table version exists");
        let decor = version.decor().clone();
        *version = TomlValue::from(package_version);
        *version.decor_mut() = decor;
        changed = true;
    }
    Ok(changed)
}

fn validate_internal_dependency_metadata(
    root: &Path,
    package_version: &str,
    runner: &mut impl CargoRunner,
) -> Result<()> {
    let args: Vec<OsString> = ["metadata", "--no-deps", "--format-version", "1"]
        .into_iter()
        .map(OsString::from)
        .collect();
    let output = runner
        .output(root, &cargo_program(), &args)
        .context("run Cargo metadata for workspace dependency synchronization")?;
    if !output.success {
        bail!(
            "Cargo metadata failed for workspace dependency synchronization: {}",
            cargo_output_detail(&output)
        );
    }
    validate_internal_dependency_metadata_json(root, package_version, &output.stdout)
}

fn validate_internal_dependency_metadata_json(
    root: &Path,
    package_version: &str,
    output: &[u8],
) -> Result<()> {
    let metadata = parse_bounded(output, "Cargo returned invalid dependency metadata")
        .map_err(anyhow::Error::msg)?;
    let workspace_identity = metadata
        .workspace_root
        .as_std_path()
        .canonicalize()
        .with_context(|| format!("resolve Cargo workspace root {}", metadata.workspace_root))?;
    let expected_root = root
        .canonicalize()
        .with_context(|| format!("resolve workspace root {}", root.display()))?;
    if workspace_identity != expected_root {
        bail!("Cargo dependency metadata selected an unexpected workspace root");
    }

    let expected_version = Version::parse(package_version)
        .with_context(|| format!("invalid workspace package version {package_version}"))?;
    let expected_requirement = VersionReq::parse(package_version)
        .with_context(|| format!("invalid workspace dependency version {package_version}"))?;
    for policy in RUST_POLICY.packages {
        let package_name = policy.package;
        let matches: Vec<_> = metadata
            .packages
            .iter()
            .filter(|package| package.name == package_name)
            .collect();
        if matches.len() != 1 {
            bail!(
                "Cargo dependency metadata did not contain exactly one {package_name} package; found {}",
                matches.len()
            );
        }
        let package = matches[0];
        if package.source.is_some() {
            bail!("Cargo dependency metadata gave {package_name} a non-workspace source");
        }
        if package.version != expected_version {
            bail!("Cargo dependency metadata gave {package_name} an unexpected release version");
        }
        let expected_manifest = expected_root
            .join(policy.path_in_vcs)
            .join("Cargo.toml")
            .canonicalize()
            .with_context(|| format!("resolve expected manifest for {package_name}"))?;
        let actual_manifest = package
            .manifest_path
            .as_std_path()
            .canonicalize()
            .with_context(|| format!("resolve Cargo manifest for {package_name}"))?;
        if actual_manifest != expected_manifest {
            bail!("Cargo dependency metadata returned an unexpected manifest for {package_name}");
        }
        for dependency in &package.dependencies {
            let dependency_name = dependency.name.as_str();
            let Some(dependency_policy) = RUST_POLICY
                .packages
                .iter()
                .find(|policy| policy.package == dependency_name)
            else {
                continue;
            };
            if dependency.source.is_some() || dependency.rename.is_some() {
                bail!(
                    "Cargo dependency metadata gave {package_name}'s {dependency_name} dependency an unexpected identity"
                );
            }
            if dependency.req != expected_requirement {
                bail!(
                    "Cargo dependency metadata gave {package_name}'s {dependency_name} dependency an unexpected release requirement"
                );
            }
            let expected_path = expected_root
                .join(dependency_policy.path_in_vcs)
                .canonicalize()
                .with_context(|| {
                    format!("resolve expected dependency path for {dependency_name}")
                })?;
            let actual_path = dependency.path.as_ref().ok_or_else(|| {
                anyhow!("Cargo dependency metadata omitted {package_name}'s {dependency_name} path")
            })?;
            let actual_path = actual_path
                .as_std_path()
                .canonicalize()
                .with_context(|| format!("resolve Cargo dependency path for {dependency_name}"))?;
            if actual_path != expected_path {
                bail!(
                    "Cargo dependency metadata returned an unexpected {dependency_name} path for {package_name}"
                );
            }
        }
    }
    Ok(())
}

fn read_workspace_version(root: &Path) -> Result<Version> {
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for release version")?;
    let value = workspace_package_version(&manifest)
        .ok_or_else(|| anyhow!("missing [workspace.package] version in root Cargo.toml"))?;
    let version = Version::parse(&value)
        .with_context(|| format!("invalid workspace package version {value}"))?;
    release_rc(&version)?;
    Ok(version)
}

fn write_workspace_version(root: &Path, version: &Version) -> Result<()> {
    let path = root.join("Cargo.toml");
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml")?;
    let mut in_section = false;
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_section = true;
        } else if in_section && trimmed.starts_with('[') {
            in_section = false;
        }

        if in_section && trimmed.starts_with("version = ") {
            if replaced {
                bail!("multiple version entries in [workspace.package]");
            }
            lines.push(set_version_on_line(line, &version.to_string())?);
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        bail!("missing version entry in [workspace.package]");
    }
    let mut updated = lines.join("\n");
    updated.push('\n');
    if updated != manifest {
        fs::write(path, updated).context("write workspace Cargo.toml")?;
    }
    Ok(())
}

fn set_version_on_line(line: &str, version: &str) -> Result<String> {
    let prefix_end = line
        .find('"')
        .ok_or_else(|| anyhow!("invalid version line: {line}"))?
        + 1;
    let suffix_start = prefix_end
        + line[prefix_end..]
            .find('"')
            .ok_or_else(|| anyhow!("invalid version line: {line}"))?;
    Ok(format!(
        "{}{}{}",
        &line[..prefix_end],
        version,
        &line[suffix_start..]
    ))
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

#[derive(Debug)]
struct ManifestPath {
    argument: PathBuf,
    identity: PathBuf,
}

fn resolve_manifest(root: &Path, path: &Path, label: &str) -> Result<ManifestPath> {
    let argument = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let identity = argument
        .canonicalize()
        .with_context(|| format!("resolve {label} manifest {}", argument.display()))?;
    if !identity.is_file()
        || identity.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml")
    {
        bail!(
            "{label} manifest is not an exact Cargo.toml file: {}",
            identity.display()
        );
    }
    Ok(ManifestPath { argument, identity })
}

#[derive(Debug)]
struct CargoOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct CargoStatus {
    success: bool,
    code: Option<i32>,
}

trait CargoRunner {
    fn output(&mut self, root: &Path, program: &OsStr, args: &[OsString]) -> Result<CargoOutput>;

    fn status(&mut self, root: &Path, program: &OsStr, args: &[OsString]) -> Result<CargoStatus>;
}

struct SystemCargoRunner;

impl CargoRunner for SystemCargoRunner {
    fn output(&mut self, root: &Path, program: &OsStr, args: &[OsString]) -> Result<CargoOutput> {
        let mut command = Command::new(program);
        command.current_dir(root).args(args);
        let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
            .map_err(|error| anyhow!("run {}: {error}", program.to_string_lossy()))?;
        Ok(CargoOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn status(&mut self, root: &Path, program: &OsStr, args: &[OsString]) -> Result<CargoStatus> {
        let mut command = Command::new(program);
        command.current_dir(root).args(args);
        let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
            .with_context(|| format!("run {}", program.to_string_lossy()))?;
        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
        Ok(CargoStatus {
            success: output.status.success(),
            code: output.status.code(),
        })
    }
}

fn cargo_output_detail(output: &CargoOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn check_api_compatibility(
    root: &Path,
    baseline_manifest: &Path,
    current_manifest: &Path,
    expected_baseline: &Version,
    expected_current: &Version,
    expected_intent: ReleaseIntent,
) -> Result<()> {
    let mut runner = SystemCargoRunner;
    check_api_compatibility_with_runner(
        root,
        baseline_manifest,
        current_manifest,
        expected_baseline,
        expected_current,
        expected_intent,
        &mut runner,
    )
}

#[allow(clippy::too_many_arguments)]
fn check_api_compatibility_with_runner(
    root: &Path,
    baseline_manifest: &Path,
    current_manifest: &Path,
    expected_baseline: &Version,
    expected_current: &Version,
    expected_intent: ReleaseIntent,
    runner: &mut impl CargoRunner,
) -> Result<()> {
    release_rc(expected_baseline)?;
    release_rc(expected_current)?;

    // Address the installed analyzer directly so Cargo aliases cannot replace it.
    let tool = runner
        .output(
            root,
            OsStr::new("cargo-semver-checks"),
            &[OsString::from("semver-checks"), OsString::from("--version")],
        )
        .context("cargo-semver-checks is unavailable")?;
    if !tool.success {
        bail!(
            "cargo-semver-checks is unavailable: {}",
            cargo_output_detail(&tool)
        );
    }
    let expected_tool = format!(
        "cargo-semver-checks {}",
        RUST_TOOLCHAIN.cargo_semver_checks_version
    );
    let actual_tool = exact_output_line(&tool.stdout, "cargo-semver-checks version")?;
    if actual_tool != expected_tool {
        bail!("expected {expected_tool}; found {actual_tool}");
    }

    let baseline_manifest = resolve_manifest(root, baseline_manifest, "baseline")?;
    let current_manifest = resolve_manifest(root, current_manifest, "current")?;
    let repository_manifest = resolve_manifest(root, &root.join("Cargo.toml"), "repository")?;
    if current_manifest.identity != repository_manifest.identity {
        bail!("the current manifest is not the repository root Cargo.toml");
    }

    let baseline_versions = metadata_versions(root, &baseline_manifest, runner)?;
    let current_versions = metadata_versions(root, &current_manifest, runner)?;
    require_common_versions(&baseline_versions, expected_baseline, "baseline")?;
    require_common_versions(&current_versions, expected_current, "current")?;
    let actual_intent = release_intent(expected_baseline, expected_current)?;
    if actual_intent != expected_intent {
        bail!(
            "candidate represents a {} bump, not requested {}",
            actual_intent.as_str(),
            expected_intent.as_str()
        );
    }
    let release_type = checker_release_type(expected_intent, expected_current);
    let baseline_root = baseline_manifest
        .argument
        .parent()
        .ok_or_else(|| anyhow!("the baseline manifest has no parent directory"))?;

    for policy in RUST_POLICY.packages {
        let package = policy.package;
        let args = [
            OsString::from("semver-checks"),
            OsString::from("check-release"),
            OsString::from("--manifest-path"),
            current_manifest.argument.as_os_str().to_owned(),
            OsString::from("--package"),
            OsString::from(package),
            OsString::from("--baseline-root"),
            baseline_root.as_os_str().to_owned(),
            OsString::from("--release-type"),
            OsString::from(release_type),
            OsString::from("--all-features"),
            OsString::from("--color"),
            OsString::from("never"),
        ];
        let status = runner
            .status(root, OsStr::new("cargo-semver-checks"), &args)
            .with_context(|| format!("run cargo-semver-checks for {package}"))?;
        if !status.success {
            bail!(
                "cargo-semver-checks failed for {package} with status {}",
                status
                    .code
                    .map_or_else(|| "signal".to_string(), |code| code.to_string())
            );
        }
    }
    eprintln!(
        "release-version: API compatibility passed for all four crates with {} intent ({release_type} Cargo release type)",
        expected_intent.as_str()
    );
    Ok(())
}

fn metadata_versions(
    root: &Path,
    manifest: &ManifestPath,
    runner: &mut impl CargoRunner,
) -> Result<Vec<(String, Version)>> {
    let mut args: Vec<OsString> = [
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--manifest-path",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(manifest.argument.as_os_str().to_owned());
    let output = runner
        .output(root, &cargo_program(), &args)
        .with_context(|| format!("run Cargo metadata for {}", manifest.argument.display()))?;
    if !output.success {
        bail!(
            "Cargo metadata failed for {}: {}",
            manifest.argument.display(),
            cargo_output_detail(&output)
        );
    }
    metadata_versions_from_json(&output.stdout, manifest)
}

fn metadata_versions_from_json(
    output: &[u8],
    manifest: &ManifestPath,
) -> Result<Vec<(String, Version)>> {
    let metadata =
        parse_bounded(output, "Cargo returned invalid metadata").map_err(anyhow::Error::msg)?;
    let workspace_identity = metadata
        .workspace_root
        .as_std_path()
        .canonicalize()
        .with_context(|| format!("resolve Cargo workspace root {}", metadata.workspace_root))?;
    let expected_root = manifest
        .identity
        .parent()
        .ok_or_else(|| anyhow!("workspace manifest has no parent"))?;
    if workspace_identity != expected_root {
        bail!("Cargo metadata workspace root does not match the selected manifest");
    }

    let mut versions = Vec::new();
    for policy in RUST_POLICY.packages {
        let name = policy.package;
        let relative = policy.path_in_vcs;
        let expected_manifest = expected_root
            .join(relative)
            .join("Cargo.toml")
            .canonicalize()
            .with_context(|| format!("resolve expected manifest for {name}"))?;
        let matches: Vec<_> = metadata
            .packages
            .iter()
            .filter(|package| package.name == name)
            .collect();
        if matches.len() != 1 {
            bail!(
                "metadata did not contain exactly one {name} package; found {}",
                matches.len()
            );
        }
        let actual_manifest = &matches[0].manifest_path;
        let actual_identity = actual_manifest
            .as_std_path()
            .canonicalize()
            .with_context(|| format!("resolve Cargo metadata manifest {actual_manifest}"))?;
        if actual_identity != expected_manifest {
            bail!("metadata returned an unexpected manifest identity for {name}");
        }
        let version = matches[0].version.clone();
        release_rc(&version)?;
        versions.push((name.to_string(), version));
    }
    Ok(versions)
}

fn require_common_versions(
    versions: &[(String, Version)],
    expected: &Version,
    label: &str,
) -> Result<()> {
    if versions.len() != RUST_POLICY.packages.len() {
        bail!("{label} metadata did not contain all four release packages");
    }
    for (package, version) in versions {
        if version != expected {
            bail!("{label} {package} version {version} does not match {expected}");
        }
    }
    Ok(())
}

fn checker_release_type(intent: ReleaseIntent, current: &Version) -> &'static str {
    match intent {
        ReleaseIntent::Major => "major",
        ReleaseIntent::Minor if current.major == 0 => "major",
        ReleaseIntent::Minor => "minor",
        ReleaseIntent::Patch if current.major != 0 => "patch",
        ReleaseIntent::Patch if current.minor == 0 => "major",
        ReleaseIntent::Patch => "minor",
    }
}

fn candidate_version(
    published: &Version,
    _current: &Version,
    bump: ReleaseBump,
) -> Result<Version> {
    let published_rc = release_rc(published)?;
    let mut target = match bump {
        ReleaseBump::Patch => match published_rc {
            None => bumped_core(published, ReleaseBump::Patch)?,
            Some(rc) => with_rc(
                published,
                rc.checked_add(1)
                    .ok_or_else(|| anyhow!("rc number overflow"))?,
            )?,
        },
        ReleaseBump::Minor | ReleaseBump::Major => bumped_core(published, bump)?,
    };
    target.build = semver::BuildMetadata::EMPTY;
    Ok(target)
}

fn bumped_core(version: &Version, bump: ReleaseBump) -> Result<Version> {
    let (major, minor, patch) = match bump {
        ReleaseBump::Patch => (
            version.major,
            version.minor,
            version
                .patch
                .checked_add(1)
                .ok_or_else(|| anyhow!("patch version overflow"))?,
        ),
        ReleaseBump::Minor => (
            version.major,
            version
                .minor
                .checked_add(1)
                .ok_or_else(|| anyhow!("minor version overflow"))?,
            0,
        ),
        ReleaseBump::Major => (
            version
                .major
                .checked_add(1)
                .ok_or_else(|| anyhow!("major version overflow"))?,
            0,
            0,
        ),
    };
    with_rc(&Version::new(major, minor, patch), 1)
}

fn require_rc(version: &Version) -> Result<u64> {
    let number = version
        .pre
        .as_str()
        .strip_prefix("rc.")
        .ok_or_else(|| anyhow!("expected an rc.N prerelease, found {version}"))?;
    let rc = number
        .parse::<u64>()
        .with_context(|| format!("expected an rc.N prerelease, found {version}"))?;
    if rc == 0 {
        bail!("expected rc.N with N at least 1, found {version}");
    }
    Ok(rc)
}

fn release_rc(version: &Version) -> Result<Option<u64>> {
    if !version.build.is_empty() {
        bail!("release versions cannot contain build metadata: {version}");
    }
    if version.pre.is_empty() {
        Ok(None)
    } else {
        require_rc(version).map(Some)
    }
}

fn release_intent(published: &Version, current: &Version) -> Result<ReleaseIntent> {
    let published_rc = release_rc(published)?;
    let current_rc = release_rc(current)?;
    let same_core = current.major == published.major
        && current.minor == published.minor
        && current.patch == published.patch;
    if same_core {
        return match (published_rc, current_rc) {
            (Some(_), None) => Ok(ReleaseIntent::Patch),
            (Some(published), Some(current)) if Some(current) == published.checked_add(1) => {
                Ok(ReleaseIntent::Patch)
            }
            _ => bail!("the release version does not exactly advance or promote the current RC"),
        };
    }

    let intent = if current.major != published.major {
        if current.major
            == published
                .major
                .checked_add(1)
                .ok_or_else(|| anyhow!("major version overflow"))?
            && current.minor == 0
            && current.patch == 0
        {
            ReleaseIntent::Major
        } else {
            bail!("the release version does not represent one patch, minor, or major line");
        }
    } else if current.minor != published.minor {
        if current.minor
            == published
                .minor
                .checked_add(1)
                .ok_or_else(|| anyhow!("minor version overflow"))?
            && current.patch == 0
        {
            ReleaseIntent::Minor
        } else {
            bail!("the release version does not represent one patch, minor, or major line");
        }
    } else if current.patch
        == published
            .patch
            .checked_add(1)
            .ok_or_else(|| anyhow!("patch version overflow"))?
    {
        if published_rc.is_some() {
            bail!("a patch intent must advance the current RC core");
        }
        ReleaseIntent::Patch
    } else {
        bail!("the release version does not represent one patch, minor, or major line");
    };

    if current_rc != Some(1) {
        bail!("a new release version line must start at rc.1");
    }
    Ok(intent)
}

fn with_rc(version: &Version, rc: u64) -> Result<Version> {
    let mut version = Version::new(version.major, version.minor, version.patch);
    version.pre = Prerelease::new(&format!("rc.{rc}"))?;
    Ok(version)
}

fn stable_version(version: &Version) -> Result<Version> {
    require_rc(version)?;
    Ok(Version::new(version.major, version.minor, version.patch))
}

/// Require the external traits crate to have one exact crates.io identity.
///
/// Cargo treats equal names and versions from registry, Git, and path sources
/// as different crates. A source override here can therefore make packaged
/// workspace crates exchange incompatible Rust types even when both copies
/// display the same semantic version.
fn validate_crates_io_traits_dependency(root: &Path) -> Result<()> {
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for traits source validation")?;
    let document: toml::Value = toml::from_str(&manifest)
        .context("parse workspace Cargo.toml for traits source validation")?;
    let dependency = document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|dependencies| dependencies.get(TRAITS_PACKAGE))
        .ok_or_else(|| anyhow!("missing [workspace.dependencies] entry for {TRAITS_PACKAGE}"))?;
    let details = dependency.as_table().ok_or_else(|| {
        anyhow!("[workspace.dependencies] {TRAITS_PACKAGE} must use an inline table")
    })?;

    for source_key in ["git", "path", "branch", "tag", "rev", "package"] {
        if details.contains_key(source_key) {
            bail!(
                "[workspace.dependencies] {TRAITS_PACKAGE} must resolve only from crates.io; remove {source_key}"
            );
        }
    }
    if let Some(registry) = details.get("registry") {
        let registry = registry.as_str().ok_or_else(|| {
            anyhow!("[workspace.dependencies] {TRAITS_PACKAGE} registry must be a string")
        })?;
        if registry != "crates-io" {
            bail!(
                "[workspace.dependencies] {TRAITS_PACKAGE} must resolve from crates.io, not registry {registry}"
            );
        }
    }

    let requirement = details
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            anyhow!("missing version in [workspace.dependencies] entry for {TRAITS_PACKAGE}")
        })?;
    exact_traits_version(requirement)?;
    Ok(())
}

/// Require stable workspaces to depend on an exact stable traits release.
fn validate_stable_traits_dependency(root: &Path, workspace_version: &Version) -> Result<()> {
    if !workspace_version.pre.is_empty() {
        return Ok(());
    }

    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for traits version validation")?;
    let (_, requirement) = workspace_traits_dependency(&manifest)?;
    let traits_version = exact_traits_version(&requirement)?;
    if !traits_version.pre.is_empty() {
        bail!(
            "stable workspace {workspace_version} cannot retain prerelease {TRAITS_PACKAGE} requirement {requirement}"
        );
    }
    Ok(())
}

/// Validate the exact split-crate pin before stable promotion mutates files.
fn validate_promotable_traits_dependency(root: &Path) -> Result<()> {
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for traits stable promotion")?;
    let (_, requirement) = workspace_traits_dependency(&manifest)?;
    let traits_version = exact_traits_version(&requirement)?;
    if !traits_version.pre.is_empty() {
        require_rc(&traits_version).with_context(|| {
            format!("{TRAITS_PACKAGE} requirement {requirement} is not an rc.N release")
        })?;
    }
    Ok(())
}

/// Strip an `rc.N` suffix from the exact split-crate requirement.
fn promote_traits_dependency_to_stable(root: &Path) -> Result<bool> {
    let path = root.join("Cargo.toml");
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for traits stable promotion")?;
    let (line_index, requirement) = workspace_traits_dependency(&manifest)?;
    let traits_version = exact_traits_version(&requirement)?;
    if traits_version.pre.is_empty() {
        return Ok(false);
    }
    require_rc(&traits_version).with_context(|| {
        format!("{TRAITS_PACKAGE} requirement {requirement} is not an rc.N release")
    })?;

    let stable = Version::new(
        traits_version.major,
        traits_version.minor,
        traits_version.patch,
    );
    let mut lines: Vec<String> = manifest.lines().map(str::to_owned).collect();
    lines[line_index] = set_dependency_version_on_line(&lines[line_index], &format!("={stable}"));
    let mut updated = lines.join("\n");
    updated.push('\n');
    fs::write(path, updated).context("write stable traits requirement to workspace Cargo.toml")?;
    eprintln!("release-version: promoted {TRAITS_PACKAGE} requirement to ={stable}");
    Ok(true)
}

/// Locate the one canonical inline-table traits entry in workspace dependencies.
fn workspace_traits_dependency(cargo_toml: &str) -> Result<(usize, String)> {
    let prefix = format!("{TRAITS_PACKAGE} = ");
    let mut in_section = false;
    let mut found = None;
    for (line_index, line) in cargo_toml.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[workspace.dependencies]" {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with('[') {
            in_section = false;
        }
        if !in_section || !trimmed.starts_with(&prefix) {
            continue;
        }
        if found.is_some() {
            bail!("multiple [workspace.dependencies] entries for {TRAITS_PACKAGE}");
        }

        let inline = trimmed
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_prefix('{'))
            .ok_or_else(|| {
                anyhow!("[workspace.dependencies] {TRAITS_PACKAGE} must use an inline table")
            })?;
        let marker = "version = ";
        let version_start = inline.find(marker).ok_or_else(|| {
            anyhow!("missing version in [workspace.dependencies] entry for {TRAITS_PACKAGE}")
        })?;
        let requirement = parse_toml_string_value(&inline[version_start + marker.len()..])
            .ok_or_else(|| {
                anyhow!("invalid version in [workspace.dependencies] entry for {TRAITS_PACKAGE}")
            })?;
        found = Some((line_index, requirement));
    }

    found.ok_or_else(|| anyhow!("missing [workspace.dependencies] entry for {TRAITS_PACKAGE}"))
}

/// Parse only a single exact Cargo requirement such as `=0.4.0-rc.1`.
fn exact_traits_version(requirement: &str) -> Result<Version> {
    let version = requirement
        .strip_prefix('=')
        .ok_or_else(|| anyhow!("{TRAITS_PACKAGE} requirement {requirement} must be exact"))?;
    Version::parse(version)
        .with_context(|| format!("invalid exact {TRAITS_PACKAGE} requirement {requirement}"))
}

fn validate_date(date: &str) -> Result<()> {
    let bytes = date.as_bytes();
    if bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        bail!("--date must use YYYY-MM-DD")
    }
}

fn ensure_candidate_changelogs(
    root: &Path,
    generated: &Version,
    target: &Version,
    date: &str,
) -> Result<()> {
    for policy in RUST_POLICY.packages {
        let crate_name = policy.package;
        let path = root.join(policy.changelog);
        let body = safe_file::read_manifest(root, Path::new(policy.changelog))
            .with_context(|| format!("read {}", path.display()))?;
        let generated_prefix = format!("## [{generated}](");
        let target_prefix = format!("## [{target}](");
        let mut changed = false;
        let mut output = Vec::new();
        for line in body.lines() {
            if line.starts_with(&generated_prefix) && generated != target {
                output.push(line.replacen(&generated.to_string(), &target.to_string(), 2));
                changed = true;
            } else {
                output.push(line.to_string());
            }
        }
        let mut updated = output.join("\n");
        updated.push('\n');
        if !updated.lines().any(|line| line.starts_with(&target_prefix)) {
            updated = insert_after_unreleased(
                &updated,
                &format!(
                    "## [{target}](https://github.com/NVIDIA/yaml-sigil-rs/releases/tag/{crate_name}-v{target}) - {date}\n\n### Other\n\n- No crate-specific changes."
                ),
            )?;
            changed = true;
        }
        if changed {
            fs::write(&path, updated).with_context(|| format!("write {}", path.display()))?;
        }
    }
    Ok(())
}

fn promote_changelogs(root: &Path, rc: &Version, stable: &Version, date: &str) -> Result<()> {
    for policy in RUST_POLICY.packages {
        let crate_name = policy.package;
        let path = root.join(policy.changelog);
        let body = safe_file::read_manifest(root, Path::new(policy.changelog))
            .with_context(|| format!("read {}", path.display()))?;
        let section = changelog_section(&body, rc)?;
        let promoted = format!(
            "## [{stable}](https://github.com/NVIDIA/yaml-sigil-rs/releases/tag/{crate_name}-v{stable}) - {date}\n{section}"
        );
        let updated = insert_after_unreleased(&body, &promoted)?;
        fs::write(&path, updated).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

fn changelog_section(body: &str, version: &Version) -> Result<String> {
    let lines: Vec<_> = body.lines().collect();
    let prefix = format!("## [{version}](");
    let start = lines
        .iter()
        .position(|line| line.starts_with(&prefix))
        .ok_or_else(|| anyhow!("missing changelog section for {version}"))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.starts_with("## ["))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Ok(format!("{}\n", lines[start + 1..end].join("\n").trim_end()))
}

fn insert_after_unreleased(body: &str, section: &str) -> Result<String> {
    let marker = "## [Unreleased]";
    let start = body
        .find(marker)
        .ok_or_else(|| anyhow!("missing [Unreleased] changelog heading"))?;
    let insert_at = start + marker.len();
    let mut output = String::with_capacity(body.len() + section.len() + 3);
    output.push_str(&body[..insert_at]);
    output.push_str("\n\n");
    output.push_str(section.trim());
    output.push_str("\n\n");
    output.push_str(body[insert_at..].trim_start_matches('\n'));
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(output)
}

fn set_dependency_version_on_line(line: &str, version: &str) -> String {
    const KEY: &str = "version = \"";
    let Some(start) = line.find(KEY) else {
        return line.to_string();
    };
    let after_key = start + KEY.len();
    let Some(end_rel) = line[after_key..].find('"') else {
        return line.to_string();
    };
    let end = after_key + end_rel;
    let mut out = String::with_capacity(line.len());
    out.push_str(&line[..after_key]);
    out.push_str(version);
    out.push_str(&line[end..]);
    out
}

fn workspace_package_version(cargo_toml: &str) -> Option<String> {
    let mut in_section = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with('[') {
            break;
        }
        if in_section && trimmed.starts_with("version = ") {
            return parse_toml_string_value(trimmed.strip_prefix("version = ")?);
        }
    }
    None
}

#[cfg(test)]
fn workspace_dependency_version(cargo_toml: &str, name: &str) -> Option<String> {
    let document = cargo_toml.parse::<DocumentMut>().ok()?;
    document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|dependencies| dependencies.get(name))
        .and_then(Item::as_inline_table)
        .and_then(|dependency| dependency.get("version"))
        .and_then(TomlValue::as_str)
        .map(str::to_string)
}

fn parse_toml_string_value(s: &str) -> Option<String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_metadata_output::test_support::{
        dependency, encoded, metadata as metadata_value, package, target,
    };

    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn system_cargo_runner_bounds_candidate_metadata_while_reading() {
        let root = temp_test_root("bounded-cargo-metadata");
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"metadata-bound-test\"\nversion = \"0.1.0\"\n\
                 edition = \"2024\"\npublish = false\n\n[package.metadata]\npadding = \"{}\"\n",
                "x".repeat(VALIDATION_OUTPUT_LIMITS.stdout)
            ),
        )
        .unwrap();
        let args = ["metadata", "--no-deps", "--format-version", "1"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();

        let error = SystemCargoRunner
            .output(&root, &cargo_program(), &args)
            .unwrap_err()
            .to_string();

        cleanup_temp_test_root(root);
        assert!(
            error.contains(&format!(
                "stdout exceeded its {}-byte limit",
                VALIDATION_OUTPUT_LIMITS.stdout
            )),
            "unexpected bounded-output error: {error}"
        );
    }

    #[test]
    fn sync_keeps_split_traits_dependency_explicit() {
        let root = temp_test_root("sync-keeps-traits");
        let workspace_version = "0.2.0-0.dev.branch.20260615.t123456";
        write_test_workspace_manifest(&root, workspace_version, "0.2.0-rc.1", "0.2.0-rc.1");
        let mut runner = workspace_sync_runner(&root, workspace_version);

        sync_workspace_dependency_versions_with_runner(&root, false, &mut runner).unwrap();

        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-core").as_deref(),
            Some("0.2.0-0.dev.branch.20260615.t123456")
        );
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-traits").as_deref(),
            Some("0.2.0-rc.1")
        );
        assert_workspace_sync_call(&runner);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn sync_removes_exact_publish_pins() {
        let root = temp_test_root("sync-removes-exact");
        let workspace_version = "0.3.0-rc.1";
        write_test_workspace_manifest(&root, workspace_version, "=0.3.0-rc.1", "0.2.0");
        let mut runner = workspace_sync_runner(&root, workspace_version);

        sync_workspace_dependency_versions_with_runner(&root, false, &mut runner).unwrap();

        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-core").as_deref(),
            Some("0.3.0-rc.1")
        );
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-signing").as_deref(),
            Some("0.3.0-rc.1")
        );
        assert_workspace_sync_call(&runner);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn check_rejects_unsynchronized_dependencies_without_writing() {
        let root = temp_test_root("check-unsynchronized");
        write_test_workspace_manifest(&root, "0.4.0-rc.2", "0.4.0-rc.1", "0.3.0-rc.1");
        let before = fs::read_to_string(root.join("Cargo.toml")).unwrap();

        assert!(sync_workspace_dependency_versions(&root, true).is_err());
        assert_eq!(fs::read_to_string(root.join("Cargo.toml")).unwrap(), before);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn sync_ignores_masking_keys_outside_workspace_dependencies() {
        let root = temp_test_root("sync-masking-table");
        write_test_workspace_manifest(&root, "0.4.0-rc.2", "0.4.0-rc.1", "0.3.0-rc.1");
        let path = root.join("Cargo.toml");
        let body = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            format!(
                "[package.metadata.mask]\n\
                 yaml-sigil-core = {{ version = \"0.4.0-rc.2\" }}\n\n\
                 {body}"
            ),
        )
        .unwrap();
        let before = fs::read_to_string(&path).unwrap();

        let error = sync_workspace_dependency_versions(&root, true).unwrap_err();
        assert!(error.to_string().contains("not synchronized"));
        assert_eq!(fs::read_to_string(path).unwrap(), before);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn sync_rejects_malformed_or_duplicate_canonical_entries() {
        for (case, replacement) in [
            ("missing", ""),
            ("non-inline", "yaml-sigil-core = \"0.4.0-rc.1\"\n"),
            (
                "non-string-version",
                "yaml-sigil-core = { version = 4, path = \"crates/yaml-sigil-core\" }\n",
            ),
            (
                "duplicate",
                "yaml-sigil-core = { version = \"0.4.0-rc.1\", path = \"crates/yaml-sigil-core\" }\n\
                 yaml-sigil-core = { version = \"0.4.0-rc.1\", path = \"crates/yaml-sigil-core\" }\n",
            ),
        ] {
            let root = temp_test_root(case);
            write_test_workspace_manifest(&root, "0.4.0-rc.1", "0.4.0-rc.1", "0.3.0-rc.1");
            let path = root.join("Cargo.toml");
            let body = fs::read_to_string(&path).unwrap();
            let malformed = body.replace(
                "yaml-sigil-core = { version = \"0.4.0-rc.1\", path = \"crates/yaml-sigil-core\", default-features = false }\n",
                replacement,
            );
            fs::write(&path, &malformed).unwrap();

            assert!(sync_workspace_dependency_versions(&root, true).is_err());
            assert_eq!(fs::read_to_string(path).unwrap(), malformed);
            cleanup_temp_test_root(root);
        }
    }

    #[test]
    fn sync_rewrites_only_canonical_internal_versions() {
        let root = temp_test_root("sync-targeted-rewrite");
        let workspace_version = "0.3.0-rc.1";
        write_test_workspace_manifest(&root, workspace_version, "=0.3.0-rc.1", "0.2.0");
        let path = root.join("Cargo.toml");
        let body = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            format!(
                "[package.metadata.mask]\n\
                 yaml-sigil-core = {{ version = \"9.9.9\" }} # preserved\n\n\
                 {body}"
            ),
        )
        .unwrap();
        let before = fs::read_to_string(&path).unwrap();
        let expected = before.replace("version = \"=0.3.0-rc.1\"", "version = \"0.3.0-rc.1\"");
        let mut runner = workspace_sync_runner(&root, workspace_version);

        assert!(sync_workspace_dependency_versions_with_runner(&root, false, &mut runner).unwrap());
        assert_eq!(fs::read_to_string(path).unwrap(), expected);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn sync_metadata_rejects_release_identity_and_requirement_mismatches() {
        let root = temp_test_root("sync-metadata-mismatch");
        let version = "0.4.0-rc.1";
        write_test_workspace_manifest(&root, version, version, "0.3.0-rc.1");

        let mut wrong_version = workspace_sync_metadata_value(&root, version);
        wrong_version["packages"][0]["version"] = serde_json::json!("0.4.0-rc.2");
        assert!(
            validate_internal_dependency_metadata_json(
                &root,
                version,
                &serde_json::to_vec(&wrong_version).unwrap(),
            )
            .is_err()
        );

        let mut wrong_requirement = workspace_sync_metadata_value(&root, version);
        wrong_requirement["packages"][1]["dependencies"][0]["req"] = serde_json::json!("*");
        assert!(
            validate_internal_dependency_metadata_json(
                &root,
                version,
                &serde_json::to_vec(&wrong_requirement).unwrap(),
            )
            .is_err()
        );

        let mut renamed_dependency = workspace_sync_metadata_value(&root, version);
        renamed_dependency["packages"][1]["dependencies"][0]["rename"] =
            serde_json::json!("renamed-core");
        assert!(
            validate_internal_dependency_metadata_json(
                &root,
                version,
                &serde_json::to_vec(&renamed_dependency).unwrap(),
            )
            .is_err()
        );
        cleanup_temp_test_root(root);
    }

    #[test]
    fn release_version_rejects_snapshot_and_other_prerelease_shapes() {
        for (case, version) in [
            ("snapshot", "0.5.0-0.pr.6.commit.shaaaaaaaaaaaaa"),
            ("beta", "0.5.0-beta.1"),
            ("zero-rc", "0.5.0-rc.0"),
            ("build", "0.5.0-rc.1+local"),
        ] {
            let root = temp_test_root(case);
            write_test_workspace_manifest(&root, version, version, "=0.4.0-rc.1");
            assert!(read_workspace_version(&root).is_err());
            cleanup_temp_test_root(root);
        }
    }

    #[test]
    fn stable_promotion_rewrites_exact_traits_rc() {
        let root = temp_test_root("promote-traits-rc");
        write_test_workspace_manifest(&root, "0.5.0-rc.1", "0.5.0-rc.1", "=0.4.0-rc.1");

        assert!(promote_traits_dependency_to_stable(&root).unwrap());

        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            workspace_dependency_version(&cargo_toml, TRAITS_PACKAGE).as_deref(),
            Some("=0.4.0")
        );
        cleanup_temp_test_root(root);
    }

    #[test]
    fn stable_promotion_preserves_exact_stable_traits() {
        let root = temp_test_root("preserve-stable-traits");
        write_test_workspace_manifest(&root, "0.5.0-rc.1", "0.5.0-rc.1", "=0.4.0");
        let before = fs::read_to_string(root.join("Cargo.toml")).unwrap();

        assert!(!promote_traits_dependency_to_stable(&root).unwrap());
        assert_eq!(fs::read_to_string(root.join("Cargo.toml")).unwrap(), before);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn stable_workspace_rejects_prerelease_traits() {
        let root = temp_test_root("reject-prerelease-traits");
        write_test_workspace_manifest(&root, "0.5.0", "0.5.0", "=0.4.0-rc.1");

        assert!(
            validate_stable_traits_dependency(&root, &Version::parse("0.5.0").unwrap()).is_err()
        );
        cleanup_temp_test_root(root);
    }

    #[test]
    fn stable_promotion_rejects_nonexact_or_non_rc_traits() {
        for (case, requirement) in [("nonexact", "0.4.0-rc.1"), ("non-rc", "=0.4.0-beta.1")] {
            let root = temp_test_root(case);
            write_test_workspace_manifest(&root, "0.5.0-rc.1", "0.5.0-rc.1", requirement);
            let before = fs::read_to_string(root.join("Cargo.toml")).unwrap();

            assert!(validate_promotable_traits_dependency(&root).is_err());
            assert_eq!(fs::read_to_string(root.join("Cargo.toml")).unwrap(), before);
            cleanup_temp_test_root(root);
        }
    }

    #[test]
    fn release_traits_dependency_accepts_crates_io_sources() {
        // Both Cargo's implicit default registry and its explicit canonical
        // name represent the same crates.io package identity.
        for (case, source) in [("implicit", ""), ("named", r#"registry = "crates-io""#)] {
            let root = temp_test_root(case);
            write_test_workspace_manifest_with_traits_source(
                &root,
                "0.5.0-rc.1",
                "0.5.0-rc.1",
                "=0.4.0-rc.1",
                source,
            );

            validate_crates_io_traits_dependency(&root).unwrap();
            cleanup_temp_test_root(root);
        }
    }

    #[test]
    fn release_traits_dependency_rejects_other_package_identities() {
        // Each source selector below could create a second traits crate whose
        // Rust types are incompatible with the registry package's types.
        for (case, source) in [
            (
                "git",
                r#"git = "https://github.com/NVIDIA/yaml-sigil-traits.git""#,
            ),
            ("path", r#"path = "../yaml-sigil-traits""#),
            ("registry", r#"registry = "internal""#),
            ("renamed", r#"package = "other-traits""#),
        ] {
            let root = temp_test_root(case);
            write_test_workspace_manifest_with_traits_source(
                &root,
                "0.5.0-rc.1",
                "0.5.0-rc.1",
                "=0.4.0-rc.1",
                source,
            );

            assert!(validate_crates_io_traits_dependency(&root).is_err());
            cleanup_temp_test_root(root);
        }
    }

    #[test]
    fn patch_advances_rc() {
        let current = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&current, &current, ReleaseBump::Patch).unwrap(),
            Version::parse("0.4.0-rc.4").unwrap()
        );
    }

    #[test]
    fn patch_starts_next_patch_rc_after_stable() {
        let current = Version::parse("0.4.0").unwrap();
        assert_eq!(
            candidate_version(&current, &current, ReleaseBump::Patch).unwrap(),
            Version::parse("0.4.1-rc.1").unwrap()
        );
    }

    #[test]
    fn explicit_minor_starts_new_rc_train() {
        let published = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&published, &published, ReleaseBump::Minor).unwrap(),
            Version::parse("0.5.0-rc.1").unwrap()
        );
    }

    #[test]
    fn release_intent_requires_one_exact_rc_transition() {
        assert_eq!(
            release_intent(
                &Version::parse("0.5.0-rc.1").unwrap(),
                &Version::parse("0.5.0-rc.2").unwrap()
            )
            .unwrap(),
            ReleaseIntent::Patch
        );
        assert_eq!(
            release_intent(
                &Version::parse("0.5.0-rc.2").unwrap(),
                &Version::parse("0.5.0").unwrap()
            )
            .unwrap(),
            ReleaseIntent::Patch
        );
        assert_eq!(
            release_intent(
                &Version::parse("0.5.0-rc.2").unwrap(),
                &Version::parse("0.6.0-rc.1").unwrap()
            )
            .unwrap(),
            ReleaseIntent::Minor
        );
        assert!(
            release_intent(
                &Version::parse("0.5.0-rc.1").unwrap(),
                &Version::parse("0.5.0-rc.3").unwrap()
            )
            .is_err()
        );
        assert!(
            release_intent(
                &Version::parse("0.5.0-rc.1").unwrap(),
                &Version::parse("0.6.0-rc.2").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn compatibility_checks_all_four_exact_workspace_packages() {
        let baseline = temp_test_root("compatibility-baseline");
        let current = temp_test_root("compatibility-current");
        write_release_workspace(&baseline, "0.5.0-rc.1");
        write_release_workspace(&current, "0.5.0-rc.2");
        let mut runner = FakeCargoRunner {
            outputs: VecDeque::from([
                cargo_success(
                    format!(
                        "cargo-semver-checks {}\n",
                        RUST_TOOLCHAIN.cargo_semver_checks_version
                    )
                    .into_bytes(),
                ),
                cargo_success(release_metadata(&baseline, "0.5.0-rc.1")),
                cargo_success(release_metadata(&current, "0.5.0-rc.2")),
            ]),
            statuses: VecDeque::from(
                RUST_POLICY
                    .packages
                    .iter()
                    .map(|_| {
                        Ok(CargoStatus {
                            success: true,
                            code: Some(0),
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            ..FakeCargoRunner::default()
        };

        check_api_compatibility_with_runner(
            &current,
            &baseline.join("Cargo.toml"),
            &current.join("Cargo.toml"),
            &Version::parse("0.5.0-rc.1").unwrap(),
            &Version::parse("0.5.0-rc.2").unwrap(),
            ReleaseIntent::Patch,
            &mut runner,
        )
        .unwrap();

        assert_eq!(runner.calls.len(), 3 + RUST_POLICY.packages.len());
        assert_eq!(runner.calls[0].program, "cargo-semver-checks");
        assert_eq!(runner.calls[0].args, ["semver-checks", "--version"]);
        for (index, policy) in RUST_POLICY.packages.iter().enumerate() {
            let call = &runner.calls[index + 3];
            assert_eq!(call.program, "cargo-semver-checks");
            assert_eq!(call.mode, CargoCallMode::Status);
            let package_index = call.args.iter().position(|arg| arg == "--package").unwrap();
            assert_eq!(call.args[package_index + 1], policy.package);
            let release_type_index = call
                .args
                .iter()
                .position(|arg| arg == "--release-type")
                .unwrap();
            assert_eq!(call.args[release_type_index + 1], "minor");
            assert!(
                call.args
                    .windows(2)
                    .any(|pair| pair == ["--all-features", "--color"])
            );
        }
        cleanup_temp_test_root(baseline);
        cleanup_temp_test_root(current);
    }

    #[test]
    fn compatibility_fails_before_analysis_on_tool_or_version_ambiguity() {
        let baseline = temp_test_root("compatibility-fail-baseline");
        let current = temp_test_root("compatibility-fail-current");
        write_release_workspace(&baseline, "0.5.0-rc.1");
        write_release_workspace(&current, "0.5.0-rc.2");

        let mut wrong_tool = FakeCargoRunner {
            outputs: VecDeque::from([cargo_success(b"cargo-semver-checks 0.48.0\n")]),
            ..FakeCargoRunner::default()
        };
        assert!(
            check_api_compatibility_with_runner(
                &current,
                &baseline.join("Cargo.toml"),
                &current.join("Cargo.toml"),
                &Version::parse("0.5.0-rc.1").unwrap(),
                &Version::parse("0.5.0-rc.2").unwrap(),
                ReleaseIntent::Patch,
                &mut wrong_tool,
            )
            .is_err()
        );
        assert!(wrong_tool.statuses.is_empty());

        let mut wrong_version = FakeCargoRunner {
            outputs: VecDeque::from([
                cargo_success(
                    format!(
                        "cargo-semver-checks {}\n",
                        RUST_TOOLCHAIN.cargo_semver_checks_version
                    )
                    .into_bytes(),
                ),
                cargo_success(release_metadata(&baseline, "0.5.0-rc.1")),
                cargo_success(release_metadata(&current, "0.5.0-rc.9")),
            ]),
            ..FakeCargoRunner::default()
        };
        assert!(
            check_api_compatibility_with_runner(
                &current,
                &baseline.join("Cargo.toml"),
                &current.join("Cargo.toml"),
                &Version::parse("0.5.0-rc.1").unwrap(),
                &Version::parse("0.5.0-rc.2").unwrap(),
                ReleaseIntent::Patch,
                &mut wrong_version,
            )
            .is_err()
        );
        assert!(wrong_version.statuses.is_empty());
        cleanup_temp_test_root(baseline);
        cleanup_temp_test_root(current);
    }

    #[test]
    fn compatibility_rejects_a_nonrepository_current_manifest() {
        let repository = temp_test_root("compatibility-repository");
        let baseline = temp_test_root("compatibility-detached");
        let foreign = temp_test_root("compatibility-foreign");
        write_release_workspace(&repository, "0.5.0-rc.2");
        write_release_workspace(&baseline, "0.5.0-rc.1");
        write_release_workspace(&foreign, "0.5.0-rc.2");
        let mut runner = FakeCargoRunner {
            outputs: VecDeque::from([cargo_success(
                format!(
                    "cargo-semver-checks {}\n",
                    RUST_TOOLCHAIN.cargo_semver_checks_version
                )
                .into_bytes(),
            )]),
            ..FakeCargoRunner::default()
        };
        assert!(
            check_api_compatibility_with_runner(
                &repository,
                &baseline.join("Cargo.toml"),
                &foreign.join("Cargo.toml"),
                &Version::parse("0.5.0-rc.1").unwrap(),
                &Version::parse("0.5.0-rc.2").unwrap(),
                ReleaseIntent::Patch,
                &mut runner,
            )
            .is_err()
        );
        assert_eq!(runner.calls.len(), 1);
        cleanup_temp_test_root(repository);
        cleanup_temp_test_root(baseline);
        cleanup_temp_test_root(foreign);
    }

    #[test]
    fn inserted_changelog_sections_remain_separated() {
        let body = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n";
        let section = "## [0.2.0](new) - 2026-08-19\n\n- New.";

        assert_eq!(
            insert_after_unreleased(body, section).unwrap(),
            "# Changelog\n\n## [Unreleased]\n\n## [0.2.0](new) - 2026-08-19\n\n- New.\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n"
        );
    }

    #[test]
    fn candidate_and_promotion_reject_oversized_changelogs_before_allocation() {
        let root = temp_test_root("oversized-changelog");
        for policy in RUST_POLICY.packages {
            let path = root.join(policy.changelog);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![b'x'; safe_file::MANIFEST_LIMIT + 1]).unwrap();
        }
        let rc = Version::parse("1.2.3-rc.1").unwrap();
        let stable = Version::parse("1.2.3").unwrap();

        for error in [
            format!(
                "{:#}",
                ensure_candidate_changelogs(&root, &rc, &rc, "2026-09-02").unwrap_err()
            ),
            format!(
                "{:#}",
                promote_changelogs(&root, &rc, &stable, "2026-09-02").unwrap_err()
            ),
        ] {
            assert!(
                error.contains(&format!(
                    "exceeds its {}-byte limit",
                    safe_file::MANIFEST_LIMIT
                )),
                "unexpected bounded changelog error: {error}"
            );
        }
        cleanup_temp_test_root(root);
    }

    #[derive(Debug, Eq, PartialEq)]
    enum CargoCallMode {
        Output,
        Status,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct CargoCall {
        mode: CargoCallMode,
        program: String,
        args: Vec<String>,
    }

    #[derive(Default)]
    struct FakeCargoRunner {
        outputs: VecDeque<Result<CargoOutput>>,
        statuses: VecDeque<Result<CargoStatus>>,
        calls: Vec<CargoCall>,
    }

    impl CargoRunner for FakeCargoRunner {
        fn output(
            &mut self,
            _root: &Path,
            program: &OsStr,
            args: &[OsString],
        ) -> Result<CargoOutput> {
            self.calls.push(CargoCall {
                mode: CargoCallMode::Output,
                program: program.to_string_lossy().into_owned(),
                args: args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            });
            self.outputs
                .pop_front()
                .expect("test supplied one output response per call")
        }

        fn status(
            &mut self,
            _root: &Path,
            program: &OsStr,
            args: &[OsString],
        ) -> Result<CargoStatus> {
            self.calls.push(CargoCall {
                mode: CargoCallMode::Status,
                program: program.to_string_lossy().into_owned(),
                args: args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            });
            self.statuses
                .pop_front()
                .expect("test supplied one status response per call")
        }
    }

    fn cargo_success(stdout: impl Into<Vec<u8>>) -> Result<CargoOutput> {
        Ok(CargoOutput {
            success: true,
            stdout: stdout.into(),
            stderr: Vec::new(),
        })
    }

    fn write_release_workspace(root: &Path, version: &str) {
        fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        for policy in RUST_POLICY.packages {
            let directory = root.join(policy.path_in_vcs);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{}\"\nversion = \"{version}\"\n",
                    policy.package
                ),
            )
            .unwrap();
        }
    }

    fn release_metadata(root: &Path, version: &str) -> Vec<u8> {
        let root = root.canonicalize().unwrap();
        let packages = RUST_POLICY
            .packages
            .iter()
            .map(|policy| {
                let package_root = root.join(policy.path_in_vcs);
                package(
                    policy.package,
                    version,
                    None,
                    &package_root.join("Cargo.toml").canonicalize().unwrap(),
                    Some(&["crates-io"]),
                    Vec::new(),
                    vec![target(
                        &policy.package.replace('-', "_"),
                        "lib",
                        &package_root.join("src/lib.rs"),
                    )],
                )
            })
            .collect();
        encoded(&metadata_value(&root, packages))
    }

    fn workspace_sync_metadata_value(root: &Path, version: &str) -> Value {
        let root = root.canonicalize().unwrap();
        let packages = RUST_POLICY
            .packages
            .iter()
            .map(|policy| {
                let dependencies: Vec<_> = match policy.package {
                    "yaml-sigil-core" => Vec::new(),
                    "yaml-sigil-transcription" => vec!["yaml-sigil-core"],
                    "yaml-sigil-signing" => {
                        vec!["yaml-sigil-core", "yaml-sigil-transcription"]
                    }
                    "yaml-sigil-verification" => vec![
                        "yaml-sigil-core",
                        "yaml-sigil-transcription",
                        "yaml-sigil-signing",
                    ],
                    package => panic!("unexpected release package {package}"),
                }
                .into_iter()
                .map(|name| {
                    let dependency_policy = RUST_POLICY
                        .packages
                        .iter()
                        .find(|policy| policy.package == name)
                        .unwrap();
                    dependency(
                        name,
                        &format!("^{version}"),
                        None,
                        None,
                        None,
                        Some(
                            &root
                                .join(dependency_policy.path_in_vcs)
                                .canonicalize()
                                .unwrap(),
                        ),
                    )
                })
                .collect();
                let package_root = root.join(policy.path_in_vcs);
                package(
                    policy.package,
                    version,
                    None,
                    &package_root.join("Cargo.toml").canonicalize().unwrap(),
                    Some(&["crates-io"]),
                    dependencies,
                    vec![target(
                        &policy.package.replace('-', "_"),
                        "lib",
                        &package_root.join("src/lib.rs"),
                    )],
                )
            })
            .collect();
        metadata_value(&root, packages)
    }

    fn workspace_sync_runner(root: &Path, version: &str) -> FakeCargoRunner {
        FakeCargoRunner {
            outputs: VecDeque::from([cargo_success(encoded(&workspace_sync_metadata_value(
                root, version,
            )))]),
            ..FakeCargoRunner::default()
        }
    }

    fn assert_workspace_sync_call(runner: &FakeCargoRunner) {
        assert_eq!(runner.calls.len(), 1);
        assert_eq!(runner.calls[0].mode, CargoCallMode::Output);
        assert_eq!(
            runner.calls[0].args,
            ["metadata", "--no-deps", "--format-version", "1"]
        );
    }

    fn temp_test_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "yaml-sigil-xtask-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn cleanup_temp_test_root(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }

    fn write_test_workspace_manifest(
        root: &Path,
        workspace_version: &str,
        internal_version: &str,
        traits_version: &str,
    ) {
        write_test_workspace_manifest_with_traits_source(
            root,
            workspace_version,
            internal_version,
            traits_version,
            "",
        );
    }

    fn write_test_workspace_manifest_with_traits_source(
        root: &Path,
        workspace_version: &str,
        internal_version: &str,
        traits_version: &str,
        traits_source: &str,
    ) {
        let traits_source = if traits_source.is_empty() {
            String::new()
        } else {
            format!("{traits_source}, ")
        };
        let cargo_toml = format!(
            r#"[workspace.package]
version = "{workspace_version}"

[workspace.dependencies]
yaml-sigil-core = {{ version = "{internal_version}", path = "crates/yaml-sigil-core", default-features = false }}
yaml-sigil-traits = {{ version = "{traits_version}", {traits_source}default-features = false }}
yaml-sigil-transcription = {{ version = "{internal_version}", path = "crates/yaml-sigil-transcription", default-features = false }}
yaml-sigil-verification = {{ version = "{internal_version}", path = "crates/yaml-sigil-verification", default-features = false }}
yaml-sigil-signing = {{ version = "{internal_version}", path = "crates/yaml-sigil-signing", default-features = false }}
"#
        );
        fs::write(root.join("Cargo.toml"), cargo_toml).unwrap();
        for policy in RUST_POLICY.packages {
            let directory = root.join(policy.path_in_vcs);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{}\"\nversion = \"{workspace_version}\"\n",
                    policy.package
                ),
            )
            .unwrap();
        }
    }
}
