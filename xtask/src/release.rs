// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral release preparation and verification tasks.

use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use cargo_metadata::{Metadata, Package, Target, TargetKind};
use clap::{Args, Subcommand};
use semver::Version;
use serde_json::Value;
use toml_edit::{DocumentMut, Item, Value as TomlValue};

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::cargo_metadata_output::{parse_bounded, publishes_to_crates_io};
use crate::release_policy::{RUST_POLICY, ReleaseToolchain, TRAITS_POLICY};
use crate::safe_file;

const REGISTRY_USER_AGENT: &str = "yaml-sigil-release-workflow/1.0";
const REGISTRY_ATTEMPTS: usize = 30;
const REGISTRY_RETRY_SECONDS: u64 = 10;
const COMPILED_RELEASE_CONFIG: &str = include_str!("../../.release-plz.toml");
#[cfg(test)]
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const TRAITS_PACKAGE: &str = TRAITS_POLICY.packages[0].package;

#[derive(Args)]
pub struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Install and verify the exact release analyzers.
    InstallTools,
    /// Require the exact ordered library-only crates.io package set.
    CheckPackages {
        /// Exact package names in dependency-safe publication order.
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },
    /// Verify exact non-yanked crates.io versions.
    VerifyRegistry {
        /// Check one exact version once instead of polling manifest versions.
        #[arg(long)]
        check_version: Option<Version>,
        /// Package names to verify.
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },
    /// Verify the exact external traits package identity and availability.
    VerifyTraits,
    /// Bind a release mutation to exact current remote main.
    RequireCurrentMain {
        /// Exact checked-out lowercase full commit SHA.
        #[arg(long)]
        head: String,
        /// Exact read-only origin URL used for remote-main verification.
        #[arg(long)]
        fetch_url: String,
    },
    /// Prepare a checkout-bound release-plz publication configuration.
    PreparePublicationConfig {
        /// Reviewed source configuration. Defaults to the compiled policy.
        #[arg(long)]
        source: Option<PathBuf>,
        /// New output path; existing files and symlinks are rejected.
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare a validation-only Cargo home with exact workspace patches.
    PrepareValidationCargoHome {
        /// New dedicated Cargo home directory.
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare an empty Cargo home for registry-ordered publication.
    PreparePublicationCargoHome {
        /// New dedicated Cargo home directory.
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare or verify an archive-bound official release baseline.
    Baseline(crate::release_baseline::BaselineArgs),
    /// Generate a provider-neutral release proposal transaction.
    Proposal(crate::release_proposal::ProposalArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Success,
    RegistryUnavailable,
}

pub fn release(root: &Path, args: ReleaseArgs) -> Result<Outcome> {
    match args.command {
        ReleaseCommand::InstallTools => {
            install_tools(root)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::CheckPackages { packages } => {
            validate_package_arguments(&packages)?;
            check_packages(root, &packages)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::VerifyRegistry {
            check_version,
            packages,
        } => {
            validate_package_arguments(&packages)?;
            verify_registry(root, check_version.as_ref(), &packages)
        }
        ReleaseCommand::VerifyTraits => verify_traits(root),
        ReleaseCommand::RequireCurrentMain { head, fetch_url } => {
            require_current_main(root, &head, &fetch_url)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::PreparePublicationConfig { source, output } => {
            prepare_publication_config(root, source.as_deref(), &output)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::PrepareValidationCargoHome { output } => {
            prepare_validation_cargo_home(root, &output)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::PreparePublicationCargoHome { output } => {
            prepare_publication_cargo_home(root, &output)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::Baseline(args) => {
            crate::release_baseline::run(root, args).map_err(anyhow::Error::msg)?;
            Ok(Outcome::Success)
        }
        ReleaseCommand::Proposal(args) => {
            crate::release_proposal::run(root, args).map_err(anyhow::Error::msg)?;
            Ok(Outcome::Success)
        }
    }
}

fn validate_package_arguments(packages: &[String]) -> Result<()> {
    if packages.is_empty() {
        bail!("at least one crate name is required");
    }
    let mut unique = BTreeSet::new();
    for package in packages {
        validate_crate_name(package)?;
        if !unique.insert(package) {
            bail!("duplicate crate name: {package}");
        }
    }
    Ok(())
}

fn validate_crate_name(package: &str) -> Result<()> {
    let mut bytes = package.bytes();
    let valid_start = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_rest = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    });
    if valid_start && valid_rest {
        Ok(())
    } else {
        bail!("invalid crate name: {package}")
    }
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

#[derive(Debug)]
struct CommandResult {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct CommandStatus {
    success: bool,
    code: Option<i32>,
}

trait Runner {
    fn output(&mut self, program: &OsStr, args: &[OsString], root: &Path) -> Result<CommandResult>;

    fn status(&mut self, program: &OsStr, args: &[OsString], root: &Path) -> Result<CommandStatus>;

    fn sleep(&mut self, duration: Duration);
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn output(&mut self, program: &OsStr, args: &[OsString], root: &Path) -> Result<CommandResult> {
        let mut command = Command::new(program);
        command.current_dir(root).args(args);
        let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
            .with_context(|| format!("run {}", program.to_string_lossy()))?;
        Ok(CommandResult {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn status(&mut self, program: &OsStr, args: &[OsString], root: &Path) -> Result<CommandStatus> {
        let status = Command::new(program)
            .current_dir(root)
            .args(args)
            .status()
            .with_context(|| format!("run {}", program.to_string_lossy()))?;
        Ok(CommandStatus {
            success: status.success(),
            code: status.code(),
        })
    }

    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

fn output_detail(output: &CommandResult) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn process_output_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

pub(crate) fn exact_output_line(output: &[u8], label: &str) -> Result<String> {
    let output = std::str::from_utf8(output)
        .with_context(|| format!("{label} returned non-UTF-8 output"))?;
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    if line.is_empty() || line.contains(['\r', '\n']) {
        bail!("{label} did not return one exact line");
    }
    Ok(line.to_string())
}

fn install_tools(root: &Path) -> Result<()> {
    let toolchain = crate::release_policy::detect(root)
        .map_err(anyhow::Error::msg)?
        .toolchain;
    let mut runner = SystemRunner;
    install_tools_with(root, toolchain, &mut runner)
}

fn install_tools_with(
    root: &Path,
    toolchain: ReleaseToolchain,
    runner: &mut impl Runner,
) -> Result<()> {
    // cargo-binstall reserves --version for package selection; -V reports
    // the installed cargo-binstall version.
    require_command_version(
        root,
        runner,
        OsStr::new("cargo-binstall"),
        &[OsString::from("-V")],
        toolchain.cargo_binstall_version,
    )?;
    let install_args = [
        OsString::from("--force"),
        OsString::from("--locked"),
        OsString::from("--no-confirm"),
        OsString::from("--strategies=crate-meta-data,compile"),
        OsString::from(format!("release-plz@{}", toolchain.release_plz_version)),
        OsString::from(format!(
            "cargo-semver-checks@{}",
            toolchain.cargo_semver_checks_version
        )),
    ];
    let status = runner.status(OsStr::new("cargo-binstall"), &install_args, root)?;
    if !status.success {
        bail!(
            "cargo-binstall failed with status {}",
            status
                .code
                .map_or_else(|| "signal".to_string(), |code| code.to_string())
        );
    }
    require_command_version(
        root,
        runner,
        OsStr::new("release-plz"),
        &[OsString::from("--version")],
        &format!("release-plz {}", toolchain.release_plz_version),
    )?;
    require_command_version(
        root,
        runner,
        OsStr::new("cargo-semver-checks"),
        &[OsString::from("semver-checks"), OsString::from("--version")],
        &format!(
            "cargo-semver-checks {}",
            toolchain.cargo_semver_checks_version
        ),
    )?;
    eprintln!("release: installed and verified the exact release analyzers");
    Ok(())
}

fn require_command_version(
    root: &Path,
    runner: &mut impl Runner,
    program: &OsStr,
    args: &[OsString],
    expected: &str,
) -> Result<()> {
    let output = runner.output(program, args, root)?;
    if !output.success {
        bail!(
            "{} version check failed: {}",
            program.to_string_lossy(),
            output_detail(&output)
        );
    }
    let actual = exact_output_line(
        &output.stdout,
        &format!("{} version", program.to_string_lossy()),
    )?;
    if actual != expected {
        bail!("expected {expected}; found {actual}");
    }
    Ok(())
}

fn cargo_metadata(
    root: &Path,
    with_dependencies: bool,
    runner: &mut impl Runner,
) -> Result<Metadata> {
    let mut args = vec![OsString::from("metadata")];
    if !with_dependencies {
        args.push(OsString::from("--no-deps"));
    }
    args.extend([OsString::from("--format-version"), OsString::from("1")]);
    let output = runner.output(&cargo_program(), &args, root)?;
    if !output.success {
        bail!("Cargo metadata failed: {}", output_detail(&output));
    }
    parse_bounded(&output.stdout, "Cargo returned invalid metadata").map_err(anyhow::Error::msg)
}

fn check_packages(root: &Path, expected: &[String]) -> Result<()> {
    let mut runner = SystemRunner;
    let metadata = cargo_metadata(root, false, &mut runner)?;
    check_packages_in_metadata(&metadata, expected)?;
    eprintln!(
        "release: validated library-only crates.io package order: {}",
        expected.join(" ")
    );
    Ok(())
}

fn check_packages_in_metadata(metadata: &Metadata, expected: &[String]) -> Result<()> {
    let mut actual = Vec::new();
    for package in &metadata.packages {
        let name = package.name.as_str();
        if !publishes_to_crates_io(package.publish.as_deref()).map_err(anyhow::Error::msg)? {
            continue;
        }
        validate_publishable_package_identity(metadata, name, package, &package.targets)?;
        for target in &package.targets {
            if target.kind.contains(&TargetKind::Bin) {
                bail!("crates.io package {name} contains a binary target");
            }
            if target.kind.contains(&TargetKind::CustomBuild) {
                validate_publishable_build_script(metadata, name, target)?;
            }
        }
        actual.push(name.to_string());
    }
    if actual != expected {
        bail!(
            "crates.io package order differs: expected [{}], found [{}]",
            expected.join(", "),
            actual.join(", ")
        );
    }
    Ok(())
}

fn validate_publishable_package_identity(
    metadata: &Metadata,
    package_name: &str,
    package: &Package,
    targets: &[Target],
) -> Result<()> {
    let relative = RUST_POLICY
        .packages
        .iter()
        .find_map(|policy| (policy.package == package_name).then_some(policy.path_in_vcs))
        .ok_or_else(|| {
            anyhow!("crates.io package {package_name} has no approved workspace identity")
        })?;
    let package_root = metadata.workspace_root.as_std_path().join(relative);
    let expected_manifest = package_root.join("Cargo.toml");
    if package.manifest_path.as_std_path() != expected_manifest {
        bail!(
            "crates.io package {package_name} manifest differs from {}",
            expected_manifest.display()
        );
    }

    let expected_library = package_root.join("src/lib.rs");
    let libraries: Vec<_> = targets
        .iter()
        .filter(|target| target.kind.as_slice() == [TargetKind::Lib])
        .collect();
    if libraries.len() != 1 {
        bail!("crates.io package {package_name} must contain one exact primary library target");
    }
    if libraries[0].src_path.as_std_path() != expected_library {
        bail!(
            "crates.io package {package_name} library differs from {}",
            expected_library.display()
        );
    }
    Ok(())
}

fn validate_publishable_build_script(
    metadata: &Metadata,
    package: &str,
    target: &Target,
) -> Result<()> {
    let core = &RUST_POLICY.packages[0];
    if package != core.package || target.kind.as_slice() != [TargetKind::CustomBuild] {
        bail!("crates.io package {package} contains an unexpected build script");
    }
    let expected = metadata
        .workspace_root
        .as_std_path()
        .join(core.path_in_vcs)
        .join("build.rs");
    if target.src_path.as_std_path() != expected {
        bail!(
            "crates.io package {package} build script differs from {}",
            expected.display()
        );
    }
    Ok(())
}

fn verify_registry(
    root: &Path,
    requested_version: Option<&Version>,
    packages: &[String],
) -> Result<Outcome> {
    let mut runner = SystemRunner;
    verify_registry_with(root, requested_version, packages, &mut runner)
}

fn verify_registry_with(
    root: &Path,
    requested_version: Option<&Version>,
    packages: &[String],
    runner: &mut impl Runner,
) -> Result<Outcome> {
    let metadata = requested_version
        .is_none()
        .then(|| cargo_metadata(root, false, runner))
        .transpose()?;
    let mut unavailable = false;

    for package in packages {
        let version = match requested_version {
            Some(version) => version.clone(),
            None => metadata_package_version(
                metadata
                    .as_ref()
                    .expect("metadata is available during publication verification"),
                package,
            )?,
        };
        let attempts = if requested_version.is_some() {
            1
        } else {
            REGISTRY_ATTEMPTS
        };
        let mut available = false;
        for attempt in 1..=attempts {
            match query_registry(root, package, &version, runner)? {
                RegistryState::Available => {
                    available = true;
                    break;
                }
                RegistryState::Missing if requested_version.is_some() => {
                    unavailable = true;
                    break;
                }
                RegistryState::Missing if attempt == attempts => {
                    bail!("crates.io did not expose {package} {version} as non-yanked");
                }
                RegistryState::Missing => {
                    runner.sleep(Duration::from_secs(REGISTRY_RETRY_SECONDS));
                }
            }
        }

        if requested_version.is_none() {
            if !available {
                bail!("crates.io did not expose {package} {version}");
            }
            verify_cargo_resolution(root, package, &version, runner)?;
            eprintln!("release: verified {package} {version} on crates.io");
        }
    }

    Ok(if unavailable {
        Outcome::RegistryUnavailable
    } else {
        Outcome::Success
    })
}

fn metadata_package_version(metadata: &Metadata, package: &str) -> Result<Version> {
    let matches: Vec<_> = metadata
        .packages
        .iter()
        .filter(|item| item.name == package)
        .collect();
    if matches.len() != 1 {
        bail!(
            "expected one workspace package named {package}; found {}",
            matches.len()
        );
    }
    Ok(matches[0].version.clone())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryState {
    Available,
    Missing,
}

fn query_registry(
    root: &Path,
    package: &str,
    version: &Version,
    runner: &mut impl Runner,
) -> Result<RegistryState> {
    let url = format!("https://crates.io/api/v1/crates/{package}/{version}");
    let args = [
        OsString::from("--silent"),
        OsString::from("--show-error"),
        OsString::from("--write-out"),
        OsString::from("\n%{http_code}"),
        OsString::from("--user-agent"),
        OsString::from(REGISTRY_USER_AGENT),
        OsString::from(url),
    ];
    let output = runner.output(OsStr::new("curl"), &args, root)?;
    if !output.success {
        bail!("crates.io request failed: {}", output_detail(&output));
    }
    parse_registry_response(package, version, &output.stdout)
}

fn parse_registry_response(
    package: &str,
    version: &Version,
    output: &[u8],
) -> Result<RegistryState> {
    let output = std::str::from_utf8(output).context("crates.io returned non-UTF-8 data")?;
    let (body, status) = output
        .rsplit_once('\n')
        .ok_or_else(|| anyhow!("crates.io response lacked an HTTP status"))?;
    match status {
        "404" => Ok(RegistryState::Missing),
        "200" => {
            let value: Value =
                serde_json::from_str(body).context("crates.io returned invalid JSON")?;
            let record = value
                .get("version")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow!("crates.io returned no exact version record"))?;
            let exact = record.get("num").and_then(Value::as_str) == Some(&version.to_string());
            let non_yanked = record.get("yanked").and_then(Value::as_bool) == Some(false);
            if exact && non_yanked {
                Ok(RegistryState::Available)
            } else {
                bail!("crates.io did not report {package} {version} as non-yanked")
            }
        }
        other => bail!("crates.io returned HTTP {other} for {package} {version}"),
    }
}

fn verify_cargo_resolution(
    root: &Path,
    package: &str,
    version: &Version,
    runner: &mut impl Runner,
) -> Result<()> {
    let args = [
        OsString::from("info"),
        OsString::from("--quiet"),
        OsString::from("--registry"),
        OsString::from("crates-io"),
        OsString::from(format!("{package}@{version}")),
    ];
    let output = runner.output(&cargo_program(), &args, root)?;
    if output.success {
        Ok(())
    } else {
        bail!(
            "Cargo could not resolve {package} {version} from crates.io: {}",
            output_detail(&output)
        )
    }
}

fn verify_traits(root: &Path) -> Result<Outcome> {
    let mut runner = SystemRunner;
    verify_traits_with(root, &mut runner)
}

fn verify_traits_with(root: &Path, runner: &mut impl Runner) -> Result<Outcome> {
    let traits_package = TRAITS_PACKAGE;
    let direct = cargo_metadata(root, false, runner)?;
    let version = exact_traits_dependency(&direct)?;
    let packages = [traits_package.to_string()];
    let readiness = verify_registry_with(root, Some(&version), &packages, runner)?;
    if readiness == Outcome::RegistryUnavailable {
        return Ok(readiness);
    }
    verify_cargo_resolution(root, traits_package, &version, runner)?;

    let resolved = cargo_metadata(root, true, runner)?;
    let identities: BTreeSet<_> = resolved
        .packages
        .iter()
        .filter(|package| package.name == traits_package)
        .map(|package| {
            let source = package
                .source
                .as_ref()
                .ok_or_else(|| anyhow!("resolved traits package has no source"))?;
            Ok((package.version.clone(), source.is_crates_io()))
        })
        .collect::<Result<_>>()?;
    let expected = (version.clone(), true);
    if identities.len() != 1 || !identities.contains(&expected) {
        bail!("Cargo did not resolve the exact yaml-sigil-traits crates.io source");
    }
    eprintln!("release: verified {traits_package} {version} from the named crates.io index");
    Ok(Outcome::Success)
}

fn exact_traits_dependency(metadata: &Metadata) -> Result<Version> {
    let traits_package = TRAITS_PACKAGE;
    let mut records = BTreeSet::new();
    for package in &metadata.packages {
        for dependency in &package.dependencies {
            if dependency.name != traits_package {
                continue;
            }
            let source = dependency
                .source
                .as_ref()
                .ok_or_else(|| anyhow!("traits dependency has no source"))?;
            records.insert((
                dependency.req.to_string(),
                source.is_crates_io(),
                dependency.registry.clone(),
                dependency.rename.clone(),
            ));
        }
    }
    let records: Vec<_> = records.into_iter().collect();
    let [(requirement, crates_io, registry, rename)] = records.as_slice() else {
        bail!("expected one exact yaml-sigil-traits dependency identity");
    };
    if !crates_io || registry.is_some() || rename.is_some() {
        bail!("yaml-sigil-traits must use one exact crates.io package identity");
    }
    let value = requirement
        .strip_prefix('=')
        .ok_or_else(|| anyhow!("yaml-sigil-traits requirement must be exact"))?;
    let version = Version::parse(value).context("invalid exact yaml-sigil-traits requirement")?;
    if requirement != &format!("={version}") {
        bail!("yaml-sigil-traits requirement must be one exact version");
    }
    Ok(version)
}

fn is_lowercase_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_current_main(root: &Path, head: &str, fetch_url: &str) -> Result<()> {
    if !is_lowercase_sha(head) {
        bail!("--head must be a lowercase full 40-character SHA");
    }
    if fetch_url.is_empty() || fetch_url.starts_with('-') || fetch_url.contains(['\0', '\r', '\n'])
    {
        bail!("--fetch-url must be one non-option Git URL");
    }
    let mut runner = SystemRunner;
    require_current_main_with(root, head, fetch_url, &mut runner)
}

fn require_current_main_with(
    root: &Path,
    head: &str,
    fetch_url: &str,
    runner: &mut impl Runner,
) -> Result<()> {
    let checkout = git_line(root, runner, &["rev-parse", "HEAD"])?;
    if checkout != head {
        bail!("the release checkout is not at the triggering main commit");
    }
    let origin = git_line(root, runner, &["remote", "get-url", "origin"])?;
    if origin != fetch_url {
        bail!("origin does not use the expected release fetch URL");
    }
    let args = [
        OsString::from("ls-remote"),
        OsString::from("--exit-code"),
        OsString::from(fetch_url),
        OsString::from("refs/heads/main"),
    ];
    let output = runner.output(OsStr::new("git"), &args, root)?;
    if !output.success {
        bail!("git ls-remote failed: {}", output_detail(&output));
    }
    let remote = exact_output_line(&output.stdout, "remote main")?;
    let (remote_head, remote_ref) = remote
        .split_once('\t')
        .ok_or_else(|| anyhow!("origin returned an invalid main ref"))?;
    if remote_ref.contains('\t')
        || !is_lowercase_sha(remote_head)
        || remote_ref != "refs/heads/main"
        || remote_head != head
    {
        bail!("remote main changed before the release mutation");
    }
    eprintln!("release: verified exact current remote main {head}");
    Ok(())
}

fn git_line(root: &Path, runner: &mut impl Runner, args: &[&str]) -> Result<String> {
    let args: Vec<_> = args.iter().map(OsString::from).collect();
    let output = runner.output(OsStr::new("git"), &args, root)?;
    if !output.success {
        bail!("Git command failed: {}", output_detail(&output));
    }
    exact_output_line(&output.stdout, "Git command")
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn require_publication_fields(
    document: &DocumentMut,
    release_always: bool,
    branch_prefix: Option<&str>,
) -> Result<()> {
    let workspace = document
        .get("workspace")
        .and_then(Item::as_table)
        .ok_or_else(|| anyhow!("release config has no workspace table"))?;
    if workspace.get("release_always").and_then(Item::as_bool) != Some(release_always) {
        bail!("reviewed config must set release_always = {release_always}");
    }
    for field in ["git_tag_enable", "git_release_enable"] {
        if workspace.get(field).and_then(Item::as_bool) != Some(false) {
            bail!("reviewed workspace config must set {field} = false");
        }
    }
    let packages = document
        .get("package")
        .and_then(Item::as_array_of_tables)
        .ok_or_else(|| anyhow!("release config has no package overrides"))?;
    if packages.len() != RUST_POLICY.packages.len() {
        bail!("release config has an unexpected package override set");
    }
    for (package, policy) in packages.iter().zip(RUST_POLICY.packages) {
        if package.get("name").and_then(Item::as_str) != Some(policy.package) {
            bail!("release config package overrides are not exact or ordered");
        }
        for field in ["git_tag_enable", "git_release_enable"] {
            if package.get(field).and_then(Item::as_bool) != Some(false) {
                bail!(
                    "reviewed {} config must set {field} = false",
                    policy.package
                );
            }
        }
    }
    match (workspace.get("pr_branch_prefix"), branch_prefix) {
        (None, None) => Ok(()),
        (Some(value), Some(expected)) if value.as_str() == Some(expected) => Ok(()),
        (Some(_), None) => bail!("reviewed config already selects a PR branch prefix"),
        _ => bail!("publication config has an invalid PR branch prefix"),
    }
}

fn release_config_relative(root: &Path, source: &Path) -> Result<PathBuf> {
    let relative = source.strip_prefix(root).unwrap_or(source);
    if relative.is_absolute() {
        bail!("release config must be inside the trusted checkout");
    }
    Ok(relative.to_path_buf())
}

fn source_newline(body: &str) -> Result<&'static str> {
    if body.contains("\r\n") {
        let without_crlf = body.replace("\r\n", "");
        if without_crlf.contains(['\r', '\n']) {
            bail!("release config uses mixed line endings");
        }
        Ok("\r\n")
    } else if body.contains('\r') {
        bail!("release config uses an unsupported line ending")
    } else {
        Ok("\n")
    }
}

fn prepare_publication_config(root: &Path, source: Option<&Path>, output: &Path) -> Result<()> {
    let output = resolve_path(root, output);
    if output.exists() {
        bail!("publication config already exists: {}", output.display());
    }
    let (body, source_label) = match source {
        Some(source) => {
            let source_relative = release_config_relative(root, source)?;
            let body = safe_file::TrustedRoot::open(root)
                .and_then(|trusted| trusted.read_manifest(&source_relative))
                .with_context(|| format!("read release config {}", source.display()))?;
            (body, source.display().to_string())
        }
        None => (
            COMPILED_RELEASE_CONFIG.to_string(),
            "compiled release policy".to_string(),
        ),
    };
    let original: DocumentMut = body
        .parse()
        .with_context(|| format!("parse release config {source_label}"))?;
    require_publication_fields(&original, false, None)?;

    let mut valid_ref_command = Command::new("git");
    valid_ref_command.current_dir(root).args([
        "check-ref-format",
        "--branch",
        "release-plz-publication",
    ]);
    let valid_ref = bounded_process::output(&mut valid_ref_command, VALIDATION_OUTPUT_LIMITS)
        .context("run git check-ref-format")?;
    if !valid_ref.status.success() {
        bail!(
            "git could not validate a known-good publication branch: {}",
            process_output_detail(&valid_ref)
        );
    }
    let mut invalid_ref_command = Command::new("git");
    invalid_ref_command.current_dir(root).args([
        "check-ref-format",
        "--branch",
        ":release-plz-publication",
    ]);
    let invalid_ref = bounded_process::output(&mut invalid_ref_command, VALIDATION_OUTPUT_LIMITS)
        .context("run git check-ref-format")?;
    if invalid_ref.status.success() {
        bail!("the publication branch prefix is a valid Git ref");
    }

    let newline = source_newline(&body)?;
    let workspace_marker = format!("[workspace]{newline}");
    if body.matches(&workspace_marker).count() != 1 {
        bail!("reviewed config has an ambiguous workspace table");
    }
    if body.matches("release_always = false").count() != 1 {
        bail!("reviewed config has an ambiguous release_always field");
    }
    let updated = body
        .replacen(
            &workspace_marker,
            &format!("{workspace_marker}pr_branch_prefix = \":\"{newline}"),
            1,
        )
        .replacen("release_always = false", "release_always = true", 1);
    write_new_verified_file(&output, updated.as_bytes(), |actual| {
        let text = std::str::from_utf8(actual).context("generated release config is not UTF-8")?;
        let document: DocumentMut = text
            .parse()
            .context("generated release config is invalid")?;
        require_publication_fields(&document, true, Some(":"))
    })?;
    eprintln!(
        "release: prepared checkout-bound publication config at {}",
        output.display()
    );
    Ok(())
}

fn write_new_verified_file(
    path: &Path,
    bytes: &[u8],
    verify: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).with_context(|| format!("write {}", path.display()));
    }
    let result = (|| {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("rewind {}", path.display()))?;
        let mut actual = Vec::with_capacity(bytes.len() + 1);
        Read::by_ref(&mut file)
            .take((bytes.len() + 1) as u64)
            .read_to_end(&mut actual)
            .with_context(|| format!("reread {}", path.display()))?;
        if actual != bytes {
            bail!("generated file bytes changed while writing");
        }
        verify(&actual)
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn create_exact_empty_directory(root: &Path, output: &Path, label: &str) -> Result<PathBuf> {
    let requested_output = resolve_path(root, output);
    let parent = requested_output
        .parent()
        .ok_or_else(|| anyhow!("{label} has no parent directory"))?;
    let name = requested_output
        .file_name()
        .ok_or_else(|| anyhow!("{label} has no final path component"))?;
    let parent_identity = parent
        .canonicalize()
        .with_context(|| format!("resolve {label} parent {}", parent.display()))?;
    if !parent_identity.is_dir() {
        bail!("{label} parent is not a directory: {}", parent.display());
    }
    // Derive the new child from the parent's filesystem identity. This keeps
    // the exact-path check valid across macOS aliases and Windows verbatim paths.
    let exact_output = parent_identity.join(name);
    match fs::symlink_metadata(&exact_output) {
        Ok(_) => bail!("{label} already exists: {}", requested_output.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect {label} {}", requested_output.display()));
        }
    }

    fs::create_dir(&exact_output)
        .with_context(|| format!("create {label} {}", requested_output.display()))?;
    let identity = exact_output
        .canonicalize()
        .with_context(|| format!("resolve {label} {}", requested_output.display()))?;
    if identity != exact_output {
        let _ = fs::remove_dir(&exact_output);
        bail!("{label} is not an exact directory");
    }
    if fs::read_dir(&exact_output)
        .with_context(|| format!("read {label} {}", requested_output.display()))?
        .next()
        .is_some()
    {
        let _ = fs::remove_dir(&exact_output);
        bail!("{label} is not empty");
    }
    Ok(exact_output)
}

fn prepare_validation_cargo_home(root: &Path, output: &Path) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolve workspace root {}", root.display()))?;

    let mut expected = Vec::new();
    for policy in RUST_POLICY.packages {
        let package = policy.package;
        let requested_path = root.join(policy.path_in_vcs);
        let path = requested_path.canonicalize().with_context(|| {
            format!(
                "resolve workspace package path {}",
                requested_path.display()
            )
        })?;
        if path != requested_path {
            bail!("workspace package {package} path is not an exact directory");
        }
        let manifest = path.join("Cargo.toml");
        let manifest_identity = manifest
            .canonicalize()
            .with_context(|| format!("resolve workspace package manifest for {package}"))?;
        if manifest_identity != manifest || !manifest_identity.is_file() {
            bail!("workspace package {package} lacks an exact Cargo.toml");
        }
        let value = path
            .to_str()
            .ok_or_else(|| anyhow!("workspace package path is not UTF-8: {}", path.display()))?;
        expected.push((package.to_string(), value.to_string()));
    }
    let mut body = String::from("[patch.crates-io]\n");
    for (package, path) in &expected {
        let encoded = serde_json::to_string(path).context("encode Cargo patch path")?;
        body.push_str(&format!("{package} = {{ path = {encoded} }}\n"));
    }

    let output = create_exact_empty_directory(&root, output, "validation Cargo home")?;
    let config = output.join("config.toml");
    let result = write_new_verified_file(&config, body.as_bytes(), |actual| {
        let text = std::str::from_utf8(actual).context("Cargo patch config is not UTF-8")?;
        let parsed: DocumentMut = text.parse().context("Cargo patch config is invalid")?;
        let table = parsed
            .get("patch")
            .and_then(Item::as_table)
            .and_then(|patch| patch.get("crates-io"))
            .and_then(Item::as_table)
            .ok_or_else(|| anyhow!("Cargo patch config lacks [patch.crates-io]"))?;
        if table.len() != expected.len() {
            bail!("Cargo patch config has an unexpected package set");
        }
        for (package, path) in &expected {
            let actual = table
                .get(package)
                .and_then(Item::as_inline_table)
                .and_then(|value| value.get("path"))
                .and_then(TomlValue::as_str);
            if actual != Some(path) {
                bail!("Cargo patch config has an unexpected path for {package}");
            }
        }
        Ok(())
    });
    if result.is_err() {
        let _ = fs::remove_file(&config);
        let _ = fs::remove_dir(&output);
    }
    result?;
    eprintln!(
        "release: prepared validation-only Cargo home at {}",
        output.display()
    );
    Ok(())
}

fn prepare_publication_cargo_home(root: &Path, output: &Path) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolve workspace root {}", root.display()))?;
    let output = create_exact_empty_directory(&root, output, "publication Cargo home")?;
    eprintln!(
        "release: prepared unpatched publication Cargo home at {}",
        output.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_metadata_output::test_support::{
        dependency, encoded, metadata as metadata_value, package, target,
    };
    use crate::release_policy::RUST_TOOLCHAIN;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    const CRATES_IO: &[&str] = &["crates-io"];
    const DISABLED: &[&str] = &[];

    #[derive(Debug, Eq, PartialEq)]
    enum CallMode {
        Output,
        Status,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Call {
        mode: CallMode,
        program: String,
        args: Vec<String>,
    }

    #[derive(Default)]
    struct FakeRunner {
        outputs: VecDeque<Result<CommandResult>>,
        statuses: VecDeque<Result<CommandStatus>>,
        calls: Vec<Call>,
        sleeps: Vec<Duration>,
    }

    impl Runner for FakeRunner {
        fn output(
            &mut self,
            program: &OsStr,
            args: &[OsString],
            _root: &Path,
        ) -> Result<CommandResult> {
            self.calls.push(Call {
                mode: CallMode::Output,
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
            program: &OsStr,
            args: &[OsString],
            _root: &Path,
        ) -> Result<CommandStatus> {
            self.calls.push(Call {
                mode: CallMode::Status,
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

        fn sleep(&mut self, duration: Duration) {
            self.sleeps.push(duration);
        }
    }

    fn success(stdout: impl Into<Vec<u8>>) -> Result<CommandResult> {
        Ok(CommandResult {
            success: true,
            stdout: stdout.into(),
            stderr: Vec::new(),
        })
    }

    fn failed(stderr: &str) -> Result<CommandResult> {
        Ok(CommandResult {
            success: false,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    fn expected_release_packages() -> Vec<String> {
        RUST_POLICY
            .packages
            .iter()
            .map(|policy| policy.package.to_string())
            .collect()
    }

    fn release_package_metadata(
        publish: Option<&[&str]>,
        include_core_build_script: bool,
        mut additional_packages: Vec<Value>,
    ) -> Value {
        let mut packages: Vec<_> = RUST_POLICY
            .packages
            .iter()
            .map(|policy| release_package_fixture(policy, publish, include_core_build_script))
            .collect();
        packages.append(&mut additional_packages);
        metadata_value(Path::new("/workspace"), packages)
    }

    fn release_package_fixture(
        policy: &crate::release_policy::PackagePolicy,
        publish: Option<&[&str]>,
        include_core_build_script: bool,
    ) -> Value {
        let package_root = Path::new("/workspace").join(policy.path_in_vcs);
        let mut targets = vec![target(
            &policy.package.replace('-', "_"),
            "lib",
            &package_root.join("src/lib.rs"),
        )];
        if include_core_build_script && policy.package == RUST_POLICY.packages[0].package {
            targets.push(target(
                "build-script-build",
                "custom-build",
                &package_root.join("build.rs"),
            ));
        }
        package(
            policy.package,
            "0.5.0-rc.1",
            None,
            &package_root.join("Cargo.toml"),
            publish,
            Vec::new(),
            targets,
        )
    }

    fn parse_test_metadata(metadata: &Value) -> Result<Metadata, String> {
        parse_bounded(&encoded(metadata), "Cargo returned invalid metadata")
    }

    fn parsed_metadata(metadata: &Value) -> Metadata {
        parse_test_metadata(metadata).unwrap()
    }

    #[test]
    fn exact_lines_accept_only_one_unpadded_record() {
        let expected = format!("release-plz {}", RUST_TOOLCHAIN.release_plz_version);
        for suffix in ["", "\n", "\r\n"] {
            let value = format!("{expected}{suffix}");
            assert_eq!(
                exact_output_line(value.as_bytes(), "version").unwrap(),
                expected
            );
        }
        for value in [
            String::new(),
            format!("{expected}\r"),
            format!("{expected}\nextra\n"),
            format!(" {expected}\n"),
        ] {
            let parsed = exact_output_line(value.as_bytes(), "version");
            if value.starts_with(' ') {
                assert_ne!(parsed.unwrap(), expected);
            } else {
                assert!(parsed.is_err());
            }
        }
        assert!(exact_output_line(&[0xff], "version").is_err());
    }

    #[test]
    fn tool_installation_binds_exact_alias_resistant_versions() {
        let mut runner = FakeRunner {
            outputs: VecDeque::from([
                success(format!("{}\n", RUST_TOOLCHAIN.cargo_binstall_version).into_bytes()),
                success(
                    format!("release-plz {}\n", RUST_TOOLCHAIN.release_plz_version).into_bytes(),
                ),
                success(
                    format!(
                        "cargo-semver-checks {}\r\n",
                        RUST_TOOLCHAIN.cargo_semver_checks_version
                    )
                    .into_bytes(),
                ),
            ]),
            statuses: VecDeque::from([Ok(CommandStatus {
                success: true,
                code: Some(0),
            })]),
            ..FakeRunner::default()
        };

        install_tools_with(Path::new("."), RUST_TOOLCHAIN, &mut runner).unwrap();

        assert_eq!(runner.calls[0].program, "cargo-binstall");
        assert_eq!(runner.calls[0].args, ["-V"]);
        assert_eq!(runner.calls[1].mode, CallMode::Status);
        assert_eq!(runner.calls[1].program, "cargo-binstall");
        assert!(runner.calls[1].args.contains(&format!(
            "release-plz@{}",
            RUST_TOOLCHAIN.release_plz_version
        )));
        assert!(runner.calls[1].args.contains(&format!(
            "cargo-semver-checks@{}",
            RUST_TOOLCHAIN.cargo_semver_checks_version
        )));
        assert_eq!(runner.calls[3].program, "cargo-semver-checks");
        assert_eq!(runner.calls[3].args, ["semver-checks", "--version"]);
    }

    #[test]
    fn tool_installation_fails_before_mutation_on_wrong_bootstrap() {
        let mut runner = FakeRunner {
            outputs: VecDeque::from([success(b"9.9.9\n")]),
            ..FakeRunner::default()
        };
        assert!(install_tools_with(Path::new("."), RUST_TOOLCHAIN, &mut runner).is_err());
        assert!(runner.statuses.is_empty());
        assert_eq!(runner.calls.len(), 1);
    }

    #[test]
    fn package_policy_requires_exact_order_and_library_targets() {
        let core = &RUST_POLICY.packages[0];
        let metadata = release_package_metadata(Some(CRATES_IO), true, Vec::new());
        let expected = expected_release_packages();
        check_packages_in_metadata(&parsed_metadata(&metadata), &expected).unwrap();

        let mut reordered = expected.clone();
        reordered.swap(0, 1);
        assert!(check_packages_in_metadata(&parsed_metadata(&metadata), &reordered).is_err());
        let mut binary = metadata.clone();
        binary["packages"][0]["targets"]
            .as_array_mut()
            .unwrap()
            .push(target(
                "yaml-sigil-core-bin",
                "bin",
                Path::new("/workspace/crates/yaml-sigil-core/src/main.rs"),
            ));
        assert!(check_packages_in_metadata(&parsed_metadata(&binary), &expected).is_err());

        let mut wrong_package = metadata.clone();
        wrong_package["packages"][1]["targets"]
            .as_array_mut()
            .unwrap()
            .push(target(
                "build-script-build",
                "custom-build",
                Path::new("/workspace/crates/yaml-sigil-transcription/build.rs"),
            ));
        assert!(check_packages_in_metadata(&parsed_metadata(&wrong_package), &expected).is_err());

        let mut wrong_source = metadata;
        wrong_source["packages"][0]["targets"][1]["src_path"] =
            serde_json::json!(format!("/workspace/{}/other.rs", core.path_in_vcs));
        assert!(check_packages_in_metadata(&parsed_metadata(&wrong_source), &expected).is_err());
    }

    #[test]
    fn package_policy_includes_cargo_default_publish_packages() {
        let expected = expected_release_packages();
        let metadata = release_package_metadata(None, false, Vec::new());
        check_packages_in_metadata(&parsed_metadata(&metadata), &expected).unwrap();

        let root = Path::new("/workspace/unreviewed");
        let extra_package = package(
            "unreviewed-default-publish",
            "0.1.0",
            None,
            &root.join("Cargo.toml"),
            None,
            Vec::new(),
            vec![target(
                "unreviewed_default_publish",
                "lib",
                &root.join("src/lib.rs"),
            )],
        );
        let extra = release_package_metadata(None, false, vec![extra_package]);
        assert!(check_packages_in_metadata(&parsed_metadata(&extra), &expected).is_err());

        let mut binary = metadata;
        binary["packages"][0]["targets"][0]["kind"] = serde_json::json!(["bin"]);
        assert!(check_packages_in_metadata(&parsed_metadata(&binary), &expected).is_err());
    }

    #[test]
    fn package_policy_binds_each_manifest_and_primary_library() {
        let expected = expected_release_packages();
        let valid = release_package_metadata(Some(CRATES_IO), false, Vec::new());
        check_packages_in_metadata(&parsed_metadata(&valid), &expected).unwrap();

        let mut relocated_manifest = valid.clone();
        relocated_manifest["packages"][1]["manifest_path"] =
            Value::String("/workspace/relocated/Cargo.toml".to_string());
        assert!(
            check_packages_in_metadata(&parsed_metadata(&relocated_manifest), &expected).is_err()
        );

        let mut relocated_library = valid.clone();
        relocated_library["packages"][2]["targets"][0]["src_path"] =
            Value::String("/workspace/crates/yaml-sigil-signing/src/other.rs".to_string());
        assert!(
            check_packages_in_metadata(&parsed_metadata(&relocated_library), &expected).is_err()
        );

        let mut missing_library = valid.clone();
        missing_library["packages"][3]["targets"] = serde_json::json!([target(
            "api",
            "test",
            Path::new("/workspace/crates/yaml-sigil-verification/tests/api.rs"),
        )]);
        assert!(check_packages_in_metadata(&parsed_metadata(&missing_library), &expected).is_err());

        let mut duplicate_library = valid;
        let library = target(
            "yaml_sigil_core",
            "lib",
            Path::new("/workspace/crates/yaml-sigil-core/src/lib.rs"),
        );
        duplicate_library["packages"][0]["targets"] = serde_json::json!([library.clone(), library]);
        assert!(
            check_packages_in_metadata(&parsed_metadata(&duplicate_library), &expected).is_err()
        );
    }

    #[test]
    fn package_policy_excludes_disabled_and_rejects_other_registries() {
        let core = &RUST_POLICY.packages[0];
        let private_root = Path::new("/workspace/private");
        let private = package(
            "private",
            "0.1.0",
            None,
            &private_root.join("Cargo.toml"),
            Some(DISABLED),
            Vec::new(),
            vec![target("private", "bin", &private_root.join("src/main.rs"))],
        );
        let metadata = metadata_value(
            Path::new("/workspace"),
            vec![
                private,
                release_package_fixture(core, Some(CRATES_IO), false),
            ],
        );
        check_packages_in_metadata(&parsed_metadata(&metadata), &[core.package.to_string()])
            .unwrap();

        let alternate_root = Path::new("/workspace/alternate-registry");
        let alternate = package(
            "alternate-registry",
            "0.1.0",
            None,
            &alternate_root.join("Cargo.toml"),
            Some(&["internal"]),
            Vec::new(),
            vec![target(
                "alternate_registry",
                "lib",
                &alternate_root.join("src/lib.rs"),
            )],
        );
        let rejected = metadata_value(
            Path::new("/workspace"),
            vec![
                release_package_fixture(core, Some(CRATES_IO), false),
                alternate,
            ],
        );
        assert!(
            check_packages_in_metadata(&parsed_metadata(&rejected), &[core.package.to_string()])
                .is_err()
        );
    }

    #[test]
    fn package_policy_rejects_malformed_metadata_before_selection() {
        let valid = release_package_metadata(None, false, Vec::new());
        assert!(parse_test_metadata(&valid).is_ok());

        for publish in [
            serde_json::json!(true),
            serde_json::json!("crates-io"),
            serde_json::json!(["crates-io", 7]),
        ] {
            let mut malformed = valid.clone();
            malformed["packages"][0]["publish"] = publish;
            assert!(parse_test_metadata(&malformed).is_err());
        }
    }

    #[test]
    fn package_arguments_reject_duplicates_and_unsafe_names() {
        assert!(validate_package_arguments(&[]).is_err());
        assert!(
            validate_package_arguments(&["yaml-sigil-core".into(), "yaml-sigil-core".into()])
                .is_err()
        );
        assert!(validate_package_arguments(&["--package".into()]).is_err());
        assert!(validate_package_arguments(&["Uppercase".into()]).is_err());
    }

    #[test]
    fn registry_response_distinguishes_available_missing_and_yanked() {
        let version = Version::parse("0.5.0-rc.1").unwrap();
        assert_eq!(
            parse_registry_response(
                "yaml-sigil-core",
                &version,
                b"{\"version\":{\"num\":\"0.5.0-rc.1\",\"yanked\":false}}\n200"
            )
            .unwrap(),
            RegistryState::Available
        );
        assert_eq!(
            parse_registry_response("yaml-sigil-core", &version, b"{}\n404").unwrap(),
            RegistryState::Missing
        );
        assert!(
            parse_registry_response(
                "yaml-sigil-core",
                &version,
                b"{\"version\":{\"num\":\"0.5.0-rc.1\",\"yanked\":true}}\n200"
            )
            .is_err()
        );
        assert!(parse_registry_response("yaml-sigil-core", &version, b"{}\n500").is_err());
    }

    #[test]
    fn readiness_reports_partial_four_crate_train_as_ordered_wait() {
        let available = |name: &str| {
            success(
                format!(
                    "{{\"version\":{{\"num\":\"0.5.0-rc.1\",\"yanked\":false,\"name\":\"{name}\"}}}}\n200"
                )
                .into_bytes(),
            )
        };
        let mut runner = FakeRunner {
            outputs: VecDeque::from([
                available("core"),
                available("transcription"),
                success(b"{}\n404"),
                available("verification"),
            ]),
            ..FakeRunner::default()
        };
        let packages = expected_release_packages();
        assert_eq!(
            verify_registry_with(
                Path::new("."),
                Some(&Version::parse("0.5.0-rc.1").unwrap()),
                &packages,
                &mut runner,
            )
            .unwrap(),
            Outcome::RegistryUnavailable
        );
        assert!(runner.sleeps.is_empty());
    }

    fn direct_traits_metadata(
        source: &str,
        requirement: &str,
        registry: Option<&str>,
        rename: Option<&str>,
    ) -> Vec<u8> {
        let root = Path::new("/workspace");
        let consumer_root = root.join("consumer");
        encoded(&metadata_value(
            root,
            vec![package(
                "consumer",
                "0.1.0",
                None,
                &consumer_root.join("Cargo.toml"),
                Some(DISABLED),
                vec![dependency(
                    TRAITS_PACKAGE,
                    requirement,
                    Some(source),
                    registry,
                    rename,
                    None,
                )],
                vec![target("consumer", "lib", &consumer_root.join("src/lib.rs"))],
            )],
        ))
    }

    fn resolved_traits_metadata(version: &str) -> Vec<u8> {
        let root = Path::new("/workspace");
        let package_root = Path::new("/registry/yaml-sigil-traits");
        encoded(&metadata_value(
            root,
            vec![package(
                TRAITS_PACKAGE,
                version,
                Some(CRATES_IO_SOURCE),
                &package_root.join("Cargo.toml"),
                Some(CRATES_IO),
                Vec::new(),
                vec![target(
                    "yaml_sigil_traits",
                    "lib",
                    &package_root.join("src/lib.rs"),
                )],
            )],
        ))
    }

    #[test]
    fn traits_preflight_binds_requirement_registry_and_resolved_identity() {
        let version = "0.4.0-rc.1";
        let mut runner = FakeRunner {
            outputs: VecDeque::from([
                success(direct_traits_metadata(
                    CRATES_IO_SOURCE,
                    "=0.4.0-rc.1",
                    None,
                    None,
                )),
                success(
                    format!("{{\"version\":{{\"num\":\"{version}\",\"yanked\":false}}}}\n200")
                        .into_bytes(),
                ),
                success(Vec::new()),
                success(resolved_traits_metadata(version)),
            ]),
            ..FakeRunner::default()
        };
        assert_eq!(
            verify_traits_with(Path::new("."), &mut runner).unwrap(),
            Outcome::Success
        );
        assert_eq!(runner.calls[2].program, cargo_program().to_string_lossy());
        assert_eq!(
            runner.calls[2].args,
            [
                "info",
                "--quiet",
                "--registry",
                "crates-io",
                "yaml-sigil-traits@0.4.0-rc.1"
            ]
        );
    }

    #[test]
    fn traits_preflight_rejects_alternate_or_renamed_identity_before_network() {
        for metadata in [
            direct_traits_metadata(
                "git+https://example.invalid/traits",
                "=0.4.0-rc.1",
                None,
                None,
            ),
            direct_traits_metadata(CRATES_IO_SOURCE, "^0.4.0-rc.1", None, None),
            direct_traits_metadata(
                CRATES_IO_SOURCE,
                "=0.4.0-rc.1",
                Some("https://example.invalid/index"),
                None,
            ),
            direct_traits_metadata(CRATES_IO_SOURCE, "=0.4.0-rc.1", None, Some("traits")),
        ] {
            let metadata = parse_bounded(&metadata, "Cargo returned invalid metadata").unwrap();
            assert!(exact_traits_dependency(&metadata).is_err());
        }
    }

    #[test]
    fn current_main_gate_binds_exact_checkout_origin_and_remote_ref() {
        let head = "a".repeat(40);
        let fetch_url = "https://github.com/NVIDIA/yaml-sigil-rs";
        let mut runner = FakeRunner {
            outputs: VecDeque::from([
                success(format!("{head}\n").into_bytes()),
                success(format!("{fetch_url}\n").into_bytes()),
                success(format!("{head}\trefs/heads/main\n").into_bytes()),
            ]),
            ..FakeRunner::default()
        };
        require_current_main_with(Path::new("."), &head, fetch_url, &mut runner).unwrap();
        assert_eq!(runner.calls[2].program, "git");
        assert_eq!(
            runner.calls[2].args,
            ["ls-remote", "--exit-code", fetch_url, "refs/heads/main"]
        );

        assert!(require_current_main(Path::new("."), &"A".repeat(40), fetch_url).is_err());
        assert!(require_current_main(Path::new("."), &head, "--upload-pack=bad").is_err());
    }

    fn reviewed_publication_config(newline: &str) -> String {
        let mut lines = vec![
            "[workspace]".to_string(),
            "release = false".to_string(),
            "release_always = false".to_string(),
            "git_tag_enable = false".to_string(),
            "git_release_enable = false".to_string(),
            String::new(),
        ];
        for policy in RUST_POLICY.packages {
            lines.extend([
                "[[package]]".to_string(),
                format!("name = {:?}", policy.package),
                "release = true".to_string(),
                "git_tag_enable = false".to_string(),
                "git_release_enable = false".to_string(),
                String::new(),
            ]);
        }
        lines.join(newline)
    }

    #[test]
    fn publication_config_changes_only_reviewed_switches() {
        let temporary = temp_root("publication-config");
        let source = temporary.join("release-plz.toml");
        let output = temporary.join("generated.toml");
        let body = reviewed_publication_config("\n");
        fs::write(&source, &body).unwrap();

        prepare_publication_config(&temporary, Some(&source), &output).unwrap();

        let actual = fs::read_to_string(&output).unwrap();
        assert_eq!(
            actual,
            body.replacen(
                "[workspace]\n",
                "[workspace]\npr_branch_prefix = \":\"\n",
                1
            )
            .replacen("release_always = false", "release_always = true", 1)
        );
        assert!(prepare_publication_config(&temporary, Some(&source), &output).is_err());
        cleanup(temporary);
    }

    #[test]
    fn default_publication_config_uses_compiled_policy_across_checkout() {
        let temporary = temp_root("compiled-publication-config");
        let historical = reviewed_publication_config("\n")
            .replace("git_tag_enable = false", "git_tag_enable = true");
        fs::write(temporary.join(".release-plz.toml"), historical).unwrap();
        let output = temporary.join("generated.toml");

        prepare_publication_config(&temporary, None, &output).unwrap();

        let newline = source_newline(COMPILED_RELEASE_CONFIG).unwrap();
        let expected = COMPILED_RELEASE_CONFIG
            .replacen(
                &format!("[workspace]{newline}"),
                &format!("[workspace]{newline}pr_branch_prefix = \":\"{newline}"),
                1,
            )
            .replacen("release_always = false", "release_always = true", 1);
        assert_eq!(fs::read_to_string(&output).unwrap(), expected);
        assert!(!expected.contains("git_tag_enable = true"));
        cleanup(temporary);
    }

    #[test]
    fn publication_config_preserves_crlf_and_rejects_ambiguity() {
        let temporary = temp_root("publication-crlf");
        let source = temporary.join("release-plz.toml");
        let output = temporary.join("generated.toml");
        fs::write(&source, reviewed_publication_config("\r\n")).unwrap();
        prepare_publication_config(&temporary, Some(&source), &output).unwrap();
        let actual = fs::read(&output).unwrap();
        assert!(actual.windows(2).any(|window| window == b"\r\n"));
        assert!(
            !actual
                .iter()
                .enumerate()
                .any(|(index, byte)| *byte == b'\n' && (index == 0 || actual[index - 1] != b'\r'))
        );

        let ambiguous = temporary.join("ambiguous.toml");
        fs::write(
            &ambiguous,
            "[workspace]\nrelease_always = false\n# release_always = false\n",
        )
        .unwrap();
        assert!(
            prepare_publication_config(
                &temporary,
                Some(&ambiguous),
                &temporary.join("rejected.toml"),
            )
            .is_err()
        );
        cleanup(temporary);
    }

    #[test]
    fn validation_cargo_home_contains_only_four_exact_workspace_patches() {
        let temporary = temp_root("validation-home");
        let workspace_name = if cfg!(windows) {
            "workspace with spaces"
        } else {
            "workspace with a \"quote\""
        };
        let root = temporary.join(workspace_name);
        fs::create_dir(&root).unwrap();
        for policy in RUST_POLICY.packages {
            let package = root.join(policy.path_in_vcs);
            fs::create_dir_all(&package).unwrap();
            fs::write(
                package.join("Cargo.toml"),
                "[package]\nname = \"fixture\"\n",
            )
            .unwrap();
        }
        let output = temporary.join("cargo home");

        prepare_validation_cargo_home(&root, &output).unwrap();

        let body = fs::read_to_string(output.join("config.toml")).unwrap();
        let document: DocumentMut = body.parse().unwrap();
        let patches = document["patch"]["crates-io"].as_table().unwrap();
        assert_eq!(patches.len(), 4);
        for policy in RUST_POLICY.packages {
            assert_eq!(
                patches[policy.package]
                    .as_inline_table()
                    .unwrap()
                    .get("path")
                    .unwrap()
                    .as_str()
                    .unwrap(),
                root.join(policy.path_in_vcs)
                    .canonicalize()
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
        }
        assert!(prepare_validation_cargo_home(&root, &output).is_err());
        cleanup(temporary);
    }

    #[test]
    fn publication_cargo_home_is_new_empty_and_unpatched() {
        let temporary = temp_root("publication-home");
        let output = temporary.join("cargo home");

        prepare_publication_cargo_home(Path::new(env!("CARGO_MANIFEST_DIR")), &output).unwrap();

        assert!(output.is_dir());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
        assert!(
            prepare_publication_cargo_home(Path::new(env!("CARGO_MANIFEST_DIR")), &output,)
                .is_err()
        );
        cleanup(temporary);
    }

    #[test]
    fn validation_cargo_home_fails_without_all_release_manifests() {
        let temporary = temp_root("validation-home-missing");
        let root = temporary.join("workspace");
        fs::create_dir(&root).unwrap();
        for policy in &RUST_POLICY.packages[..3] {
            let package = root.join(policy.path_in_vcs);
            fs::create_dir_all(&package).unwrap();
            fs::write(
                package.join("Cargo.toml"),
                "[package]\nname = \"fixture\"\n",
            )
            .unwrap();
        }
        let output = temporary.join("cargo-home");
        assert!(prepare_validation_cargo_home(&root, &output).is_err());
        assert!(!output.exists());
        cleanup(temporary);
    }

    static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

    fn temp_root(name: &str) -> PathBuf {
        let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "yaml-sigil-rs-release-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn cleanup(path: PathBuf) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn failed_command_detail_prefers_stderr() {
        assert_eq!(
            output_detail(&failed("specific failure").unwrap()),
            "specific failure"
        );
    }
}
