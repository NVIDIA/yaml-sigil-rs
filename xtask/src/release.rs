// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral local release preparation and validation.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use semver::Version;
use toml_edit::{DocumentMut, Item};

use crate::bounded_process::{self, OutputLimits, VALIDATION_OUTPUT_LIMITS};
use crate::release_policy::{RELEASE_PLZ_VERSION, RUST_POLICY};
use crate::{safe_file, versions};

const RELEASE_CONFIG: &str = ".release-plz.toml";
const MANUAL_BRANCH_PREFIX: &str = "release-plz-manual-";
const ACTIVATION_BRANCH_PREFIX: &str = "activate-";
const RELEASE_OUTPUT_LIMITS: OutputLimits = OutputLimits {
    stdout: 1024 * 1024,
    stderr: 4 * 1024 * 1024,
};
const MANAGED_PATHS: &[&str] = &[
    "Cargo.toml",
    "crates/yaml-sigil-core/Cargo.toml",
    "crates/yaml-sigil-core/CHANGELOG.md",
    "crates/yaml-sigil-transcription/Cargo.toml",
    "crates/yaml-sigil-transcription/CHANGELOG.md",
    "crates/yaml-sigil-signing/Cargo.toml",
    "crates/yaml-sigil-signing/CHANGELOG.md",
    "crates/yaml-sigil-verification/Cargo.toml",
    "crates/yaml-sigil-verification/CHANGELOG.md",
];
const ACTIVATION_PATHS: &[&str] = &["Cargo.toml"];
const TOKEN_ENVIRONMENTS: &[&str] = &[
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "CARGO_REGISTRIES_CRATES_IO_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GIT_TOKEN",
];
const TRACKED_RELEASE_DIFF_ARGS: &[&str] = &[
    "diff",
    "--no-renames",
    "--name-only",
    "--diff-filter=ACDMRTUXB",
    "-z",
    "HEAD",
    "--",
];
const UNTRACKED_RELEASE_DIFF_ARGS: &[&str] =
    &["ls-files", "--others", "--exclude-standard", "-z", "--"];

#[derive(Args)]
pub(crate) struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Prepare an unpublished rc.0 coordination-line activation from exact main.
    Activate {
        /// Stable target version whose coordination state starts at rc.0.
        #[arg(long)]
        version: Version,
    },
    /// Run release-plz update and require one maintainer-selected version.
    Prepare {
        /// Exact stable or prerelease version for all four source crates.
        #[arg(long)]
        version: Version,
    },
    /// Validate exact prepared release source without credentials or publishing.
    Check {
        /// Exact expected version for all four source crates.
        #[arg(long)]
        version: Version,
    },
}

pub(crate) fn run(root: &Path, args: ReleaseArgs) -> Result<()> {
    match args.command {
        ReleaseCommand::Activate { version } => activate(root, &version),
        ReleaseCommand::Prepare { version } => prepare(root, &version),
        ReleaseCommand::Check { version } => check(root, &version),
    }
}

fn activate(root: &Path, target: &Version) -> Result<()> {
    let current = versions::current(root)?;
    let selected = activation_version(&current, target)?;
    require_root_lock_absent(root)?;
    require_clean(root)?;
    require_origin_main_base(root)?;
    require_activation_branch(root, target)?;

    // rc.0 is a non-release safety stub for the coordination line. Keep
    // release-plz and every changelog out of this transition; release-plz
    // first participates after promotion for a real RC or stable release.
    versions::set_workspace_release_version(root, &current, &selected)?;
    let synchronized = without_persisted_root_lock(root, "coordination activation", || {
        versions::sync_workspace_dependency_versions(root, false)
    })?;
    if !synchronized {
        bail!("coordination activation did not update internal requirements");
    }
    require_exact_changed_paths(root, ACTIVATION_PATHS, "coordination activation")?;
    require_root_lock_absent(root)?;
    if versions::current(root)? != selected {
        bail!("coordination activation did not retain exact version {selected}");
    }
    eprintln!(
        "release: prepared unpublished coordination state {selected}; only Cargo.toml changed"
    );
    Ok(())
}

fn activation_version(current: &Version, target: &Version) -> Result<Version> {
    if !current.pre.is_empty() || !current.build.is_empty() {
        bail!("coordination activation requires a stable current main version");
    }
    if !target.pre.is_empty() || !target.build.is_empty() {
        bail!("coordination target must be a stable MAJOR.MINOR.PATCH version");
    }
    let selected = Version::parse(&format!("{target}-rc.0"))
        .context("derive coordination activation version")?;
    if selected <= *current {
        bail!("coordination version {selected} must advance current main {current}");
    }
    Ok(selected)
}

fn prepare(root: &Path, selected: &Version) -> Result<()> {
    versions::parse_release_version(&selected.to_string())?;
    validate_policy(root)?;
    require_release_plz(root)?;
    require_root_lock_absent(root)?;
    require_clean(root)?;
    require_origin_main_base(root)?;
    let current = versions::current(root)?;
    if selected <= &current {
        bail!("selected release version {selected} must advance {current}");
    }
    let branch = git_line(root, &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    if branch != format!("{MANUAL_BRANCH_PREFIX}{selected}") {
        bail!("release preparation requires branch {MANUAL_BRANCH_PREFIX}{selected}");
    }

    // release-plz remains the release proposal engine: update first derives
    // the reviewed manifest and changelog transaction without credentials.
    let mut update = release_plz_update(root);
    without_persisted_root_lock(root, "release-plz update", || {
        run_release_plz(&mut update, "release-plz update")
    })?;

    let derived = versions::current(root)?;
    if &derived != selected {
        apply_exact_version(root, &current, &derived, selected)?;
    }

    // The maintainer-selected version remains a strict postcondition after
    // release-plz's derivation and its bounded exact-selection compatibility
    // path.
    without_persisted_root_lock(root, "release metadata validation", || {
        versions::validate(root, selected, false).map(|_| ())
    })?;
    require_managed_diff(root)?;
    require_root_lock_absent(root)?;
    eprintln!(
        "release: prepared {selected}; inspect the complete diff before signing the release commit"
    );
    Ok(())
}

fn apply_exact_version(
    root: &Path,
    original: &Version,
    derived: &Version,
    selected: &Version,
) -> Result<()> {
    let adjustment = require_exact_version_adjustment(original, derived, selected)?;
    let inherited_manifests = snapshot_inherited_manifests(root)?;

    // Pinned release-plz performs the exact prerelease-to-stable selection
    // only after update has derived the changelog and preliminary version.
    let mut set_version = release_plz_set_version(root, selected);
    without_persisted_root_lock(root, "release-plz set-version", || {
        run_release_plz(&mut set_version, "release-plz set-version")
    })?;
    require_managed_diff(root)?;

    restore_inherited_manifests(root, selected, &inherited_manifests)?;
    versions::set_workspace_release_version(root, derived, selected)?;
    // set-version, rather than the xtask, must have synchronized every
    // internal requirement. This check deliberately refuses to repair one.
    without_persisted_root_lock(root, "release dependency validation", || {
        versions::sync_workspace_dependency_versions(root, true).map(|_| ())
    })?;
    eprintln!("release: {adjustment}; adjusted release-plz-derived {derived} to {selected}");
    Ok(())
}

fn require_exact_version_adjustment(
    original: &Version,
    derived: &Version,
    selected: &Version,
) -> Result<&'static str> {
    let same_core = derived.major == selected.major
        && derived.minor == selected.minor
        && derived.patch == selected.patch;
    let stable_promotion = !original.pre.is_empty()
        && selected.pre.is_empty()
        && original.major == selected.major
        && original.minor == selected.minor
        && original.patch == selected.patch
        && !derived.pre.is_empty()
        && derived >= original
        && derived < selected;
    if same_core && stable_promotion {
        return Ok("promoted the current prerelease to stable");
    }
    let new_prerelease = original.pre.is_empty()
        && !selected.pre.is_empty()
        && derived.pre.is_empty()
        && original < selected
        && selected < derived;
    if same_core && new_prerelease {
        return Ok("started the release-plz-derived version as a prerelease");
    }
    bail!(
        "release-plz derived {derived}, not selected release {selected}; only a new \
         prerelease or promotion of the current same-core prerelease is supported"
    )
}

#[derive(Debug)]
struct InheritedManifest {
    path: PathBuf,
    body: String,
}

fn snapshot_inherited_manifests(root: &Path) -> Result<Vec<InheritedManifest>> {
    RUST_POLICY
        .packages
        .iter()
        .map(|policy| {
            let path = Path::new(policy.path_in_vcs).join("Cargo.toml");
            let body = safe_file::read_manifest(root, &path)
                .with_context(|| format!("read inherited manifest {}", path.display()))?;
            expected_literal_manifest(&body, &Version::new(0, 0, 0))
                .with_context(|| format!("validate inherited manifest {}", path.display()))?;
            Ok(InheritedManifest { path, body })
        })
        .collect()
}

fn restore_inherited_manifests(
    root: &Path,
    selected: &Version,
    manifests: &[InheritedManifest],
) -> Result<()> {
    for manifest in manifests {
        let actual = safe_file::read_manifest(root, &manifest.path)
            .with_context(|| format!("read updated manifest {}", manifest.path.display()))?;
        let expected = expected_literal_manifest(&manifest.body, selected)?;
        if actual != expected {
            bail!(
                "release-plz set-version changed {} beyond its inherited package version",
                manifest.path.display()
            );
        }
    }
    for manifest in manifests {
        versions::write_manifest(&root.join(&manifest.path), &manifest.body)?;
    }
    Ok(())
}

fn expected_literal_manifest(body: &str, selected: &Version) -> Result<String> {
    let mut document = body
        .parse::<DocumentMut>()
        .context("parse inherited package manifest")?;
    let version = document
        .get_mut("package")
        .and_then(Item::as_table_like_mut)
        .and_then(|package| package.get_mut("version"))
        .ok_or_else(|| anyhow!("package manifest lacks inherited version"))?;
    let inherited = version
        .as_table_like()
        .filter(|table| table.len() == 1)
        .and_then(|table| table.get("workspace"))
        .and_then(Item::as_bool);
    if inherited != Some(true) {
        bail!("package version must inherit from the workspace");
    }
    *version = toml_edit::value(selected.to_string());
    Ok(document.to_string())
}

pub(crate) fn check(root: &Path, expected: &Version) -> Result<()> {
    versions::parse_release_version(&expected.to_string())?;
    validate_policy(root)?;
    require_root_lock_absent(root)?;
    require_clean(root)?;
    if versions::current(root)? != *expected {
        bail!("workspace version does not equal expected release {expected}");
    }
    without_persisted_root_lock(root, "release source validation", || {
        versions::sync_workspace_dependency_versions(root, true)?;
        versions::validate(root, expected, true).map(|_| ())
    })?;
    require_root_lock_absent(root)?;
    require_clean(root)?;
    eprintln!("release: validated exact four-crate release {expected}");
    Ok(())
}

pub(crate) fn validate_policy(root: &Path) -> Result<()> {
    let body = safe_file::read_manifest(root, Path::new(RELEASE_CONFIG))
        .context("read release-plz configuration")?;
    let document = body
        .parse::<DocumentMut>()
        .context("parse release-plz configuration")?;
    let top_level_keys = document
        .iter()
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    if top_level_keys != BTreeSet::from(["package", "workspace"]) {
        bail!("release-plz configuration has unexpected top-level policy");
    }
    let workspace = document
        .get("workspace")
        .and_then(Item::as_table_like)
        .ok_or_else(|| anyhow!("release-plz configuration lacks [workspace]"))?;
    let workspace_keys = workspace
        .iter()
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();
    let expected_workspace_keys = BTreeSet::from([
        "changelog_update",
        "git_release_enable",
        "git_release_type",
        "git_tag_enable",
        "pr_branch_prefix",
        "publish_allow_dirty",
        "publish_no_verify",
        "publish_timeout",
        "release",
        "release_always",
        "semver_check",
    ]);
    if workspace_keys != expected_workspace_keys {
        bail!("release-plz workspace policy fields are not exact");
    }
    let expected = [
        ("release", Some(false)),
        ("release_always", Some(false)),
        ("changelog_update", Some(true)),
        ("git_tag_enable", Some(false)),
        ("git_release_enable", Some(false)),
        ("publish_allow_dirty", Some(false)),
        ("publish_no_verify", Some(false)),
        ("semver_check", Some(false)),
    ];
    for (name, value) in expected {
        if workspace.get(name).and_then(Item::as_bool) != value {
            bail!("release-plz workspace field {name} differs from release policy");
        }
    }
    if workspace.get("pr_branch_prefix").and_then(Item::as_str) != Some(MANUAL_BRANCH_PREFIX) {
        bail!("release-plz branch prefix differs from {MANUAL_BRANCH_PREFIX}");
    }
    for (name, expected) in [("git_release_type", "auto"), ("publish_timeout", "5m")] {
        if workspace.get(name).and_then(Item::as_str) != Some(expected) {
            bail!("release-plz workspace field {name} differs from release policy");
        }
    }
    let packages = document
        .get("package")
        .and_then(Item::as_array_of_tables)
        .ok_or_else(|| anyhow!("release-plz configuration lacks package policy"))?;
    if packages.len() != RUST_POLICY.packages.len() {
        bail!("release-plz configuration must name exactly four packages");
    }
    for (table, policy) in packages.iter().zip(RUST_POLICY.packages) {
        let tag_name = format!("{}{{{{ version }}}}", policy.tag_prefix);
        let publish_all_features = policy.package != "yaml-sigil-transcription";
        let mut expected_package_keys = BTreeSet::from([
            "changelog_path",
            "changelog_update",
            "git_release_body",
            "git_release_enable",
            "git_release_name",
            "git_release_type",
            "git_tag_enable",
            "git_tag_name",
            "name",
            "publish",
            "release",
            "version_group",
        ]);
        if publish_all_features {
            expected_package_keys.insert("publish_all_features");
        }
        let package_keys = table.iter().map(|(name, _)| name).collect::<BTreeSet<_>>();
        if table.get("name").and_then(Item::as_str) != Some(policy.package)
            || package_keys != expected_package_keys
            || table.get("version_group").and_then(Item::as_str) != Some("yaml-sigil-rs")
            || table.get("release").and_then(Item::as_bool) != Some(true)
            || table.get("publish").and_then(Item::as_bool) != Some(true)
            || table.get("publish_all_features").and_then(Item::as_bool)
                != publish_all_features.then_some(true)
            || table.get("changelog_update").and_then(Item::as_bool) != Some(true)
            || table.get("changelog_path").and_then(Item::as_str) != Some(policy.changelog)
            || table.get("git_tag_enable").and_then(Item::as_bool) != Some(false)
            || table.get("git_tag_name").and_then(Item::as_str) != Some(tag_name.as_str())
            || table.get("git_release_enable").and_then(Item::as_bool) != Some(false)
            || table.get("git_release_name").and_then(Item::as_str) != Some(tag_name.as_str())
            || table.get("git_release_body").and_then(Item::as_str) != Some("{{ changelog }}")
            || table.get("git_release_type").and_then(Item::as_str) != Some("auto")
        {
            bail!("release-plz package policy differs for {}", policy.package);
        }
    }
    Ok(())
}

fn require_release_plz(root: &Path) -> Result<()> {
    // Bind every local analyzer invocation to the reviewed executable version.
    let mut command = release_plz(root);
    command.arg("--version");
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .context("run release-plz --version")?;
    if !output.status.success() {
        bail!("release-plz --version failed");
    }
    let version = one_line(&output.stdout, "release-plz version")?;
    if version != format!("release-plz {RELEASE_PLZ_VERSION}") {
        bail!(
            "release-plz {} is required; found {version}",
            RELEASE_PLZ_VERSION
        );
    }
    Ok(())
}

fn require_managed_diff(root: &Path) -> Result<()> {
    let mut paths = nul_paths(
        &git_output(root, TRACKED_RELEASE_DIFF_ARGS)?,
        "tracked release diff",
    )?;
    paths.extend(nul_paths(
        &git_output(root, UNTRACKED_RELEASE_DIFF_ARGS)?,
        "untracked release diff",
    )?);
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        bail!("release-plz produced no release changes");
    }
    let allowed = MANAGED_PATHS.iter().copied().collect::<BTreeSet<_>>();
    for path in paths {
        if !allowed.contains(path.as_str()) {
            bail!("release preparation changed unexpected path {path}");
        }
    }
    Ok(())
}

fn require_exact_changed_paths(root: &Path, expected: &[&str], label: &str) -> Result<()> {
    let mut actual = nul_paths(
        &git_output(root, TRACKED_RELEASE_DIFF_ARGS)?,
        "tracked release diff",
    )?;
    actual.extend(nul_paths(
        &git_output(root, UNTRACKED_RELEASE_DIFF_ARGS)?,
        "untracked release diff",
    )?);
    actual.sort();
    actual.dedup();
    let mut expected = expected
        .iter()
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        bail!(
            "{label} paths differ: expected [{}], found [{}]",
            expected.join(", "),
            actual.join(", ")
        );
    }
    Ok(())
}

fn require_no_tracked_root_lock(root: &Path) -> Result<()> {
    let tracked = git_line(root, &["ls-files", "--", "Cargo.lock"])?;
    if !tracked.is_empty() {
        bail!("the root Cargo.lock must remain untracked");
    }
    Ok(())
}

fn require_root_lock_absent(root: &Path) -> Result<()> {
    require_no_tracked_root_lock(root)?;
    require_root_lock_absent_on_disk(root)
}

fn require_root_lock_absent_on_disk(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root.join("Cargo.lock")) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect root Cargo.lock"),
        Ok(_) => bail!("the root Cargo.lock must be absent"),
    }
}

fn without_persisted_root_lock<T>(
    root: &Path,
    label: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    require_root_lock_absent_on_disk(root)?;
    let result = operation();
    let cleanup = remove_generated_root_lock(root, label);
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "{label} also left an unsafe root Cargo.lock: {cleanup_error:#}"
        ))),
    }
}

fn remove_generated_root_lock(root: &Path, label: &str) -> Result<()> {
    let path = root.join("Cargo.lock");
    let metadata = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect generated root Cargo.lock"),
        Ok(metadata) => metadata,
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("{label} left a root Cargo.lock that is not a regular file");
    }
    fs::remove_file(&path).with_context(|| format!("remove {label}-generated root Cargo.lock"))?;
    require_root_lock_absent_on_disk(root)
}

fn require_clean(root: &Path) -> Result<()> {
    let status = git_output(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if !status.is_empty() {
        bail!("release operation requires a clean checkout");
    }
    Ok(())
}

fn require_origin_main_base(root: &Path) -> Result<()> {
    let head = git_line(root, &["rev-parse", "HEAD"])?;
    let origin_main = git_line(root, &["rev-parse", "refs/remotes/origin/main"])?;
    validate_origin_main_base(&head, &origin_main)
}

fn require_activation_branch(root: &Path, target: &Version) -> Result<()> {
    let expected = format!("{ACTIVATION_BRANCH_PREFIX}{target}");
    let observed = git_line(root, &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    if observed != expected {
        bail!("coordination activation branch differs: expected {expected}, found {observed}");
    }
    Ok(())
}

fn validate_origin_main_base(head: &str, origin_main: &str) -> Result<()> {
    if head.len() != 40
        || origin_main.len() != 40
        || !head.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !origin_main.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("release base is not an exact full commit SHA");
    }
    if head != origin_main {
        bail!("release preparation must start at exact origin/main");
    }
    Ok(())
}

fn release_plz(root: &Path) -> Command {
    let mut command = Command::new(
        std::env::var_os("RELEASE_PLZ").unwrap_or_else(|| OsString::from("release-plz")),
    );
    command.current_dir(root);
    for name in TOKEN_ENVIRONMENTS {
        command.env_remove(name);
    }
    command
}

fn release_plz_update(root: &Path) -> Command {
    let mut command = release_plz(root);
    command.args([
        "update",
        "--manifest-path",
        "Cargo.toml",
        "--config",
        RELEASE_CONFIG,
    ]);
    command
}

fn release_plz_set_version(root: &Path, selected: &Version) -> Command {
    let mut command = release_plz(root);
    command.arg("set-version");
    for policy in RUST_POLICY.packages {
        command.arg(format!("{}@{selected}", policy.package));
    }
    command.args(["--manifest-path", "Cargo.toml", "--config", RELEASE_CONFIG]);
    command
}

fn run_release_plz(command: &mut Command, label: &str) -> Result<()> {
    let output = bounded_process::output(command, RELEASE_OUTPUT_LIMITS)
        .with_context(|| format!("run {label}"))?;
    if !output.status.success() {
        bail!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = bounded_process::output(
        Command::new("git").current_dir(root).args(args),
        VALIDATION_OUTPUT_LIMITS,
    )
    .with_context(|| format!("run git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_line(root: &Path, args: &[&str]) -> Result<String> {
    one_line(&git_output(root, args)?, "Git output")
}

fn one_line(bytes: &[u8], label: &str) -> Result<String> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let value = text.trim_end_matches(['\r', '\n']);
    if value.contains(['\r', '\n']) {
        bail!("{label} is not one line");
    }
    Ok(value.to_string())
}

fn nul_paths(bytes: &[u8], label: &str) -> Result<Vec<String>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(&[0]) {
        bail!("{label} is not NUL terminated");
    }
    let mut values = Vec::new();
    for raw in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        let path = std::str::from_utf8(raw).with_context(|| format!("{label} is not UTF-8"))?;
        if path.is_empty() || path.contains(['\r', '\n']) {
            bail!("{label} contains an unsafe path");
        }
        values.push(path.to_string());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_authority_is_stripped_from_release_plz_commands() {
        let command = release_plz(Path::new("."));
        for name in TOKEN_ENVIRONMENTS {
            assert!(
                command
                    .get_envs()
                    .any(|(key, value)| key == *name && value.is_none())
            );
        }
    }

    #[test]
    fn exact_version_adjustment_is_limited_to_release_boundaries() {
        let selected = Version::parse("0.5.0").unwrap();
        assert!(
            require_exact_version_adjustment(
                &Version::parse("0.5.0-rc.2").unwrap(),
                &Version::parse("0.5.0-rc.3").unwrap(),
                &selected,
            )
            .is_ok()
        );
        assert!(
            require_exact_version_adjustment(
                &Version::parse("0.5.0-rc.2").unwrap(),
                &Version::parse("0.5.0-rc.2").unwrap(),
                &selected,
            )
            .is_ok()
        );
        assert!(
            require_exact_version_adjustment(
                &Version::parse("0.5.0").unwrap(),
                &Version::parse("0.6.0").unwrap(),
                &Version::parse("0.6.0-rc.1").unwrap(),
            )
            .is_ok()
        );
        for (original, derived, selected) in [
            ("0.5.0", "0.5.1", "0.5.1"),
            ("0.5.0-rc.2", "0.5.0-rc.3", "0.5.0-rc.4"),
            ("0.5.0-rc.2", "0.6.0-rc.1", "0.5.0"),
            ("0.5.0-rc.3", "0.5.0-rc.2", "0.5.0"),
            ("0.5.0", "0.5.1", "0.6.0-rc.1"),
        ] {
            assert!(
                require_exact_version_adjustment(
                    &Version::parse(original).unwrap(),
                    &Version::parse(derived).unwrap(),
                    &Version::parse(selected).unwrap(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn coordination_activation_derives_only_a_forward_rc_zero() {
        let current = Version::parse("0.5.0").unwrap();
        assert_eq!(
            activation_version(&current, &Version::parse("0.6.0").unwrap()).unwrap(),
            Version::parse("0.6.0-rc.0").unwrap()
        );
        for target in ["0.5.0", "0.6.0-rc.1", "0.6.0+local"] {
            assert!(activation_version(&current, &Version::parse(target).unwrap()).is_err());
        }
        assert!(
            activation_version(
                &Version::parse("0.5.1-rc.1").unwrap(),
                &Version::parse("0.6.0").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn exact_version_command_names_every_package_once() {
        let selected = Version::parse("0.5.0").unwrap();
        let command = release_plz_set_version(Path::new("."), &selected);
        let args = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "set-version",
                "yaml-sigil-core@0.5.0",
                "yaml-sigil-transcription@0.5.0",
                "yaml-sigil-signing@0.5.0",
                "yaml-sigil-verification@0.5.0",
                "--manifest-path",
                "Cargo.toml",
                "--config",
                RELEASE_CONFIG,
            ]
        );
    }

    #[test]
    fn inherited_manifest_restoration_accepts_only_the_literal_version_rewrite() {
        let inherited =
            "[package]\nname = \"example\"\nversion.workspace = true\npublish = [\"crates-io\"]\n";
        let selected = Version::parse("1.2.3").unwrap();
        let literal = expected_literal_manifest(inherited, &selected).unwrap();
        assert_eq!(
            literal,
            "[package]\nname = \"example\"\nversion = \"1.2.3\"\npublish = [\"crates-io\"]\n"
        );
        assert!(
            expected_literal_manifest(
                "[package]\nname = \"example\"\nversion = \"1.2.2\"\n",
                &selected,
            )
            .is_err()
        );
    }

    #[test]
    fn release_operations_remove_only_their_generated_root_lock() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let lock = root.join("Cargo.lock");

        let value = without_persisted_root_lock(root, "fixture", || {
            fs::write(&lock, "generated\n")?;
            Ok(7)
        })
        .unwrap();
        assert_eq!(value, 7);
        assert!(!lock.exists());

        let error = without_persisted_root_lock(root, "failing fixture", || -> Result<()> {
            fs::write(&lock, "generated\n")?;
            bail!("operation failed")
        })
        .unwrap_err();
        assert!(error.to_string().contains("operation failed"));
        assert!(!lock.exists());

        fs::write(&lock, "pre-existing\n").unwrap();
        assert!(without_persisted_root_lock(root, "fixture", || Ok(())).is_err());
        assert_eq!(fs::read_to_string(lock).unwrap(), "pre-existing\n");
    }

    #[test]
    fn release_diff_inventory_includes_deletions_and_untracked_additions() {
        assert!(TRACKED_RELEASE_DIFF_ARGS.contains(&"--no-renames"));
        assert!(TRACKED_RELEASE_DIFF_ARGS.contains(&"--diff-filter=ACDMRTUXB"));
        assert!(UNTRACKED_RELEASE_DIFF_ARGS.contains(&"--others"));
        assert_eq!(
            nul_paths(b"deleted-path\0untracked-path\0", "fixture").unwrap(),
            ["deleted-path", "untracked-path"]
        );
        assert!(nul_paths(b"unterminated", "fixture").is_err());
    }

    #[test]
    fn managed_diff_rejects_disallowed_source_renamed_to_allowed_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        git_output(root, &["init", "--quiet"]).unwrap();
        std::fs::write(root.join("unexpected-source.txt"), "release notes\n").unwrap();
        git_output(root, &["add", "unexpected-source.txt"]).unwrap();
        git_output(
            root,
            &[
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "--message=base",
            ],
        )
        .unwrap();

        let allowed = root.join("crates/yaml-sigil-core/CHANGELOG.md");
        std::fs::create_dir_all(allowed.parent().unwrap()).unwrap();
        std::fs::rename(root.join("unexpected-source.txt"), &allowed).unwrap();
        git_output(root, &["add", "--all"]).unwrap();

        let rename_collapsed = nul_paths(
            &git_output(
                root,
                &[
                    "diff",
                    "--name-only",
                    "--diff-filter=ACDMRTUXB",
                    "-z",
                    "HEAD",
                    "--",
                ],
            )
            .unwrap(),
            "rename-aware fixture",
        )
        .unwrap();
        assert_eq!(rename_collapsed, ["crates/yaml-sigil-core/CHANGELOG.md"]);

        let error = require_managed_diff(root).unwrap_err().to_string();
        assert!(error.contains("unexpected-source.txt"));
    }

    #[test]
    fn release_preparation_requires_exact_origin_main_base() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        assert!(validate_origin_main_base(head, head).is_ok());
        assert!(
            validate_origin_main_base(head, "1123456789abcdef0123456789abcdef01234567").is_err()
        );
        assert!(validate_origin_main_base("short", "short").is_err());
    }

    #[test]
    fn repository_release_plz_policy_is_exact() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is inside repository root");
        validate_policy(root).unwrap();
    }
}
