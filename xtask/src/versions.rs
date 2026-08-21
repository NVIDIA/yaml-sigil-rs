// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Workspace version synchronization helpers.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};
use semver::{Prerelease, Version};

const WORKSPACE_INTERNAL_DEPS: &[&str] = &[
    "yaml-sigil-core",
    "yaml-sigil-transcription",
    "yaml-sigil-verification",
    "yaml-sigil-signing",
];

const EXTERNAL_TRAITS_DEP: &str = "yaml-sigil-traits";

const CHANGELOGS: &[(&str, &str)] = &[
    ("yaml-sigil-core", "crates/yaml-sigil-core/CHANGELOG.md"),
    (
        "yaml-sigil-transcription",
        "crates/yaml-sigil-transcription/CHANGELOG.md",
    ),
    (
        "yaml-sigil-signing",
        "crates/yaml-sigil-signing/CHANGELOG.md",
    ),
    (
        "yaml-sigil-verification",
        "crates/yaml-sigil-verification/CHANGELOG.md",
    ),
];

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
    /// Set an ephemeral pull-request snapshot version.
    Snapshot {
        /// Pull-request number.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        pr: u64,
        /// Full pull-request head commit SHA.
        #[arg(long)]
        sha: String,
    },
    /// Set the next RC candidate after release-plz computes changelogs.
    Candidate {
        /// Version currently published for every release crate.
        #[arg(long)]
        published: Version,
        /// Automatic or explicit release-line advancement.
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
    Auto,
    Patch,
    Minor,
    Major,
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
        ReleaseVersionCommand::Snapshot { pr, sha } => {
            validate_crates_io_traits_dependency(root)?;
            let version = snapshot_version(&read_workspace_version(root)?, pr, &sha)?;
            write_workspace_version(root, &version)?;
            sync_workspace_dependency_versions(root, false)?;
            println!("{version}");
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
    let path = root.join("Cargo.toml");
    let cargo_toml =
        fs::read_to_string(&path).context("read workspace Cargo.toml for version sync")?;
    let package_version = workspace_package_version(&cargo_toml)
        .ok_or_else(|| anyhow!("missing [workspace.package] version in root Cargo.toml"))?;

    let mut changed = false;
    let mut lines: Vec<String> = Vec::new();
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        let mut out = line.to_string();
        for dep in WORKSPACE_INTERNAL_DEPS {
            if trimmed.starts_with(&format!("{dep} = ")) {
                if let Some(current) = workspace_dependency_version(&cargo_toml, dep) {
                    if current != package_version {
                        out = set_dependency_version_on_line(line, &package_version);
                        changed = true;
                    }
                } else {
                    bail!("missing version in [workspace.dependencies] entry for {dep}");
                }
                break;
            }
        }
        lines.push(out);
    }

    if changed && check {
        bail!(
            "[workspace.dependencies] versions are not synchronized with {package_version}; run `cargo xtask sync-workspace-versions`"
        );
    } else if changed {
        let mut body = lines.join("\n");
        body.push('\n');
        fs::write(&path, body).context("write workspace Cargo.toml after version sync")?;
        eprintln!(
            "sync-workspace-versions: set [workspace.dependencies] versions to {package_version}"
        );
    } else {
        eprintln!("sync-workspace-versions: [workspace.dependencies] already at {package_version}");
    }
    Ok(changed)
}

fn read_workspace_version(root: &Path) -> Result<Version> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .context("read workspace Cargo.toml for release version")?;
    let value = workspace_package_version(&manifest)
        .ok_or_else(|| anyhow!("missing [workspace.package] version in root Cargo.toml"))?;
    Version::parse(&value).with_context(|| format!("invalid workspace package version {value}"))
}

fn write_workspace_version(root: &Path, version: &Version) -> Result<()> {
    let path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(&path).context("read workspace Cargo.toml")?;
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

fn snapshot_version(current: &Version, pr: u64, sha: &str) -> Result<Version> {
    if sha.len() < 12 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("--sha must contain at least 12 hexadecimal characters");
    }
    let short_sha = sha[..12].to_ascii_lowercase();
    Version::parse(&format!(
        "{}.{}.{}-0.pr.{pr}.commit.sha{short_sha}",
        current.major, current.minor, current.patch
    ))
    .context("construct snapshot version")
}

fn candidate_version(published: &Version, current: &Version, bump: ReleaseBump) -> Result<Version> {
    let mut target = match bump {
        ReleaseBump::Auto if current != published => {
            if current.pre.is_empty() {
                with_rc(current, 1)?
            } else {
                require_rc(current)?;
                current.clone()
            }
        }
        ReleaseBump::Auto => {
            if published.pre.is_empty() {
                bumped_core(published, ReleaseBump::Patch)?
            } else {
                let rc = require_rc(published)?;
                with_rc(
                    published,
                    rc.checked_add(1)
                        .ok_or_else(|| anyhow!("rc number overflow"))?,
                )?
            }
        }
        ReleaseBump::Patch | ReleaseBump::Minor | ReleaseBump::Major => {
            bumped_core(published, bump)?
        }
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
        ReleaseBump::Auto => bail!("auto is not a direct core-version bump"),
    };
    with_rc(&Version::new(major, minor, patch), 1)
}

fn require_rc(version: &Version) -> Result<u64> {
    let number = version
        .pre
        .as_str()
        .strip_prefix("rc.")
        .ok_or_else(|| anyhow!("expected an rc.N prerelease, found {version}"))?;
    number
        .parse::<u64>()
        .with_context(|| format!("expected an rc.N prerelease, found {version}"))
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
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .context("read workspace Cargo.toml for traits source validation")?;
    let document: toml::Value = toml::from_str(&manifest)
        .context("parse workspace Cargo.toml for traits source validation")?;
    let dependency = document
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|dependencies| dependencies.get(EXTERNAL_TRAITS_DEP))
        .ok_or_else(|| {
            anyhow!("missing [workspace.dependencies] entry for {EXTERNAL_TRAITS_DEP}")
        })?;
    let details = dependency.as_table().ok_or_else(|| {
        anyhow!("[workspace.dependencies] {EXTERNAL_TRAITS_DEP} must use an inline table")
    })?;

    for source_key in ["git", "path", "branch", "tag", "rev", "package"] {
        if details.contains_key(source_key) {
            bail!(
                "[workspace.dependencies] {EXTERNAL_TRAITS_DEP} must resolve only from crates.io; remove {source_key}"
            );
        }
    }
    if let Some(registry) = details.get("registry") {
        let registry = registry.as_str().ok_or_else(|| {
            anyhow!("[workspace.dependencies] {EXTERNAL_TRAITS_DEP} registry must be a string")
        })?;
        if registry != "crates-io" {
            bail!(
                "[workspace.dependencies] {EXTERNAL_TRAITS_DEP} must resolve from crates.io, not registry {registry}"
            );
        }
    }

    let requirement = details
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            anyhow!("missing version in [workspace.dependencies] entry for {EXTERNAL_TRAITS_DEP}")
        })?;
    exact_traits_version(requirement)?;
    Ok(())
}

/// Require stable workspaces to depend on an exact stable traits release.
fn validate_stable_traits_dependency(root: &Path, workspace_version: &Version) -> Result<()> {
    if !workspace_version.pre.is_empty() {
        return Ok(());
    }

    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .context("read workspace Cargo.toml for traits version validation")?;
    let (_, requirement) = workspace_traits_dependency(&manifest)?;
    let traits_version = exact_traits_version(&requirement)?;
    if !traits_version.pre.is_empty() {
        bail!(
            "stable workspace {workspace_version} cannot retain prerelease {EXTERNAL_TRAITS_DEP} requirement {requirement}"
        );
    }
    Ok(())
}

/// Validate the exact split-crate pin before stable promotion mutates files.
fn validate_promotable_traits_dependency(root: &Path) -> Result<()> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .context("read workspace Cargo.toml for traits stable promotion")?;
    let (_, requirement) = workspace_traits_dependency(&manifest)?;
    let traits_version = exact_traits_version(&requirement)?;
    if !traits_version.pre.is_empty() {
        require_rc(&traits_version).with_context(|| {
            format!("{EXTERNAL_TRAITS_DEP} requirement {requirement} is not an rc.N release")
        })?;
    }
    Ok(())
}

/// Strip an `rc.N` suffix from the exact split-crate requirement.
fn promote_traits_dependency_to_stable(root: &Path) -> Result<bool> {
    let path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(&path)
        .context("read workspace Cargo.toml for traits stable promotion")?;
    let (line_index, requirement) = workspace_traits_dependency(&manifest)?;
    let traits_version = exact_traits_version(&requirement)?;
    if traits_version.pre.is_empty() {
        return Ok(false);
    }
    require_rc(&traits_version).with_context(|| {
        format!("{EXTERNAL_TRAITS_DEP} requirement {requirement} is not an rc.N release")
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
    eprintln!("release-version: promoted {EXTERNAL_TRAITS_DEP} requirement to ={stable}");
    Ok(true)
}

/// Locate the one canonical inline-table traits entry in workspace dependencies.
fn workspace_traits_dependency(cargo_toml: &str) -> Result<(usize, String)> {
    let prefix = format!("{EXTERNAL_TRAITS_DEP} = ");
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
            bail!("multiple [workspace.dependencies] entries for {EXTERNAL_TRAITS_DEP}");
        }

        let inline = trimmed
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_prefix('{'))
            .ok_or_else(|| {
                anyhow!("[workspace.dependencies] {EXTERNAL_TRAITS_DEP} must use an inline table")
            })?;
        let marker = "version = ";
        let version_start = inline.find(marker).ok_or_else(|| {
            anyhow!("missing version in [workspace.dependencies] entry for {EXTERNAL_TRAITS_DEP}")
        })?;
        let requirement = parse_toml_string_value(&inline[version_start + marker.len()..])
            .ok_or_else(|| {
                anyhow!(
                    "invalid version in [workspace.dependencies] entry for {EXTERNAL_TRAITS_DEP}"
                )
            })?;
        found = Some((line_index, requirement));
    }

    found.ok_or_else(|| anyhow!("missing [workspace.dependencies] entry for {EXTERNAL_TRAITS_DEP}"))
}

/// Parse only a single exact Cargo requirement such as `=0.4.0-rc.1`.
fn exact_traits_version(requirement: &str) -> Result<Version> {
    let version = requirement
        .strip_prefix('=')
        .ok_or_else(|| anyhow!("{EXTERNAL_TRAITS_DEP} requirement {requirement} must be exact"))?;
    Version::parse(version)
        .with_context(|| format!("invalid exact {EXTERNAL_TRAITS_DEP} requirement {requirement}"))
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
    for (crate_name, relative_path) in CHANGELOGS {
        let path = root.join(relative_path);
        let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
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
    for (crate_name, relative_path) in CHANGELOGS {
        let path = root.join(relative_path);
        let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
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

fn workspace_dependency_version(cargo_toml: &str, name: &str) -> Option<String> {
    let prefix = format!("{name} = ");
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&prefix) {
            continue;
        }
        let rest = trimmed.strip_prefix(&prefix)?;
        if let Some(inner) = rest.strip_prefix('{') {
            let version_key = "version = ";
            if let Some(start) = inner.find(version_key) {
                let after = &inner[start + version_key.len()..];
                return parse_toml_string_value(after.trim());
            }
        }
    }
    None
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

    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sync_keeps_split_traits_dependency_explicit() {
        let root = temp_test_root("sync-keeps-traits");
        write_test_workspace_manifest(
            &root,
            "0.2.0-0.dev.branch.20260615.t123456",
            "0.2.0-rc.1",
            "0.2.0-rc.1",
        );

        sync_workspace_dependency_versions(&root, false).unwrap();

        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-core").as_deref(),
            Some("0.2.0-0.dev.branch.20260615.t123456")
        );
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-traits").as_deref(),
            Some("0.2.0-rc.1")
        );
        cleanup_temp_test_root(root);
    }

    #[test]
    fn sync_removes_exact_publish_pins() {
        let root = temp_test_root("sync-removes-exact");
        write_test_workspace_manifest(&root, "0.3.0-rc.1", "=0.3.0-rc.1", "0.2.0");

        sync_workspace_dependency_versions(&root, false).unwrap();

        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-core").as_deref(),
            Some("0.3.0-rc.1")
        );
        assert_eq!(
            workspace_dependency_version(&cargo_toml, "yaml-sigil-signing").as_deref(),
            Some("0.3.0-rc.1")
        );
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
    fn stable_promotion_rewrites_exact_traits_rc() {
        let root = temp_test_root("promote-traits-rc");
        write_test_workspace_manifest(&root, "0.5.0-rc.1", "0.5.0-rc.1", "=0.4.0-rc.1");

        assert!(promote_traits_dependency_to_stable(&root).unwrap());

        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            workspace_dependency_version(&cargo_toml, EXTERNAL_TRAITS_DEP).as_deref(),
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
    fn snapshot_rejects_git_traits_without_writing() {
        // Snapshot version mutation must fail closed before touching the PR
        // manifest when a review-only Git source remains present.
        let root = temp_test_root("snapshot-git-traits");
        write_test_workspace_manifest_with_traits_source(
            &root,
            "0.5.0-rc.1",
            "0.5.0-rc.1",
            "=0.4.0-rc.1",
            r#"git = "https://github.com/NVIDIA/yaml-sigil-traits.git""#,
        );
        let before = fs::read_to_string(root.join("Cargo.toml")).unwrap();

        let result = release_version(
            &root,
            ReleaseVersionArgs {
                command: ReleaseVersionCommand::Snapshot {
                    pr: 10,
                    sha: "e573f163a0749ac59ee95dfe2551ebde9f5620f8".to_owned(),
                },
            },
        );

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(root.join("Cargo.toml")).unwrap(), before);
        cleanup_temp_test_root(root);
    }

    #[test]
    fn snapshot_uses_core_and_twelve_hex_characters() {
        let current = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            snapshot_version(&current, 17, "ABCDEF0123456789").unwrap(),
            Version::parse("0.4.0-0.pr.17.commit.shaabcdef012345").unwrap()
        );
    }

    #[test]
    fn auto_advances_rc() {
        let current = Version::parse("0.4.0-rc.3").unwrap();
        assert_eq!(
            candidate_version(&current, &current, ReleaseBump::Auto).unwrap(),
            Version::parse("0.4.0-rc.4").unwrap()
        );
    }

    #[test]
    fn auto_starts_next_patch_rc_after_stable() {
        let current = Version::parse("0.4.0").unwrap();
        assert_eq!(
            candidate_version(&current, &current, ReleaseBump::Auto).unwrap(),
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
    fn inserted_changelog_sections_remain_separated() {
        let body = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n";
        let section = "## [0.2.0](new) - 2026-08-19\n\n- New.";

        assert_eq!(
            insert_after_unreleased(body, section).unwrap(),
            "# Changelog\n\n## [Unreleased]\n\n## [0.2.0](new) - 2026-08-19\n\n- New.\n\n## [0.1.0](old) - 2026-01-01\n\n- Old.\n"
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
    }
}
