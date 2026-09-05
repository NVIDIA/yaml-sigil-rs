// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral workspace version and dependency consistency checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use cargo_metadata::{Metadata, Package, TargetKind};
use semver::{Version, VersionReq};
use toml_edit::{DocumentMut, Item};

use crate::bounded_process::{self, VALIDATION_OUTPUT_LIMITS};
use crate::cargo_metadata_output::{parse_bounded, publishes_to_crates_io};
use crate::release_policy::RUST_POLICY;
use crate::safe_file;

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const TRAITS_PACKAGE: &str = "yaml-sigil-traits";

pub(crate) fn current(root: &Path) -> Result<Version> {
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml")?;
    let document = manifest
        .parse::<DocumentMut>()
        .context("parse workspace Cargo.toml")?;
    let value = document
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(Item::as_str)
        .ok_or_else(|| anyhow!("missing [workspace.package] version"))?;
    parse_release_version(value)
}

pub(crate) fn parse_release_version(value: &str) -> Result<Version> {
    let version =
        Version::parse(value).with_context(|| format!("invalid release version {value}"))?;
    if !version.build.is_empty() {
        bail!("release versions cannot contain build metadata");
    }
    Ok(version)
}

pub(crate) fn sync_workspace_dependency_versions(root: &Path, check: bool) -> Result<bool> {
    let path = root.join("Cargo.toml");
    let manifest = safe_file::read_manifest(root, Path::new("Cargo.toml"))
        .context("read workspace Cargo.toml for dependency synchronization")?;
    let mut document = manifest
        .parse::<DocumentMut>()
        .context("parse workspace Cargo.toml for dependency synchronization")?;
    let version = document
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("version"))
        .and_then(Item::as_str)
        .ok_or_else(|| anyhow!("missing [workspace.package] version"))?
        .to_string();
    parse_release_version(&version)?;

    let dependencies = document
        .get_mut("workspace")
        .and_then(|workspace| workspace.get_mut("dependencies"))
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| anyhow!("missing [workspace.dependencies] table"))?;
    let mut changed = false;
    for policy in RUST_POLICY.packages {
        let item = dependencies
            .get_mut(policy.package)
            .ok_or_else(|| anyhow!("missing workspace dependency {}", policy.package))?;
        let table = item.as_inline_table_mut().ok_or_else(|| {
            anyhow!(
                "workspace dependency {} must use an inline table",
                policy.package
            )
        })?;
        let current = table
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow!("workspace dependency {} lacks version", policy.package))?;
        if current != version {
            table.insert("version", toml_edit::Value::from(version.as_str()));
            changed = true;
        }
    }

    if changed && check {
        bail!(
            "workspace dependency versions differ from {version}; run `cargo xtask sync-workspace-versions`"
        );
    }
    if changed {
        write_manifest(&path, &document.to_string())?;
    }
    validate(root, &Version::parse(&version)?, false)?;
    Ok(changed)
}

pub(crate) fn validate(root: &Path, expected: &Version, resolve_traits: bool) -> Result<Metadata> {
    let metadata = cargo_metadata(root, resolve_traits)?;
    validate_metadata(root, &metadata, expected, resolve_traits)?;
    Ok(metadata)
}

fn validate_metadata(
    root: &Path,
    metadata: &Metadata,
    expected: &Version,
    resolve_traits: bool,
) -> Result<()> {
    let expected_root = root
        .canonicalize()
        .with_context(|| format!("resolve workspace root {}", root.display()))?;
    if metadata
        .workspace_root
        .as_std_path()
        .canonicalize()
        .context("resolve Cargo metadata workspace root")?
        != expected_root
    {
        bail!("Cargo metadata selected an unexpected workspace root");
    }

    let publishable = ordered_publishable_packages(metadata)?;
    for (package, policy) in publishable.iter().zip(RUST_POLICY.packages) {
        validate_package(&expected_root, package, policy.package, expected)?;
    }
    validate_internal_dependencies(&expected_root, &publishable, expected)?;
    validate_traits_declaration(&publishable)?;
    if resolve_traits {
        validate_resolved_traits(metadata, &publishable)?;
    }
    Ok(())
}

fn ordered_publishable_packages(metadata: &Metadata) -> Result<Vec<&Package>> {
    let mut packages_by_name = BTreeMap::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| package.source.is_none())
    {
        if !publishes_to_crates_io(package.publish.as_deref()).map_err(anyhow::Error::msg)? {
            continue;
        }
        let name = package.name.as_ref();
        if !RUST_POLICY
            .packages
            .iter()
            .any(|policy| policy.package == name)
        {
            bail!("unexpected crates.io release package {name}");
        }
        if packages_by_name.insert(name, package).is_some() {
            bail!("duplicate crates.io release package {name}");
        }
    }

    let mut ordered = Vec::with_capacity(RUST_POLICY.packages.len());
    for policy in RUST_POLICY.packages {
        let package = packages_by_name
            .remove(policy.package)
            .ok_or_else(|| anyhow!("missing crates.io release package {}", policy.package))?;
        ordered.push(package);
    }
    debug_assert!(packages_by_name.is_empty());
    Ok(ordered)
}

fn cargo_metadata(root: &Path, with_dependencies: bool) -> Result<Metadata> {
    let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    command
        .current_dir(root)
        .args(["metadata", "--format-version", "1"]);
    for token in [
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GIT_TOKEN",
    ] {
        command.env_remove(token);
    }
    if !with_dependencies {
        command.arg("--no-deps");
    }
    let output = bounded_process::output(&mut command, VALIDATION_OUTPUT_LIMITS)
        .context("run Cargo metadata")?;
    if !output.status.success() {
        bail!(
            "Cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_bounded(&output.stdout, "Cargo returned invalid release metadata")
        .map_err(anyhow::Error::msg)
}

fn validate_package(
    root: &Path,
    package: &Package,
    expected_name: &str,
    expected_version: &Version,
) -> Result<()> {
    if package.name.as_ref() != expected_name || package.version != *expected_version {
        bail!(
            "release package {} does not match {} {expected_version}",
            package.name,
            expected_name
        );
    }
    let policy = RUST_POLICY
        .packages
        .iter()
        .find(|policy| policy.package == expected_name)
        .expect("release package policy is complete");
    let expected_manifest = root.join(policy.path_in_vcs).join("Cargo.toml");
    if package.manifest_path.as_std_path() != expected_manifest {
        bail!("release package {expected_name} has an unexpected manifest path");
    }
    let libraries = package
        .targets
        .iter()
        .filter(|target| target.kind.contains(&TargetKind::Lib))
        .collect::<Vec<_>>();
    if libraries.len() != 1 {
        bail!("release package {expected_name} must expose exactly one library target");
    }
    Ok(())
}

fn validate_internal_dependencies(
    root: &Path,
    packages: &[&Package],
    expected: &Version,
) -> Result<()> {
    let canonical = VersionReq::parse(&expected.to_string())?;
    for (package_index, package) in packages.iter().enumerate() {
        let expected_internal = RUST_POLICY.packages[package_index]
            .internal_dependencies
            .iter()
            .map(|name| (*name).to_string())
            .collect::<BTreeSet<_>>();
        let actual_internal = package
            .dependencies
            .iter()
            .filter(|dependency| {
                RUST_POLICY
                    .packages
                    .iter()
                    .any(|policy| policy.package == dependency.name)
            })
            .map(|dependency| dependency.name.to_string())
            .collect::<Vec<_>>();
        if actual_internal.len() != expected_internal.len()
            || actual_internal.iter().cloned().collect::<BTreeSet<_>>() != expected_internal
        {
            bail!("{} has an unexpected internal dependency set", package.name);
        }
        for dependency in &package.dependencies {
            let Some((dependency_index, policy)) = RUST_POLICY
                .packages
                .iter()
                .enumerate()
                .find(|(_, policy)| policy.package == dependency.name)
            else {
                continue;
            };
            if dependency_index >= package_index {
                bail!(
                    "{} must be published before {}",
                    dependency.name,
                    package.name
                );
            }
            if dependency.source.is_some() || dependency.rename.is_some() {
                bail!(
                    "{} dependency on {} has an unexpected identity",
                    package.name,
                    dependency.name
                );
            }
            let dependency_path = dependency
                .path
                .as_ref()
                .ok_or_else(|| anyhow!("{} dependency lacks a local path", dependency.name))?;
            if dependency_path.as_std_path() != root.join(policy.path_in_vcs) {
                bail!(
                    "{} dependency has an unexpected local path",
                    dependency.name
                );
            }
            if dependency.req != canonical || !dependency.req.matches(expected) {
                bail!(
                    "{} dependency requirement {} is not canonical for {expected}",
                    dependency.name,
                    dependency.req
                );
            }
        }
    }
    Ok(())
}

fn validate_traits_declaration(packages: &[&Package]) -> Result<Version> {
    let mut requirements = Vec::new();
    for package in packages {
        let matches = package
            .dependencies
            .iter()
            .filter(|dependency| dependency.name == TRAITS_PACKAGE)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!(
                "{} must have one exact {TRAITS_PACKAGE} dependency",
                package.name
            );
        }
        let dependency = matches[0];
        let source = dependency
            .source
            .as_ref()
            .ok_or_else(|| anyhow!("{TRAITS_PACKAGE} dependency lacks registry source"))?;
        if !source.is_crates_io() || dependency.registry.is_some() || dependency.rename.is_some() {
            bail!("{TRAITS_PACKAGE} must resolve as its exact crates.io package identity");
        }
        requirements.push(dependency.req.clone());
    }
    let first = requirements
        .first()
        .ok_or_else(|| anyhow!("release packages do not depend on {TRAITS_PACKAGE}"))?;
    if requirements.iter().any(|requirement| requirement != first) {
        bail!("release packages disagree on the {TRAITS_PACKAGE} requirement");
    }
    let exact = first
        .to_string()
        .strip_prefix('=')
        .ok_or_else(|| anyhow!("{TRAITS_PACKAGE} requirement must be exact"))?
        .to_string();
    let version = Version::parse(&exact).context("parse exact traits dependency version")?;
    if *first != VersionReq::parse(&format!("={version}"))? {
        bail!("{TRAITS_PACKAGE} requirement is not canonical");
    }
    Ok(version)
}

fn validate_resolved_traits(metadata: &Metadata, packages: &[&Package]) -> Result<()> {
    let expected = validate_traits_declaration(packages)?;
    let matches = metadata
        .packages
        .iter()
        .filter(|package| package.name == TRAITS_PACKAGE)
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0].version != expected
        || matches[0]
            .source
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(CRATES_IO_SOURCE)
    {
        bail!("Cargo did not resolve exact {TRAITS_PACKAGE} {expected} from crates.io");
    }
    Ok(())
}

fn write_manifest(path: &Path, body: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect manifest {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("manifest path is not a regular file");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("manifest path has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary manifest in {}", parent.display()))?;
    use std::io::Write as _;
    temporary
        .write_all(body.as_bytes())
        .context("write temporary manifest")?;
    temporary
        .as_file()
        .set_permissions(metadata.permissions())
        .context("preserve manifest permissions")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync temporary manifest")?;
    temporary
        .persist(path)
        .map_err(|error| anyhow!("replace manifest {}: {}", path.display(), error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_metadata_output::{parse_bounded, test_support as fixture};

    fn metadata_document(root: &Path, version: &str, core_requirement: &str) -> serde_json::Value {
        let registry = CRATES_IO_SOURCE;
        let traits_dependency = || {
            fixture::dependency(
                TRAITS_PACKAGE,
                "=0.4.0-rc.1",
                Some(registry),
                None,
                None,
                None,
            )
        };
        let local_dependency = |name: &str, requirement: &str| {
            let policy = RUST_POLICY
                .packages
                .iter()
                .find(|policy| policy.package == name)
                .unwrap();
            fixture::dependency(
                name,
                requirement,
                None,
                None,
                None,
                Some(&root.join(policy.path_in_vcs)),
            )
        };
        let mut packages = Vec::new();
        for policy in RUST_POLICY.packages {
            let dependencies = match policy.package {
                "yaml-sigil-core" => vec![traits_dependency()],
                "yaml-sigil-transcription" => vec![
                    local_dependency("yaml-sigil-core", core_requirement),
                    traits_dependency(),
                ],
                "yaml-sigil-signing" => vec![
                    local_dependency("yaml-sigil-core", version),
                    local_dependency("yaml-sigil-transcription", version),
                    traits_dependency(),
                ],
                "yaml-sigil-verification" => vec![
                    local_dependency("yaml-sigil-core", version),
                    local_dependency("yaml-sigil-signing", version),
                    local_dependency("yaml-sigil-transcription", version),
                    traits_dependency(),
                ],
                _ => unreachable!(),
            };
            packages.push(fixture::package(
                policy.package,
                version,
                None,
                &root.join(policy.path_in_vcs).join("Cargo.toml"),
                Some(&["crates-io"]),
                dependencies,
                vec![fixture::target(
                    policy.package,
                    "lib",
                    &root.join(policy.path_in_vcs).join("src/lib.rs"),
                )],
            ));
        }
        packages.push(fixture::package(
            TRAITS_PACKAGE,
            "0.4.0-rc.1",
            Some(registry),
            &root.join("registry/yaml-sigil-traits/Cargo.toml"),
            Some(&["crates-io"]),
            Vec::new(),
            vec![fixture::target(
                TRAITS_PACKAGE,
                "lib",
                &root.join("registry/yaml-sigil-traits/src/lib.rs"),
            )],
        ));
        fixture::metadata(root, packages)
    }

    fn metadata(root: &Path, version: &str, core_requirement: &str) -> Metadata {
        parse_bounded(
            &fixture::encoded(&metadata_document(root, version, core_requirement)),
            "invalid release fixture",
        )
        .unwrap()
    }

    #[test]
    fn release_versions_accept_stable_and_prerelease_but_not_build_metadata() {
        assert!(parse_release_version("1.2.3").is_ok());
        assert!(parse_release_version("1.2.3-rc.4").is_ok());
        assert!(parse_release_version("1.2.3+build").is_err());
    }

    #[test]
    fn release_policy_has_exact_dependency_order() {
        assert_eq!(
            RUST_POLICY
                .packages
                .iter()
                .map(|package| package.package)
                .collect::<Vec<_>>(),
            [
                "yaml-sigil-core",
                "yaml-sigil-transcription",
                "yaml-sigil-signing",
                "yaml-sigil-verification",
            ]
        );
    }

    #[test]
    fn four_crate_versions_dependencies_and_traits_source_are_exact() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();
        let metadata = metadata(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        validate_metadata(&root, &metadata, &version, true).unwrap();
    }

    #[test]
    fn four_crate_validation_accepts_permuted_metadata_package_order() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();
        let mut metadata = metadata(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        let transcription = metadata
            .packages
            .iter()
            .position(|package| package.name == "yaml-sigil-transcription")
            .unwrap();
        let signing = metadata
            .packages
            .iter()
            .position(|package| package.name == "yaml-sigil-signing")
            .unwrap();
        metadata.packages.swap(transcription, signing);

        validate_metadata(&root, &metadata, &version, true).unwrap();
    }

    #[test]
    fn four_crate_validation_rejects_missing_extra_or_duplicate_packages() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();

        let mut missing = metadata(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        missing
            .packages
            .retain(|package| package.name != "yaml-sigil-signing");
        let error = validate_metadata(&root, &missing, &version, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing crates.io release package yaml-sigil-signing")
        );

        let mut extra_document =
            metadata_document(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        extra_document["packages"]
            .as_array_mut()
            .unwrap()
            .push(fixture::package(
                "yaml-sigil-extra",
                version.to_string().as_str(),
                None,
                &root.join("crates/yaml-sigil-extra/Cargo.toml"),
                Some(&["crates-io"]),
                Vec::new(),
                vec![fixture::target(
                    "yaml-sigil-extra",
                    "lib",
                    &root.join("crates/yaml-sigil-extra/src/lib.rs"),
                )],
            ));
        let extra = parse_bounded(
            &fixture::encoded(&extra_document),
            "invalid release fixture",
        )
        .unwrap();
        let error = validate_metadata(&root, &extra, &version, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unexpected crates.io release package yaml-sigil-extra")
        );

        let mut duplicate = metadata(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        let signing = duplicate
            .packages
            .iter()
            .find(|package| package.name == "yaml-sigil-signing")
            .unwrap()
            .clone();
        duplicate.packages.push(signing);
        let error = validate_metadata(&root, &duplicate, &version, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate crates.io release package yaml-sigil-signing")
        );
    }

    #[test]
    fn four_crate_validation_rejects_wrong_internal_requirement() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();
        let metadata = metadata(&root, version.to_string().as_str(), "^0.4.0");
        assert!(validate_metadata(&root, &metadata, &version, true).is_err());
    }

    #[test]
    fn four_crate_validation_rejects_missing_internal_or_traits_edges() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();

        let mut missing_internal = metadata(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        let transcription = missing_internal
            .packages
            .iter_mut()
            .find(|package| package.name == "yaml-sigil-transcription")
            .unwrap();
        transcription
            .dependencies
            .retain(|dependency| dependency.name != "yaml-sigil-core");
        assert!(validate_metadata(&root, &missing_internal, &version, true).is_err());

        let mut missing_traits = metadata(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        let core = missing_traits
            .packages
            .iter_mut()
            .find(|package| package.name == "yaml-sigil-core")
            .unwrap();
        core.dependencies
            .retain(|dependency| dependency.name != TRAITS_PACKAGE);
        assert!(validate_metadata(&root, &missing_traits, &version, true).is_err());
    }

    #[test]
    fn four_crate_validation_rejects_one_divergent_version() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let expected = Version::parse("0.5.0-rc.2").unwrap();
        let metadata = metadata(&root, "0.5.0-rc.3", "^0.5.0-rc.3");
        assert!(validate_metadata(&root, &metadata, &expected, true).is_err());
    }

    #[test]
    fn four_crate_validation_rejects_wrong_manifest_path() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();
        let mut document = metadata_document(&root, version.to_string().as_str(), "^0.5.0-rc.2");
        let signing = document["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["name"] == "yaml-sigil-signing")
            .unwrap();
        signing["manifest_path"] = serde_json::Value::String(
            root.join("unexpected/yaml-sigil-signing/Cargo.toml")
                .display()
                .to_string(),
        );
        let metadata =
            parse_bounded(&fixture::encoded(&document), "invalid release fixture").unwrap();

        let error = validate_metadata(&root, &metadata, &version, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("has an unexpected manifest path")
        );
    }
}
