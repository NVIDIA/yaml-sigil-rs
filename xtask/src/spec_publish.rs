// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Workspace dependency version synchronization helpers.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

const WORKSPACE_INTERNAL_DEPS: &[&str] = &[
    "yaml-sigil-core",
    "yaml-sigil-transcription",
    "yaml-sigil-verification",
    "yaml-sigil-signing",
];

/// Rewrite in-workspace `[workspace.dependencies]` `version = "..."` values from
/// `[workspace.package].version` because Cargo cannot inherit `version` into
/// that table.
pub fn sync_workspace_dependency_versions(root: &Path) -> Result<bool> {
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

    if changed {
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

        sync_workspace_dependency_versions(&root).unwrap();

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

        sync_workspace_dependency_versions(&root).unwrap();

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
        let cargo_toml = format!(
            r#"[workspace.package]
version = "{workspace_version}"

[workspace.dependencies]
yaml-sigil-core = {{ version = "{internal_version}", path = "crates/yaml-sigil-core", default-features = false }}
yaml-sigil-traits = {{ version = "{traits_version}", git = "https://github.com/NVIDIA/yaml-sigil-traits.git", default-features = false }}
yaml-sigil-transcription = {{ version = "{internal_version}", path = "crates/yaml-sigil-transcription", default-features = false }}
yaml-sigil-verification = {{ version = "{internal_version}", path = "crates/yaml-sigil-verification", default-features = false }}
yaml-sigil-signing = {{ version = "{internal_version}", path = "crates/yaml-sigil-signing", default-features = false }}
"#
        );
        fs::write(root.join("Cargo.toml"), cargo_toml).unwrap();
    }
}
