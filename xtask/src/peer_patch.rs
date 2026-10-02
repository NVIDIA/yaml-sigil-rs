// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Scoped Cargo configuration for validating a paired traits checkout.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use toml_edit::{DocumentMut, Item, Table, value};

pub(crate) struct PeerPatch {
    path: PathBuf,
    original: Vec<u8>,
    patched: Vec<u8>,
    lock: Option<(PathBuf, Vec<u8>, Vec<u8>)>,
}

impl PeerPatch {
    pub(crate) fn install(root: &Path, traits_path: Option<&Path>) -> Result<Option<Self>> {
        let Some(traits_path) = traits_path else {
            return Ok(None);
        };
        let traits_path = traits_path
            .canonicalize()
            .context("resolve traits checkout")?;
        let manifest =
            fs::read_to_string(traits_path.join("Cargo.toml"))?.parse::<DocumentMut>()?;
        ensure!(
            manifest["package"]["name"].as_str() == Some("yaml-sigil-traits"),
            "--traits-path must identify yaml-sigil-traits"
        );
        let path = root.join(".cargo/config.toml");
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "Cargo configuration must be a regular file"
        );
        let original = fs::read(&path)?;
        let mut configuration = std::str::from_utf8(&original)?.parse::<DocumentMut>()?;
        ensure!(
            configuration.get("patch").is_none(),
            "Cargo configuration already has a patch table; use its existing peer configuration"
        );
        let mut dependency = Table::new();
        dependency["path"] = value(traits_path.to_str().context("traits path is not UTF-8")?);
        configuration["patch"]["crates-io"]["yaml-sigil-traits"] = Item::Table(dependency);
        let patched = configuration.to_string().into_bytes();
        let lock_path = root.join("xtask/Cargo.lock");
        let original_lock = if lock_path.exists() {
            Some(fs::read(&lock_path)?)
        } else {
            None
        };
        fs::write(&path, &patched)?;
        let mut guard = Self {
            path,
            original,
            patched,
            lock: original_lock.map(|bytes| (lock_path, bytes.clone(), bytes)),
        };
        // Cargo records unused patches even for an unrelated workspace. Model
        // that temporary marker before its locked checks, then restore the
        // committed developer lockfile alongside the scoped configuration.
        if guard.lock.is_some() {
            let mut command = Command::new("cargo");
            command.current_dir(root).args([
                "metadata",
                "--offline",
                "--manifest-path",
                "xtask/Cargo.toml",
                "--format-version",
                "1",
            ]);
            let output = crate::bounded_process::output(
                &mut command,
                crate::bounded_process::VALIDATION_OUTPUT_LIMITS,
            )?;
            if let Some((path, _, patched)) = &mut guard.lock {
                *patched = fs::read(path)?;
            }
            crate::require_success(output.status, "temporary peer patch metadata")?;
        }
        Ok(Some(guard))
    }
}

impl Drop for PeerPatch {
    fn drop(&mut self) {
        if let Some((path, original, patched)) = &self.lock {
            if fs::read(path).is_ok_and(|current| current == *patched) {
                if let Err(error) = fs::write(path, original) {
                    eprintln!("could not restore developer lockfile: {error}");
                }
            } else {
                eprintln!(
                    "developer lockfile changed during validation; preserving it for inspection"
                );
            }
        }
        match fs::read(&self.path) {
            Ok(current) if current == self.patched => {
                if let Err(error) = fs::write(&self.path, &self.original) {
                    eprintln!("could not restore Cargo configuration: {error}");
                }
            }
            _ => eprintln!(
                "Cargo configuration changed during validation; preserving it for inspection"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_patch_restores_original_bytes_and_preserves_concurrent_changes() {
        let root = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".cargo")).unwrap();
        let config = root.path().join(".cargo/config.toml");
        let original = b"# original bytes\n[alias]\nxtask = 'test'\n";
        fs::write(&config, original).unwrap();
        fs::write(
            peer.path().join("Cargo.toml"),
            "[package]\nname = 'yaml-sigil-traits'\n",
        )
        .unwrap();
        {
            let _guard = PeerPatch::install(root.path(), Some(peer.path()))
                .unwrap()
                .unwrap();
            let installed = fs::read_to_string(&config)
                .unwrap()
                .parse::<DocumentMut>()
                .unwrap();
            assert_eq!(
                installed["patch"]["crates-io"]["yaml-sigil-traits"]["path"].as_str(),
                peer.path().canonicalize().unwrap().to_str()
            );
        }
        assert_eq!(fs::read(&config).unwrap(), original);
        let guard = PeerPatch::install(root.path(), Some(peer.path()))
            .unwrap()
            .unwrap();
        fs::write(&config, b"# concurrently changed\n").unwrap();
        drop(guard);
        assert_eq!(fs::read(&config).unwrap(), b"# concurrently changed\n");
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[test]
    fn independent_locked_workspace_works_and_its_lockfile_is_restored() {
        let root = tempfile::tempdir().unwrap();
        let peer = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".cargo")).unwrap();
        fs::write(
            root.path().join(".cargo/config.toml"),
            "# original config\n",
        )
        .unwrap();
        fs::create_dir(root.path().join("xtask")).unwrap();
        fs::write(root.path().join("xtask/Cargo.toml"), "[package]\nname='peer-patch-fixture'\nversion='0.0.0'\nedition='2024'\n[workspace]\n[lib]\npath='lib.rs'\n").unwrap();
        fs::write(root.path().join("xtask/lib.rs"), "").unwrap();
        fs::write(peer.path().join("Cargo.toml"), "[package]\nname='yaml-sigil-traits'\nversion='0.4.1'\nedition='2024'\n[lib]\npath='lib.rs'\n").unwrap();
        fs::write(peer.path().join("lib.rs"), "").unwrap();
        let lock_path = root.path().join("xtask/Cargo.lock");
        let mut metadata = Command::new("cargo");
        metadata.current_dir(root.path()).args([
            "metadata",
            "--offline",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--format-version",
            "1",
        ]);
        assert!(
            crate::bounded_process::output(
                &mut metadata,
                crate::bounded_process::VALIDATION_OUTPUT_LIMITS
            )
            .unwrap()
            .status
            .success()
        );
        let original = fs::read(&lock_path).unwrap();
        {
            let _guard = PeerPatch::install(root.path(), Some(peer.path()))
                .unwrap()
                .unwrap();
            metadata.arg("--locked");
            assert!(
                crate::bounded_process::output(
                    &mut metadata,
                    crate::bounded_process::VALIDATION_OUTPUT_LIMITS
                )
                .unwrap()
                .status
                .success()
            );
        }
        assert_eq!(fs::read(&lock_path).unwrap(), original);
        assert_eq!(
            fs::read_to_string(root.path().join(".cargo/config.toml")).unwrap(),
            "# original config\n"
        );
    }
}
