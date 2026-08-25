// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local entry point for the repository's provider-neutral validation sequence.

use std::path::Path;
use std::process::Command;

use anyhow::Result;

use super::{package_content, require_success, require_tool, run as run_command, versions};

const CARGO_MACHETE_INSTALL_GUIDANCE: &str = "cargo install --locked cargo-machete --version 0.9.2";
const CARGO_DENY_INSTALL_GUIDANCE: &str = "cargo install --locked cargo-deny --version 0.20.2";

#[derive(Clone, Copy, Debug)]
struct Step {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

impl Step {
    fn command(self, root: &Path) -> Command {
        let mut command = if self.program == "buf" {
            Command::new(buf_tools::buf_bin_path())
        } else {
            Command::new(self.program)
        };
        command.current_dir(root).args(self.args);
        command
    }
}

const BEFORE_PACKAGE_CONTENT: &[Step] = &[
    Step {
        label: "Markdown lint",
        program: "rumdl",
        args: &["check", "."],
    },
    Step {
        label: "Protobuf build",
        program: "buf",
        args: &["build", "crates/yaml-sigil-core"],
    },
    Step {
        label: "Protobuf lint",
        program: "buf",
        args: &["lint", "crates/yaml-sigil-core"],
    },
    Step {
        label: "Protobuf formatting",
        program: "buf",
        args: &["format", "crates/yaml-sigil-core", "--diff", "--exit-code"],
    },
    Step {
        label: "Rust formatting",
        program: "cargo",
        args: &["fmt", "--all", "--check"],
    },
    Step {
        label: "xtask formatting",
        program: "cargo",
        args: &[
            "fmt",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--all",
            "--check",
        ],
    },
];

const AFTER_PACKAGE_CONTENT: &[Step] = &[
    Step {
        label: "Rust lint",
        program: "cargo",
        args: &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    },
    Step {
        label: "xtask lint",
        program: "cargo",
        args: &[
            "clippy",
            "--locked",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    },
    Step {
        label: "Rust tests",
        program: "cargo",
        args: &["test", "--workspace", "--all-features"],
    },
    Step {
        label: "xtask tests",
        program: "cargo",
        args: &["test", "--locked", "--manifest-path", "xtask/Cargo.toml"],
    },
    // A Cargo-launched xtask must invoke this binary directly. In cargo-machete
    // 0.9.2, inherited Cargo package variables otherwise make `cargo machete`
    // parse its subcommand name as an input path.
    Step {
        label: "Unused Rust dependencies",
        program: "cargo-machete",
        args: &["--with-metadata"],
    },
    Step {
        label: "Rust dependency policy",
        program: "cargo",
        args: &[
            "deny", "check", "bans", "licenses", "sources", "-D", "warnings",
        ],
    },
    Step {
        label: "xtask dependency policy",
        program: "cargo",
        args: &[
            "deny",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--locked",
            "check",
            "bans",
            "licenses",
            "sources",
            "-D",
            "warnings",
            "-A",
            "unnecessary-skip",
            "-A",
            "unmatched-skip",
        ],
    },
    Step {
        label: "Rust dependency audit",
        program: "cargo",
        args: &["audit"],
    },
    Step {
        label: "xtask dependency audit",
        program: "cargo",
        args: &["audit", "--file", "xtask/Cargo.lock"],
    },
];

pub(crate) fn run(root: &Path) -> Result<()> {
    require_tool("cargo-machete", CARGO_MACHETE_INSTALL_GUIDANCE)?;
    require_tool("cargo-deny", CARGO_DENY_INSTALL_GUIDANCE)?;
    for step in BEFORE_PACKAGE_CONTENT {
        run_step(root, *step)?;
    }
    versions::sync_workspace_dependency_versions(root, true)?;
    package_content::run(root)?;
    for step in AFTER_PACKAGE_CONTENT {
        run_step(root, *step)?;
    }
    Ok(())
}

fn run_step(root: &Path, step: Step) -> Result<()> {
    require_success(run_command(step.command(root))?, step.label)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT_GUIDANCE: &str = include_str!("../../AGENTS.md");

    #[test]
    fn cargo_machete_guidance_is_aligned_and_actionable() {
        assert_eq!(
            CARGO_MACHETE_INSTALL_GUIDANCE,
            "cargo install --locked cargo-machete --version 0.9.2"
        );
        assert!(AGENT_GUIDANCE.contains(CARGO_MACHETE_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains("cargo-machete --with-metadata"));
    }

    #[cfg(windows)]
    #[test]
    fn candidate_working_directory_does_not_shadow_cargo() {
        let (candidate, marker) = candidate_with_cargo_decoy();
        let cargo_step = BEFORE_PACKAGE_CONTENT
            .iter()
            .copied()
            .find(|step| step.program == "cargo")
            .expect("protected validation must contain a Cargo step");

        run_step(candidate.path(), cargo_step).unwrap();
        assert!(
            !marker.exists(),
            "candidate cargo.exe shadowed the protected validation step"
        );

        let package_result = crate::package_content::check_test_package(candidate.path());
        assert!(
            !marker.exists(),
            "candidate cargo.exe shadowed package-content validation"
        );
        assert_eq!(package_result.unwrap(), 4);
    }

    #[cfg(windows)]
    fn candidate_with_cargo_decoy() -> (tempfile::TempDir, std::path::PathBuf) {
        let candidate = tempfile::tempdir().unwrap();
        let root = candidate.path();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\n\
             name = \"candidate-package\"\n\
             version = \"0.1.0\"\n\
             edition = \"2024\"\n\
             license = \"Apache-2.0\"\n\
             exclude = [\"cargo.exe\", \"cargo-decoy.rs\", \"shadow-marker\"]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "pub fn value() -> u8 {\n    1\n}\n",
        )
        .unwrap();

        let marker = root.join("shadow-marker");
        let decoy_build = tempfile::tempdir().unwrap();
        let decoy_source = decoy_build.path().join("cargo-decoy.rs");
        let decoy_executable = decoy_build.path().join("cargo.exe");
        std::fs::write(
            &decoy_source,
            format!(
                "fn main() {{ std::fs::write({:?}, b\"shadowed\").unwrap(); }}\n",
                marker.to_string_lossy()
            ),
        )
        .unwrap();
        let output = std::process::Command::new("rustc")
            .arg(&decoy_source)
            .arg("--crate-name")
            .arg("candidate_cargo_decoy")
            .arg("-o")
            .arg(&decoy_executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to compile harmless cargo.exe decoy: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::copy(decoy_executable, root.join("cargo.exe")).unwrap();
        assert!(
            !std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .any(|entry| entry == root)
        );
        (candidate, marker)
    }

    #[test]
    fn cargo_deny_guidance_is_aligned_and_actionable() {
        assert_eq!(
            CARGO_DENY_INSTALL_GUIDANCE,
            "cargo install --locked cargo-deny --version 0.20.2"
        );
        assert!(AGENT_GUIDANCE.contains(CARGO_DENY_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains(
            "cargo deny --manifest-path xtask/Cargo.toml --locked check bans licenses sources"
        ));
    }
}
