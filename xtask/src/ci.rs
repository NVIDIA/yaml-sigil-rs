// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral validation sequence shared by local and hosted CI.

use std::io::{self, Write as _};
use std::path::Path;
use std::process::Command;

use anyhow::Result;

use super::{bounded_process, package_content, require_success, require_tool, versions};

const CARGO_AUDIT_INSTALL_GUIDANCE: &str =
    "cargo +1.98.0 install --locked cargo-audit --version 0.22.2";
const CARGO_MACHETE_INSTALL_GUIDANCE: &str =
    "cargo +1.98.0 install --locked cargo-machete --version 0.9.2";
#[cfg(test)]
const BUF_VERSION: &str = "1.72.0";

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
    Step {
        label: "Unused Rust dependencies",
        program: "cargo-machete",
        args: &["--with-metadata"],
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
    require_tool("cargo-audit", CARGO_AUDIT_INSTALL_GUIDANCE)?;
    require_tool("cargo-machete", CARGO_MACHETE_INSTALL_GUIDANCE)?;
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
    let output = bounded_process::output(
        &mut step.command(root),
        bounded_process::VALIDATION_OUTPUT_LIMITS,
    )?;
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    require_success(output.status, step.label)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT_GUIDANCE: &str = include_str!("../../AGENTS.md");

    #[test]
    fn dependency_tool_guidance_is_aligned() {
        assert!(AGENT_GUIDANCE.contains(CARGO_AUDIT_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains(CARGO_MACHETE_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains("cargo-machete --with-metadata"));
    }

    #[test]
    fn pinned_buf_tools_path_has_exact_cli_version() {
        let path = buf_tools::buf_bin_path();
        assert!(path.is_absolute());
        assert!(path.is_file());
        let output = Command::new(path)
            .arg("--version")
            .output()
            .expect("execute pinned Buf CLI");
        assert!(output.status.success());
        assert_eq!(
            std::str::from_utf8(&output.stdout)
                .expect("Buf version is UTF-8")
                .trim(),
            BUF_VERSION
        );
    }

    #[test]
    fn provider_neutral_steps_do_not_read_ci_environment() {
        let programs = BEFORE_PACKAGE_CONTENT
            .iter()
            .chain(AFTER_PACKAGE_CONTENT)
            .map(|step| step.program)
            .collect::<Vec<_>>();
        assert!(!programs.contains(&"gh"));
        assert!(!programs.contains(&"gitlab"));
    }
}
