// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local entry point for the repository's provider-neutral validation sequence.

use std::path::Path;
use std::process::Command;

use anyhow::Result;

use super::{require_success, require_tool, run as run_command};

const CARGO_MACHETE_INSTALL_GUIDANCE: &str = "cargo install --locked cargo-machete --version 0.9.2";

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

const CI_STEPS: &[Step] = &[
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
    for step in CI_STEPS {
        require_success(run_command(step.command(root))?, step.label)?;
    }
    Ok(())
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
}
