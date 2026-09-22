// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Provider-neutral checks in a canonical, selectable order.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use clap::{Args, ValueEnum};

use crate::features::FeatureArgs;
use crate::{bounded_process, package_content, require_success, require_tool, tools, versions};

const CARGO_AUDIT_INSTALL_GUIDANCE: &str =
    "cargo +1.98.0 install --locked cargo-audit --version 0.22.2";
const CARGO_DENY_INSTALL_GUIDANCE: &str =
    "cargo +1.98.0 install --locked cargo-deny --version 0.20.2";
const CARGO_MACHETE_INSTALL_GUIDANCE: &str =
    "cargo +1.98.0 install --locked cargo-machete --version 0.9.2";
#[cfg(test)]
const BUF_VERSION_REQUIREMENT: &str = ">=1.73.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CheckStep {
    Markdown,
    Protobuf,
    Fmt,
    Versions,
    PackageContent,
    Check,
    Clippy,
    Test,
    Downstream,
    Machete,
    Deny,
    Audit,
}

impl CheckStep {
    const ALL: [Self; 12] = [
        Self::Markdown,
        Self::Protobuf,
        Self::Fmt,
        Self::Versions,
        Self::PackageContent,
        Self::Check,
        Self::Clippy,
        Self::Test,
        Self::Downstream,
        Self::Machete,
        Self::Deny,
        Self::Audit,
    ];

    fn preflight(self) -> Result<()> {
        match self {
            Self::Markdown => {
                require_tool("rumdl", "cargo +1.98.0 install rumdl")?;
            }
            Self::Protobuf => tools::probe(
                &buf_tools::buf_bin_path(),
                &["--version"],
                "Buf",
                "rebuild the xtask with its Cargo-resolved buf-tools dependency",
            )?,
            Self::Fmt => tools::require_cargo_tool("fmt", "rustup component add rustfmt")?,
            Self::Clippy => tools::require_cargo_tool("clippy", "rustup component add clippy")?,
            Self::Machete => {
                require_tool("cargo-machete", CARGO_MACHETE_INSTALL_GUIDANCE)?;
            }
            Self::Deny => tools::require_cargo_tool("deny", CARGO_DENY_INSTALL_GUIDANCE)?,
            Self::Audit => tools::require_cargo_tool("audit", CARGO_AUDIT_INSTALL_GUIDANCE)?,
            Self::Versions | Self::PackageContent | Self::Check | Self::Test | Self::Downstream => {
            }
        }
        Ok(())
    }
}

#[derive(Args, Debug, Default)]
pub(crate) struct CheckArgs {
    /// Run only these checks, in registry order.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        conflicts_with = "exclude",
        value_name = "CHECK,..."
    )]
    only: Vec<CheckStep>,
    /// Run all checks except these.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        conflicts_with = "only",
        value_name = "CHECK,..."
    )]
    exclude: Vec<CheckStep>,
    #[command(flatten)]
    features: FeatureArgs,
}

impl CheckArgs {
    pub(crate) fn selected(&self) -> Result<Vec<CheckStep>> {
        let selected = CheckStep::ALL
            .into_iter()
            .filter(|check| {
                (self.only.is_empty() || self.only.contains(check)) && !self.exclude.contains(check)
            })
            .collect::<Vec<_>>();
        ensure!(!selected.is_empty(), "check selection contains no checks");
        Ok(selected)
    }
}

#[derive(Clone, Copy, Debug)]
struct Step {
    label: &'static str,
    program: &'static str,
    args: &'static [&'static str],
}

impl Step {
    fn command(self, root: &Path, features: &FeatureArgs) -> Command {
        let mut command = if self.program == "buf" {
            Command::new(buf_tools::buf_bin_path())
        } else {
            Command::new(self.program)
        };
        command.current_dir(root).args(self.arguments(features));
        command
    }

    fn arguments(self, features: &FeatureArgs) -> Vec<OsString> {
        let mut args = self.args.iter().map(OsString::from).collect::<Vec<_>>();
        if self.program == "cargo" && self.args.contains(&"--workspace") {
            let position = self
                .args
                .iter()
                .position(|arg| *arg == "--all-features")
                .expect("workspace compile and test recipes declare a feature default");
            args.splice(position..=position, features.cargo_args());
        } else if self.program == "cargo" && self.args.starts_with(&["deny", "check"]) {
            args.splice(1..1, features.cargo_args());
        }
        args
    }
}

const MARKDOWN: &[Step] = &[Step {
    label: "Markdown lint",
    program: "rumdl",
    args: &["check", "."],
}];

const PROTOBUF: &[Step] = &[
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
];

const FMT: &[Step] = &[
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

const CHECK: &[Step] = &[
    Step {
        label: "Rust compile check",
        program: "cargo",
        args: &["check", "--workspace", "--all-targets", "--all-features"],
    },
    Step {
        label: "xtask compile check",
        program: "cargo",
        args: &[
            "check",
            "--locked",
            "--manifest-path",
            "xtask/Cargo.toml",
            "--all-targets",
            "--all-features",
        ],
    },
];

const CLIPPY: &[Step] = &[
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
];

const TEST: &[Step] = &[
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
];

const DOWNSTREAM: &[Step] = &[
    Step {
        label: "core-only downstream facade test",
        program: "cargo",
        args: &[
            "test",
            "--manifest-path",
            "tests/downstream/Cargo.toml",
            "--package",
            "yaml-sigil-core-downstream-core-only",
        ],
    },
    Step {
        label: "independent Buffa downstream facade test",
        program: "cargo",
        args: &[
            "test",
            "--manifest-path",
            "tests/downstream/Cargo.toml",
            "--package",
            "yaml-sigil-core-downstream-buffa-0-5",
        ],
    },
    Step {
        label: "independent noyalib downstream Serde test",
        program: "cargo",
        args: &[
            "test",
            "--manifest-path",
            "tests/downstream/Cargo.toml",
            "--package",
            "yaml-sigil-core-downstream-noyalib-0-0-35",
        ],
    },
    Step {
        label: "downstream resource API test",
        program: "cargo",
        args: &[
            "test",
            "--manifest-path",
            "tests/downstream/Cargo.toml",
            "--package",
            "yaml-sigil-downstream-resource-api",
        ],
    },
];

const MACHETE: &[Step] = &[Step {
    label: "Unused Rust dependencies",
    program: "cargo-machete",
    args: &["--with-metadata"],
}];

const DENY: &[Step] = &[
    Step {
        label: "Rust dependency policy",
        program: "cargo",
        args: &[
            "deny", "check", "bans", "licenses", "sources", "-D", "warnings",
        ],
    },
    Step {
        label: "downstream dependency policy",
        program: "cargo",
        args: &[
            "deny",
            "--manifest-path",
            "tests/downstream/Cargo.toml",
            "--locked",
            "check",
            "licenses",
            "sources",
            "-D",
            "warnings",
            "-A",
            "no-license-field",
            "-A",
            "unlicensed",
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
];

const AUDIT: &[Step] = &[
    Step {
        label: "Rust dependency audit",
        program: "cargo",
        args: &["audit"],
    },
    Step {
        label: "downstream dependency audit",
        program: "cargo",
        args: &[
            "audit",
            "--file",
            "tests/downstream/Cargo.lock",
            "--no-fetch",
        ],
    },
    Step {
        label: "xtask dependency audit",
        program: "cargo",
        args: &["audit", "--file", "xtask/Cargo.lock"],
    },
];

fn steps(check: CheckStep) -> &'static [Step] {
    match check {
        CheckStep::Markdown => MARKDOWN,
        CheckStep::Protobuf => PROTOBUF,
        CheckStep::Fmt => FMT,
        CheckStep::Versions | CheckStep::PackageContent => &[],
        CheckStep::Check => CHECK,
        CheckStep::Clippy => CLIPPY,
        CheckStep::Test => TEST,
        CheckStep::Downstream => DOWNSTREAM,
        CheckStep::Machete => MACHETE,
        CheckStep::Deny => DENY,
        CheckStep::Audit => AUDIT,
    }
}

pub(crate) fn run(root: &Path, args: CheckArgs) -> Result<()> {
    for check in args.selected()? {
        check.preflight()?;
        match check {
            CheckStep::Versions => {
                versions::sync_workspace_dependency_versions(root, true)?;
            }
            CheckStep::PackageContent => package_content::run(root)?,
            CheckStep::Deny => ensure_lockfile(root, "tests/downstream/Cargo.toml")?,
            CheckStep::Audit => {
                ensure_lockfile(root, "Cargo.toml")?;
                ensure_lockfile(root, "tests/downstream/Cargo.toml")?;
            }
            _ => {}
        }
        for step in steps(check) {
            run_step(root, *step, &args.features)?;
        }
    }
    Ok(())
}

fn ensure_lockfile(root: &Path, manifest: &'static str) -> Result<()> {
    let lockfile = root.join(manifest).with_file_name("Cargo.lock");
    if !lockfile.try_exists()? {
        let mut command = crate::cargo(root, ["generate-lockfile", "--manifest-path", manifest]);
        run_command(&mut command, "resolve dependency lockfile")?;
    }
    Ok(())
}

fn run_step(root: &Path, step: Step, features: &FeatureArgs) -> Result<()> {
    run_command(&mut step.command(root, features), step.label)
}

fn run_command(command: &mut Command, label: &str) -> Result<()> {
    eprintln!("+ {}", crate::format_cmd(command));
    let output = bounded_process::output(command, bounded_process::VALIDATION_OUTPUT_LIMITS)?;
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    require_success(output.status, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    const AGENT_GUIDANCE: &str = include_str!("../../AGENTS.md");

    fn parse(arguments: &[&str]) -> CheckArgs {
        let cli =
            crate::Cli::try_parse_from(std::iter::once("xtask").chain(arguments.iter().copied()))
                .unwrap();
        let crate::Task::Check(args) = cli.command else {
            panic!("expected check command");
        };
        args
    }

    #[test]
    fn selectors_deduplicate_and_keep_registry_order_for_both_names() {
        assert_eq!(parse(&["check"]).selected().unwrap(), CheckStep::ALL);
        for name in ["check", "ci"] {
            assert_eq!(
                parse(&[name, "--only=test,fmt,test"]).selected().unwrap(),
                [CheckStep::Fmt, CheckStep::Test]
            );
            let selected = parse(&[name, "--exclude=fmt,fmt,check"])
                .selected()
                .unwrap();
            assert_eq!(selected.len(), CheckStep::ALL.len() - 2);
            assert!(!selected.contains(&CheckStep::Fmt));
            assert!(!selected.contains(&CheckStep::Check));
        }
        let parser = crate::Cli::command();
        let check = parser.find_subcommand("check").unwrap();
        assert_eq!(check.get_visible_aliases().collect::<Vec<_>>(), ["ci"]);
    }

    #[test]
    fn invalid_and_empty_selections_fail_before_execution() {
        for flags in [
            vec!["--only="],
            vec!["--exclude="],
            vec!["--only=fmt,,test"],
            vec!["--only=imaginary"],
            vec!["--exclude=imaginary"],
            vec!["--only=fmt", "--exclude=test"],
        ] {
            assert!(
                crate::Cli::try_parse_from(["xtask", "check"].into_iter().chain(flags)).is_err()
            );
        }
        assert!(parse(&["check", "--exclude=markdown,protobuf,fmt,versions,package-content,check,clippy,test,downstream,machete,deny,audit"])
            .selected().is_err());
    }

    #[test]
    fn feature_selection_does_not_change_independent_workspace_contracts() {
        let options = parse(&[
            "check",
            "--features=json-schema-validate",
            "--no-default-features",
        ]);
        for check in [CheckStep::Check, CheckStep::Clippy, CheckStep::Test] {
            let root = steps(check)[0].arguments(&options.features);
            assert!(!root.contains(&OsString::from("--all-features")));
            assert!(root.contains(&OsString::from("json-schema-validate")));
            assert!(root.contains(&OsString::from("--no-default-features")));
            let independent = steps(check)[1];
            assert_eq!(
                independent.arguments(&options.features),
                independent
                    .args
                    .iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            );
        }
        for check in [CheckStep::Fmt, CheckStep::Downstream] {
            for step in steps(check) {
                assert_eq!(
                    step.arguments(&options.features),
                    step.args.iter().map(OsString::from).collect::<Vec<_>>()
                );
            }
        }
        assert_eq!(
            DENY[0].arguments(&options.features)[..4],
            [
                "deny",
                "--features",
                "json-schema-validate",
                "--no-default-features"
            ]
            .map(OsString::from)
        );
        for step in &DENY[1..] {
            assert_eq!(
                step.arguments(&options.features),
                step.args.iter().map(OsString::from).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn dependency_lock_creation_is_idempotent_and_uses_the_selected_graph() {
        let root = tempfile::tempdir().unwrap();
        let downstream = root.path().join("tests/downstream");
        std::fs::create_dir_all(downstream.join("src")).unwrap();
        std::fs::write(
            downstream.join("Cargo.toml"),
            "[workspace]\n[package]\nname='lock-fixture'\nversion='0.0.0'\n",
        )
        .unwrap();
        std::fs::write(downstream.join("src/lib.rs"), "").unwrap();
        ensure_lockfile(root.path(), "tests/downstream/Cargo.toml").unwrap();
        let lock = std::fs::read(downstream.join("Cargo.lock")).unwrap();
        assert!(!root.path().join("Cargo.lock").exists());
        ensure_lockfile(root.path(), "tests/downstream/Cargo.toml").unwrap();
        assert_eq!(std::fs::read(downstream.join("Cargo.lock")).unwrap(), lock);
    }

    #[test]
    fn dependency_tool_guidance_is_aligned() {
        assert!(AGENT_GUIDANCE.contains(CARGO_AUDIT_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains(CARGO_DENY_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains(CARGO_MACHETE_INSTALL_GUIDANCE));
        assert!(AGENT_GUIDANCE.contains("cargo-machete --with-metadata"));
        assert!(AGENT_GUIDANCE.contains(
            "cargo deny --manifest-path xtask/Cargo.toml --locked check bans licenses sources"
        ));
        assert!(AGENT_GUIDANCE.contains(
            "cargo deny --manifest-path tests/downstream/Cargo.toml --locked check licenses sources"
        ));
        assert!(
            AGENT_GUIDANCE.contains("cargo audit --file tests/downstream/Cargo.lock --no-fetch")
        );
    }

    #[test]
    fn buf_tools_path_meets_minimum_cli_version() {
        let path = buf_tools::buf_bin_path();
        assert!(path.is_absolute());
        assert!(path.is_file());
        let output = Command::new(path)
            .arg("--version")
            .output()
            .expect("execute Cargo-resolved Buf CLI");
        assert!(output.status.success());
        let version = semver::Version::parse(
            std::str::from_utf8(&output.stdout)
                .expect("Buf version is UTF-8")
                .trim(),
        )
        .expect("Buf reports a semantic version");
        let requirement = semver::VersionReq::parse(BUF_VERSION_REQUIREMENT).unwrap();
        assert!(
            requirement.matches(&version),
            "unsupported Buf CLI: {version}"
        );
    }

    #[test]
    fn provider_neutral_steps_do_not_read_ci_environment() {
        let programs = CheckStep::ALL
            .into_iter()
            .flat_map(steps)
            .map(|step| step.program)
            .collect::<Vec<_>>();
        assert!(!programs.contains(&"gh"));
        assert!(!programs.contains(&"gitlab"));
    }
}
