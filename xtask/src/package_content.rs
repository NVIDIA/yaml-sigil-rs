// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Static source-package inventory validation without archive assembly.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::process::Command;

#[derive(Clone, Copy, Debug)]
struct PackageSpec {
    name: &'static str,
    inventory_path: &'static str,
    inventory: &'static str,
}

const PACKAGE_SPECS: &[PackageSpec] = &[
    PackageSpec {
        name: "yaml-sigil-core",
        inventory_path: "xtask/package-contents/yaml-sigil-core.txt",
        inventory: include_str!("../package-contents/yaml-sigil-core.txt"),
    },
    PackageSpec {
        name: "yaml-sigil-transcription",
        inventory_path: "xtask/package-contents/yaml-sigil-transcription.txt",
        inventory: include_str!("../package-contents/yaml-sigil-transcription.txt"),
    },
    PackageSpec {
        name: "yaml-sigil-signing",
        inventory_path: "xtask/package-contents/yaml-sigil-signing.txt",
        inventory: include_str!("../package-contents/yaml-sigil-signing.txt"),
    },
    PackageSpec {
        name: "yaml-sigil-verification",
        inventory_path: "xtask/package-contents/yaml-sigil-verification.txt",
        inventory: include_str!("../package-contents/yaml-sigil-verification.txt"),
    },
];

const SYNTHETIC_LOCKFILE: &str = "Cargo.lock";

/// Compare Cargo's modeled package paths with the committed exact inventories.
///
/// `cargo package --list` is deliberately run with `--exclude-lockfile` so a
/// root lockfile does not trigger dependency resolution for the unpublished
/// workspace. Cargo would generate a package-local lockfile during real
/// package assembly, so this validator adds that one path to the observed set.
pub(crate) fn run(root: &Path) -> io::Result<()> {
    let mut failures = Vec::new();

    for package in PACKAGE_SPECS {
        match check_package(root, *package) {
            Ok(count) => eprintln!("{}: package contents match ({count} paths)", package.name),
            Err(error) => failures.push(error),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "package content validation failed:\n\n{}",
            failures.join("\n\n")
        )))
    }
}

fn check_package(root: &Path, package: PackageSpec) -> Result<usize, String> {
    let expected = parse_inventory(package.inventory, package.inventory_path)
        .map_err(|error| format!("{}: {error}", package.name))?;
    let args = package_list_args(package.name);
    eprintln!("+ cargo {} (cwd {})", args.join(" "), root.display());

    let output = Command::new("cargo")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| {
            format!(
                "{}: failed to run cargo package --list: {error}",
                package.name
            )
        })?;

    if !output.stderr.is_empty() {
        io::stderr()
            .lock()
            .write_all(&output.stderr)
            .map_err(|error| format!("{}: failed to relay Cargo stderr: {error}", package.name))?;
    }
    if !output.status.success() {
        return Err(format!(
            "{}: cargo package --list failed (exit {})",
            package.name,
            output.status.code().unwrap_or(-1)
        ));
    }

    let actual_text = String::from_utf8(output.stdout).map_err(|error| {
        format!(
            "{}: cargo package --list produced non-UTF-8 output: {error}",
            package.name
        )
    })?;
    let mut actual = parse_cargo_list(&actual_text, "cargo package --list output")
        .map_err(|error| format!("{}: {error}", package.name))?;
    actual.insert(SYNTHETIC_LOCKFILE.to_owned());

    if let Some(difference) = inventory_difference(package.name, &expected, &actual) {
        Err(difference)
    } else {
        Ok(expected.len())
    }
}

fn package_list_args(package: &str) -> [&str; 6] {
    [
        "package",
        "--list",
        "--allow-dirty",
        "--exclude-lockfile",
        "--package",
        package,
    ]
}

fn parse_inventory(text: &str, label: &str) -> io::Result<BTreeSet<String>> {
    if text.is_empty() {
        return Err(invalid_data(format!("{label} is empty")));
    }
    if !text.ends_with('\n') {
        return Err(invalid_data(format!("{label} must end with a line feed")));
    }
    if text.contains('\r') {
        return Err(invalid_data(format!(
            "{label} must use line-feed terminators"
        )));
    }

    let mut paths = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for (index, path) in text.lines().enumerate() {
        let line = index + 1;
        if path.is_empty() {
            return Err(invalid_data(format!("{label}:{line}: blank path")));
        }
        if path.starts_with('#') {
            return Err(invalid_data(format!(
                "{label}:{line}: comments are not allowed"
            )));
        }
        if path.contains('\\')
            || path
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
            || !Path::new(path)
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(invalid_data(format!(
                "{label}:{line}: path must be crate-relative: {path}"
            )));
        }
        if let Some(prior) = previous {
            match prior.as_bytes().cmp(path.as_bytes()) {
                std::cmp::Ordering::Greater => {
                    return Err(invalid_data(format!(
                        "{label}:{line}: paths are not bytewise sorted: {path} follows {prior}"
                    )));
                }
                std::cmp::Ordering::Equal => {
                    return Err(invalid_data(format!(
                        "{label}:{line}: duplicate path: {path}"
                    )));
                }
                std::cmp::Ordering::Less => {}
            }
        }
        paths.insert(path.to_owned());
        previous = Some(path);
    }
    Ok(paths)
}

fn parse_cargo_list(text: &str, label: &str) -> io::Result<BTreeSet<String>> {
    let normalized = normalize_platform_separators(text, std::path::MAIN_SEPARATOR);
    parse_inventory(&normalized, label)
}

fn normalize_platform_separators(text: &str, separator: char) -> String {
    text.replace(separator, "/")
}

fn inventory_difference(
    package: &str,
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
) -> Option<String> {
    let missing: Vec<_> = expected.difference(actual).collect();
    let unexpected: Vec<_> = actual.difference(expected).collect();
    if missing.is_empty() && unexpected.is_empty() {
        return None;
    }

    let mut lines = vec![format!("{package}: package contents differ")];
    if !missing.is_empty() {
        lines.push("missing from package:".to_owned());
        lines.extend(missing.into_iter().map(|path| format!("  {path}")));
    }
    if !unexpected.is_empty() {
        lines.push("unexpected in package:".to_owned());
        lines.extend(unexpected.into_iter().map(|path| format!("  {path}")));
    }
    Some(lines.join("\n"))
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_scope_and_order_are_explicit() {
        assert_eq!(
            PACKAGE_SPECS
                .iter()
                .map(|package| package.name)
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
    fn package_list_flags_are_exact() {
        assert_eq!(
            package_list_args("example"),
            [
                "package",
                "--list",
                "--allow-dirty",
                "--exclude-lockfile",
                "--package",
                "example",
            ]
        );
    }

    #[test]
    fn committed_inventories_are_canonical() {
        for package in PACKAGE_SPECS {
            parse_inventory(package.inventory, package.inventory_path)
                .unwrap_or_else(|error| panic!("{}: {error}", package.name));
        }
    }

    #[test]
    fn parser_rejects_noncanonical_inventory_text() {
        for (text, message) in [
            ("", "is empty"),
            ("src/lib.rs", "must end with a line feed"),
            ("src/lib.rs\r\n", "must use line-feed terminators"),
            ("src/lib.rs\n\n", "blank path"),
            ("# note\n", "comments are not allowed"),
            ("/src/lib.rs\n", "path must be crate-relative"),
            ("src//lib.rs\n", "path must be crate-relative"),
            ("src/./lib.rs\n", "path must be crate-relative"),
            ("src/\n", "path must be crate-relative"),
            ("src/z.rs\nsrc/a.rs\n", "not bytewise sorted"),
            ("src/lib.rs\nsrc/lib.rs\n", "duplicate path"),
        ] {
            let error = parse_inventory(text, "test inventory")
                .expect_err("noncanonical inventory must fail")
                .to_string();
            assert!(error.contains(message), "unexpected error: {error}");
        }
    }

    #[test]
    fn cargo_output_normalizes_only_the_platform_separator() {
        assert_eq!(
            normalize_platform_separators("src\\lib.rs\n", '\\'),
            "src/lib.rs\n"
        );
        assert_eq!(
            normalize_platform_separators("src\\lib.rs\n", '/'),
            "src\\lib.rs\n"
        );
    }

    #[test]
    fn differences_name_missing_and_unexpected_paths_deterministically() {
        let expected = paths(&["README.md", "src/lib.rs"]);
        let actual = paths(&["README.md", "src/new.rs"]);
        assert_eq!(
            inventory_difference("example", &expected, &actual).as_deref(),
            Some(concat!(
                "example: package contents differ\n",
                "missing from package:\n",
                "  src/lib.rs\n",
                "unexpected in package:\n",
                "  src/new.rs"
            ))
        );
        assert!(inventory_difference("example", &expected, &expected).is_none());
    }

    fn paths(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }
}
