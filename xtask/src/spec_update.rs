// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result, bail};

pub const DEFAULT_SPEC_REF: &str = "origin/main";

const SPEC_REPOSITORY: &str = "https://github.com/NVIDIA-dev/yaml-sigil-spec.git";
const CHECKOUT_DIR: &str = "target/spec-update/yaml-sigil-spec";

const SOURCE_PROTO: &str = "proto/yaml_sigil/v1alpha1/yaml_sigil.proto";
const DEST_PROTO: &str = "crates/yaml-sigil-core/spec/proto/yaml_sigil/v1alpha1/yaml_sigil.proto";
const SOURCE_SCHEMA: &str = "schema/YamlSigilSignature.v1alpha1.schema.json";
const DEST_SCHEMA: &str =
    "crates/yaml-sigil-core/spec/schema/YamlSigilSignature.v1alpha1.schema.json";
const SOURCE_THIRD_PARTY_NOTICES: &str = "THIRD_PARTY_NOTICES.md";
const DEST_THIRD_PARTY_NOTICES: &str = "THIRD_PARTY_NOTICES.md";
const DEST_CONFORMANCE_THIRD_PARTY_NOTICES: &str =
    "crates/yaml-sigil-conformance/THIRD_PARTY_NOTICES.md";

const FIXTURE_DIRS: &[&str] = &[
    "alg-ecdsa",
    "alg-ed25519",
    "base64",
    "key-id",
    "protobuf-conformance",
    "schema-alignment",
    "transcoding",
    "verification-runtime",
    "yaml-decomposition",
    "yaml-signature-conformance",
];

type Run = fn(Command) -> Result<ExitStatus>;

pub fn update_spec(root: &Path, spec_ref: &str, run: Run) -> Result<()> {
    let checkout = root.join(CHECKOUT_DIR);
    ensure_spec_checkout(&checkout, run)?;

    let commit = resolve_spec_ref(&checkout, spec_ref)?;
    let mut checkout_cmd = git_in(&checkout);
    checkout_cmd.args(["checkout", "--detach", &commit]);
    require_success(
        run(checkout_cmd)?,
        &format!("checkout yaml-sigil-spec ref `{spec_ref}`"),
    )?;

    import_spec_artifacts(root, &checkout)?;

    eprintln!("updated local spec artifacts from yaml-sigil-spec {spec_ref} ({commit})");
    eprintln!("review `git diff` and apply any required Rust, test, or doc changes");
    Ok(())
}

fn ensure_spec_checkout(checkout: &Path, run: Run) -> Result<()> {
    if checkout.join(".git").is_dir() {
        let mut set_url = git_in(checkout);
        set_url.args(["remote", "set-url", "origin", SPEC_REPOSITORY]);
        require_success(run(set_url)?, "set yaml-sigil-spec origin URL")?;
    } else {
        if checkout.exists() {
            bail!(
                "{} exists but is not a git checkout; remove it or choose a clean target",
                checkout.display()
            );
        }
        fs::create_dir_all(
            checkout
                .parent()
                .with_context(|| format!("derive parent for {}", checkout.display()))?,
        )
        .with_context(|| format!("create {}", checkout.display()))?;

        let mut clone = Command::new("git");
        clone
            .arg("clone")
            .arg("--no-checkout")
            .arg(SPEC_REPOSITORY)
            .arg(checkout);
        require_success(run(clone)?, "clone yaml-sigil-spec")?;
    }

    let mut fetch = git_in(checkout);
    fetch.args(["fetch", "origin", "--prune"]);
    require_success(run(fetch)?, "fetch yaml-sigil-spec origin")
}

fn resolve_spec_ref(checkout: &Path, spec_ref: &str) -> Result<String> {
    let mut candidates = vec![spec_ref.to_owned()];
    if !spec_ref.starts_with("origin/") && !spec_ref.starts_with("refs/") {
        candidates.push(format!("origin/{spec_ref}"));
    }
    candidates.dedup();

    for candidate in candidates {
        if let Some(commit) = rev_parse_commit(checkout, &candidate)? {
            return Ok(commit);
        }
    }

    bail!("could not resolve yaml-sigil-spec ref `{spec_ref}`")
}

fn rev_parse_commit(checkout: &Path, candidate: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .current_dir(checkout)
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{candidate}^{{commit}}"),
        ])
        .output()
        .with_context(|| format!("resolve yaml-sigil-spec ref `{candidate}`"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let commit = String::from_utf8(output.stdout)
        .with_context(|| format!("parse commit for yaml-sigil-spec ref `{candidate}`"))?
        .trim()
        .to_owned();
    if commit.is_empty() {
        bail!("git resolved `{candidate}` to an empty commit");
    }
    Ok(Some(commit))
}

fn import_spec_artifacts(root: &Path, checkout: &Path) -> Result<()> {
    copy_file(checkout, SOURCE_PROTO, root, DEST_PROTO)?;
    copy_file(checkout, SOURCE_SCHEMA, root, DEST_SCHEMA)?;
    copy_file(
        checkout,
        SOURCE_THIRD_PARTY_NOTICES,
        root,
        DEST_THIRD_PARTY_NOTICES,
    )?;
    copy_file(
        checkout,
        SOURCE_THIRD_PARTY_NOTICES,
        root,
        DEST_CONFORMANCE_THIRD_PARTY_NOTICES,
    )?;
    mirror_fixtures(checkout, root)
}

fn copy_file(source_root: &Path, source_rel: &str, dest_root: &Path, dest_rel: &str) -> Result<()> {
    let source = source_root.join(source_rel);
    let metadata = checked_source_metadata(source_root, &source)?;
    if !metadata.file_type().is_file() {
        bail!("source is not a regular file: {}", source.display());
    }

    let dest = dest_root.join(dest_rel);
    fs::create_dir_all(
        dest.parent()
            .with_context(|| format!("derive parent for {}", dest.display()))?,
    )
    .with_context(|| format!("create parent for {}", dest.display()))?;
    fs::copy(&source, &dest)
        .with_context(|| format!("copy {} to {}", source.display(), dest.display()))?;
    Ok(())
}

fn mirror_fixtures(checkout: &Path, root: &Path) -> Result<()> {
    let source = checkout.join("conformance");
    let dest = root.join("crates/yaml-sigil-conformance/fixtures");

    if dest.exists() {
        fs::remove_dir_all(&dest).with_context(|| format!("remove {}", dest.display()))?;
    }
    fs::create_dir_all(&dest).with_context(|| format!("create {}", dest.display()))?;

    for fixture_dir in FIXTURE_DIRS {
        copy_tree(checkout, &source.join(fixture_dir), &dest.join(fixture_dir))?;
    }
    Ok(())
}

fn checked_source_metadata(source_root: &Path, source: &Path) -> Result<fs::Metadata> {
    let metadata =
        fs::symlink_metadata(source).with_context(|| format!("stat {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to copy symlink {}", source.display());
    }

    let canonical_root = fs::canonicalize(source_root)
        .with_context(|| format!("resolve source root {}", source_root.display()))?;
    let canonical_source =
        fs::canonicalize(source).with_context(|| format!("resolve source {}", source.display()))?;
    if !canonical_source.starts_with(&canonical_root) {
        bail!(
            "refusing to copy {} resolved outside source root {}",
            source.display(),
            source_root.display()
        );
    }

    Ok(metadata)
}

fn copy_tree(source_root: &Path, source: &Path, dest: &Path) -> Result<()> {
    let file_type = checked_source_metadata(source_root, source)?.file_type();
    if file_type.is_file() {
        fs::create_dir_all(
            dest.parent()
                .with_context(|| format!("derive parent for {}", dest.display()))?,
        )
        .with_context(|| format!("create parent for {}", dest.display()))?;
        fs::copy(source, dest)
            .with_context(|| format!("copy {} to {}", source.display(), dest.display()))?;
        return Ok(());
    }
    if !file_type.is_dir() {
        bail!("unsupported fixture path type at {}", source.display());
    }

    fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry.with_context(|| format!("read entry under {}", source.display()))?;
        if entry.file_name() == "README.md" {
            continue;
        }
        copy_tree(source_root, &entry.path(), &dest.join(entry.file_name()))?;
    }
    Ok(())
}

fn git_in(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir);
    cmd
}

fn require_success(status: ExitStatus, context: &str) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!("{context} (exit {})", status.code().unwrap_or(-1));
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_dir(label: &str) -> PathBuf {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yaml-sigil-spec-update-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        path
    }

    #[test]
    fn copy_file_copies_regular_source() {
        let root = test_dir("regular-source");
        let source_root = root.join("checkout");
        let dest_root = root.join("workspace");
        fs::create_dir(&source_root).expect("create source root");
        fs::write(source_root.join("schema.json"), b"schema").expect("write source");

        copy_file(&source_root, "schema.json", &dest_root, "imported.json")
            .expect("copy regular source");

        assert_eq!(
            fs::read(dest_root.join("imported.json")).expect("read imported file"),
            b"schema"
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn copy_tree_omits_fixture_readmes() {
        let root = test_dir("omit-fixture-readmes");
        let source_root = root.join("checkout");
        let source = source_root.join("conformance/base64");
        let dest = root.join("workspace/fixtures/base64");
        fs::create_dir_all(&source).expect("create fixture source");
        fs::write(source.join("README.md"), b"upstream documentation")
            .expect("write fixture README");
        fs::write(source.join("valid.txt"), b"fixture").expect("write fixture data");

        copy_tree(&source_root, &source, &dest).expect("copy fixture tree");

        assert_eq!(
            fs::read(dest.join("valid.txt")).expect("read copied fixture"),
            b"fixture"
        );
        assert!(!dest.join("README.md").exists());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn copy_file_rejects_source_symlink() {
        use std::os::unix::fs::symlink;

        let root = test_dir("source-symlink");
        let source_root = root.join("checkout");
        let dest_root = root.join("workspace");
        fs::create_dir(&source_root).expect("create source root");
        let outside = root.join("outside.json");
        fs::write(&outside, b"outside").expect("write outside file");
        symlink(&outside, source_root.join("schema.json")).expect("create source symlink");

        let error = copy_file(&source_root, "schema.json", &dest_root, "imported.json")
            .expect_err("source symlink must fail");

        assert!(error.to_string().contains("refusing to copy symlink"));
        assert!(!dest_root.join("imported.json").exists());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn copy_file_rejects_symlinked_parent_outside_source_root() {
        use std::os::unix::fs::symlink;

        let root = test_dir("parent-symlink");
        let source_root = root.join("checkout");
        let outside_dir = root.join("outside");
        let dest_root = root.join("workspace");
        fs::create_dir(&source_root).expect("create source root");
        fs::create_dir(&outside_dir).expect("create outside directory");
        fs::write(outside_dir.join("schema.json"), b"outside").expect("write outside file");
        symlink(&outside_dir, source_root.join("schema")).expect("create parent symlink");

        let error = copy_file(
            &source_root,
            "schema/schema.json",
            &dest_root,
            "imported.json",
        )
        .expect_err("symlinked parent outside source root must fail");

        assert!(error.to_string().contains("resolved outside source root"));
        assert!(!dest_root.join("imported.json").exists());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn copy_tree_rejects_symlinked_parent_outside_source_root() {
        use std::os::unix::fs::symlink;

        let root = test_dir("tree-parent-symlink");
        let source_root = root.join("checkout");
        let outside_dir = root.join("outside");
        let dest = root.join("workspace/fixtures");
        fs::create_dir(&source_root).expect("create source root");
        fs::create_dir(&outside_dir).expect("create outside directory");
        let outside_fixture_dir = outside_dir.join("fixture-dir");
        fs::create_dir(&outside_fixture_dir).expect("create outside fixture directory");
        fs::write(outside_fixture_dir.join("fixture.txt"), b"outside")
            .expect("write outside fixture");
        symlink(&outside_dir, source_root.join("conformance")).expect("create parent symlink");

        let error = copy_tree(
            &source_root,
            &source_root.join("conformance/fixture-dir"),
            &dest,
        )
        .expect_err("symlinked tree root must fail");

        assert!(error.to_string().contains("resolved outside source root"));
        assert!(!dest.exists());
        fs::remove_dir_all(root).expect("remove test root");
    }
}
