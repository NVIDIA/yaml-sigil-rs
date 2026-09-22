// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Local coverage and profiling reports.

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

use crate::features::FeatureArgs;
use crate::{cargo, format_cmd, require_success, require_tool, run};

const E2E_PACKAGE: &str = "yaml-sigil-conformance";
const E2E_TEST: &str = "e2e_buildtime_keys";
const COVERAGE_HTML_DIR: &str = "target/llvm-cov-html";
const COVERAGE_INDEX: &str = "target/llvm-cov-html/html/index.html";
const PROFILE_BUILD_PROFILE: &str = "profiling";
const PROFILE_DIR: &str = "target/profile";
const PROFILE_JSON: &str = "target/profile/profile.json";
pub(crate) const DEFAULT_PROFILE_ITERATIONS: u32 = 100;
pub(crate) const CARGO_LLVM_COV_INSTALL: &str = "cargo install --locked cargo-llvm-cov";
pub(crate) const SAMPLY_INSTALL: &str = "cargo install --locked samply";
pub(crate) const CARGO_TARPAULIN_INSTALL: &str = "cargo install --locked cargo-tarpaulin";
const TARPAULIN_DIR: &str = "target/coverage/tarpaulin";
const TARPAULIN_BUILD_DIR: &str = "target/coverage/tarpaulin/build";
const TARPAULIN_INDEX: &str = "target/coverage/tarpaulin/tarpaulin-report.html";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub(crate) enum CoverageEngine {
    #[default]
    LlvmCov,
    Tarpaulin,
}

#[derive(Args, Clone, Debug, Default)]
pub(crate) struct CoverageOptions {
    /// Coverage report generator.
    #[arg(long, value_enum, default_value_t = CoverageEngine::LlvmCov)]
    pub(crate) engine: CoverageEngine,
    #[command(flatten)]
    pub(crate) features: FeatureArgs,
}

#[derive(Args, Debug)]
pub(crate) struct CoverageArgs {
    #[command(flatten)]
    pub(crate) options: CoverageOptions,
    /// Open the HTML report after generating it successfully.
    #[arg(long)]
    pub(crate) open: bool,
}

#[derive(Args, Debug)]
pub(crate) struct CoverageViewArgs {
    /// Generator of the existing report to open.
    #[arg(long, value_enum, default_value_t = CoverageEngine::LlvmCov)]
    pub(crate) engine: CoverageEngine,
}

#[derive(Args, Debug)]
pub(crate) struct ProfileOptions {
    /// Number of times to run the short E2E test while recording.
    #[arg(long, default_value_t = DEFAULT_PROFILE_ITERATIONS, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) iterations: u32,
}

#[derive(Args, Debug)]
pub(crate) struct ProfileArgs {
    #[command(flatten)]
    pub(crate) options: ProfileOptions,
    /// Open the interactive Firefox Profiler UI after recording.
    #[arg(long)]
    pub(crate) open: bool,
}

fn build_e2e_profile(root: &Path) -> Result<PathBuf> {
    let mut build = cargo(
        root,
        [
            "test",
            "-p",
            E2E_PACKAGE,
            "--test",
            E2E_TEST,
            "--no-run",
            "--profile",
            PROFILE_BUILD_PROFILE,
            "--message-format=json-render-diagnostics",
        ],
    );
    eprintln!("+ {}", format_cmd(&build));
    let output = build
        .stderr(Stdio::inherit())
        .output()
        .context("run Cargo profiling build")?;
    let artifact = profile_test_artifact(&output.stdout)?;
    require_success(output.status, "build E2E test binary (profiling)")?;

    let artifact = artifact.context("Cargo did not report the E2E test artifact")?;
    if !artifact.is_file() {
        bail!(
            "Cargo-reported test artifact is not a file: {}",
            artifact.display()
        );
    }
    Ok(artifact)
}

fn profile_test_artifact(messages: &[u8]) -> Result<Option<PathBuf>> {
    let mut artifact = None;
    for line in messages
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: serde_json::Value =
            serde_json::from_slice(line).context("parse Cargo JSON message")?;

        if let Some(rendered) = message
            .get("message")
            .and_then(|diagnostic| diagnostic.get("rendered"))
            .and_then(serde_json::Value::as_str)
        {
            eprint!("{rendered}");
        }

        let is_e2e_test = message.get("reason").and_then(serde_json::Value::as_str)
            == Some("compiler-artifact")
            && message
                .get("target")
                .and_then(|target| target.get("name"))
                .and_then(serde_json::Value::as_str)
                == Some(E2E_TEST)
            && message
                .get("target")
                .and_then(|target| target.get("kind"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("test")));
        if !is_e2e_test {
            continue;
        }

        let Some(executable) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let executable = PathBuf::from(executable);
        if artifact
            .as_ref()
            .is_some_and(|existing| existing != &executable)
        {
            bail!("Cargo reported multiple E2E test artifacts");
        }
        artifact = Some(executable);
    }
    Ok(artifact)
}

pub(crate) fn profile(root: &Path, open: bool, iterations: u32) -> Result<()> {
    let samply = require_tool("samply", SAMPLY_INSTALL)?;
    if cfg!(target_os = "linux")
        && let Ok(value) = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
    {
        eprintln!(
            "Linux perf_event_paranoid={}; profiling must be permitted by local host policy.",
            value.trim()
        );
    }
    let e2e = build_e2e_profile(root)?;
    let out_dir = root.join(PROFILE_DIR);
    std::fs::create_dir_all(&out_dir)?;
    let profile_path = root.join(PROFILE_JSON);

    let samply_cmd = profile_command(root, &samply, &e2e, iterations);
    generate_report(
        &profile_path,
        "profile",
        open,
        || require_success(run(samply_cmd)?, "samply record"),
        || profile_view(root),
    )?;
    if !open {
        eprintln!("Run `cargo xtask profile-view` to view it in the browser.");
    }
    Ok(())
}

pub(crate) fn profile_view(root: &Path) -> Result<()> {
    let samply = require_tool("samply", SAMPLY_INSTALL)?;
    let profile = root.join(PROFILE_JSON);
    if !profile.is_file() {
        bail!(
            "missing {} — run `cargo xtask profile` first",
            profile.display()
        );
    }
    let mut load = Command::new(samply);
    load.current_dir(root).arg("load").arg(&profile);
    require_success(run(load)?, "samply load")
}

fn profile_command(root: &Path, samply: &Path, e2e: &Path, iterations: u32) -> Command {
    let mut command = Command::new(samply);
    // Pass libtest flags directly after the executable; a second separator
    // makes libtest interpret them as test-name filters.
    command
        .current_dir(root)
        .args([
            "record",
            "--save-only",
            "--no-open",
            "--iteration-count",
            &iterations.to_string(),
            "--profile-name",
            "yaml-sigil-rs E2E",
            "--output",
        ])
        .arg(root.join(PROFILE_JSON))
        .arg("--")
        .arg(e2e)
        .arg("--test-threads=1");
    command
}

impl CoverageEngine {
    fn index(self) -> &'static str {
        match self {
            Self::LlvmCov => COVERAGE_INDEX,
            Self::Tarpaulin => TARPAULIN_INDEX,
        }
    }

    fn preflight(self) -> Result<()> {
        match self {
            Self::LlvmCov => crate::tools::require_cargo_tool("llvm-cov", CARGO_LLVM_COV_INSTALL),
            Self::Tarpaulin => {
                crate::tools::require_cargo_tool("tarpaulin", CARGO_TARPAULIN_INSTALL)
            }
        }
    }
}

fn coverage_commands(root: &Path, options: &CoverageOptions) -> Vec<Command> {
    let features = options.features.cargo_args();
    match options.engine {
        CoverageEngine::LlvmCov => {
            let clean = cargo(root, ["llvm-cov", "clean", "--workspace"]);
            let mut test = cargo(root, ["llvm-cov", "test", "--workspace"]);
            test.args(features)
                .args(["--html", "--output-dir", COVERAGE_HTML_DIR]);
            vec![clean, test]
        }
        CoverageEngine::Tarpaulin => {
            let mut test = cargo(root, ["tarpaulin", "--workspace"]);
            test.args(features).args([
                "--out",
                "Html",
                "--output-dir",
                TARPAULIN_DIR,
                "--target-dir",
                TARPAULIN_BUILD_DIR,
                "--exclude-files",
                "xtask/*",
                "tests/downstream/*",
            ]);
            vec![test]
        }
    }
}

pub(crate) fn coverage(root: &Path, open: bool, options: &CoverageOptions) -> Result<()> {
    options.engine.preflight()?;
    let index = root.join(options.engine.index());
    generate_report(
        &index,
        "coverage",
        open,
        || {
            for command in coverage_commands(root, options) {
                require_success(run(command)?, "generate coverage report")?;
            }
            Ok(())
        },
        || coverage_view(root, options.engine),
    )
}

fn generate_report(
    path: &Path,
    command: &str,
    open: bool,
    generate: impl FnOnce() -> Result<()>,
    view: impl FnOnce() -> Result<()>,
) -> Result<()> {
    remove_previous_report(path)?;
    generate()?;
    ensure_report(path, command)?;
    eprintln!("Wrote {}", path.display());
    if open {
        view()?;
    }
    Ok(())
}

fn remove_previous_report(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove previous report {}", path.display()))
        }
    }
}

fn ensure_report(path: &Path, command: &str) -> Result<()> {
    if !path.is_file() {
        bail!(
            "missing {} — run `cargo xtask {command}` to generate it",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn coverage_view(root: &Path, engine: CoverageEngine) -> Result<()> {
    let index = root.join(engine.index());
    ensure_report(&index, "coverage")?;
    open_in_browser(&index)
}

fn open_in_browser(path: &Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| path.display().to_string())?;
    open_canonical_path(&path)
}

#[cfg(target_os = "linux")]
fn open_canonical_path(path: &Path) -> Result<()> {
    let mut command = Command::new("xdg-open");
    command.arg(path);
    open_with_command(command, path)
}

#[cfg(target_os = "macos")]
fn open_canonical_path(path: &Path) -> Result<()> {
    let mut command = Command::new("open");
    command.arg(path);
    open_with_command(command, path)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_with_command(mut command: Command, path: &Path) -> Result<()> {
    match command.status() {
        Ok(status) => require_success(
            status,
            &format!("open browser; open {} manually if needed", path.display()),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "No browser opener is available; open {} manually.",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(error).context("launch browser opener"),
    }
}

#[cfg(target_os = "windows")]
fn open_canonical_path(path: &Path) -> Result<()> {
    use windows_sys::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

    struct ComApartment;

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: this guard exists only after a successful CoInitializeEx
            // on the current thread and is dropped on that same thread.
            unsafe { CoUninitialize() };
        }
    }

    // SAFETY: the reserved pointer is required to be null. This initializes
    // the current CLI thread exactly for the duration of the shell operation.
    let com_result = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if com_result < 0 {
        bail!(
            "Windows could not initialize the browser shell apartment (HRESULT 0x{:08X})",
            com_result as u32
        );
    }
    let _com_apartment = ComApartment;

    let operation = windows_wide_argument(OsStr::new("open"), "browser operation")?;
    let path = windows_shell_path_argument(path.as_os_str())?;
    // SAFETY: both input buffers are NUL-terminated for the duration of the
    // call, and every other pointer is an explicitly permitted null optional
    // parameter. ShellExecuteW receives the path as data, never shell text.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOW,
        )
    };
    if result as usize as isize <= 32 {
        bail!(
            "Windows could not open the browser path (code {})",
            result as usize
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_wide_argument(value: &OsStr, label: &str) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut encoded = value.encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        bail!("Windows {label} contains a NUL code unit");
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(target_os = "windows")]
fn windows_shell_path_argument(value: &OsStr) -> Result<Vec<u16>> {
    const BACKSLASH: u16 = b'\\' as u16;
    const COLON: u16 = b':' as u16;
    const VERBATIM_PREFIX: &[u16] = &[BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH];
    const VERBATIM_UNC_PREFIX: &[u16] = &[
        BACKSLASH,
        BACKSLASH,
        b'?' as u16,
        BACKSLASH,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        BACKSLASH,
    ];

    let encoded = windows_wide_argument(value, "browser path")?;
    let encoded = &encoded[..encoded.len() - 1];
    let mut shell_path = if let Some(rest) = encoded.strip_prefix(VERBATIM_UNC_PREFIX) {
        let mut path = Vec::with_capacity(rest.len() + 3);
        path.extend_from_slice(&[BACKSLASH, BACKSLASH]);
        path.extend_from_slice(rest);
        path
    } else if let Some(rest) = encoded.strip_prefix(VERBATIM_PREFIX) {
        // `canonicalize` returns DOS drive paths in this form. Other verbatim
        // namespaces are not paths the Windows shell promises to interpret.
        if rest.len() < 3 || rest[1] != COLON || rest[2] != BACKSLASH {
            bail!("canonical Windows browser path is not a drive or UNC path");
        }
        rest.to_vec()
    } else {
        encoded.to_vec()
    };
    shell_path.push(0);
    Ok(shell_path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn open_canonical_path(path: &Path) -> Result<()> {
    bail!(
        "no default browser opener for this OS; open {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn options(arguments: &[&str]) -> CoverageOptions {
        let cli =
            crate::Cli::try_parse_from(std::iter::once("xtask").chain(arguments.iter().copied()))
                .unwrap();
        match cli.command {
            crate::Task::Coverage(args) => args.options,
            crate::Task::CoverageOpen(options) => options,
            _ => panic!("expected coverage command"),
        }
    }

    fn argv(command: &Command) -> Vec<OsString> {
        command.get_args().map(OsString::from).collect()
    }

    #[test]
    fn coverage_engines_and_opening_alias_share_features_and_reports() {
        let defaults = coverage_commands(Path::new("."), &options(&["coverage"]));
        assert_eq!(
            argv(&defaults[0]),
            ["llvm-cov", "clean", "--workspace"].map(OsString::from)
        );
        assert_eq!(
            argv(&defaults[1]),
            [
                "llvm-cov",
                "test",
                "--workspace",
                "--all-features",
                "--html",
                "--output-dir",
                COVERAGE_HTML_DIR
            ]
            .map(OsString::from)
        );
        for name in ["coverage", "coverage-open"] {
            let options = options(&[
                name,
                "--engine=tarpaulin",
                "--features=json-schema-validate",
                "--no-default-features",
            ]);
            let commands = coverage_commands(Path::new("."), &options);
            assert_eq!(commands.len(), 1);
            assert_eq!(
                argv(&commands[0]),
                [
                    "tarpaulin",
                    "--workspace",
                    "--features",
                    "json-schema-validate",
                    "--no-default-features",
                    "--out",
                    "Html",
                    "--output-dir",
                    TARPAULIN_DIR,
                    "--target-dir",
                    TARPAULIN_BUILD_DIR,
                    "--exclude-files",
                    "xtask/*",
                    "tests/downstream/*"
                ]
                .map(OsString::from)
            );
            assert_eq!(options.engine.index(), TARPAULIN_INDEX);
        }
        assert_eq!(CoverageEngine::LlvmCov.index(), COVERAGE_INDEX);
    }

    #[test]
    fn existing_report_viewers_remain_separate_from_generation() {
        assert!(matches!(
            crate::Cli::try_parse_from(["xtask", "coverage-view"])
                .unwrap()
                .command,
            crate::Task::CoverageView(_)
        ));
        assert!(matches!(
            crate::Cli::try_parse_from(["xtask", "profile-view"])
                .unwrap()
                .command,
            crate::Task::ProfileView
        ));
        for command in ["profile", "profile-open"] {
            let cli =
                crate::Cli::try_parse_from(["xtask", command, "--iterations", "250"]).unwrap();
            let iterations = match cli.command {
                crate::Task::Profile(args) => args.options.iterations,
                crate::Task::ProfileOpen(args) => args.iterations,
                _ => unreachable!(),
            };
            assert_eq!(iterations, 250);
            assert!(crate::Cli::try_parse_from(["xtask", command, "--iterations=0"]).is_err());
        }
        let cli = crate::Cli::try_parse_from(["xtask", "profile"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::Task::Profile(ProfileArgs {
                options: ProfileOptions { iterations: 100 },
                open: false
            })
        ));
    }

    #[test]
    fn reports_open_only_after_successful_fresh_generation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("report.html");
        std::fs::write(&path, b"stale").unwrap();
        generate_report(
            &path,
            "coverage",
            true,
            || {
                assert!(!path.exists());
                std::fs::write(&path, b"fresh")?;
                Ok(())
            },
            || {
                assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
                Ok(())
            },
        )
        .unwrap();

        let error = generate_report(
            &path,
            "coverage",
            true,
            || bail!("test failed"),
            || panic!("must not open after failure"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("test failed"));
        assert!(!path.exists());
        assert!(
            generate_report(
                &path,
                "coverage",
                true,
                || Ok(()),
                || panic!("must not open without a report")
            )
            .is_err()
        );
        generate_report(
            &path,
            "coverage",
            false,
            || {
                std::fs::write(&path, b"fresh")?;
                Ok(())
            },
            || panic!("non-interactive generation must not open"),
        )
        .unwrap();
    }

    #[test]
    fn profile_command_keeps_the_e2e_workload_and_direct_libtest_flag() {
        let root = Path::new("workspace with spaces");
        let executable = root.join("target/profiling/e2e-test");
        let command = profile_command(root, Path::new("samply"), &executable, 250);
        let args = argv(&command);
        assert_eq!(args.iter().filter(|arg| *arg == "--").count(), 1);
        assert_eq!(args[3..5], ["--iteration-count", "250"].map(OsString::from));
        assert_eq!(args[8], root.join(PROFILE_JSON));
        assert_eq!(args[10], executable);
        assert_eq!(args[11], "--test-threads=1");
    }

    #[test]
    fn profile_artifact_rejects_ambiguous_and_malformed_cargo_messages() {
        assert!(profile_test_artifact(b"not JSON").is_err());
        assert_eq!(
            profile_test_artifact(br#"{"reason":"build-finished","success":true}"#).unwrap(),
            None
        );
        let mut messages = Vec::new();
        for executable in ["first", "second"] {
            let message = serde_json::json!({
                "reason": "compiler-artifact",
                "target": {"kind": ["test"], "name": E2E_TEST},
                "executable": executable,
            });
            messages.extend(serde_json::to_vec(&message).unwrap());
            messages.push(b'\n');
        }
        assert!(profile_test_artifact(&messages).is_err());
    }

    fn test_dir(label: &str) -> PathBuf {
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "yaml-sigil-xtask-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create test directory");
        path
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_browser_path_is_data_even_with_shell_metacharacters() {
        use std::os::windows::ffi::OsStringExt as _;

        let path = Path::new(r"C:\workspace & ^ (group)% name\coverage\index.html");
        let encoded = windows_shell_path_argument(path.as_os_str()).unwrap();
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(
            std::ffi::OsString::from_wide(&encoded[..encoded.len() - 1]),
            path.as_os_str()
        );

        for (canonical, shell_path) in [
            (
                r"\\?\C:\workspace & ^ (group)% name\coverage\index.html",
                r"C:\workspace & ^ (group)% name\coverage\index.html",
            ),
            (
                r"\\?\UNC\server\share & ^ (group)% name\coverage\index.html",
                r"\\server\share & ^ (group)% name\coverage\index.html",
            ),
        ] {
            let encoded = windows_shell_path_argument(OsStr::new(canonical)).unwrap();
            assert_eq!(
                std::ffi::OsString::from_wide(&encoded[..encoded.len() - 1]),
                OsStr::new(shell_path)
            );
        }

        let embedded_nul = std::ffi::OsString::from_wide(&[
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'a' as u16,
            0,
            b'b' as u16,
        ]);
        assert!(windows_shell_path_argument(&embedded_nul).is_err());
        assert!(windows_shell_path_argument(OsStr::new(r"\\?\Volume{test}\index.html")).is_err());
        assert!(!include_str!("reports.rs").contains("Command::new(\"cmd\")"));
    }

    #[test]
    fn profiling_uses_cargo_reported_artifact_among_stale_matches() {
        let root = test_dir("profile-artifact");
        let deps = root.join("target/profiling/deps");
        std::fs::create_dir_all(&deps).expect("create profiling directory");
        std::fs::write(deps.join(format!("{E2E_TEST}-00000000")), b"stale")
            .expect("write stale artifact");
        let intended = deps.join(format!("{E2E_TEST}-11111111"));
        std::fs::write(&intended, b"current").expect("write current artifact");
        std::fs::write(deps.join(format!("{E2E_TEST}-zzzzzzzz")), b"planted")
            .expect("write planted artifact");

        let message = serde_json::json!({
            "reason": "compiler-artifact",
            "target": { "kind": ["test"], "name": E2E_TEST },
            "executable": intended.to_str().expect("UTF-8 test path"),
        });
        let output = serde_json::to_vec(&message).expect("serialize Cargo message");

        assert_eq!(
            profile_test_artifact(&output).expect("parse Cargo message"),
            Some(intended)
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }
}
