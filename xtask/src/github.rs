// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Narrow, typed GitHub operations for release qualification and finalization.

mod transport;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use flate2::read::GzDecoder;
use semver::Version;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::bounded_process::{self, OutputLimits, VALIDATION_OUTPUT_LIMITS};
use crate::release;
use crate::release_policy::{PackagePolicy, RUST_POLICY};
use crate::versions;
use transport::{GhCli, Transport};

const REPOSITORY: &str = "NVIDIA/yaml-sigil-rs";
const PUBLISH_WORKFLOW_ID: u64 = 337_417_483;
const PUBLISH_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const APP_SLUG: &str = "nvidia-yamlsigil-release-pr";
const APP_LOGIN: &str = "nvidia-yamlsigil-release-pr[bot]";
const APP_ID: u64 = 318_780_254;
const APP_EMAIL: &str = "318780254+nvidia-yamlsigil-release-pr[bot]@users.noreply.github.com";
const RELEASE_SIGNER_LOGIN: &str = "ddurst-nvidia";
const RELEASE_SIGNER_ID: u64 = 267_424_412;
const RELEASE_AUTHOR_NAME: &str = "ddurst";
const RELEASE_AUTHOR_EMAIL: &str = "267424412+ddurst-nvidia@users.noreply.github.com";
const DCO_TRAILER: &str =
    "Signed-off-by: ddurst <267424412+ddurst-nvidia@users.noreply.github.com>";
const MANUAL_BRANCH_PREFIX: &str = "release-plz-manual-";
const CRATES_IO_USER_AGENT: &str =
    "yaml-sigil-release-verifier/1.0 (https://github.com/NVIDIA/yaml-sigil-rs)";
const CRATES_IO_REQUEST_DELAY: Duration = Duration::from_secs(1);
const CRATE_RESPONSE_LIMITS: OutputLimits = OutputLimits {
    stdout: 32 * 1024 * 1024,
    stderr: 64 * 1024,
};
const VCS_INFO_LIMIT: u64 = 64 * 1024;
const MAX_CRATE_ARCHIVE_ENTRIES: usize = 4096;
const MAX_CRATE_UNPACKED_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Args)]
pub(crate) struct GithubArgs {
    #[command(subcommand)]
    command: GithubCommand,
}

#[derive(Subcommand)]
enum GithubCommand {
    /// Qualify or finalize one repository-owned release.
    Release(ReleaseArgs),
}

#[derive(Args)]
struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Inspect exact source and registry state without mutation.
    Qualify(QualifyArgs),
    /// Create or verify deterministic annotated tags and zero-asset Releases.
    Finalize(FinalizeArgs),
}

#[derive(Args)]
struct QualifyArgs {
    /// Separate checkout containing the exact release source as data.
    #[arg(long)]
    source_root: PathBuf,
    /// Exact source commit checked out by the workflow.
    #[arg(long, value_name = "SHA")]
    source_sha: String,
    /// Automatic main release, validation-only dispatch, or same-source recovery.
    #[arg(long, value_enum)]
    operation: Operation,
    /// Original main-triggered workflow run, required only for recovery.
    #[arg(long)]
    original_run_id: Option<u64>,
    /// Exact original attempt, required only for recovery.
    #[arg(long)]
    original_run_attempt: Option<u64>,
    /// Wait at most 20 minutes for all exact crates before returning.
    #[arg(long)]
    wait_for_registry: bool,
}

#[derive(Args)]
struct FinalizeArgs {
    /// Separate checkout containing the exact published source as data.
    #[arg(long)]
    source_root: PathBuf,
    /// Exact source commit whose crates are already public.
    #[arg(long, value_name = "SHA")]
    source_sha: String,
    /// Exact common version of the four published crates.
    #[arg(long)]
    version: Version,
    /// App slug observed from the protected token-minting action.
    #[arg(long)]
    app_slug: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Operation {
    Auto,
    Validate,
    Recover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Decision {
    publish: bool,
    finalize: bool,
}

pub(crate) fn run(root: &Path, args: GithubArgs) -> Result<(), String> {
    match args.command {
        GithubCommand::Release(release) => match release.command {
            ReleaseCommand::Qualify(arguments) => qualify(root, &arguments),
            ReleaseCommand::Finalize(arguments) => finalize(root, &arguments),
        },
    }
}

fn qualify(root: &Path, arguments: &QualifyArgs) -> Result<(), String> {
    let mut github = GhCli::new()?;
    let policy_main_sha = main_sha(&mut github)?;
    require_separate_checkouts(
        root,
        &arguments.source_root,
        &policy_main_sha,
        &arguments.source_sha,
    )?;
    release::validate_policy(root).map_err(|error| error.to_string())?;
    let version = versions::current(&arguments.source_root).map_err(|error| error.to_string())?;
    release::validate_policy(&arguments.source_root).map_err(|error| error.to_string())?;

    match arguments.operation {
        Operation::Recover => {
            let (Some(run_id), Some(run_attempt)) =
                (arguments.original_run_id, arguments.original_run_attempt)
            else {
                return Err("recovery requires the original run ID and attempt".to_string());
            };
            bind_original_run(&mut github, &arguments.source_sha, run_id, run_attempt)?;
            require_main_ancestry(&mut github, &arguments.source_sha, &policy_main_sha)?;
        }
        Operation::Auto | Operation::Validate => {
            if arguments.original_run_id.is_some() || arguments.original_run_attempt.is_some() {
                return Err("original run inputs are accepted only for recovery".to_string());
            }
            if arguments.source_sha != policy_main_sha {
                return Err(
                    "automatic and validation operations require exact current main".into(),
                );
            }
        }
    }

    if arguments.operation == Operation::Validate {
        versions::validate(&arguments.source_root, &version, true)
            .map_err(|error| error.to_string())?;
        let skipped = maybe_reconcile_registry(Operation::Validate, false, || {
            registry_states(&arguments.source_sha, &version)
        })?;
        debug_assert!(skipped.is_none());
        append_qualification_outputs(
            &arguments.source_sha,
            &version,
            Decision {
                publish: false,
                finalize: false,
            },
            "validation",
        )?;
        println!("validated protected release policy without publication");
        return Ok(());
    }

    let release = classify_release_pull_request(&mut github, &arguments.source_sha, &version)?;
    if !release {
        let skipped = maybe_reconcile_registry(arguments.operation, false, || {
            registry_states(&arguments.source_sha, &version)
        })?;
        debug_assert!(skipped.is_none());
        let decision = ordinary_decision(arguments.operation)?;
        append_qualification_outputs(&arguments.source_sha, &version, decision, "ordinary")?;
        println!(
            "qualified ordinary main commit {} as a no-op",
            arguments.source_sha
        );
        return Ok(());
    }

    versions::validate(&arguments.source_root, &version, true)
        .map_err(|error| error.to_string())?;
    let states = maybe_reconcile_registry(arguments.operation, true, || {
        if arguments.wait_for_registry {
            wait_for_registry(&arguments.source_sha, &version)
        } else {
            registry_states(&arguments.source_sha, &version)
        }
    })?
    .ok_or_else(|| "release qualification skipped registry reconciliation".to_string())?;
    let decision = decide(arguments.operation, &states)?;
    append_qualification_outputs(
        &arguments.source_sha,
        &version,
        decision,
        registry_state(&states),
    )?;
    println!(
        "qualified {} {} at {} (publish={}, finalize={})",
        RUST_POLICY.packages.len(),
        version,
        arguments.source_sha,
        decision.publish,
        decision.finalize
    );
    Ok(())
}

fn finalize(root: &Path, arguments: &FinalizeArgs) -> Result<(), String> {
    let mut github = GhCli::new()?;
    let policy_main_sha = main_sha(&mut github)?;
    require_separate_checkouts(
        root,
        &arguments.source_root,
        &policy_main_sha,
        &arguments.source_sha,
    )?;
    release::validate_policy(root).map_err(|error| error.to_string())?;
    release::validate_policy(&arguments.source_root).map_err(|error| error.to_string())?;
    if versions::current(&arguments.source_root).map_err(|error| error.to_string())?
        != arguments.version
    {
        return Err("finalizer version differs from checked-out source".to_string());
    }
    versions::validate(&arguments.source_root, &arguments.version, true)
        .map_err(|error| error.to_string())?;
    let states = registry_states(&arguments.source_sha, &arguments.version)?;
    if states.iter().any(|published| !published) {
        return Err("all four crates must be public before finalization".to_string());
    }
    verify_app_scope(&mut github, &arguments.app_slug)?;
    let mutation_main_sha = main_sha(&mut github)?;
    require_unchanged_main(&policy_main_sha, &mutation_main_sha)?;
    require_separate_checkouts(
        root,
        &arguments.source_root,
        &mutation_main_sha,
        &arguments.source_sha,
    )?;
    require_main_ancestry(&mut github, &arguments.source_sha, &mutation_main_sha)?;
    let source = source_commit(&mut github, &arguments.source_sha)?;
    let date = source
        .commit
        .committer
        .as_ref()
        .ok_or_else(|| "release source raw committer is missing".to_string())?
        .date
        .clone();
    for package in RUST_POLICY.packages {
        require_current_mutation_policy(&mut github, &arguments.source_sha, &policy_main_sha)?;
        finalize_package(
            &mut github,
            package,
            &arguments.version,
            &arguments.source_sha,
            &policy_main_sha,
            &date,
        )?;
    }
    println!(
        "finalized four immutable source-only Releases for {} at {}",
        arguments.version, arguments.source_sha
    );
    Ok(())
}

fn require_unchanged_main(initial: &str, current: &str) -> Result<(), String> {
    require_sha(initial, "initial protected main SHA")?;
    require_sha(current, "mutation-time protected main SHA")?;
    if initial != current {
        return Err("protected main changed before release-object mutation".to_string());
    }
    Ok(())
}

fn wait_for_registry(source_sha: &str, version: &Version) -> Result<Vec<bool>, String> {
    const ATTEMPTS: usize = 40;
    for attempt in 0..ATTEMPTS {
        let states = registry_states(source_sha, version)?;
        if states.iter().all(|published| *published) {
            return Ok(states);
        }
        if attempt + 1 < ATTEMPTS {
            thread::sleep(Duration::from_secs(30));
        }
    }
    Err("all four crates were not visible within 20 minutes".to_string())
}

fn require_separate_checkouts(
    policy_root: &Path,
    source_root: &Path,
    main_sha: &str,
    source_sha: &str,
) -> Result<(), String> {
    if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || env::var("GITHUB_REPOSITORY").as_deref() != Ok(REPOSITORY)
    {
        return Err(format!(
            "GitHub release commands require {REPOSITORY} Actions"
        ));
    }
    let policy = require_exact_checkout(policy_root, main_sha, "protected current-main policy")?;
    let source = require_exact_checkout(source_root, source_sha, "release source data")?;
    if policy == source {
        return Err("release policy and source data require separate checkouts".to_string());
    }
    Ok(())
}

fn require_exact_checkout(root: &Path, expected_sha: &str, label: &str) -> Result<PathBuf, String> {
    require_sha(expected_sha, label)?;
    let canonical = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize {label} checkout: {error}"))?;
    let top = git_line(root, &["rev-parse", "--show-toplevel"])?;
    let top =
        fs::canonicalize(top).map_err(|error| format!("canonicalize {label} root: {error}"))?;
    if canonical != top {
        return Err(format!("{label} path is not its Git worktree root"));
    }
    let head = git_line(root, &["rev-parse", "HEAD"])?;
    if head != expected_sha {
        return Err(format!("{label} HEAD differs from its exact commit"));
    }
    if !git_output(root, &["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty() {
        return Err(format!("{label} checkout is not clean"));
    }
    Ok(canonical)
}

fn main_sha(github: &mut impl Transport) -> Result<String, String> {
    let reference: GitRef = github.get(&format!("repos/{REPOSITORY}/git/ref/heads/main"))?;
    if reference.name != "refs/heads/main" || reference.object.kind != "commit" {
        return Err("main is not one exact commit ref".to_string());
    }
    require_sha(&reference.object.sha, "main SHA")?;
    Ok(reference.object.sha)
}

fn require_main_ancestry(
    github: &mut impl Transport,
    source_sha: &str,
    main_sha: &str,
) -> Result<(), String> {
    let comparison: Comparison = github.get(&format!(
        "repos/{REPOSITORY}/compare/{source_sha}...{main_sha}"
    ))?;
    if !matches!(comparison.status.as_str(), "ahead" | "identical")
        || comparison.base_commit.sha != source_sha
        || comparison.merge_base_commit.sha != source_sha
    {
        return Err("recovery source is no longer an ancestor of current main".to_string());
    }
    Ok(())
}

fn require_current_mutation_policy(
    github: &mut impl Transport,
    source_sha: &str,
    policy_main_sha: &str,
) -> Result<(), String> {
    require_main_ancestry(github, source_sha, policy_main_sha)?;
    let current_main_sha = main_sha(github)?;
    require_unchanged_main(policy_main_sha, &current_main_sha)
}

fn bind_original_run(
    github: &mut impl Transport,
    source_sha: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<(), String> {
    if run_id == 0 || run_attempt == 0 {
        return Err("original run identity must be positive".to_string());
    }
    let workflow: Workflow = github.get(&format!(
        "repos/{REPOSITORY}/actions/workflows/{PUBLISH_WORKFLOW_ID}"
    ))?;
    validate_publish_workflow(&workflow)?;
    let attempt: WorkflowRun = github.get(&format!(
        "repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{run_attempt}"
    ))?;
    let current: WorkflowRun = github.get(&format!("repos/{REPOSITORY}/actions/runs/{run_id}"))?;
    validate_original_run_pair(&attempt, &current, source_sha, run_id, run_attempt)?;
    let artifacts: ArtifactInventory = github.get(&format!(
        "repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100"
    ))?;
    validate_artifact_inventory(&artifacts)
}

fn validate_original_run_pair(
    attempt: &WorkflowRun,
    current: &WorkflowRun,
    source_sha: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<(), String> {
    validate_original_run(attempt, source_sha, run_id, run_attempt)?;
    validate_original_run(current, source_sha, run_id, run_attempt).map_err(|_| {
        "original publication run was rerun or changed after the selected attempt".to_string()
    })
}

fn validate_publish_workflow(workflow: &Workflow) -> Result<(), String> {
    if workflow.id != PUBLISH_WORKFLOW_ID
        || workflow.path != PUBLISH_WORKFLOW_PATH
        || workflow.state != "active"
    {
        return Err("replacement publication workflow identity or state changed".to_string());
    }
    Ok(())
}

fn validate_original_run(
    run: &WorkflowRun,
    source_sha: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<(), String> {
    let conclusion = run.conclusion.as_deref().unwrap_or_default();
    if run.id != run_id
        || run.run_attempt != run_attempt
        || run.workflow_id != PUBLISH_WORKFLOW_ID
        || run.path != PUBLISH_WORKFLOW_PATH
        || run.event != "push"
        || run.head_branch != "main"
        || run.head_sha != source_sha
        || run.repository.full_name != REPOSITORY
        || run.head_repository.full_name != REPOSITORY
        || run.status != "completed"
        || !matches!(
            conclusion,
            "success" | "failure" | "cancelled" | "timed_out" | "action_required"
        )
    {
        return Err("recovery does not match one completed original main run".to_string());
    }
    Ok(())
}

fn validate_artifact_inventory(inventory: &ArtifactInventory) -> Result<(), String> {
    if inventory.total_count != 0 || !inventory.artifacts.is_empty() {
        return Err("original publication run retained an artifact".to_string());
    }
    Ok(())
}

fn classify_release_pull_request(
    github: &mut impl Transport,
    source_sha: &str,
    version: &Version,
) -> Result<bool, String> {
    let source = source_commit(github, source_sha)?;
    let associated: Vec<AssociatedPullRequest> = github.get(&format!(
        "repos/{REPOSITORY}/commits/{source_sha}/pulls?per_page=100"
    ))?;
    let matching = select_merged_associations(&associated)?;
    let mut pulls = Vec::with_capacity(matching.len());
    for item in matching {
        let pull: PullRequest = github.get(&format!("repos/{REPOSITORY}/pulls/{}", item.number))?;
        pulls.push(pull);
    }
    let release_indexes = pulls
        .iter()
        .enumerate()
        .filter_map(|(index, pull)| {
            pull.head
                .reference
                .starts_with(MANUAL_BRANCH_PREFIX)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    if release_indexes.is_empty() {
        return Ok(false);
    }
    if pulls.len() != 1 || release_indexes.len() != 1 {
        return Err("release source must have one exact merged pull request".to_string());
    }

    require_verified_dco_commit(&source, source_sha, "release squash commit")?;
    if source.parents.len() != 1 {
        return Err("release squash commit must have exactly one parent".to_string());
    }

    let pull = &pulls[release_indexes[0]];
    if !canonical_release_pull(pull, version, &source.parents[0].sha) {
        return Err("merged release pull request differs from canonical policy".to_string());
    }

    let commits: Vec<Commit> = github.get(&format!(
        "repos/{REPOSITORY}/pulls/{}/commits?per_page=100",
        pull.number
    ))?;
    if commits.len() != 1 {
        return Err("release pull request must contain exactly one reviewed commit".to_string());
    }
    let signature = release_head_signature(github, pull.number, &pull.head.sha, source_sha)?;
    require_reviewed_release_head(&commits[0], &signature, &pull.head.sha, &pull.base.sha)?;
    if commits[0].commit.tree.sha != source.commit.tree.sha {
        return Err("release squash tree differs from the reviewed release tree".to_string());
    }

    let files: Vec<PullFile> = github.get(&format!(
        "repos/{REPOSITORY}/pulls/{}/files?per_page=100",
        pull.number
    ))?;
    validate_release_files(&files, pull.changed_files)?;
    Ok(true)
}

fn select_merged_associations(
    associated: &[AssociatedPullRequest],
) -> Result<Vec<&AssociatedPullRequest>, String> {
    if associated.len() >= 100 {
        return Err("source pull-request association inventory is not bounded".to_string());
    }
    // The commit-scoped endpoint binds this response to the requested source;
    // current REST responses no longer carry a duplicate merge SHA field.
    Ok(associated
        .iter()
        .filter(|pull| pull.state == "closed" && pull.merged_at.is_some())
        .collect())
}

fn canonical_release_pull(pull: &PullRequest, version: &Version, source_parent: &str) -> bool {
    let expected_branch = format!("{MANUAL_BRANCH_PREFIX}{version}");
    pull.state == "closed"
        && pull.merged_at.is_some()
        && pull.base.reference == "main"
        && pull.base.repo.full_name == REPOSITORY
        && pull.base.sha == source_parent
        && pull.head.reference == expected_branch
        && pull.head.repo.full_name == REPOSITORY
        && pull.changed_files > 0
        && pull.changed_files <= 9
}

fn validate_release_files(files: &[PullFile], changed_files: u64) -> Result<(), String> {
    if files.len() as u64 != changed_files || files.is_empty() {
        return Err("release pull-request file inventory is incomplete".to_string());
    }
    for file in files {
        if file.status != "modified" || !allowed_release_path(&file.filename) {
            return Err(format!(
                "release pull request changes unexpected path {}",
                file.filename
            ));
        }
    }
    if !files.iter().any(|file| file.filename == "Cargo.toml") {
        return Err("release pull request must update the workspace manifest".to_string());
    }
    Ok(())
}

fn ordinary_decision(operation: Operation) -> Result<Decision, String> {
    match operation {
        Operation::Auto | Operation::Validate => Ok(Decision {
            publish: false,
            finalize: false,
        }),
        Operation::Recover => {
            Err("recovery source is not a canonical merged release pull request".to_string())
        }
    }
}

fn maybe_reconcile_registry<F>(
    operation: Operation,
    release: bool,
    reconcile: F,
) -> Result<Option<Vec<bool>>, String>
where
    F: FnOnce() -> Result<Vec<bool>, String>,
{
    match operation {
        Operation::Validate => Ok(None),
        Operation::Auto if !release => Ok(None),
        Operation::Recover if !release => {
            Err("recovery source is not a canonical merged release pull request".to_string())
        }
        Operation::Auto | Operation::Recover => reconcile().map(Some),
    }
}

fn source_commit(github: &mut impl Transport, source_sha: &str) -> Result<Commit, String> {
    let commit: Commit = github.get(&format!("repos/{REPOSITORY}/commits/{source_sha}"))?;
    if commit.sha != source_sha {
        return Err("GitHub returned a different source commit".to_string());
    }
    Ok(commit)
}

fn require_verified_dco_commit(
    commit: &Commit,
    expected_sha: &str,
    label: &str,
) -> Result<(), String> {
    if commit.sha != expected_sha
        || !commit.commit.verification.verified
        || commit.commit.verification.reason != "valid"
        || !commit
            .commit
            .message
            .lines()
            .any(|line| line == DCO_TRAILER)
    {
        return Err(format!("{label} is not GitHub-verified and DCO-signed"));
    }
    Ok(())
}

fn require_reviewed_release_head(
    commit: &Commit,
    signature: &CommitSignature,
    head_sha: &str,
    base_sha: &str,
) -> Result<(), String> {
    require_sha(head_sha, "release pull-request head SHA")?;
    require_sha(base_sha, "release pull-request base SHA")?;
    if commit.sha != head_sha || commit.parents.len() != 1 || commit.parents[0].sha != base_sha {
        return Err(
            "release pull-request commit is not based on its exact current base".to_string(),
        );
    }
    require_verified_dco_commit(commit, head_sha, "release pull-request commit")?;
    require_release_signature_identity(commit, signature)
}

fn release_head_signature(
    github: &mut impl Transport,
    pull_number: u64,
    head_sha: &str,
    merge_sha: &str,
) -> Result<CommitSignature, String> {
    if pull_number == 0 || pull_number > i32::MAX as u64 {
        return Err("release pull-request number is outside the GraphQL bound".to_string());
    }
    require_sha(head_sha, "release pull-request signature head SHA")?;
    require_sha(merge_sha, "release pull-request merge SHA")?;
    let response: SignatureResponse = github.graphql(&json!({
        "query": concat!(
            "query($owner:String!,$name:String!,$number:Int!){",
            "repository(owner:$owner,name:$name){pullRequest(number:$number){",
            "mergeCommit{oid}",
            "commits(first:2){totalCount nodes{commit{oid signature{",
            "__typename email isValid state wasSignedByGitHub ",
            "signer{databaseId login __typename}}}}pageInfo{hasNextPage}}}}}"
        ),
        "variables": {
            "owner": "NVIDIA",
            "name": "yaml-sigil-rs",
            "number": pull_number,
        },
    }))?;
    validate_signature_response(response, head_sha, merge_sha)
}

fn validate_signature_response(
    response: SignatureResponse,
    head_sha: &str,
    merge_sha: &str,
) -> Result<CommitSignature, String> {
    if response.errors.is_some() {
        return Err("GitHub GraphQL signature query returned errors".to_string());
    }
    let pull = response
        .data
        .and_then(|data| data.repository)
        .and_then(|repository| repository.pull_request)
        .ok_or_else(|| "GitHub GraphQL returned no release commit inventory".to_string())?;
    if pull.merge_commit.as_ref().map(|commit| commit.oid.as_str()) != Some(merge_sha) {
        return Err("release pull request merge commit differs".to_string());
    }
    let connection = pull.commits;
    if connection.total_count != 1
        || connection.nodes.len() != 1
        || connection.page_info.has_next_page
    {
        return Err("release signature inventory is incomplete or ambiguous".to_string());
    }
    let commit = connection
        .nodes
        .into_iter()
        .next()
        .ok_or_else(|| "release signature inventory is empty".to_string())?
        .commit;
    if commit.oid != head_sha {
        return Err("release signature result does not match the reviewed head".to_string());
    }
    commit
        .signature
        .ok_or_else(|| "release pull-request signature is missing".to_string())
}

fn require_release_signature_identity(
    commit: &Commit,
    signature: &CommitSignature,
) -> Result<(), String> {
    let signer = signature
        .signer
        .as_ref()
        .ok_or_else(|| "release pull-request signature signer is missing".to_string())?;
    if !matches!(
        signature.kind.as_str(),
        "GpgSignature" | "SshSignature" | "SmimeSignature"
    ) || !signature.is_valid
        || signature.state != "VALID"
        || signature.was_signed_by_github
        || signer.database_id != Some(RELEASE_SIGNER_ID)
        || signer.login != RELEASE_SIGNER_LOGIN
        || signer.kind != "User"
    {
        return Err("release pull-request signature signer is not exact".to_string());
    }

    let exact_account = |account: Option<&GitHubAccount>| {
        account.is_some_and(|account| {
            account.id == RELEASE_SIGNER_ID
                && account.login == RELEASE_SIGNER_LOGIN
                && account.kind == "User"
        })
    };
    if !exact_account(commit.author.as_ref()) || !exact_account(commit.committer.as_ref()) {
        return Err(
            "release pull-request REST identities do not match the verified signer".to_string(),
        );
    }

    let raw_author = commit
        .commit
        .author
        .as_ref()
        .ok_or_else(|| "release pull-request raw author is missing".to_string())?;
    let raw_committer = commit
        .commit
        .committer
        .as_ref()
        .ok_or_else(|| "release pull-request raw committer is missing".to_string())?;
    let author_dco = format!("Signed-off-by: {} <{}>", raw_author.name, raw_author.email);
    let dco_lines = commit
        .commit
        .message
        .lines()
        .filter(|line| line.starts_with("Signed-off-by: "))
        .collect::<Vec<_>>();
    if raw_author.name != RELEASE_AUTHOR_NAME
        || signature.email != RELEASE_AUTHOR_EMAIL
        || raw_author.email != signature.email
        || raw_committer.email != signature.email
        || author_dco != DCO_TRAILER
        || dco_lines != [author_dco.as_str()]
    {
        return Err(
            "release pull-request signature, raw identities, and author DCO differ".to_string(),
        );
    }
    Ok(())
}

fn allowed_release_path(path: &str) -> bool {
    path == "Cargo.toml"
        || RUST_POLICY.packages.iter().any(|package| {
            path == format!("{}/Cargo.toml", package.path_in_vcs) || path == package.changelog
        })
}

fn decide(operation: Operation, states: &[bool]) -> Result<Decision, String> {
    if states.len() != RUST_POLICY.packages.len() {
        return Err("registry state does not cover exactly four packages".to_string());
    }
    if operation == Operation::Validate {
        return Ok(Decision {
            publish: false,
            finalize: false,
        });
    }
    let mut missing_seen = false;
    for published in states {
        if !published {
            missing_seen = true;
        } else if missing_seen {
            return Err(
                "published crates do not form the exact dependency-order prefix".to_string(),
            );
        }
    }
    let published = states.iter().filter(|state| **state).count();
    match operation {
        Operation::Validate => unreachable!("validation returned before registry interpretation"),
        Operation::Auto if published == 0 => Ok(Decision {
            publish: true,
            finalize: true,
        }),
        Operation::Auto if published == states.len() => Ok(Decision {
            publish: false,
            finalize: false,
        }),
        Operation::Auto => Err(
            "partial publication requires bounded recovery from the original source".to_string(),
        ),
        Operation::Recover => Ok(Decision {
            publish: published != states.len(),
            finalize: true,
        }),
    }
}

fn registry_state(states: &[bool]) -> &'static str {
    let count = states.iter().filter(|state| **state).count();
    if count == 0 {
        "none"
    } else if count == states.len() {
        "complete"
    } else {
        "partial"
    }
}

fn registry_states(source_sha: &str, version: &Version) -> Result<Vec<bool>, String> {
    let mut states = Vec::with_capacity(RUST_POLICY.packages.len());
    for package in RUST_POLICY.packages {
        let record = registry_record(package.package, version)?;
        if let Some(record) = record {
            verify_published_source(package, version, source_sha, &record)?;
            states.push(true);
        } else {
            states.push(false);
        }
    }
    Ok(states)
}

fn registry_record(package: &str, version: &Version) -> Result<Option<RegistryRecord>, String> {
    require_package_name(package)?;
    let url = format!("https://crates.io/api/v1/crates/{package}/{version}");
    let (status, body) = curl_response(&url)?;
    if status == 404 {
        return Ok(None);
    }
    if status != 200 {
        return Err(format!(
            "crates.io returned HTTP {status} for {package} {version}"
        ));
    }
    let response: RegistryResponse = serde_json::from_slice(&body)
        .map_err(|error| format!("invalid crates.io response for {package} {version}: {error}"))?;
    validate_registry_record(package, version, &response.version)?;
    Ok(Some(response.version))
}

fn validate_registry_record(
    package: &str,
    version: &Version,
    record: &RegistryRecord,
) -> Result<(), String> {
    require_checksum(&record.checksum)?;
    if record.num != version.to_string() || record.yanked {
        return Err(format!(
            "crates.io returned conflicting metadata for {package} {version}"
        ));
    }
    Ok(())
}

fn verify_published_source(
    package: &PackagePolicy,
    version: &Version,
    source_sha: &str,
    record: &RegistryRecord,
) -> Result<(), String> {
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{version}/download",
        package.package
    );
    let (status, archive) = curl_response(&url)?;
    if status != 200 {
        return Err(format!(
            "crates.io returned HTTP {status} for {} {version} source",
            package.package
        ));
    }
    verify_published_archive(package, version, source_sha, record, &archive)
}

fn verify_published_archive(
    package: &PackagePolicy,
    version: &Version,
    source_sha: &str,
    record: &RegistryRecord,
    archive: &[u8],
) -> Result<(), String> {
    require_sha(source_sha, "published source SHA")?;
    let actual = format!("{:x}", Sha256::digest(archive));
    if actual != record.checksum {
        return Err(format!(
            "published checksum differs for {} {version}",
            package.package
        ));
    }
    let expected_path = format!("{}-{version}/.cargo_vcs_info.json", package.package);
    let mut found = None;
    let mut tar = tar::Archive::new(GzDecoder::new(Cursor::new(&archive)));
    let entries = tar
        .entries()
        .map_err(|error| format!("open {} {version} source: {error}", package.package))?;
    let mut entry_count = 0;
    let mut unpacked_bytes = 0;
    for entry in entries {
        let mut entry =
            entry.map_err(|error| format!("read {} {version} source: {error}", package.package))?;
        accumulate_archive_work(&mut entry_count, &mut unpacked_bytes, entry.size())?;
        let path = entry
            .path()
            .map_err(|error| format!("read crate path: {error}"))?;
        if path.to_string_lossy() != expected_path {
            continue;
        }
        if found.is_some()
            || !entry.header().entry_type().is_file()
            || entry.size() > VCS_INFO_LIMIT
        {
            return Err(format!(
                "{} {version} has invalid .cargo_vcs_info.json",
                package.package
            ));
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read .cargo_vcs_info.json: {error}"))?;
        found = Some(bytes);
    }
    let bytes = found.ok_or_else(|| {
        format!(
            "{} {version} lacks bounded .cargo_vcs_info.json",
            package.package
        )
    })?;
    let vcs: CargoVcsInfo = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid .cargo_vcs_info.json: {error}"))?;
    require_sha(&vcs.git.sha1, "published VCS SHA")?;
    if vcs.git.sha1 != source_sha
        || vcs.git.dirty
        || vcs.path_in_vcs.as_deref() != Some(package.path_in_vcs)
    {
        return Err(format!(
            "{} {version} was not packaged from exact source {source_sha}",
            package.package
        ));
    }
    Ok(())
}

fn accumulate_archive_work(
    entries: &mut usize,
    unpacked_bytes: &mut u64,
    entry_size: u64,
) -> Result<(), String> {
    *entries = entries
        .checked_add(1)
        .ok_or_else(|| "crate archive entry count overflowed".to_string())?;
    *unpacked_bytes = unpacked_bytes
        .checked_add(entry_size)
        .ok_or_else(|| "crate archive size overflowed".to_string())?;
    if *entries > MAX_CRATE_ARCHIVE_ENTRIES || *unpacked_bytes > MAX_CRATE_UNPACKED_BYTES {
        return Err("crate archive exceeds bounded inspection limits".to_string());
    }
    Ok(())
}

fn crates_io_request_command(request_args: &[&str], sleep: impl FnOnce(Duration)) -> Command {
    let mut command = Command::new("curl");
    command.args(["--disable", "--user-agent", CRATES_IO_USER_AGENT]);
    command.args(request_args);
    sleep(CRATES_IO_REQUEST_DELAY);
    command
}

fn curl_response(url: &str) -> Result<(u16, Vec<u8>), String> {
    if !url.starts_with("https://crates.io/api/v1/crates/") || url.contains(['\0', '\r', '\n']) {
        return Err("crates.io request URL is not fixed and safe".to_string());
    }
    let mut command = crates_io_request_command(
        &[
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "60",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--write-out",
            "\n%{http_code}",
            url,
        ],
        thread::sleep,
    );
    for token in [
        "CARGO_REGISTRY_TOKEN",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GIT_TOKEN",
    ] {
        command.env_remove(token);
    }
    let output = bounded_process::output(&mut command, CRATE_RESPONSE_LIMITS)
        .map_err(|error| format!("query crates.io: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "query crates.io failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let split = output
        .stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or_else(|| "crates.io response lacks HTTP status".to_string())?;
    let status = std::str::from_utf8(&output.stdout[split + 1..])
        .map_err(|_| "crates.io HTTP status is not UTF-8".to_string())?
        .parse::<u16>()
        .map_err(|_| "crates.io HTTP status is malformed".to_string())?;
    Ok((status, output.stdout[..split].to_vec()))
}

fn verify_app_scope(github: &mut impl Transport, observed_slug: &str) -> Result<(), String> {
    let installation: InstallationRepositories =
        github.get("installation/repositories?per_page=100")?;
    validate_app_scope(observed_slug, &installation)
}

fn validate_app_scope(
    observed_slug: &str,
    installation: &InstallationRepositories,
) -> Result<(), String> {
    if observed_slug != APP_SLUG {
        return Err("token-minting action reported an unexpected App slug".to_string());
    }
    if installation.total_count != 1
        || installation.repositories.len() != 1
        || installation.repositories[0].full_name != REPOSITORY
    {
        return Err("App token is not scoped to exactly this repository".to_string());
    }
    Ok(())
}

fn finalize_package(
    github: &mut impl Transport,
    package: &PackagePolicy,
    version: &Version,
    source_sha: &str,
    policy_main_sha: &str,
    tagger_date: &str,
) -> Result<(), String> {
    let spec = ReleaseSpec::new(package, version, source_sha)?;
    let tag_object_sha = reconcile_tag(github, &spec, source_sha, policy_main_sha, tagger_date)?;
    reconcile_release(
        github,
        &spec,
        source_sha,
        policy_main_sha,
        tagger_date,
        &tag_object_sha,
    )
}

fn reconcile_release(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    policy_main_sha: &str,
    tagger_date: &str,
    tag_object_sha: &str,
) -> Result<(), String> {
    if inspect_release(github, spec, source_sha)? {
        require_exact_tag_object(github, spec, source_sha, tagger_date, tag_object_sha)?;
        return Ok(());
    }
    create_release(
        github,
        spec,
        source_sha,
        policy_main_sha,
        tagger_date,
        tag_object_sha,
    )?;
    if !inspect_release(github, spec, source_sha)? {
        return Err(format!("immutable Release {} was not retained", spec.tag));
    }
    require_exact_tag_object(github, spec, source_sha, tagger_date, tag_object_sha)?;
    Ok(())
}

#[derive(Debug)]
struct ReleaseSpec {
    tag: String,
    body: String,
    prerelease: bool,
    message: String,
}

impl ReleaseSpec {
    fn new(package: &PackagePolicy, version: &Version, source_sha: &str) -> Result<Self, String> {
        let tag = package.tag(&version.to_string());
        require_tag(&tag)?;
        Ok(Self {
            message: format!(
                "chore: release package {} version {version}",
                package.package
            ),
            body: format!(
                "Source: https://github.com/{REPOSITORY}/commit/{source_sha}\n\nThis source-only Release contains no attached assets."
            ),
            prerelease: !version.pre.is_empty(),
            tag,
        })
    }
}

fn reconcile_tag(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    policy_main_sha: &str,
    tagger_date: &str,
) -> Result<String, String> {
    if let Some(object_sha) = inspect_tag(github, spec, source_sha, tagger_date)? {
        return Ok(object_sha);
    }
    let object = create_tag_object(github, spec, source_sha, policy_main_sha, tagger_date)?;
    create_tag_ref(
        github,
        spec,
        source_sha,
        policy_main_sha,
        tagger_date,
        &object.sha,
    )?;
    require_exact_tag_object(github, spec, source_sha, tagger_date, &object.sha)?;
    Ok(object.sha)
}

fn inspect_tag(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    tagger_date: &str,
) -> Result<Option<String>, String> {
    let path = format!("repos/{REPOSITORY}/git/ref/tags/{}", spec.tag);
    let Some(reference): Option<GitRef> = github.get_optional(&path)? else {
        return Ok(None);
    };
    let object_sha = validate_tag_ref(&reference, spec)?;
    let object: AnnotatedTag = github.get(&format!("repos/{REPOSITORY}/git/tags/{object_sha}"))?;
    validate_tag(&object, spec, source_sha, tagger_date, &object_sha)?;
    Ok(Some(object_sha))
}

fn validate_tag_ref(reference: &GitRef, spec: &ReleaseSpec) -> Result<String, String> {
    if reference.name != format!("refs/tags/{}", spec.tag) || reference.object.kind != "tag" {
        return Err(format!("{} is not an annotated tag", spec.tag));
    }
    require_sha(&reference.object.sha, "tag object SHA")?;
    Ok(reference.object.sha.clone())
}

fn require_exact_tag_object(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    tagger_date: &str,
    expected_object_sha: &str,
) -> Result<(), String> {
    let observed = inspect_tag(github, spec, source_sha, tagger_date)?;
    if observed.as_deref() != Some(expected_object_sha) {
        return Err(format!(
            "annotated tag {} does not retain exact object {expected_object_sha}",
            spec.tag
        ));
    }
    Ok(())
}

fn validate_tag(
    object: &AnnotatedTag,
    spec: &ReleaseSpec,
    source_sha: &str,
    tagger_date: &str,
    object_sha: &str,
) -> Result<(), String> {
    if object.sha != object_sha
        || object.tag != spec.tag
        || object.message != spec.message
        || object.object.kind != "commit"
        || object.object.sha != source_sha
        || object.tagger.name != APP_LOGIN
        || object.tagger.email != APP_EMAIL
        || object.tagger.date != tagger_date
    {
        return Err(format!("annotated tag {} has conflicting state", spec.tag));
    }
    Ok(())
}

fn create_tag_object(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    policy_main_sha: &str,
    tagger_date: &str,
) -> Result<AnnotatedTag, String> {
    let payload = json!({
        "tag": spec.tag,
        "message": spec.message,
        "object": source_sha,
        "type": "commit",
        "tagger": {
            "name": APP_LOGIN,
            "email": APP_EMAIL,
            "date": tagger_date,
        },
    });
    require_current_mutation_policy(github, source_sha, policy_main_sha)?;
    let object: AnnotatedTag = github.post(&format!("repos/{REPOSITORY}/git/tags"), &payload)?;
    require_sha(&object.sha, "created tag object SHA")?;
    validate_tag(&object, spec, source_sha, tagger_date, &object.sha)?;
    let readback: AnnotatedTag =
        github.get(&format!("repos/{REPOSITORY}/git/tags/{}", object.sha))?;
    validate_tag(&readback, spec, source_sha, tagger_date, &object.sha)?;
    Ok(object)
}

fn create_tag_ref(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    policy_main_sha: &str,
    tagger_date: &str,
    object_sha: &str,
) -> Result<(), String> {
    let path = format!("repos/{REPOSITORY}/git/refs");
    let payload = json!({"ref": format!("refs/tags/{}", spec.tag), "sha": object_sha});
    require_current_mutation_policy(github, source_sha, policy_main_sha)?;
    let result: Result<GitRef, String> = github.post(&path, &payload);
    match result {
        Ok(reference) => {
            if validate_tag_ref(&reference, spec)? != object_sha {
                return Err(format!(
                    "GitHub created {} at a different tag object",
                    spec.tag
                ));
            }
        }
        Err(error) => {
            if require_exact_tag_object(github, spec, source_sha, tagger_date, object_sha).is_err()
            {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn inspect_release(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
) -> Result<bool, String> {
    let Some(release): Option<Release> =
        github.get_optional(&format!("repos/{REPOSITORY}/releases/tags/{}", spec.tag))?
    else {
        return Ok(false);
    };
    validate_release(&release, spec, source_sha)?;
    Ok(true)
}

fn create_release(
    github: &mut impl Transport,
    spec: &ReleaseSpec,
    source_sha: &str,
    policy_main_sha: &str,
    tagger_date: &str,
    tag_object_sha: &str,
) -> Result<(), String> {
    let payload = json!({
        "tag_name": spec.tag,
        "target_commitish": source_sha,
        "name": spec.tag,
        "body": spec.body,
        "draft": false,
        "prerelease": spec.prerelease,
        "generate_release_notes": false,
        "make_latest": "false",
    });
    require_current_mutation_policy(github, source_sha, policy_main_sha)?;
    require_exact_tag_object(github, spec, source_sha, tagger_date, tag_object_sha)?;
    let result: Result<Release, String> =
        github.post(&format!("repos/{REPOSITORY}/releases"), &payload);
    match result {
        Ok(release) => validate_release(&release, spec, source_sha),
        Err(error) => {
            if inspect_release(github, spec, source_sha)? {
                require_exact_tag_object(github, spec, source_sha, tagger_date, tag_object_sha)?;
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn validate_release(release: &Release, spec: &ReleaseSpec, source_sha: &str) -> Result<(), String> {
    if release.id == 0
        || release.tag_name != spec.tag
        || release.target_commitish != source_sha
        || release.name != spec.tag
        || release.body != spec.body
        || release.draft
        || release.prerelease != spec.prerelease
        || !release.immutable
        || release.author.login != APP_LOGIN
        || release.author.id != APP_ID
        || release.author.kind != "Bot"
        || !release.assets.is_empty()
    {
        return Err(format!(
            "GitHub Release {} is not exact, immutable, App-authored, and zero-asset",
            spec.tag
        ));
    }
    Ok(())
}

fn append_qualification_outputs(
    source_sha: &str,
    version: &Version,
    decision: Decision,
    state: &str,
) -> Result<(), String> {
    append_output("source_sha", source_sha)?;
    append_output("version", &version.to_string())?;
    append_output("publish", bool_text(decision.publish))?;
    append_output("finalize", bool_text(decision.finalize))?;
    append_output("registry_state", state)
}

fn append_output(name: &str, value: &str) -> Result<(), String> {
    if !matches!(
        name,
        "source_sha" | "version" | "publish" | "finalize" | "registry_state"
    ) || value.is_empty()
        || value.contains(['\r', '\n'])
    {
        return Err("workflow output is malformed".to_string());
    }
    let path =
        env::var_os("GITHUB_OUTPUT").ok_or_else(|| "GITHUB_OUTPUT is required".to_string())?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| format!("open GITHUB_OUTPUT: {error}"))?;
    writeln!(file, "{name}={value}").map_err(|error| format!("write GITHUB_OUTPUT: {error}"))
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn require_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{label} is not a lowercase full SHA"));
    }
    Ok(())
}

fn require_checksum(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("crates.io checksum is not lowercase SHA-256".to_string());
    }
    Ok(())
}

fn require_package_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("release package name is malformed".to_string());
    }
    Ok(())
}

fn require_tag(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'v')
        })
    {
        return Err("release tag is malformed".to_string());
    }
    Ok(())
}

fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = bounded_process::output(
        Command::new("git").current_dir(root).args(args),
        VALIDATION_OUTPUT_LIMITS,
    )
    .map_err(|error| format!("run git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn git_line(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_output(root, args)?;
    let value = std::str::from_utf8(&output)
        .map_err(|_| "Git output is not UTF-8".to_string())?
        .trim_end_matches(['\r', '\n']);
    if value.contains(['\r', '\n']) {
        return Err("Git output is not one line".to_string());
    }
    Ok(value.to_string())
}

#[derive(Deserialize)]
struct GitRef {
    #[serde(rename = "ref")]
    name: String,
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct Comparison {
    status: String,
    base_commit: ShaObject,
    merge_base_commit: ShaObject,
}

#[derive(Deserialize)]
struct ShaObject {
    sha: String,
}

#[derive(Clone, Deserialize)]
struct Repository {
    full_name: String,
}

#[derive(Clone, Deserialize)]
struct WorkflowRun {
    id: u64,
    run_attempt: u64,
    workflow_id: u64,
    path: String,
    event: String,
    head_branch: String,
    head_sha: String,
    repository: Repository,
    head_repository: Repository,
    status: String,
    conclusion: Option<String>,
}

#[derive(Clone, Deserialize)]
struct Workflow {
    id: u64,
    path: String,
    state: String,
}

#[derive(Deserialize)]
struct ArtifactInventory {
    total_count: u64,
    artifacts: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Commit {
    sha: String,
    author: Option<GitHubAccount>,
    committer: Option<GitHubAccount>,
    parents: Vec<ShaObject>,
    commit: CommitData,
}

#[derive(Deserialize)]
struct CommitData {
    author: Option<RawGitIdentity>,
    committer: Option<RawGitIdentity>,
    message: String,
    verification: Verification,
    tree: ShaObject,
}

#[derive(Deserialize)]
struct Verification {
    verified: bool,
    reason: String,
}

#[derive(Deserialize)]
struct RawGitIdentity {
    name: String,
    email: String,
    date: String,
}

#[derive(Deserialize)]
struct GitHubAccount {
    id: u64,
    login: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct SignatureResponse {
    #[serde(default)]
    data: Option<SignatureData>,
    #[serde(default)]
    errors: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct SignatureData {
    repository: Option<SignatureRepository>,
}

#[derive(Deserialize)]
struct SignatureRepository {
    #[serde(rename = "pullRequest")]
    pull_request: Option<SignaturePullRequest>,
}

#[derive(Deserialize)]
struct SignaturePullRequest {
    #[serde(rename = "mergeCommit")]
    merge_commit: Option<SignatureMergeCommit>,
    commits: SignatureConnection,
}

#[derive(Deserialize)]
struct SignatureMergeCommit {
    oid: String,
}

#[derive(Deserialize)]
struct SignatureConnection {
    #[serde(rename = "totalCount")]
    total_count: u64,
    nodes: Vec<SignatureNode>,
    #[serde(rename = "pageInfo")]
    page_info: SignaturePageInfo,
}

#[derive(Deserialize)]
struct SignaturePageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
}

#[derive(Deserialize)]
struct SignatureNode {
    commit: SignatureCommit,
}

#[derive(Deserialize)]
struct SignatureCommit {
    oid: String,
    signature: Option<CommitSignature>,
}

#[derive(Clone, Deserialize)]
struct CommitSignature {
    #[serde(rename = "__typename")]
    kind: String,
    email: String,
    #[serde(rename = "isValid")]
    is_valid: bool,
    state: String,
    #[serde(rename = "wasSignedByGitHub")]
    was_signed_by_github: bool,
    signer: Option<SignatureSigner>,
}

#[derive(Clone, Deserialize)]
struct SignatureSigner {
    #[serde(rename = "databaseId")]
    database_id: Option<u64>,
    login: String,
    #[serde(rename = "__typename")]
    kind: String,
}

#[derive(Deserialize)]
struct PullRequest {
    number: u64,
    state: String,
    merged_at: Option<String>,
    changed_files: u64,
    base: PullRef,
    head: PullRef,
}

#[derive(Deserialize)]
struct AssociatedPullRequest {
    number: u64,
    state: String,
    merged_at: Option<String>,
}

#[derive(Deserialize)]
struct PullRef {
    #[serde(rename = "ref")]
    reference: String,
    sha: String,
    repo: Repository,
}

#[derive(Deserialize)]
struct PullFile {
    filename: String,
    status: String,
}

#[derive(Deserialize)]
struct RegistryResponse {
    version: RegistryRecord,
}

#[derive(Deserialize)]
struct RegistryRecord {
    checksum: String,
    num: String,
    yanked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoVcsInfo {
    git: CargoVcsGit,
    path_in_vcs: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoVcsGit {
    sha1: String,
    dirty: bool,
}

#[derive(Deserialize)]
struct InstallationRepositories {
    total_count: usize,
    repositories: Vec<Repository>,
}

#[derive(Deserialize)]
struct AnnotatedTag {
    sha: String,
    tag: String,
    message: String,
    tagger: Tagger,
    object: GitObject,
}

#[derive(Deserialize)]
struct Tagger {
    name: String,
    email: String,
    date: String,
}

#[derive(Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    target_commitish: String,
    name: String,
    body: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    author: ReleaseAuthor,
    assets: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct ReleaseAuthor {
    login: String,
    id: u64,
    #[serde(rename = "type")]
    kind: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::cell::Cell;

    const TEST_SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const TEST_POLICY_SHA: &str = "1123456789abcdef0123456789abcdef01234567";
    const TEST_DRIFT_SHA: &str = "2123456789abcdef0123456789abcdef01234567";
    const TEST_TAG_OBJECT_SHA: &str = "3123456789abcdef0123456789abcdef01234567";
    const TEST_REPLACEMENT_TAG_OBJECT_SHA: &str = "4123456789abcdef0123456789abcdef01234567";
    const TEST_DRIFT_TAG_OBJECT_SHA: &str = "5123456789abcdef0123456789abcdef01234567";

    #[derive(Clone, Copy)]
    enum TagChange {
        Deleted,
        LightweightReplacement,
        ObjectReplacement,
        SourceDrift,
    }

    struct MutationTransport {
        source_sha: String,
        policy_sha: String,
        tag: String,
        message: String,
        body: String,
        prerelease: bool,
        tagger_date: String,
        drift_after_tag_object: bool,
        tag_object_created: bool,
        tag_ref_created: bool,
        release_created: bool,
        release_posted: bool,
        release_read_back: bool,
        tag_change_after_release_boundary: Option<TagChange>,
        events: Vec<String>,
    }

    impl MutationTransport {
        fn new(spec: &ReleaseSpec, tagger_date: &str, drift_after_tag_object: bool) -> Self {
            Self {
                source_sha: TEST_SOURCE_SHA.to_string(),
                policy_sha: TEST_POLICY_SHA.to_string(),
                tag: spec.tag.clone(),
                message: spec.message.clone(),
                body: spec.body.clone(),
                prerelease: spec.prerelease,
                tagger_date: tagger_date.to_string(),
                drift_after_tag_object,
                tag_object_created: false,
                tag_ref_created: false,
                release_created: false,
                release_posted: false,
                release_read_back: false,
                tag_change_after_release_boundary: None,
                events: Vec::new(),
            }
        }

        fn change_tag_after_release_boundary(&mut self, change: TagChange) {
            self.tag_change_after_release_boundary = Some(change);
        }

        fn release_boundary_crossed(&self) -> bool {
            self.release_posted || self.release_read_back
        }

        fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, String> {
            serde_json::from_value(value).map_err(|error| error.to_string())
        }

        fn comparison(&self) -> serde_json::Value {
            json!({
                "status": "ahead",
                "base_commit": {"sha": self.source_sha},
                "merge_base_commit": {"sha": self.source_sha},
            })
        }

        fn main_ref(&self) -> serde_json::Value {
            let sha = if self.drift_after_tag_object
                && self.tag_object_created
                && !self.tag_ref_created
            {
                TEST_DRIFT_SHA
            } else {
                &self.policy_sha
            };
            json!({
                "ref": "refs/heads/main",
                "object": {"sha": sha, "type": "commit"},
            })
        }

        fn tag_object(&self) -> serde_json::Value {
            json!({
                "sha": TEST_TAG_OBJECT_SHA,
                "tag": self.tag,
                "message": self.message,
                "tagger": {
                    "name": APP_LOGIN,
                    "email": APP_EMAIL,
                    "date": self.tagger_date,
                },
                "object": {"sha": self.source_sha, "type": "commit"},
            })
        }

        fn replacement_tag_object(&self) -> serde_json::Value {
            json!({
                "sha": TEST_REPLACEMENT_TAG_OBJECT_SHA,
                "tag": self.tag,
                "message": self.message,
                "tagger": {
                    "name": APP_LOGIN,
                    "email": APP_EMAIL,
                    "date": self.tagger_date,
                },
                "object": {"sha": self.source_sha, "type": "commit"},
            })
        }

        fn drift_tag_object(&self) -> serde_json::Value {
            json!({
                "sha": TEST_DRIFT_TAG_OBJECT_SHA,
                "tag": self.tag,
                "message": self.message,
                "tagger": {
                    "name": APP_LOGIN,
                    "email": APP_EMAIL,
                    "date": self.tagger_date,
                },
                "object": {"sha": TEST_DRIFT_SHA, "type": "commit"},
            })
        }

        fn tag_ref(&self) -> serde_json::Value {
            if self.release_boundary_crossed()
                && matches!(
                    self.tag_change_after_release_boundary,
                    Some(TagChange::LightweightReplacement)
                )
            {
                return json!({
                    "ref": format!("refs/tags/{}", self.tag),
                    "object": {"sha": self.source_sha, "type": "commit"},
                });
            }
            if self.release_boundary_crossed()
                && matches!(
                    self.tag_change_after_release_boundary,
                    Some(TagChange::ObjectReplacement)
                )
            {
                return json!({
                    "ref": format!("refs/tags/{}", self.tag),
                    "object": {"sha": TEST_REPLACEMENT_TAG_OBJECT_SHA, "type": "tag"},
                });
            }
            if self.release_boundary_crossed()
                && matches!(
                    self.tag_change_after_release_boundary,
                    Some(TagChange::SourceDrift)
                )
            {
                return json!({
                    "ref": format!("refs/tags/{}", self.tag),
                    "object": {"sha": TEST_DRIFT_TAG_OBJECT_SHA, "type": "tag"},
                });
            }
            json!({
                "ref": format!("refs/tags/{}", self.tag),
                "object": {"sha": TEST_TAG_OBJECT_SHA, "type": "tag"},
            })
        }

        fn release(&self) -> serde_json::Value {
            json!({
                "id": 1,
                "tag_name": self.tag,
                "target_commitish": self.source_sha,
                "name": self.tag,
                "body": self.body,
                "draft": false,
                "prerelease": self.prerelease,
                "immutable": true,
                "author": {"login": APP_LOGIN, "id": APP_ID, "type": "Bot"},
                "assets": [],
            })
        }
    }

    impl Transport for MutationTransport {
        fn get<T: serde::de::DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
            self.events.push(format!("GET {path}"));
            if path
                == format!(
                    "repos/{REPOSITORY}/compare/{}...{}",
                    self.source_sha, self.policy_sha
                )
            {
                Self::decode(self.comparison())
            } else if path == format!("repos/{REPOSITORY}/git/ref/heads/main") {
                Self::decode(self.main_ref())
            } else if path == format!("repos/{REPOSITORY}/git/tags/{TEST_TAG_OBJECT_SHA}") {
                Self::decode(self.tag_object())
            } else if path
                == format!("repos/{REPOSITORY}/git/tags/{TEST_REPLACEMENT_TAG_OBJECT_SHA}")
            {
                Self::decode(self.replacement_tag_object())
            } else if path == format!("repos/{REPOSITORY}/git/tags/{TEST_DRIFT_TAG_OBJECT_SHA}") {
                Self::decode(self.drift_tag_object())
            } else {
                Err(format!("unexpected GET {path}"))
            }
        }

        fn get_optional<T: serde::de::DeserializeOwned>(
            &mut self,
            path: &str,
        ) -> Result<Option<T>, String> {
            self.events.push(format!("GET? {path}"));
            if path == format!("repos/{REPOSITORY}/git/ref/tags/{}", self.tag) {
                if self.release_boundary_crossed()
                    && matches!(
                        self.tag_change_after_release_boundary,
                        Some(TagChange::Deleted)
                    )
                {
                    return Ok(None);
                }
                self.tag_ref_created
                    .then(|| Self::decode(self.tag_ref()))
                    .transpose()
            } else if path == format!("repos/{REPOSITORY}/releases/tags/{}", self.tag) {
                let release = self
                    .release_created
                    .then(|| Self::decode(self.release()))
                    .transpose()?;
                self.release_read_back = release.is_some();
                Ok(release)
            } else {
                Err(format!("unexpected optional GET {path}"))
            }
        }

        fn post<T: serde::de::DeserializeOwned, P: serde::Serialize>(
            &mut self,
            path: &str,
            _payload: &P,
        ) -> Result<T, String> {
            self.events.push(format!("POST {path}"));
            if path == format!("repos/{REPOSITORY}/git/tags") {
                self.tag_object_created = true;
                Self::decode(self.tag_object())
            } else if path == format!("repos/{REPOSITORY}/git/refs") {
                self.tag_ref_created = true;
                Self::decode(self.tag_ref())
            } else if path == format!("repos/{REPOSITORY}/releases") {
                self.release_created = true;
                self.release_posted = true;
                Self::decode(self.release())
            } else {
                Err(format!("unexpected POST {path}"))
            }
        }
    }

    fn reviewed_commit(parent_sha: &str) -> Commit {
        Commit {
            sha: TEST_SOURCE_SHA.to_string(),
            author: Some(GitHubAccount {
                id: RELEASE_SIGNER_ID,
                login: RELEASE_SIGNER_LOGIN.to_string(),
                kind: "User".to_string(),
            }),
            committer: Some(GitHubAccount {
                id: RELEASE_SIGNER_ID,
                login: RELEASE_SIGNER_LOGIN.to_string(),
                kind: "User".to_string(),
            }),
            parents: vec![ShaObject {
                sha: parent_sha.to_string(),
            }],
            commit: CommitData {
                author: Some(RawGitIdentity {
                    name: RELEASE_AUTHOR_NAME.to_string(),
                    email: RELEASE_AUTHOR_EMAIL.to_string(),
                    date: "2026-09-04T12:00:00Z".to_string(),
                }),
                committer: Some(RawGitIdentity {
                    name: RELEASE_AUTHOR_NAME.to_string(),
                    email: RELEASE_AUTHOR_EMAIL.to_string(),
                    date: "2026-09-04T12:00:00Z".to_string(),
                }),
                message: format!("chore: release\n\n{DCO_TRAILER}"),
                verification: Verification {
                    verified: true,
                    reason: "valid".to_string(),
                },
                tree: ShaObject {
                    sha: TEST_TAG_OBJECT_SHA.to_string(),
                },
            },
        }
    }

    fn release_signature() -> CommitSignature {
        CommitSignature {
            kind: "SshSignature".to_string(),
            email: RELEASE_AUTHOR_EMAIL.to_string(),
            is_valid: true,
            state: "VALID".to_string(),
            was_signed_by_github: false,
            signer: Some(SignatureSigner {
                database_id: Some(RELEASE_SIGNER_ID),
                login: RELEASE_SIGNER_LOGIN.to_string(),
                kind: "User".to_string(),
            }),
        }
    }

    fn signature_response(
        oid: &str,
        merge_oid: &str,
        signature: Option<CommitSignature>,
    ) -> SignatureResponse {
        SignatureResponse {
            data: Some(SignatureData {
                repository: Some(SignatureRepository {
                    pull_request: Some(SignaturePullRequest {
                        merge_commit: Some(SignatureMergeCommit {
                            oid: merge_oid.to_string(),
                        }),
                        commits: SignatureConnection {
                            total_count: 1,
                            nodes: vec![SignatureNode {
                                commit: SignatureCommit {
                                    oid: oid.to_string(),
                                    signature,
                                },
                            }],
                            page_info: SignaturePageInfo {
                                has_next_page: false,
                            },
                        },
                    }),
                }),
            }),
            errors: None,
        }
    }

    #[test]
    fn automatic_release_is_all_or_nothing() {
        assert_eq!(
            decide(Operation::Auto, &[false, false, false, false]).unwrap(),
            Decision {
                publish: true,
                finalize: true,
            }
        );
        assert!(decide(Operation::Auto, &[true, false, false, false]).is_err());
        assert_eq!(
            decide(Operation::Auto, &[true, true, true, true]).unwrap(),
            Decision {
                publish: false,
                finalize: false,
            }
        );
    }

    #[test]
    fn ordinary_main_is_a_noop_before_registry_reconciliation() {
        let calls = Cell::new(0);
        let states = maybe_reconcile_registry(Operation::Auto, false, || {
            calls.set(calls.get() + 1);
            Ok(vec![true; 4])
        })
        .unwrap();
        assert!(states.is_none());
        assert_eq!(calls.get(), 0);
        assert_eq!(
            ordinary_decision(Operation::Auto).unwrap(),
            Decision {
                publish: false,
                finalize: false,
            }
        );
        assert!(ordinary_decision(Operation::Recover).is_err());
    }

    #[test]
    fn versioned_pull_responses_bind_without_removed_merge_sha_field() {
        let association = || {
            serde_json::from_value::<AssociatedPullRequest>(json!({
                "number": 90,
                "state": "closed",
                "merged_at": "2026-09-05T00:00:00Z",
            }))
            .unwrap()
        };
        let observed = association();
        assert_eq!(
            select_merged_associations(&[observed]).unwrap()[0].number,
            90
        );
        let oversized = (0..100).map(|_| association()).collect::<Vec<_>>();
        assert!(select_merged_associations(&oversized).is_err());

        let unmerged: AssociatedPullRequest = serde_json::from_value(json!({
            "number": 90,
            "state": "open",
            "merged_at": null,
        }))
        .unwrap();
        assert!(select_merged_associations(&[unmerged]).unwrap().is_empty());

        let mut pull: PullRequest = serde_json::from_value(json!({
            "number": 90,
            "state": "closed",
            "merged_at": "2026-09-05T00:00:00Z",
            "changed_files": 9,
            "base": {
                "ref": "main",
                "sha": TEST_POLICY_SHA,
                "repo": {"full_name": REPOSITORY},
            },
            "head": {
                "ref": "release-plz-manual-0.5.0-rc.2",
                "sha": TEST_SOURCE_SHA,
                "repo": {"full_name": REPOSITORY},
            },
        }))
        .unwrap();
        let version = Version::parse("0.5.0-rc.2").unwrap();
        assert!(canonical_release_pull(&pull, &version, TEST_POLICY_SHA));
        pull.base.reference = "develop".to_string();
        assert!(!canonical_release_pull(&pull, &version, TEST_POLICY_SHA));
    }

    #[test]
    fn recovery_stays_on_exact_source_and_completes_objects() {
        assert_eq!(
            decide(Operation::Recover, &[true, false, false, false]).unwrap(),
            Decision {
                publish: true,
                finalize: true,
            }
        );
        assert_eq!(
            decide(Operation::Recover, &[true, true, true, true]).unwrap(),
            Decision {
                publish: false,
                finalize: true,
            }
        );
        assert!(decide(Operation::Recover, &[false, true, false, false]).is_err());
        assert!(decide(Operation::Recover, &[true, false, true, false]).is_err());
    }

    #[test]
    fn finalizer_rejects_policy_drift_at_mutation_boundary() {
        let initial = "0123456789abcdef0123456789abcdef01234567";
        assert!(require_unchanged_main(initial, initial).is_ok());
        assert!(
            require_unchanged_main(initial, "1123456789abcdef0123456789abcdef01234567").is_err()
        );
    }

    #[test]
    fn finalizer_rebinds_policy_and_tag_immediately_before_each_post() {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0").unwrap();
        let date = "2026-09-04T12:00:00Z";
        let spec = ReleaseSpec::new(package, &version, TEST_SOURCE_SHA).unwrap();
        let mut github = MutationTransport::new(&spec, date, false);

        finalize_package(
            &mut github,
            package,
            &version,
            TEST_SOURCE_SHA,
            TEST_POLICY_SHA,
            date,
        )
        .unwrap();

        let compare =
            format!("GET repos/{REPOSITORY}/compare/{TEST_SOURCE_SHA}...{TEST_POLICY_SHA}");
        let main = format!("GET repos/{REPOSITORY}/git/ref/heads/main");
        let posts = github
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.starts_with("POST "))
            .collect::<Vec<_>>();
        assert_eq!(posts.len(), 3);
        for (index, event) in posts {
            if event.ends_with("/releases") {
                assert_eq!(github.events[index - 4], compare);
                assert_eq!(github.events[index - 3], main);
                assert_eq!(
                    github.events[index - 2],
                    format!("GET? repos/{REPOSITORY}/git/ref/tags/{}", spec.tag)
                );
                assert_eq!(
                    github.events[index - 1],
                    format!("GET repos/{REPOSITORY}/git/tags/{TEST_TAG_OBJECT_SHA}")
                );
                continue;
            }
            assert_eq!(github.events[index - 2], compare);
            assert_eq!(github.events[index - 1], main);
        }
    }

    fn assert_tag_change_across_release_post_is_rejected(change: TagChange) {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0").unwrap();
        let date = "2026-09-04T12:00:00Z";
        let spec = ReleaseSpec::new(package, &version, TEST_SOURCE_SHA).unwrap();

        let mut github = MutationTransport::new(&spec, date, false);
        if matches!(change, TagChange::ObjectReplacement) {
            let original = github.tag_object();
            let replacement = github.replacement_tag_object();
            assert_ne!(original["sha"], replacement["sha"]);
            for field in ["tag", "message", "tagger", "object"] {
                assert_eq!(original[field], replacement[field]);
            }
        }
        github.change_tag_after_release_boundary(change);
        let error = finalize_package(
            &mut github,
            package,
            &version,
            TEST_SOURCE_SHA,
            TEST_POLICY_SHA,
            date,
        )
        .unwrap_err();

        assert!(error.contains(&spec.tag));
        assert!(
            github
                .events
                .contains(&format!("POST repos/{REPOSITORY}/releases"))
        );
        assert!(github.events.iter().any(|event| {
            event == &format!("GET? repos/{REPOSITORY}/releases/tags/{}", spec.tag)
        }));
    }

    #[test]
    fn finalizer_rejects_tag_deletion_across_release_post() {
        assert_tag_change_across_release_post_is_rejected(TagChange::Deleted);
    }

    #[test]
    fn finalizer_rejects_lightweight_tag_replacement_across_release_post() {
        assert_tag_change_across_release_post_is_rejected(TagChange::LightweightReplacement);
    }

    #[test]
    fn finalizer_rejects_annotated_tag_object_replacement_across_release_post() {
        assert_tag_change_across_release_post_is_rejected(TagChange::ObjectReplacement);
    }

    #[test]
    fn finalizer_rejects_tag_source_drift_across_release_post() {
        assert_tag_change_across_release_post_is_rejected(TagChange::SourceDrift);
    }

    #[test]
    fn idempotent_release_still_requires_surviving_exact_tag() {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0").unwrap();
        let date = "2026-09-04T12:00:00Z";
        let spec = ReleaseSpec::new(package, &version, TEST_SOURCE_SHA).unwrap();
        let mut github = MutationTransport::new(&spec, date, false);
        github.tag_object_created = true;
        github.tag_ref_created = true;
        github.release_created = true;
        github.change_tag_after_release_boundary(TagChange::Deleted);

        let error = finalize_package(
            &mut github,
            package,
            &version,
            TEST_SOURCE_SHA,
            TEST_POLICY_SHA,
            date,
        )
        .unwrap_err();

        assert!(error.contains("does not retain exact object"));
        assert!(!github.events.iter().any(|event| event.starts_with("POST ")));
    }

    #[test]
    fn finalizer_rejects_main_drift_between_tag_object_and_ref() {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0").unwrap();
        let date = "2026-09-04T12:00:00Z";
        let spec = ReleaseSpec::new(package, &version, TEST_SOURCE_SHA).unwrap();
        let mut github = MutationTransport::new(&spec, date, true);

        let error = finalize_package(
            &mut github,
            package,
            &version,
            TEST_SOURCE_SHA,
            TEST_POLICY_SHA,
            date,
        )
        .unwrap_err();

        assert!(error.contains("protected main changed"));
        assert!(
            github
                .events
                .contains(&format!("POST repos/{REPOSITORY}/git/tags"))
        );
        assert!(
            !github
                .events
                .contains(&format!("POST repos/{REPOSITORY}/git/refs"))
        );
        assert!(
            !github
                .events
                .contains(&format!("POST repos/{REPOSITORY}/releases"))
        );
        assert_eq!(
            github.events[github.events.len() - 2],
            format!("GET repos/{REPOSITORY}/compare/{TEST_SOURCE_SHA}...{TEST_POLICY_SHA}")
        );
        assert_eq!(
            github.events.last().unwrap(),
            &format!("GET repos/{REPOSITORY}/git/ref/heads/main")
        );
    }

    #[test]
    fn recovery_rejects_workflow_run_attempt_and_artifact_drift() {
        let source = "0123456789abcdef0123456789abcdef01234567";
        let exact_workflow = Workflow {
            id: PUBLISH_WORKFLOW_ID,
            path: PUBLISH_WORKFLOW_PATH.to_string(),
            state: "active".to_string(),
        };
        validate_publish_workflow(&exact_workflow).unwrap();
        for workflow in [
            Workflow {
                id: PUBLISH_WORKFLOW_ID + 1,
                ..exact_workflow.clone()
            },
            Workflow {
                path: ".github/workflows/other.yml".to_string(),
                ..exact_workflow.clone()
            },
            Workflow {
                state: "disabled_manually".to_string(),
                ..exact_workflow.clone()
            },
        ] {
            assert!(validate_publish_workflow(&workflow).is_err());
        }

        let run = workflow_run_fixture(source, 42, 3);
        validate_original_run(&run, source, 42, 3).unwrap();
        validate_original_run_pair(&run, &run, source, 42, 3).unwrap();
        let stale = workflow_run_fixture(source, 42, 4);
        assert!(validate_original_run(&stale, source, 42, 3).is_err());
        assert!(validate_original_run_pair(&run, &stale, source, 42, 3).is_err());
        let wrong_source = workflow_run_fixture("1123456789abcdef0123456789abcdef01234567", 42, 3);
        assert!(validate_original_run(&wrong_source, source, 42, 3).is_err());
        let mut wrong_workflow = run.clone();
        wrong_workflow.workflow_id += 1;
        assert!(validate_original_run(&wrong_workflow, source, 42, 3).is_err());
        let mut wrong_path = run.clone();
        wrong_path.path = ".github/workflows/other.yml".to_string();
        assert!(validate_original_run(&wrong_path, source, 42, 3).is_err());
        let mut wrong_repository = run.clone();
        wrong_repository.repository.full_name = "NVIDIA/other".to_string();
        assert!(validate_original_run(&wrong_repository, source, 42, 3).is_err());
        let mut pending = run;
        pending.status = "in_progress".to_string();
        pending.conclusion = None;
        assert!(validate_original_run(&pending, source, 42, 3).is_err());

        validate_artifact_inventory(&ArtifactInventory {
            total_count: 0,
            artifacts: Vec::new(),
        })
        .unwrap();
        assert!(
            validate_artifact_inventory(&ArtifactInventory {
                total_count: 1,
                artifacts: Vec::new(),
            })
            .is_err()
        );
        assert!(
            validate_artifact_inventory(&ArtifactInventory {
                total_count: 0,
                artifacts: vec![json!({"id": 1})],
            })
            .is_err()
        );
    }

    #[test]
    fn validation_never_mutates_even_for_partial_state() {
        assert_eq!(
            decide(Operation::Validate, &[true, false, true, false]).unwrap(),
            Decision {
                publish: false,
                finalize: false,
            }
        );
        assert!(decide(Operation::Validate, &[false]).is_err());

        let calls = Cell::new(0);
        let states = maybe_reconcile_registry(Operation::Validate, true, || {
            calls.set(calls.get() + 1);
            Ok(vec![true; 4])
        })
        .unwrap();
        assert!(states.is_none());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn release_paths_are_exact_and_bounded() {
        assert!(allowed_release_path("Cargo.toml"));
        assert!(allowed_release_path("crates/yaml-sigil-core/CHANGELOG.md"));
        assert!(!allowed_release_path("src/lib.rs"));
        assert!(!allowed_release_path("Cargo.lock"));
    }

    #[test]
    fn release_specs_distinguish_prereleases() {
        let package = &RUST_POLICY.packages[0];
        let prerelease = ReleaseSpec::new(
            package,
            &Version::parse("0.6.0-rc.1").unwrap(),
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();
        assert!(prerelease.prerelease);
        assert!(prerelease.body.contains("no attached assets"));
        let stable = ReleaseSpec::new(
            package,
            &Version::parse("0.6.0").unwrap(),
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();
        assert!(!stable.prerelease);
    }

    #[test]
    fn published_archive_binds_checksum_source_and_workspace_path() {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0-rc.1").unwrap();
        let source = "0123456789abcdef0123456789abcdef01234567";
        let archive = crate_archive(package, &version, source, Some(package.path_in_vcs));
        let record = registry_fixture(&version, &archive);
        verify_published_archive(package, &version, source, &record, &archive).unwrap();

        let wrong_source = "1123456789abcdef0123456789abcdef01234567";
        assert!(
            verify_published_archive(package, &version, wrong_source, &record, &archive).is_err()
        );
        let wrong_checksum = RegistryRecord {
            checksum: "0".repeat(64),
            num: version.to_string(),
            yanked: false,
        };
        assert!(
            verify_published_archive(package, &version, source, &wrong_checksum, &archive).is_err()
        );
    }

    #[test]
    fn crates_io_request_uses_exact_identity_and_pacing() {
        const URL: &str = "https://crates.io/api/v1/crates/yaml-sigil-core/0.6.0";
        let observed_delay = Cell::new(None);
        let command = crates_io_request_command(&["--silent", URL], |delay| {
            observed_delay.set(Some(delay));
        });
        let args = command
            .get_args()
            .map(|argument| argument.to_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(observed_delay.get(), Some(Duration::from_secs(1)));
        assert_eq!(
            args,
            [
                "--disable",
                "--user-agent",
                CRATES_IO_USER_AGENT,
                "--silent",
                URL,
            ]
        );
        assert!(!CRATES_IO_USER_AGENT.to_ascii_lowercase().contains("curl"));
    }

    #[test]
    fn published_archive_rejects_missing_or_wrong_path_vcs_info() {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0").unwrap();
        let source = "0123456789abcdef0123456789abcdef01234567";
        let archive = crate_archive(package, &version, source, None);
        let record = registry_fixture(&version, &archive);
        assert!(verify_published_archive(package, &version, source, &record, &archive).is_err());

        let archive = crate_archive(package, &version, source, Some("wrong/path"));
        let record = registry_fixture(&version, &archive);
        assert!(verify_published_archive(package, &version, source, &record, &archive).is_err());
    }

    #[test]
    fn registry_metadata_rejects_wrong_version_and_yanked_crates() {
        let version = Version::parse("0.6.0").unwrap();
        let exact = RegistryRecord {
            checksum: "a".repeat(64),
            num: version.to_string(),
            yanked: false,
        };
        validate_registry_record("yaml-sigil-core", &version, &exact).unwrap();

        let mut wrong = RegistryRecord {
            checksum: exact.checksum.clone(),
            num: "0.6.1".to_string(),
            yanked: false,
        };
        assert!(validate_registry_record("yaml-sigil-core", &version, &wrong).is_err());
        wrong.num = version.to_string();
        wrong.yanked = true;
        assert!(validate_registry_record("yaml-sigil-core", &version, &wrong).is_err());
    }

    #[test]
    fn published_vcs_info_rejects_dirty_unknown_and_noncanonical_identity() {
        let package = &RUST_POLICY.packages[0];
        let version = Version::parse("0.6.0").unwrap();
        let source = "0123456789abcdef0123456789abcdef01234567";
        for vcs in [
            json!({
                "git": {"sha1": source, "dirty": true},
                "path_in_vcs": package.path_in_vcs,
            }),
            json!({
                "git": {"sha1": source, "dirty": false, "other": true},
                "path_in_vcs": package.path_in_vcs,
            }),
            json!({
                "git": {"sha1": source.to_uppercase(), "dirty": false},
                "path_in_vcs": package.path_in_vcs,
            }),
        ] {
            let archive = crate_archive_with_vcs(package, &version, &vcs);
            let record = registry_fixture(&version, &archive);
            assert!(
                verify_published_archive(package, &version, source, &record, &archive).is_err()
            );
        }
    }

    #[test]
    fn crate_archive_work_is_explicitly_bounded() {
        let mut entries = MAX_CRATE_ARCHIVE_ENTRIES;
        let mut bytes = 0;
        assert!(accumulate_archive_work(&mut entries, &mut bytes, 0).is_err());

        let mut entries = 0;
        let mut bytes = MAX_CRATE_UNPACKED_BYTES;
        assert!(accumulate_archive_work(&mut entries, &mut bytes, 1).is_err());
    }

    #[test]
    fn release_files_reject_add_remove_rename_and_unexpected_paths() {
        let exact = [PullFile {
            filename: "Cargo.toml".to_string(),
            status: "modified".to_string(),
        }];
        validate_release_files(&exact, 1).unwrap();
        for status in ["added", "removed", "renamed", "copied"] {
            let files = [PullFile {
                filename: "Cargo.toml".to_string(),
                status: status.to_string(),
            }];
            assert!(validate_release_files(&files, 1).is_err());
        }
        let unexpected = [PullFile {
            filename: "src/lib.rs".to_string(),
            status: "modified".to_string(),
        }];
        assert!(validate_release_files(&unexpected, 1).is_err());
    }

    #[test]
    fn reviewed_release_head_requires_one_exact_current_base_parent() {
        let exact = reviewed_commit(TEST_POLICY_SHA);
        let signature = release_signature();
        require_reviewed_release_head(&exact, &signature, TEST_SOURCE_SHA, TEST_POLICY_SHA)
            .unwrap();

        let mut no_parent = reviewed_commit(TEST_POLICY_SHA);
        no_parent.parents.clear();
        assert!(
            require_reviewed_release_head(
                &no_parent,
                &signature,
                TEST_SOURCE_SHA,
                TEST_POLICY_SHA,
            )
            .is_err()
        );

        let wrong_parent = reviewed_commit(TEST_DRIFT_SHA);
        assert!(
            require_reviewed_release_head(
                &wrong_parent,
                &signature,
                TEST_SOURCE_SHA,
                TEST_POLICY_SHA,
            )
            .is_err()
        );

        let mut merge = reviewed_commit(TEST_POLICY_SHA);
        merge.parents.push(ShaObject {
            sha: TEST_DRIFT_SHA.to_string(),
        });
        assert!(
            require_reviewed_release_head(&merge, &signature, TEST_SOURCE_SHA, TEST_POLICY_SHA,)
                .is_err()
        );
    }

    #[test]
    fn release_head_requires_exact_graphql_signer_raw_identities_and_dco() {
        let exact = reviewed_commit(TEST_POLICY_SHA);
        let signature = release_signature();
        require_release_signature_identity(&exact, &signature).unwrap();

        let mut null_signer = signature.clone();
        null_signer.signer = None;
        assert!(require_release_signature_identity(&exact, &null_signer).is_err());

        let mut wrong_id = signature.clone();
        wrong_id.signer.as_mut().unwrap().database_id = Some(RELEASE_SIGNER_ID + 1);
        assert!(require_release_signature_identity(&exact, &wrong_id).is_err());

        let mut null_id = signature.clone();
        null_id.signer.as_mut().unwrap().database_id = None;
        assert!(require_release_signature_identity(&exact, &null_id).is_err());

        let mut wrong_login = signature.clone();
        wrong_login.signer.as_mut().unwrap().login = "lookalike".to_string();
        assert!(require_release_signature_identity(&exact, &wrong_login).is_err());

        let mut wrong_type = signature.clone();
        wrong_type.signer.as_mut().unwrap().kind = "Bot".to_string();
        assert!(require_release_signature_identity(&exact, &wrong_type).is_err());

        let mut wrong_email = signature.clone();
        wrong_email.email = "lookalike@example.invalid".to_string();
        assert!(require_release_signature_identity(&exact, &wrong_email).is_err());

        let mut web_flow = signature.clone();
        web_flow.was_signed_by_github = true;
        assert!(require_release_signature_identity(&exact, &web_flow).is_err());

        let mut invalid = signature.clone();
        invalid.is_valid = false;
        assert!(require_release_signature_identity(&exact, &invalid).is_err());

        let mut wrong_state = signature.clone();
        wrong_state.state = "UNVERIFIED_EMAIL".to_string();
        assert!(require_release_signature_identity(&exact, &wrong_state).is_err());

        let mut forged_dco = reviewed_commit(TEST_POLICY_SHA);
        forged_dco.commit.message =
            format!("chore: release\n\nSigned-off-by: Lookalike <{RELEASE_AUTHOR_EMAIL}>");
        assert!(require_release_signature_identity(&forged_dco, &signature).is_err());

        let mut wrong_raw_email = reviewed_commit(TEST_POLICY_SHA);
        wrong_raw_email.commit.committer.as_mut().unwrap().email =
            "lookalike@example.invalid".to_string();
        assert!(require_release_signature_identity(&wrong_raw_email, &signature).is_err());

        let mut wrong_rest_account = reviewed_commit(TEST_POLICY_SHA);
        wrong_rest_account.author.as_mut().unwrap().id = RELEASE_SIGNER_ID + 1;
        assert!(require_release_signature_identity(&wrong_rest_account, &signature).is_err());

        let mut null_rest_account = reviewed_commit(TEST_POLICY_SHA);
        null_rest_account.committer = None;
        assert!(require_release_signature_identity(&null_rest_account, &signature).is_err());
    }

    #[test]
    fn release_signature_inventory_is_exact_and_bounded() {
        let exact = validate_signature_response(
            signature_response(TEST_SOURCE_SHA, TEST_SOURCE_SHA, Some(release_signature())),
            TEST_SOURCE_SHA,
            TEST_SOURCE_SHA,
        )
        .unwrap();
        assert_eq!(exact.email, RELEASE_AUTHOR_EMAIL);

        assert!(
            validate_signature_response(
                signature_response(TEST_DRIFT_SHA, TEST_SOURCE_SHA, Some(release_signature()),),
                TEST_SOURCE_SHA,
                TEST_SOURCE_SHA,
            )
            .is_err()
        );
        assert!(
            validate_signature_response(
                signature_response(TEST_SOURCE_SHA, TEST_SOURCE_SHA, None),
                TEST_SOURCE_SHA,
                TEST_SOURCE_SHA,
            )
            .is_err()
        );
        assert!(
            validate_signature_response(
                signature_response(TEST_SOURCE_SHA, TEST_DRIFT_SHA, Some(release_signature()),),
                TEST_SOURCE_SHA,
                TEST_SOURCE_SHA,
            )
            .is_err()
        );

        let mut ambiguous =
            signature_response(TEST_SOURCE_SHA, TEST_SOURCE_SHA, Some(release_signature()));
        ambiguous
            .data
            .as_mut()
            .unwrap()
            .repository
            .as_mut()
            .unwrap()
            .pull_request
            .as_mut()
            .unwrap()
            .commits
            .page_info
            .has_next_page = true;
        assert!(validate_signature_response(ambiguous, TEST_SOURCE_SHA, TEST_SOURCE_SHA).is_err());

        let mut errors =
            signature_response(TEST_SOURCE_SHA, TEST_SOURCE_SHA, Some(release_signature()));
        errors.errors = Some(json!([{"message": "partial"}]));
        assert!(validate_signature_response(errors, TEST_SOURCE_SHA, TEST_SOURCE_SHA).is_err());
    }

    #[test]
    fn finalizer_requires_observed_app_and_one_repository_scope() {
        let exact = InstallationRepositories {
            total_count: 1,
            repositories: vec![Repository {
                full_name: REPOSITORY.to_string(),
            }],
        };
        validate_app_scope(APP_SLUG, &exact).unwrap();
        assert!(validate_app_scope("other-app", &exact).is_err());

        let broad = InstallationRepositories {
            total_count: 2,
            repositories: vec![
                Repository {
                    full_name: REPOSITORY.to_string(),
                },
                Repository {
                    full_name: "NVIDIA/other".to_string(),
                },
            ],
        };
        assert!(validate_app_scope(APP_SLUG, &broad).is_err());
    }

    fn crate_archive(
        package: &PackagePolicy,
        version: &Version,
        source: &str,
        path_in_vcs: Option<&str>,
    ) -> Vec<u8> {
        crate_archive_with_vcs(
            package,
            version,
            &json!({
                "git": {"sha1": source, "dirty": false},
                "path_in_vcs": path_in_vcs,
            }),
        )
    }

    fn crate_archive_with_vcs(
        package: &PackagePolicy,
        version: &Version,
        vcs: &serde_json::Value,
    ) -> Vec<u8> {
        let mut encoded = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut builder = tar::Builder::new(&mut encoded);
            let body = serde_json::to_vec(vcs).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    format!("{}-{version}/.cargo_vcs_info.json", package.package),
                    body.as_slice(),
                )
                .unwrap();
            builder.finish().unwrap();
        }
        encoded.finish().unwrap()
    }

    fn registry_fixture(version: &Version, archive: &[u8]) -> RegistryRecord {
        RegistryRecord {
            checksum: format!("{:x}", Sha256::digest(archive)),
            num: version.to_string(),
            yanked: false,
        }
    }

    fn workflow_run_fixture(source: &str, id: u64, attempt: u64) -> WorkflowRun {
        WorkflowRun {
            id,
            run_attempt: attempt,
            workflow_id: PUBLISH_WORKFLOW_ID,
            path: PUBLISH_WORKFLOW_PATH.to_string(),
            event: "push".to_string(),
            head_branch: "main".to_string(),
            head_sha: source.to_string(),
            repository: Repository {
                full_name: REPOSITORY.to_string(),
            },
            head_repository: Repository {
                full_name: REPOSITORY.to_string(),
            },
            status: "completed".to_string(),
            conclusion: Some("failure".to_string()),
        }
    }
}
