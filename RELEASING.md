# Release the YamlSigil Rust crates

One release publishes exactly these crates.io source packages in dependency
order:

1. `yaml-sigil-core`.
2. `yaml-sigil-transcription`.
3. `yaml-sigil-signing`.
4. `yaml-sigil-verification`.

All four crates use one version. The conformance, test-key, workspace, and
xtask packages remain unpublished. Releases never contain executable assets,
installers, containers, or retained CI artifacts.

## Prepare the release pull request

Start from a clean checkout of exact current `main` with current tags:

```shell
git fetch origin main --tags
git switch main
git merge --ff-only origin/main
git status --short
```

Choose the reviewed stable or prerelease version and create its canonical
same-repository branch. Do not reuse a prior release branch.

```shell
version="MAJOR.MINOR.PATCH[-PRERELEASE]"
git switch -c "release-plz-manual-${version}"
```

Install and verify the reviewed release analyzer. The repository does not use
`release-plz/action`.

```shell
cargo binstall --force --locked --no-confirm release-plz@0.3.160
# Confirm that the reviewed analyzer, rather than another installed version,
# will derive the release transaction.
release-plz --version
```

Prepare the exact version. This command requires the branch to start at exact
`origin/main`, lets `release-plz update` derive all version, dependency, and
changelog edits, then requires the maintainer-selected version as a strict
postcondition. It rejects changes outside Cargo manifests and the four
changelogs.

```shell
cargo xtask release prepare --version "${version}"
git diff --check
git diff --stat
git diff
```

Review every generated changelog entry and version change. Then run the full
provider-neutral validation sequence.

```shell
cargo xtask ci
git status --short
```

Create one explicitly SSH-signed, DCO-compliant commit with the repository
identity. No other commit belongs in the release pull request.

```shell
git config user.name ddurst
git config user.email 267424412+ddurst-nvidia@users.noreply.github.com
git add Cargo.toml \
  crates/yaml-sigil-core/Cargo.toml \
  crates/yaml-sigil-core/CHANGELOG.md \
  crates/yaml-sigil-transcription/Cargo.toml \
  crates/yaml-sigil-transcription/CHANGELOG.md \
  crates/yaml-sigil-signing/Cargo.toml \
  crates/yaml-sigil-signing/CHANGELOG.md \
  crates/yaml-sigil-verification/Cargo.toml \
  crates/yaml-sigil-verification/CHANGELOG.md
git commit -S --signoff -m "chore(release): prepare ${version}"
git verify-commit HEAD
```

Push the branch and open the canonical pull request.

```shell
git push -u origin "release-plz-manual-${version}"
gh pr create \
  --base main \
  --head "release-plz-manual-${version}" \
  --title "chore(release): prepare ${version}" \
  --body "Prepare the four YamlSigil Rust source crates for ${version}."
```

After GitHub records the pull-request association, run the credential-free,
non-publishing source check:

```shell
cargo xtask release check --version "${version}"
```

`release check` verifies the exact four-package inventory, shared version,
dependency order, crates.io `yaml-sigil-traits` resolution, release-plz
configuration, and the absence of unexpected source changes. It does not call
release-plz, accept a forge credential, or publish.

At the exact signed and DCO-compliant pull-request head, run the separately
reviewed release-plz acceptance check. Supply an approved read-only forge token
through `READ_ONLY_GIT_TOKEN`; only the dry-run process receives it:

```shell
reviewed_head=FULL_REVIEWED_PULL_REQUEST_HEAD_SHA
test -z "$(git status --porcelain=v1 --untracked-files=all)"
test "$(git rev-parse HEAD)" = "${reviewed_head}"
# Bind the acceptance evidence to the repository's reviewed analyzer version.
release-plz --version | grep -Fx 'release-plz 0.3.160'
evidence="<APPROVED-EVIDENCE-DIR>/release-plz-dry-run-${reviewed_head}.json"
set -o pipefail
# Exercise the exact reviewed release transaction without granting forge write
# permission or publishing any package.
env -u CARGO_REGISTRY_TOKEN \
  -u CARGO_REGISTRIES_CRATES_IO_TOKEN \
  -u GH_TOKEN \
  -u GITHUB_TOKEN \
  GIT_TOKEN="${READ_ONLY_GIT_TOKEN:?provide an approved read-only forge token}" \
  release-plz release \
    --dry-run \
    --config .release-plz.toml \
    --manifest-path Cargo.toml \
    --output json | tee "${evidence}"
sha256sum "${evidence}"
```

Preserve the reported head SHA and JSON checksum outside the checkout as
exact-head pull-request acceptance evidence. Never upload it as a workflow
artifact. The token must have no forge write permission, and the dry run must
select exactly the four intended package versions and tags.

Merge only after the exact head passes review and required CI. Release pull
requests use an explicitly authorized squash. Verify the resulting `main`
commit has one parent, a GitHub Verified signature, the DCO trailer, the pull
request association, and a tree equal to the reviewed head.

## Publish from main

The enabled `publish.yml` workflow qualifies each `main` push without secrets.
Ordinary pushes that are not the squash of a canonical release pull request
are successful no-ops before any exact-source crates.io reconciliation.
Only a nonempty qualified release enters the protected `crates-io` environment,
and only its publication job receives OIDC. Pinned release-plz is the sole Cargo
publisher.

After all four source packages are visible with matching checksums and
`.cargo_vcs_info.json`, the repository-scoped GitHub App creates or verifies
the four deterministic annotated tags and immutable, zero-asset Releases.

Approve the exact qualified publication job when it reaches the `crates-io`
environment. That approval authorizes only crates.io publication; it does not
satisfy the later GitHub finalizer preflight.

After workflow cutover and before the first validation or release operation,
configure `protected-automation` with required reviewer `ddurst-nvidia`
(`267424412`), administrator bypass disabled, self-review permitted, and the
existing custom deployment branch policy restricted to `main`. Preserve this
policy thereafter.

After publication and registry confirmation, the finalizer waits at the
separate `protected-automation` environment. Do not approve that deployment
yet. Immediately before approval, a repository administrator performs this
read-only operator preflight with the exact values shown by the pending run.
The two ruleset IDs are repository policy: `21898912` protects tag creation,
and `21898913` protects tag update and deletion.

```shell
set -euo pipefail
repository=NVIDIA/yaml-sigil-rs
policy_sha=FULL_CURRENT_MAIN_SHA
source_sha=FULL_QUALIFIED_RELEASE_SOURCE_SHA
run_id=PENDING_RUN_ID
run_attempt=PENDING_RUN_ATTEMPT
expected_event=EXPECTED_PUSH_OR_WORKFLOW_DISPATCH
tag_creation_ruleset_id=21898912
tag_update_deletion_ruleset_id=21898913
finalizer_environment=protected-automation
finalizer_environment_id=20345456136
finalizer_branch_policy_id=57933874

operator_login="$(gh api user --jq .login)"
test "$(gh api \
  "repos/${repository}/collaborators/${operator_login}/permission" \
  --jq .permission)" = admin

check_live_bindings() {
  test "$(gh api "repos/${repository}/git/ref/heads/main" --jq .object.sha)" = \
    "${policy_sha}"
  run_path="repos/${repository}/actions/runs/${run_id}/attempts/${run_attempt}"
  run_json="$(gh api "${run_path}")"
  test "$(jq -r .id <<< "${run_json}")" = "${run_id}"
  test "$(jq -r .run_attempt <<< "${run_json}")" = "${run_attempt}"
  test "$(jq -r .workflow_id <<< "${run_json}")" = 337417483
  test "$(jq -r .path <<< "${run_json}")" = .github/workflows/publish.yml
  test "$(jq -r .event <<< "${run_json}")" = "${expected_event}"
  test "$(jq -r .head_branch <<< "${run_json}")" = main
  test "$(jq -r .head_sha <<< "${run_json}")" = "${policy_sha}"
  test "$(jq -r .repository.full_name <<< "${run_json}")" = \
    "${repository}"
  test "$(jq -r '.conclusion == null' <<< "${run_json}")" = true
  test "$(jq -r '
    .status == "queued" or .status == "in_progress" or
    .status == "waiting" or .status == "pending"
  ' <<< "${run_json}")" = true
  jobs_json="$(gh api \
    "${run_path}/jobs?per_page=100")"
  test "$(jq '[.jobs[] \
    | select(.name == "Confirm exact published sources" \
      and .status == "completed" and .conclusion == "success")] \
    | length' <<< "${jobs_json}")" = 1
  test "$(jq '[.jobs[] \
    | select(.name == "Finalize source-only GitHub Releases" \
      and .status == "waiting" and .conclusion == null)] \
    | length' <<< "${jobs_json}")" = 1
  pending_json="$(gh api \
    "repos/${repository}/actions/runs/${run_id}/pending_deployments")"
  test "$(jq length <<< "${pending_json}")" = 1
  test "$(jq -r '.[0].environment.id' <<< "${pending_json}")" = \
    "${finalizer_environment_id}"
  test "$(jq -r '.[0].environment.name' <<< "${pending_json}")" = \
    "${finalizer_environment}"
  test "$(jq -r '.[0].current_user_can_approve' \
    <<< "${pending_json}")" = true
  comparison_json="$(gh api \
    "repos/${repository}/compare/${source_sha}...${policy_sha}")"
  compare_status="$(jq -r .status <<< "${comparison_json}")"
  compare_base="$(jq -r .base_commit.sha <<< "${comparison_json}")"
  compare_merge_base="$(jq -r .merge_base_commit.sha \
    <<< "${comparison_json}")"
  test "${compare_base}" = "${source_sha}"
  test "${compare_merge_base}" = "${source_sha}"
  # Only the exact current source or an older commit on current main lineage
  # remains eligible for approval.
  case "${compare_status}" in
    identical | ahead) ;;
    *) return 1 ;;
  esac
}

check_live_bindings
environment_json="$(gh api \
  "repos/${repository}/environments/${finalizer_environment}")"
test "$(jq -r .name <<< "${environment_json}")" = \
  "${finalizer_environment}"
test "$(jq -r .id <<< "${environment_json}")" = \
  "${finalizer_environment_id}"
test "$(jq -r .can_admins_bypass <<< "${environment_json}")" = false
test "$(jq -r .deployment_branch_policy.protected_branches \
  <<< "${environment_json}")" = false
test "$(jq -r .deployment_branch_policy.custom_branch_policies \
  <<< "${environment_json}")" = true
test "$(jq '.protection_rules | length' <<< "${environment_json}")" = 1
test "$(jq '[.protection_rules[] | select(.type == "required_reviewers")] \
  | length' <<< "${environment_json}")" = 1
test "$(jq -r '.protection_rules[] \
  | select(.type == "required_reviewers") \
  | .prevent_self_review' <<< "${environment_json}")" = false
test "$(jq '[.protection_rules[] \
  | select(.type == "required_reviewers") \
  | .reviewers[]] | length' <<< "${environment_json}")" = 1
test "$(jq -r '.protection_rules[] \
  | select(.type == "required_reviewers") \
  | .reviewers[0].type' <<< "${environment_json}")" = User
test "$(jq -r '.protection_rules[] \
  | select(.type == "required_reviewers") \
  | .reviewers[0].reviewer.login' <<< "${environment_json}")" = \
  ddurst-nvidia
test "$(jq -r '.protection_rules[] \
  | select(.type == "required_reviewers") \
  | .reviewers[0].reviewer.id' <<< "${environment_json}")" = 267424412
branch_policy_json="$(gh api \
  "repos/${repository}/environments/${finalizer_environment}/deployment-branch-policies?per_page=100")"
test "$(jq .total_count <<< "${branch_policy_json}")" = 1
test "$(jq -r .branch_policies[0].id <<< "${branch_policy_json}")" = \
  "${finalizer_branch_policy_id}"
test "$(jq -r .branch_policies[0].name <<< "${branch_policy_json}")" = main
test "$(jq -r .branch_policies[0].type <<< "${branch_policy_json}")" = branch
test "$(gh api "repos/${repository}/immutable-releases" --jq .enabled)" = true
gh api "repos/${repository}/immutable-releases" \
  --jq '{enabled,enforced_by_owner}'
creation_ruleset_json="$(gh api \
  "repos/${repository}/rulesets/${tag_creation_ruleset_id}")"
test "$(jq -e '
  .id == 21898912
  and .name == "Protect release tag creation"
  and .source == "NVIDIA/yaml-sigil-rs"
  and .source_type == "Repository"
  and .target == "tag"
  and .enforcement == "active"
  and .bypass_actors == [{
    "actor_id": 4653064,
    "actor_type": "Integration",
    "bypass_mode": "always"
  }]
  and .conditions == {"ref_name": {
    "exclude": [],
    "include": [
      "refs/tags/yaml-sigil-core-v*",
      "refs/tags/yaml-sigil-transcription-v*",
      "refs/tags/yaml-sigil-signing-v*",
      "refs/tags/yaml-sigil-verification-v*"
    ]
  }}
  and .rules == [{"type": "creation"}]
' <<< "${creation_ruleset_json}")" = true
jq '{id,name,target,enforcement,bypass_actors,conditions,rules}' \
  <<< "${creation_ruleset_json}"
update_ruleset_json="$(gh api \
  "repos/${repository}/rulesets/${tag_update_deletion_ruleset_id}")"
test "$(jq -e '
  .id == 21898913
  and .name == "Protect release tag updates and deletion"
  and .source == "NVIDIA/yaml-sigil-rs"
  and .source_type == "Repository"
  and .target == "tag"
  and .enforcement == "active"
  and .bypass_actors == []
  and .conditions == {"ref_name": {
    "exclude": [],
    "include": [
      "refs/tags/yaml-sigil-core-v*",
      "refs/tags/yaml-sigil-transcription-v*",
      "refs/tags/yaml-sigil-signing-v*",
      "refs/tags/yaml-sigil-verification-v*"
    ]
  }}
  and .rules == [{"type": "update"}, {"type": "deletion"}]
' <<< "${update_ruleset_json}")" = true
jq '{id,name,target,enforcement,bypass_actors,conditions,rules}' \
  <<< "${update_ruleset_json}"
# Re-read every dynamic binding after the settings evidence so drift fails the
# preflight rather than carrying stale evidence into environment approval.
check_live_bindings
```

Approve only when the run has workflow ID `337417483`, path
`.github/workflows/publish.yml`, and the expected attempt, repository, and
current `main`; the qualified source is identical to or an ancestor of that
main commit; release immutability reports `enabled: true`; and both exact tag
rulesets report target `tag`, enforcement `active`, and their complete frozen
reviewed bypass actors, conditions, and rules. The operator must compare every
field shown for both rulesets with the frozen review evidence before approving
the exact `protected-automation` deployment. The separate `crates-io` approval
does not substitute for this immediately pre-finalizer check. These commands
grant no workflow credential and make no settings, App, ruleset, environment,
tag, or Release change.

Run the validation-only operation against exact current `main` without
publication, registry reconciliation, OIDC, App mutation, tags, or Releases:

```shell
source_sha="$(git rev-parse origin/main)"
gh workflow run publish.yml \
  --ref main \
  -f operation=validate \
  -f source_sha="${source_sha}"
```

Recovery stays bound to the original source and original workflow attempt. It
verifies every already-published checksum and bounded `.cargo_vcs_info.json`
before release-plz may publish a missing suffix or the App may fill missing
GitHub objects.

```shell
gh workflow run publish.yml \
  --ref main \
  -f operation=recover \
  -f source_sha="FULL_ORIGINAL_SOURCE_SHA" \
  -f original_run_id="ORIGINAL_RUN_ID" \
  -f original_run_attempt="ORIGINAL_RUN_ATTEMPT"
```

Never run `cargo publish` or a local non-dry-run `release-plz release`. Never
move an existing tag, replace a conflicting Release, or advance a partial
release to newer `main`.
