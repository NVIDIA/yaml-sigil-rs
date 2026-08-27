# Release the YamlSigil Rust crates

This repository publishes these crates.io `.crate` source packages as one
versioned release transaction:

- `yaml-sigil-core`;
- `yaml-sigil-transcription`;
- `yaml-sigil-signing`; and
- `yaml-sigil-verification`.

Official publications create one annotated version tag and one source-only
GitHub Release per crate from its reviewed changelog. Neither release-plz nor
any other release step builds or attaches binary assets. The workflow retains
no build artifacts or separately generated archives. GitHub's automatic source
archives are expected. Keep the workspace default, conformance, test-key, and
xtask packages unpublished.

Cargo disables implicit binary targets in every publishable crate. Release
validation also rejects unexpected package identities, binary targets, and
build scripts. Only `yaml-sigil-core` may use its exact reviewed `build.rs`.
Do not distribute compiled executables from this repository.

## Release authorization

The `Release proposal` workflow owns the `release-plz-next` branch and opens or
updates its pull request against `main`. Release-plz analyzes Conventional
Commits and generates each crate's changelog content. The repository xtask
applies the RC policy and synchronizes the workspace versions. A
least-privilege GitHub App creates the commit through GitHub, so GitHub reports
the commit as Verified. The commit also includes a DCO trailer for the App bot
identity.

Do not add human commits to `release-plz-next`. The workflow refuses to replace
the branch if its exact owner, ref, pull request, or unique commit differs from
the expected App state. Review and merge the release pull request through the
normal protected-branch path. Its exact head must pass `Required CI`, including
all three Rust platform jobs. Merging that pull request is the authorization
signal for release-plz because `.release-plz.toml` sets
`release_always = false` and the branch uses the `release-plz-` prefix.

### Preserve reviewed commits at integration

Preserve a release pull request's individual commits when review finds them
coherent, correctly scoped, and useful to retain on `main`. Every retained
commit must carry its own cryptographic signature and DCO sign-off and leave
the repository in a coherent state. If the submitted sequence is noisy,
partial, or not independently meaningful, curate or squash it on the
contributor branch and re-sign the result before requesting final
authorization. Do not make the integrating repository writer repair avoidable
history problems at merge time.

Do not use GitHub's **Rebase and merge** option. It rewrites reviewed commits
on the server and cannot preserve their signatures. **Squash and merge** also
replaces the reviewed commits. Use it when review concludes that the submitted
commit sequence is not worth retaining as-is, not as the default for coherent
history. This repository disables server-side rebase merging.

Bring a human-owned branch up to date before final CI with
`git rebase --gpg-sign origin/main` and the approved SSH signing key. Push
rewritten history only with `--force-with-lease`, then request `Required CI`
for the new exact head SHA. Do not rewrite `release-plz-next`; have the
`Release proposal` workflow refresh that App-owned branch instead. Every
rewritten head invalidates the earlier authorization and check.

After the exact head is current, GitHub Verified, DCO-compliant, and green
under `Required CI`, a repository writer re-fetches `origin` and integrates
that immutable commit with a normal fast-forward push:

```shell
git fetch origin
expected_main="$(git rev-parse origin/main)"
expected_head="<exact-40-character-PR-head-SHA>"
git merge-base --is-ancestor "${expected_main}" "${expected_head}"
git push origin "${expected_head}:refs/heads/main"
```

Re-check the pull request's base, head, and `Required CI` binding immediately
before the push. A concurrent `main` update makes the normal push fail closed;
rebase and re-sign the human-owned branch, or refresh the App-owned proposal,
then rerun exact-head CI. Never force-push `main`.

The workflow remains a successful no-op while the GitHub App configuration is
absent. It also waits without advancing the train until the shared version on
`main` is available and non-yanked for all four crates on crates.io.

A push or `repository_dispatch` event may create one default `patch` proposal
when no exact App-owned proposal exists. Once that proposal exists, background
events leave it untouched. A repository writer must dispatch `Release
proposal` with an explicit `patch`, `minor`, or `major` selection to revise the
proposal. The workflow uses that dispatch input directly and does not store
release intent in pull-request text.

Release proposals enter `protected-automation`, which is restricted to exact
`main` and supplies only the App credential. Official publication enters
`crates-io`, whose configured approval gates the OIDC-enabled publication job.
Validation enters neither environment and receives no OIDC permission.

Every proposal resolves its comparison baseline from the last complete set of
official annotated tags:

- `yaml-sigil-core-v<version>`;
- `yaml-sigil-transcription-v<version>`;
- `yaml-sigil-signing-v<version>`; and
- `yaml-sigil-verification-v<version>`.

All four tags must exist, identify annotated tag objects, dereference to one
commit, match origin, and be ancestors of current remote `main`. The exact
tagged version must be available and non-yanked for all four crates. Registry
prereleases that lack the complete official tag set never become
release-analysis baselines.

Before proposal analysis, validation, and publication, the xtask requires the
exact `yaml-sigil-traits` version from the manifests to be available and
non-yanked from the named crates.io index. It rejects source replacement,
unexpected registry identity, and a requirement other than one exact version.

### Manual release-proposal fallback

> [!IMPORTANT]
> This fallback changes proposal authorship only. It does not authorize local
> publication, a crates.io token, a protected-environment bypass, or binary
> artifacts. Official publication still uses the protected Trusted Publishing
> workflow.

Use this procedure when the App is unavailable or cannot safely update its
owned proposal. A repository writer may prepare the same release transaction
on a human-authored branch. Use Rust `1.95.0`, cargo-binstall `1.20.1`,
release-plz `0.3.160`, and cargo-semver-checks `0.49.0`. Create a
same-repository branch named `release-plz-manual-<target>` from exact current
`main`; do not reuse the workflow-owned `release-plz-next` branch.

Before creating the manual branch, inspect any existing `release-plz-next`
proposal and the selected manual branch name. Do not append a human commit to
the App-owned branch, replace a foreign branch, or run the two proposal paths
concurrently. Finish, close, or deliberately rename the colliding proposal,
then repeat the remote-main, tag, registry, and baseline checks.

Fetch current main and tags, verify the analyzers, verify the current official
version and traits dependency, and prepare the detached official baseline:

```shell
export RUSTUP_TOOLCHAIN=1.95.0
fetch_url="https://github.com/NVIDIA/yaml-sigil-rs"
test "$(git remote get-url origin)" = "${fetch_url}"
git fetch origin main --tags
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
rustc_version="$(rustc --version)"
test "${rustc_version%% (*}" = "rustc 1.95.0"
test "$(cargo-binstall -V)" = "1.20.1"
cargo xtask release install-tools
published_version="$(cargo xtask release-version show)"
cargo xtask release verify-registry \
  --check-version "${published_version}" \
  yaml-sigil-core \
  yaml-sigil-transcription \
  yaml-sigil-signing \
  yaml-sigil-verification
cargo xtask release verify-traits
baseline_parent="$(mktemp -d)"
baseline_root="${baseline_parent}/official-release"
inventory_path="${baseline_parent}/official-tags.json"
baseline_result="${baseline_parent}/baseline-result.json"
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  cargo xtask release baseline prepare \
    --version "${published_version}" \
    --head "$(git rev-parse HEAD)" \
    --output "${baseline_root}" \
    --result "${baseline_result}" \
    --inventory-output "${inventory_path}" \
    --expected-fetch-url "${fetch_url}"
registry_manifest_path="$(jq --exit-status --raw-output \
  '.manifest' "${baseline_result}")"
test "$(jq --exit-status --raw-output '.inventory' "${baseline_result}")" = \
  "${inventory_path}"
```

Stop if current main, the traits source, a registry record, any tag type or
target, tag ancestry, or remote ref differs. For the next substantive RC
proposal, set the reviewed intent and run:

```shell
release_date="$(date -u +%F)"
bump="patch"
# Generate the Conventional Commit changelogs and preliminary version change.
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  release-plz update \
    --config .release-plz.toml \
    --registry-manifest-path "${registry_manifest_path}"
git diff --name-only -- crates/*/CHANGELOG.md
```

The command must list at least one of the four published crate changelogs. If
it does not, stop before advancing the version because a manual proposal must
not create an empty seed. Complete the candidate transaction with the reviewed
intent:

```shell
target="$(cargo xtask release-version candidate \
  --published "${published_version}" \
  --bump "${bump}" \
  --date "${release_date}" \
  --release-notes)"
cargo xtask sync-workspace-versions
cargo xtask sync-workspace-versions --check
```

Set `bump` explicitly to the reviewed `patch`, `minor`, or `major` version-line
advance. A patch advances the current RC on the same core, or starts the next
patch RC after a stable release. Never infer the baseline from a higher
registry prerelease.

For stable promotion, use the same baseline preparation and require all four
official tags to dereference to exact current `main`. Then create the manual
branch and run:

```shell
release_date="$(date -u +%F)"
bump="patch"
for crate in core transcription signing verification; do
  test "$(git rev-parse "yaml-sigil-${crate}-v${published_version}^{commit}")" \
    = "$(git rev-parse HEAD)"
done
target="$(cargo xtask release-version promote-stable --date "${release_date}")"
cargo xtask sync-workspace-versions
cargo xtask sync-workspace-versions --check
```

For either path, review and validate the complete transaction:

```shell
cargo xtask release-version check
cargo xtask release-version check-compatibility \
  --baseline-manifest "${registry_manifest_path}" \
  --current-manifest Cargo.toml \
  --expected-baseline-version "${published_version}" \
  --expected-current-version "${target}" \
  --intent "${bump}"
cargo xtask release verify-traits
cargo xtask ci
cargo xtask release check-packages \
  yaml-sigil-core \
  yaml-sigil-transcription \
  yaml-sigil-signing \
  yaml-sigil-verification
git diff --check
git status --short
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=remote.origin.pushurl \
GIT_CONFIG_VALUE_0=disabled://yaml-sigil-release-proposal \
  cargo xtask release baseline verify \
    --head "$(git rev-parse HEAD)" \
    --inventory "${inventory_path}" \
    --expected-fetch-url "${fetch_url}"
```

The direct compatibility check converts the selected bump into Cargo's
pre-`1.0` release type and treats every analyzer error as a failure.
Release-plz's built-in semver check is disabled so it cannot reinterpret that
result. The complete diff must contain only the intended root `Cargo.toml` and
four crate changelog changes. The package gate checks the exact crates.io
inventory, source paths, library targets, and approved core build script. Its
registry checks preserve exit status `3` for an exact missing version and treat
yanked, malformed, or failed registry responses as errors.

Do not commit a generated root `Cargo.lock` or package archive. Commit the
complete transaction with an SSH signature and DCO sign-off. Prepare a
validation-only Cargo home and validate the clean exact commit before pushing:

```shell
validation_temp="$(mktemp -d)"
validation_cargo_home="${validation_temp}/cargo-home"
cargo xtask release prepare-validation-cargo-home \
  --output "${validation_cargo_home}"
CARGO_HOME="${validation_cargo_home}" \
  cargo package --package yaml-sigil-core --all-features
CARGO_HOME="${validation_cargo_home}" \
  cargo package --package yaml-sigil-transcription
CARGO_HOME="${validation_cargo_home}" \
  cargo package --package yaml-sigil-signing --all-features
CARGO_HOME="${validation_cargo_home}" \
  cargo package --package yaml-sigil-verification --all-features
git status --short
```

Push the branch and open its pull request against `main`. The pull request
association is required for a useful release-plz dry run because
`release_always = false` authorizes only commits from a `release-plz-*` branch.
After the pull request exists, use that same shell and validation Cargo home:

```shell
# Supply the existing gh credential only for read-only forge discovery.
CARGO_HOME="${validation_cargo_home}" \
  GIT_TOKEN="$(gh auth token)" \
  release-plz release --dry-run --forge github --config .release-plz.toml
git status --short
```

The process-scoped `GIT_TOKEN` must not be echoed, pasted, or persisted. Verify
that the dry run plans all four crates in dependency order and does not report
that the current commit is outside a release pull request. It must not publish
or create tags or GitHub Releases.

Review and integrate the exact head through the ordinary protected path only
after `Required CI` and all three Rust platform jobs pass. If a repair is
needed, amend the signed commit while retaining one DCO trailer, force-push
with lease, and repeat the clean-commit and dry-run checks. Merging that
`release-plz-*` pull request is the authorization signal for the protected
official publication workflow. Do not run a local non-dry-run release command.

After the manual proposal is integrated or closed, delete only its exact
manual branch, confirm current `main`, tags, registry, and traits state, and
dispatch a fresh `Release proposal` run. Let the workflow create or update its
own branch from that state. Do not copy the human-authored commit onto
`release-plz-next`.

## RC progression and synchronized versions

The default release progression is:

- a published stable `MAJOR.MINOR.PATCH` starts the next patch train as
  `MAJOR.MINOR.(PATCH+1)-rc.1`;
- a published `MAJOR.MINOR.PATCH-rc.N` advances to
  `MAJOR.MINOR.PATCH-rc.(N+1)`; and
- a background event creates a default patch proposal only when the App-owned
  proposal does not already exist.

The workflow creates every new proposal as a draft and converts an exact
existing App proposal to draft before changing its branch. It marks a proposal
with release notes ready only after the exact App commit repeats every source
gate and passes the association-dependent release-plz dry run. An empty
next-version seed remains draft.

For every `major`, `minor`, or `patch` advance, a repository writer can
dispatch `Release proposal` with mode `next-candidate` and the intended bump.
That manual dispatch may create the proposal or replace its App-owned commit.
Later pushes and post-publication notifications do not revise an existing
proposal. Another explicit writer dispatch is required to incorporate later
changes or select a different release line.

All four crates use `[workspace.package].version`. Every official RC or stable
proposal runs both commands and commits their complete result on the release
branch:

```shell
cargo xtask sync-workspace-versions
cargo xtask sync-workspace-versions --check
```

Never change one member version independently. Official publication rejects an
unsynchronized or dirty source tree.

## Promote an RC to stable

Stable promotion is an explicit review operation. First publish and verify all
four RC crates from `main`. Every matching official annotated tag must resolve
to the exact current `main` commit. Then a repository writer must manually
dispatch `Release proposal` with mode `promote-stable`. Background events
cannot select stable promotion. The workflow deterministically uses patch
compatibility intent, removes the prerelease component, synchronizes internal
dependency requirements, promotes the exact `yaml-sigil-traits` RC requirement
to its stable version, and copies each reviewed RC changelog section to the
stable version.

Review and merge that exact proposal before publishing the stable version. Do
not edit a contributor branch to remove `rc.N`, and do not promote source that
differs from the tagged RC.

## Validate an official release

Before validation or publication, confirm:

- the exact required `yaml-sigil-traits` version is available and non-yanked
  from the named crates.io index;
- `main` is the exact merged head of the intended `release-plz-*` pull request;
- the head is GitHub Verified, DCO-compliant, and green under required and
  platform CI;
- all four manifests, dependency requirements, and changelogs are synchronized;
- all four crates.io Trusted Publishers match
  `.github/workflows/publish.yml` and the `crates-io` environment;
- the `crates-io` environment requires its configured approval and has no
  long-lived registry token; and
- no intended version, tag, or GitHub Release exists, except when deliberately
  recovering a partial run.

Run validation from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=validate
```

Validation compares all four candidates with the detached last official tagged
workspace using cargo-semver-checks before ordinary Cargo packaging and a
release-plz dry run. A validation-only Cargo home patches only the unpublished
implementation crates to their reviewed workspace paths. It never patches
`yaml-sigil-traits`, so Cargo must resolve that exact version from crates.io.
Validation has no OIDC permission, uploads nothing, and does not enter the
publication environment.

## Publish an official release

Dispatch publication from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=publish
```

The validation job runs first. The publication job starts only after
validation succeeds and the `crates-io` environment is approved. Only that job
receives `id-token: write` and `contents: write`. Release-plz exchanges the job
identity for a short-lived crates.io credential, publishes the four source
packages in dependency order, and creates each configured annotated tag and
source-only GitHub Release. Prerelease versions become GitHub prereleases.

Both validation and publication independently require exact current `main` to
be the merge result of one reviewed App proposal or the documented signed
same-repository manual fallback. Stable promotion additionally requires that
proposal's base and the release commit's sole parent be the exact tagged RC
commit, so intervening source cannot enter the stable release. Immediately
before publication, the workflow rechecks the complete official-tag inventory,
the traits dependency, and remote `main`. Its ephemeral release-plz
configuration authorizes only the already-checked checkout and prevents
release-plz from selecting or checking out another commit.

The OIDC-authorized publication and recovery steps use a new unpatched Cargo
home. They resolve workspace dependencies through crates.io in publication
order instead of substituting local paths. Only the no-OIDC validation job uses
the validation-only `[patch.crates-io]` configuration.

The publication invocation deliberately omits release-plz's `--dry-run` CLI
flag. After a successful publication, the workflow requests the next release
proposal.

## Verify and recover

The workflow waits for crates.io to expose all four versions as non-yanked and
confirms Cargo can resolve them. It then requires each configured tag to be an
annotated tag whose object targets exact publication `main`. Each GitHub Release
must use its crate-specific tag and name, contain the exact reviewed version
section from that crate's changelog, have the expected prerelease state, and
have no attached assets. Record the workflow run, packages, tags, and Releases
in the workspace release records.

Never blindly retry a failed publication. Inspect crates.io, all four tags, and
all four GitHub Releases first. An existing crate version cannot be overwritten,
even if yanked. On a reviewed retry, the workflow accepts only these ordered
states:

- If no exact non-yanked crate version exists, all four crates and their forge
  objects must be absent.
- If publication stopped partway through the transaction, the published crates
  must form the exact dependency-order prefix of `yaml-sigil-core`,
  `yaml-sigil-transcription`, `yaml-sigil-signing`, and
  `yaml-sigil-verification`. Every published source archive must bind to exact
  current `main`; any existing tag or Release for that prefix must also be
  exact. Every crate and forge object in the remaining suffix must be absent.
  The workflow then permits release-plz to resume only that same transaction.
- If all four exact non-yanked crate versions already exist, the workflow skips
  release-plz and every registry mutation. It may create only missing annotated
  tags and source-only GitHub Releases after independently rechecking crates.io
  package checksums and exact source provenance.

Recovery never moves or replaces an existing ref, edits an existing Release,
deletes an object, or uploads an asset. A non-prefix partial publication, a
source mismatch, a lightweight or wrong-target tag, a mismatched Release body
or state, an attached asset, a yanked crate, or a creation race fails closed for
operator review. Do not replace Trusted Publishing with a long-lived token,
bypass an environment, reuse a version, or attach binary assets as a recovery
shortcut.
