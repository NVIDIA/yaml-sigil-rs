# Release the YamlSigil Rust crates

This repository publishes these crates.io `.crate` source packages:

- `yaml-sigil-core`;
- `yaml-sigil-transcription`;
- `yaml-sigil-signing`; and
- `yaml-sigil-verification`.

Release-plz also creates a version tag and GitHub Release for each published
crate. Each release body comes from that crate's reviewed changelog. Release-plz
does not build or attach binary assets, and the workflow retains no artifacts
or separately generated archives. GitHub's automatic source archives are
source-only and are expected. Cargo disables automatic binary targets in each
publishable crate, and hosted validation rejects an explicit binary target. Do
not distribute compiled executables from this repository. Keep the workspace
default, conformance, test-key, and xtask packages unpublished.

## Release source and authorization

Prepare each publication train in a pull request whose branch starts with
`release-plz-`. From a clean branch based on current `main`, use release-plz to
update workspace versions and per-crate changelogs:

```shell
release-plz update --config .release-plz.toml
```

Review the workspace and crate manifests, `Cargo.lock`, dependency ordering,
and each generated `CHANGELOG.md`. Commit the result with the repository's
required SSH signature and DCO sign-off. Open the release pull request, require
its exact head to pass `Required CI` and the platform jobs, and integrate that
exact head only after approval.

This human-signed release-PR preparation keeps the normal DCO and commit-signing
controls. The release-plz GitHub Action is not used to author the pull request
commit because its generated commit cannot carry this repository's required DCO
trailer. The `release-plz-` branch prefix is significant: with
`release_always = false`, release-plz publishes only when the current `main`
commit is associated with a merged release pull request using that prefix.

The protected branch, reviewed release PR, manifests, changelogs, and
`.release-plz.toml` define the release. The workflow does not hard-code a source
commit or crate version.

## Prerequisites

Before validation or publication:

- Publish and verify the required `yaml-sigil-traits` version on crates.io.
- Confirm `main` is the exact integrated head of the intended `release-plz-`
  pull request and contains the reviewed versions, dependency requirements,
  package contents, and changelogs.
- Confirm that commit is SSH-signed, DCO-compliant, GitHub Verified, and green
  under required and platform CI.
- Confirm the crates.io owners and reusable Trusted Publisher configurations
  are correct for this repository, `.github/workflows/publish.yml`, and the
  `crates-io` environment.
- Confirm the `crates-io` environment requires its configured approval and has
  no long-lived registry token.
- Confirm every intended version is absent from crates.io and that its tag and
  GitHub Release do not already exist.

Do not enable the crates.io setting that requires Trusted Publishing for every
new version until at least two complete prerelease publication trains have
succeeded. Run another successful prerelease train after a material publication
workflow change.

## Validate

Run the default operation from `main` only after the required traits version is
available on crates.io:

```shell
gh workflow run publish.yml --ref main -f operation=validate
```

Watch it to completion:

```shell
gh run watch --exit-status
```

Validation gives Cargo a temporary home that patches only the unpublished
implementation crates to their reviewed workspace paths. It deliberately does
not patch `yaml-sigil-traits`, so ordinary Cargo package verification must
resolve that dependency's manifest version from crates.io. The workflow then
runs `cargo package` for each publishable crate and performs a release-plz dry
run. The dry run also verifies eligibility under the release-PR authorization
rule. Validation has no OIDC permission, uploads nothing, and does not enter the
protected environment.

Inspect the completed run before publication and confirm that it retained no
artifacts.

## Publish

Inspect crates.io, repository tags, and GitHub Releases immediately before
dispatch. If any object for an intended version already exists, determine
whether it came from an earlier partial or completed run before continuing.

Dispatch the stable publication operation from `main`:

```shell
gh workflow run publish.yml --ref main -f operation=publish
```

The validation job runs first. The publication job can start only after
validation succeeds and the configured reviewer approves the `crates-io`
environment. Only that job receives `id-token: write` and `contents: write`.
Release-plz exchanges the workflow identity for a short-lived crates.io
credential, publishes the workspace in dependency order, and creates each
version tag and GitHub Release from the reviewed changelog. Pre-release versions
are marked as GitHub pre-releases. The workflow has no Cargo registry token
input or secret, and no step builds or attaches release assets.

The publication invocation omits release-plz's `dry_run` input. Setting that
input to the string `false` would still enable dry-run behavior. Release-plz
skips exact versions already present on crates.io, supporting a carefully
reviewed partial-run retry.

## Verify publication

The workflow reads the expected versions from Cargo metadata, waits for
crates.io to expose all four as non-yanked, and confirms that Cargo can resolve
them from the registry. After the run:

- inspect every crates.io package page and owner list;
- confirm every version tag targets the exact released `main` commit;
- confirm every GitHub Release uses the corresponding tag and reviewed
  changelog;
- confirm the GitHub Releases have no attached assets; and
- record the workflow run, packages, tags, and releases in the workspace
  release records.

## Recover from a partial run

Never blindly retry a failed publication. Inspect crates.io, every intended
tag, and every GitHub Release first:

- If a crate version exists and is correct, do not try to overwrite it. Confirm
  which later dependencies or repository release objects remain absent before
  retrying.
- If a crate version exists but is defective, decide explicitly whether to yank
  it. A yank does not permit reusing the same version. Prepare and review a
  later release PR.
- If no target version exists, diagnose validation, release-PR association,
  environment approval, OIDC exchange, or Cargo publication before considering
  another dispatch.
- If a tag or GitHub Release exists with incorrect metadata, stop and review the
  exact remote state before changing or deleting it.

Do not replace Trusted Publishing with a long-lived token, bypass the
environment, or attach binary assets as a recovery shortcut.
