# xtask guidance

These instructions apply to the developer-only `xtask` crate.

Keep `cargo xtask ci` and every namespace except `github` provider-neutral and
credential-free. Development commands may validate, package, import, profile,
or prepare local source, but they must not inspect GitHub, GitLab, runner, or
workflow environment state.

The only provider-specific namespace is `cargo xtask github`. Limit it to typed
release qualification and finalization for the exact compiled repository and
four-crate policy. Accept tokens only through environment variables. Do not
add an API passthrough, accept tokens as CLI arguments, or parse, embed, test,
or snapshot workflow YAML, triggers, permissions, job names, Action pins, or
secrets.

Release commands have these boundaries:

- `cargo xtask release prepare --version <SEMVER>` runs pinned release-plz
  update locally and may change only expected manifests and changelogs.
- `cargo xtask release check --version <SEMVER>` is non-publishing and requires
  the exact four packages, versions, dependency order, and crates.io traits
  source without any forge credential.
- `cargo xtask github release qualify` reads exact GitHub and crates.io state
  and emits bounded workflow outputs without mutation.
- `cargo xtask github release finalize` uses a repository-scoped App token only
  after registry confirmation to create or verify deterministic annotated tags
  and immutable, zero-asset Releases.

Keep the root workspace lockfile untracked and keep `xtask/Cargo.lock`
committed. Run formatting, Clippy with warnings denied, and the xtask tests for
every change. Preserve bounded process output, safe-file handling, exact
package policy, and focused rejection tests.
