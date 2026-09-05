# Contributing to yaml-sigil-rs

`yaml-sigil-rs` is developed agent-first. Use agents to explore the workspace,
run diagnostics, and draft changes, then review the result as the responsible
author before submitting it.

## The Critical Rule

**You must understand your code.** AI-assisted contributions are welcome, but
you must be able to explain what changed, why it changed, and how it interacts
with the rest of the implementation. Do not submit generated code, tests, or
documentation that you cannot defend without the agent open.

## AI Usage

`yaml-sigil-rs` is agent-first, not agent-only.

- **Do** use agents to read the codebase, run checks, generate drafts, and
  iterate on implementations.
- **Do** use the skills in `.agents/skills/`; they capture repository-specific
  workflows for spec updates and implementation review.
- **Do** question the agent until you understand the behavior, edge cases, and
  test impact of your change.
- **Do not** submit changes you cannot explain in your own words.
- **Do not** use agents as a substitute for reading the relevant code, specs,
  and maintainer guidance.

## Express release-version intent

Use an accurate Conventional Commit type and breaking-change marker when the
change itself establishes its release impact. Do not edit workspace or crate
versions on an ordinary feature or fix branch. State release impact in the pull
request when the commits do not make it clear. Maintainers select the exact
stable or prerelease version later and prepare the dedicated
`release-plz-manual-<version>` pull request described in `RELEASING.md`.

All four published crates share `[workspace.package].version`. Never change a
member version independently. A version change belongs only in the canonical
single-commit release pull request and must pass both checks:

```shell
cargo xtask sync-workspace-versions --check
cargo xtask release check --version MAJOR.MINOR.PATCH[-PRERELEASE]
```

Official RC and stable publication rejects an unsynchronized or dirty source
tree. Pull requests do not publish preview versions.

## Pull-request CI

The repository uses `copy-pr-bot` for explicit contributor admission. A
repository writer reviews the exact latest pull-request head and comments:

```text
/ok to test <full-40-character-head-sha>
```

The bot copies only that authorized head to `pull-request/<number>`. Draft and
ready pull requests do not synchronize automatically. Every new head requires
a new review and exact-SHA authorization; a stale authorization never runs the
new head.

Contributor admission has two deliberate human steps. First, a writer posts
the exact-head command above. After the authoritative candidate lanes finish,
the configured `ddurst-nvidia` reviewer approves that run's exact
`protected-automation` reporter deployment. The reporter then repeats every
live binding before the App writes `Required CI`. This per-deployment approval
does not authorize a release finalizer or a different candidate head.

Candidate setup completes before source materialization. The checkout uses
anonymous Git transport, rejects requested Git filters, disables Git LFS, and
ignores candidate-selected submodule configuration. Candidate execution
receives no repository credential, secret, OIDC permission, protected
environment, trusted cache-save path, or retained artifact. No privileged
post-step consumes candidate-writable state.

Every human-authored pull-request commit must form a linear history from
current `main`, be GitHub Verified, and contain the exact DCO identity required
for that author. A writer's command authorizes testing only and does not
authorize integration.

Before final authorization, fetch current upstream `main`, rebase the original
contributor branch with `git rebase --gpg-sign <upstream>/main`, and push the
rewritten branch back to the same fork with `--force-with-lease`. Confirm every
rewritten commit is GitHub Verified and DCO-compliant, then request testing for
the new exact SHA.

The authoritative candidate result is `Candidate CI (Linux)` on the NVIDIA
runner. A separate protected, checkout-free reporter binds the workflow ID,
run and attempt, repository, open pull request, copied ref, current head,
authoritative job conclusion, and zero-artifact result before the
repository-scoped App creates `Required CI` on that exact head. Stable macOS
and Windows jobs are advisory and cannot influence the required verdict. The
independent Rust `1.95.0` Linux lane protects the documented minimum version.

#### Signing Off Your Work

* We require that all contributors "sign-off" on their commits. This certifies that the contribution is your original work, or you have rights to submit it under the same license, or a compatible license.

  * Any contribution which contains commits that are not Signed-Off will not be accepted.

* To sign off on a commit you simply use the `--signoff` (or `-s`) option when committing your changes:
  ```bash
  $ git commit -s -m "Add cool feature."
  ```
  This will append the following to your commit message:
  ```
  Signed-off-by: Your Name <your@email.com>
  ```

* Full text of the DCO (https://developercertificate.org/):

  ```
    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.
  ```
