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
versions on an ordinary feature or fix branch. The release-proposal workflow
calculates and commits versions on its dedicated `release-plz-*` branch.

When the required `major`, `minor`, or `patch` advance is not discoverable from
the commits, state the intended impact in the contribution pull request. A
repository writer can dispatch the `Release proposal` workflow with
`next-candidate` and the matching bump override. The workflow records an
explicit override in the release pull request so later updates preserve it.
Dispatch `auto` to clear that override and return to automatic calculation.

While the release-proposal GitHub App is unavailable, repository writers use
the temporary manual release-proposal procedure in `RELEASING.md`. Contributors
still express version intent here and do not edit versions on their change
branches.

All four published crates share `[workspace.package].version`. Never change a
member version independently. A release-version change is complete only after
running both commands and committing every resulting tracked change in the
same release pull request:

```shell
cargo xtask sync-workspace-versions
cargo xtask sync-workspace-versions --check
```

Official RC and stable publication rejects an unsynchronized or dirty source
tree. Pull-request snapshots are different. Their `0.pr` versions are applied
only in an ephemeral checkout and may be published from that intentionally
dirty tree without mutating the contributor's branch.

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
