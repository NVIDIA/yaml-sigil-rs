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
