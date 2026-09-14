# Examples

Runnable examples demonstrate the public `yaml-sigil` APIs. Run the commands
below from the repository root.

## Example index

| Example | Demonstrates |
|---------|--------------|
| [`github-keys`](./github-keys/README.md) | YAML signing and verification with Ed25519 keys from GitHub's anonymous authentication-key and signing-key APIs or an explicit public key, selected with `--signer`. |

## Run an example

Each example documents its usage and limitations.
For the GitHub example, start with its help and
[fixture walkthrough](./github-keys/README.md#try-the-fixtures).
It accepts files, HTTP(S) URLs, or `stdin` through `--input`. Signing writes
the artifact to stdout when `--output` is omitted. Progress headings and status
messages go to stderr. Signing places `====== STATUS ======` before its final
status.
Input documents and signed output are capped at 4 MiB.
Verification begins with a reminder about the signing layer's scope and ends
with the result.
Discovery collects all pages of both account key lists and combines their
supported keys. It needs no GitHub token and reports anonymous API rate limits
as errors.
Verification uses your `--signer` choice. The artifact's optional `keyid`
hint does not constrain verification or change where keys are requested.
For a run without key discovery, pass a quoted OpenSSH public-key line as
`--signer`. See [rate limits and offline runs](./github-keys/README.md#github-api-rate-limits-and-offline-runs)
for copyable commands. Use a file or `stdin` as input for a fully offline run.

```shell
cargo run --package yaml-sigil-examples --example github-keys -- --help
```

## Sign your own YAML

> [!WARNING]
> The GitHub example takes ownership of private-key material in its own process.
> See the planned [SSH agent transition](./github-keys/README.md#ssh-agent-transition).

Follow the [GitHub signing instructions](./github-keys/README.md#sign-your-own-yaml)
for key-file handling and copyable commands. Use a dedicated Ed25519 key
registered with GitHub for authentication, signing, or both for username-based
discovery, or pass its public half directly with `--signer`. Verification needs
only public keys.

## Tests and packaging

The unpublished `yaml-sigil-examples` workspace member registers runnable
targets with `test = true`. The existing `cargo xtask ci` sequence compiles
them during all-target Clippy and runs their tests during
`cargo test --workspace --all-features`.

```shell
cargo test --package yaml-sigil-examples
```

GitHub example tests use synthetic keys and a recorded public-key snapshot.
They require no network, account credentials, private personal key, or SSH
agent. Live key discovery is a separate manual check.

Dependencies are development dependencies, annotated by example and purpose
in [`Cargo.toml`](./Cargo.toml). Executable build outputs stay local.
