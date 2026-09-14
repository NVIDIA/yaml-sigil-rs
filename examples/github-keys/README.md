# Sign and verify YAML with GitHub account keys

This example signs YAML with an Ed25519 private key and verifies a signature
against keys listed on GitHub for a username.

> [!WARNING]
> This is an easy to use usage example, not an example of security best
> practices.
> Use this only for local experimentation. Do not use it as a production
> verification gate.
> Use a disposable demo key, preferably registered for signing only, rather
> than an existing login key. Signing loads private-key material into this process.

You will need to pass the GitHub username with `--signer USERNAME`, and it will
attempt to capture the public keys from
`https://api.github.com/users/USERNAME/keys` and
`https://api.github.com/users/USERNAME/ssh_signing_keys`.

## Try the fixtures

> [!NOTE]
> Discovery uses anonymous GitHub requests and accepts authentication and
> signing keys.
> You can also pass a quoted OpenSSH public-key line as `--signer` to skip
> key discovery. See [rate limits and offline runs](#github-api-rate-limits-and-offline-runs).
>
> In username mode, this example trusts GitHub to associate the
> returned public keys with the selected account.
> A username provides no identity continuity. Account compromise, key replacement,
> or [username reuse](https://docs.github.com/en/account-and-profile/concepts/username-changes)
> can change the accepted keys. Pin an independently trusted key with
> [direct-key mode](#github-api-rate-limits-and-offline-runs).
> Verification establishes neither signing time nor freshness and does not
> prevent replay.

### Quick Verification

Run these commands from the repository root. Verification makes an anonymous
HTTPS request to GitHub; it needs no token, private key, or SSH agent.

```shell
cargo run --package yaml-sigil-examples --example github-keys -- verify \
  --signer ddurst-nvidia \
  --input examples/github-keys/fixtures/signed.yaml
```

or

```shell
# The raw URLs target fixtures published on upstream `main`. If they are not
# available on that ref, use a local fixture path or standard input.

cargo run --package yaml-sigil-examples --example github-keys -- verify \
  --signer ddurst-nvidia \
  --input https://raw.githubusercontent.com/NVIDIA/yaml-sigil-rs/main/examples/github-keys/fixtures/signed.yaml
```

or

```shell
cargo run --package yaml-sigil-examples --example github-keys -- verify \
  --signer ddurst-nvidia --input stdin < examples/github-keys/fixtures/signed.yaml
```

It should report the matching SHA-256 public-key fingerprint on stderr and end with
`Signature verified (N payload bytes).` on success, with exit status `0`.

> Verification leaves stdout empty and does not print unverified payload bytes.

### Misc Fixtures

We do offer some basic fixtures here, to help you reason about what we do and
do not do with YAML-Sigil.

| File | Expected result | Reason |
|------|-----------------|--------|
| [`unsigned.yaml`](./fixtures/unsigned.yaml) | Failure. | No signature is present; this is the input used to create the signed sample. |
| [`signed.yaml`](./fixtures/signed.yaml) | Success. | The signature matches the unchanged payload and the recorded Ed25519 key. |
| [`tampered-payload.yaml`](./fixtures/tampered-payload.yaml) | Failure. | The port changes from `8080` to `8081` without a new signature. |
| [`tampered-signature.yaml`](./fixtures/tampered-signature.yaml) | Failure. | A signature byte changes while the payload stays the same. |
| [`changed-keyid.yaml`](./fixtures/changed-keyid.yaml) | Success. | **Changing the unsigned `keyid` hint leaves the signature intact; verification still uses the caller-selected signer.** |
| [`signed-application-invalid.yaml`](./fixtures/signed-application-invalid.yaml) | Success. | **The signature matches even though `port: not-an-integer` violates the illustrative application's integer-port rule.** |

> [!NOTE]
> The last sample signs [`application-invalid.yaml`](./fixtures/application-invalid.yaml).
> The example performs no application-level port check. Syntactically acceptable
> YAML and a matching signature do not imply a usable application configuration.
> The `changed-keyid.yaml` sample verifies in both username and direct-key modes
> because changing the hint leaves the payload's cryptographic signature intact.
> The unsigned and tampered samples fail in both modes.

### Fixture provenance

The `signed.yaml` and `signed-application-invalid.yaml` samples were created
with a dedicated `ddurst-nvidia` Ed25519 signing key through an SSH agent. The
[public-key snapshot](./fixtures/ddurst-nvidia.pub-key) contains that key's public
half. Live verification resolves keys through both of the account's public
key lists.
The matching fingerprint is:

```text
SHA256:EVFfVelC8GKlyPd1Tl9KLhtfTqzLkAYXsH6LP7PdCQg
```

The modified samples derive from `signed.yaml` through the changes listed
above.

## Read and write documents

Both commands require `--input <FILE>`, `--input <URL>`, or `--input stdin`.
Documents are capped at 4 MiB, including signed output. `stdin` reads standard
input; `./stdin` names a file with that basename.
HTTP and HTTPS input URLs are fetched anonymously with a 20-second timeout.

## Stages

### Verification

```text
REMINDER: We are validating the document's signature, not the document itself.
====== 1/4 Read signed YAML ======
====== 2/4 Check signature metadata ======
====== 3/4 Resolve public keys ======
====== 4/4 Verify the signature ======
```

### Signing

```text
REMINDER: Signing a document does not validate its contents.
====== 1/5 Read unsigned YAML ======
====== 2/5 Load private key ======
====== 3/5 Resolve signer and match the public key ======
====== 4/5 Sign YAML ======
====== 5/5 Write signed YAML ======
====== STATUS ======
```

## Sign your own YAML

> [!WARNING]
> This example takes ownership of your private-key material in its own process,
> including decrypting encrypted key files. The example and its dependencies
> can access the raw key during signing. See the planned
> [SSH agent transition](#ssh-agent-transition) for signing through an agent.
>
> Review a local copy before signing. URL input is signed without a preview.
> HTTP permits substitution in transit. HTTPS authenticates the server connection.
> Neither confirms what you intend to sign.

Use a dedicated ordinary OpenSSH Ed25519 private-key file whose public half
is registered with GitHub for authentication, signing, or both.
Replace `YOUR-USERNAME` and select your actual key file; the
filename below is the convention used for this demo.

```shell
cargo run --package yaml-sigil-examples --example github-keys -- sign \
  --signer YOUR-USERNAME \
  --private-key "$HOME/.ssh/id_ed25519-github-yaml-sigil-signing" \
  --input https://raw.githubusercontent.com/NVIDIA/yaml-sigil-rs/main/examples/github-keys/fixtures/unsigned.yaml \
  > signed-example.yaml
cargo run --package yaml-sigil-examples --example github-keys -- verify \
  --signer YOUR-USERNAME \
  --input stdin < signed-example.yaml
```

Encrypted keys prompt for a passphrase on the terminal without echoing it.
A session without a terminal cannot decrypt an encrypted file. Passphrases
are not accepted as command arguments. The private-key parser, passphrase
buffer, and native signing key clear their secret buffers on drop.

In username mode, signing confirms that the private key's public half is in
either of the account's public key lists. With an explicit public key, it
requires that exact key to match. Signing appends a missing final newline
before signing a nonempty YAML payload, then writes
the artifact bytes returned by `sign_yaml`. It refuses an existing output
path when `--output FILE` is supplied. Input arguments select a file, URL,
or standard input; they do not accept inline YAML.

The executable supports ordinary `ssh-ed25519` keys. It skips other public-key
algorithms in mixed lists and rejects signing with RSA, P-256, certificates,
or security-key forms such as `sk-ssh-ed25519@openssh.com`.

Omitting `--output` writes the exact signed artifact to stdout. Use
`--output FILE` to create a new file; existing paths are refused. Progress and
verification results stay on stderr so you can redirect or pipe stdout as YAML.
Combining stderr and stdout produces a terminal transcript that cannot be
parsed as a YAML stream.
Payloads may contain terminal controls. Direct untrusted signed output to
`--output FILE` or a redirected file.

### SSH agent transition

The intended `0.6.0` update replaces private-key-file loading with an
SSH-agent-backed signing provider using that release's crypto-provider
interfaces. Key discovery, the `keyid` hint, caller-selected account or key,
and signature verification remain separate from signing-key access.
An agent reduces key exposure; it does not make requested signatures or
document contents trustworthy.

That adapter must request a signature over the payload bytes supplied by
`yaml-sigil`. An OpenSSH `ssh-keygen -Y sign` SSHSIG envelope signs different
bytes and cannot be substituted for a `yaml-sigil` signature. The current
example **does not implement agent signing**.

## Discovery and verification

[`main.rs`](./main.rs) keeps the public library calls visible. It loads a
signing key or calls `pre_verify_yaml`, checks the signature metadata, and uses
`verify_from_pre_verify_yaml` with each caller-selected candidate Ed25519 key.
It accepts only `VerifierState::Verified`. The caller retains responsibility
for any use of the authenticated payload.

[`input.rs`](./input.rs) reads document bytes from the caller-selected source.
A document's origin never changes the expected account or key-discovery URLs.

[`github.rs`](./github.rs) implements the example's URL and HTTP policy.
It accepts a GitHub username and constructs two URLs.

- `https://api.github.com/users/USERNAME/keys`.
- `https://api.github.com/users/USERNAME/ssh_signing_keys`.

The username argument must omit the URL and `@` prefix.
This prevents credentials, alternate ports, extra path components, query strings,
or fragments from entering the URLs. Signing emits the URL containing the
matching key as the optional `keyid` hint. If a key appears in both lists,
the authentication-key URL is used. Verification selects both endpoints from
`--signer` independently of the artifact's hint. Requests use GitHub REST API
version `2026-03-10` and accept JSON. The example rejects redirects, non-`200`
statuses, and unexpected media types. Each request has a 20-second timeout.
A complete lookup is limited to 10 pages per resource and 256 KiB of response
bodies across both resources. These are example operational limits, separate
from artifact conformance; exceeding either limit fails discovery without
using a partial key set.

The example requests 100 entries per page and reads the next page number from
GitHub's `Link` header. Every request retains the caller-selected username,
including when GitHub's links use a numeric account alias. Unexpected origins,
resources, repeated or skipped page numbers, and changed page sizes are errors.
Discovery finishes both lists before selecting a signing key or verifying a
signature. An error in either list fails the operation even if a previous
response contained a matching key.

Each JSON record must contain one OpenSSH public-key line in its `key` field.
The `ssh-key` parser decodes that line. The
base64 field contains an SSH wire blob with the algorithm and public-key data.
The example passes the extracted point to
`resolve_ed25519_verifying_key` for the library's admissibility check.
It deduplicates supported Ed25519 keys across both lists, reports their count,
and tries them until one verifies. A mismatch with one candidate does not skip
the remaining keys; verification fails if none match. Either list can be empty
or contain only unsupported algorithms when the other list has a supported
key. Malformed lines, inadmissible Ed25519 keys, and a combined list without
supported keys produce errors.

### GitHub key purposes

GitHub documents separate
[authentication-key](https://docs.github.com/en/rest/users/keys#list-public-keys-for-a-user)
and
[SSH signing-key](https://docs.github.com/en/rest/users/ssh-signing-keys#list-ssh-signing-keys-for-a-user)
REST resources. This example accepts ordinary Ed25519 keys from either
resource, regardless of their GitHub registration purpose. An existing
authentication key or a signing-only key is sufficient. GitHub's registration
categories do not change what `yaml-sigil` verifies or authorize the contents
of arbitrary YAML documents or their use by an application.

The `https://github.com/USERNAME.keys` shortcut exports authentication keys
without purpose metadata and can omit signing-only registrations. This example
queries both REST resources to include either registration type.

### GitHub API rate limits and offline runs

Both public key lists require no token or login. GitHub applies an anonymous
API rate limit shared by requests from the same public IP address. On a rate
limit response, the example reports `Retry-After` seconds or the Unix timestamp
in `X-RateLimit-Reset` when available. Retry after that time. It does not prompt
for GitHub credentials or retry through an authenticated path.
See [GitHub's rate-limit documentation](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

#### Verification

For an example run without GitHub key discovery, supply the public key
explicitly. This command verifies the local signed fixture using its recorded
public-key snapshot.

```shell
cargo run --package yaml-sigil-examples --example github-keys -- verify \
  --signer "$(cat examples/github-keys/fixtures/ddurst-nvidia.pub-key)" \
  --input examples/github-keys/fixtures/signed.yaml
```

`--signer` takes the complete OpenSSH line, such as `ssh-ed25519 AAAA...`,
including an optional comment. It does not take a filename or a fingerprint.
The shell command above reads the public-key file and passes its contents.
Select a key you trust; do not accept an untrusted document's suggested key.

This mode verifies only against the supplied key. It does not check the
account's current GitHub registration and never resolves the artifact's
unsigned `keyid`. It can therefore verify the URL-labeled fixtures while
GitHub is unavailable. Key discovery never switches to this mode automatically.
URL inputs still make HTTP requests; use a local file or `stdin` for an
offline run.

#### Signing

You can sign offline with the same dedicated private key and its public half.
Replace the paths when your key has a different filename.

```shell
cargo run --package yaml-sigil-examples --example github-keys -- sign \
  --signer "$(cat "$HOME/.ssh/id_ed25519-github-yaml-sigil-signing.pub")" \
  --private-key "$HOME/.ssh/id_ed25519-github-yaml-sigil-signing" \
  --input examples/github-keys/fixtures/unsigned.yaml \
  > signed-offline.yaml
cargo run --package yaml-sigil-examples --example github-keys -- verify \
  --signer "$(cat "$HOME/.ssh/id_ed25519-github-yaml-sigil-signing.pub")" \
  --input stdin < signed-offline.yaml
```

Direct-key signing omits `keyid` because a public key alone does not identify
a GitHub account. You can verify that artifact with the explicit public key
or with a username whose authentication-key or signing-key list contains the
same key.

## Find the endpoint for other VCS systems

> [!NOTE]
> Only GitHub's public authentication-key and signing-key APIs are implemented
> here. The other rows identify discovery options for another application;
> supplying those URLs as `--signer` fails.

| Host | Account public-key URL | Response and access |
|------|------------------------|---------------------|
| [GitHub](https://github.com/) | `https://github.com/USERNAME.keys` | Public OpenSSH text export. |
| [GitHub SSH authentication keys](https://github.com/) | `https://api.github.com/users/USERNAME/keys` | Anonymous, paginated JSON; used by this example. |
| [GitHub SSH signing keys](https://github.com/) | `https://api.github.com/users/USERNAME/ssh_signing_keys` | Anonymous, paginated JSON; used by this example. |
| [GitLab.com](https://about.gitlab.com/) | `https://gitlab.com/USERNAME.keys` | OpenSSH text; instance access rules apply. |
| [Self-managed GitLab](https://about.gitlab.com/) | `https://YOUR-GITLAB-HOST/USERNAME.keys` | OpenSSH text; network and instance sign-in rules apply. |
| [Gitea](https://about.gitea.com/) | `https://GITEA-HOST/USERNAME.keys` | OpenSSH text; profile and instance visibility apply. |
| [Codeberg](https://codeberg.org/Codeberg) | `https://codeberg.org/USERNAME.keys` | OpenSSH text; profile visibility applies. |
| [Forgejo](https://codeberg.org/forgejo), including private instances | `https://FORGEJO-HOST/USERNAME.keys` | OpenSSH text; profile and instance visibility apply. |
| [Bitbucket Cloud](https://www.atlassian.com/) | `https://api.bitbucket.org/2.0/users/{selected_user}/ssh-keys` | Authenticated, paginated JSON. |
| [Bitbucket Data Center](https://www.atlassian.com/) | `https://HOST/rest/ssh/1.0/keys?user=USERNAME` | Authenticated, paginated JSON; target-user permissions apply. |
| [GitLawb](https://github.com/Gitlawb) | Decode the identity's `did:key:z6Mk...` locally. | Embedded Ed25519 public key; no documented `.keys` shortcut in the reviewed source. |

## Adapt the example for P-256

The executable remains Ed25519-only. For a P-256 variant, parse
`ecdsa-sha2-nistp256` with `ssh-key`, require its `NistP256` variant, and
use the native `p256` library to obtain the uncompressed point expected by
`resolve_p256_verifying_key`.

```rust
use anyhow::{Result, bail};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use ssh_key::{PublicKey, public::EcdsaPublicKey};
use yaml_sigil_verification::resolve_p256_verifying_key;

fn resolve_ssh_p256(line: &str) -> Result<p256::ecdsa::VerifyingKey> {
    let parsed = PublicKey::from_openssh(line)
        .map_err(|error| anyhow::anyhow!("invalid OpenSSH key: {error}"))?;
    let Some(EcdsaPublicKey::NistP256(point)) = parsed.key_data().ecdsa() else {
        bail!("expected an ordinary P-256 SSH public key");
    };
    let native = p256::PublicKey::from_sec1_bytes(point.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid P-256 point"))?;
    let uncompressed = native.to_encoded_point(false);
    Ok(resolve_p256_verifying_key(uncompressed.as_bytes())?)
}
```

For signing, decode the OpenSSH P-256 private scalar into
`p256::ecdsa::SigningKey`. Select `AlgorithmId::EcdsaP256Sha256` and
`SigningKey::EcdsaP256Sha256` in `SignYamlParams`. For verification, supply
the resolved key through `PublicKeys.p256` and enable that algorithm in
`VerifierOptions`. Resolve keys from the caller's selected account or explicit
public key, and require the private/public-key match when signing. Keep `keyid`
as an optional hint.

Let the library produce its fixed-width signature and apply SHA-256. Do not
substitute an SSH signature blob, DER encoding, or an SSHSIG envelope, or
prehash the message before handing it to the library.
The P-256 adaptation test exercises this conversion and a library round trip
without adding a P-256 CLI option.

## Tests and dependencies

```shell
cargo test --package yaml-sigil-examples --example github-keys
cargo xtask ci
```

The target's `test = true` registration makes the existing workspace CI run
its tests. They cover CLI arguments, file/URL/stdin signing and verification,
stdout artifact bytes, progress steps, encrypted keys, key selection, malformed
key records, pagination, later-page failures, anonymous rate limits, HTTP
response and read failures, document size boundaries, cumulative discovery limits,
caller-selected URLs, direct-key signing and verification without network
access, optional and changed `keyid` hints, fixture outcomes in both modes,
and the P-256 recipe.
The tests use synthetic private keys or the recorded public-key snapshot.
HTTP responses are supplied locally to keep tests offline. Live HTTP transport
and GitHub verification are separate manual checks.

The example uses `clap`, `anyhow`, `ssh-key` `0.6.7`, `ureq` `3.4`, `serde_json`,
`rpassword`, `zeroize`, and the workspace's RustCrypto bindings and public
`yaml-sigil` APIs. They are development dependencies of the unpublished
example package, with usage documented in [`Cargo.toml`](../Cargo.toml).
