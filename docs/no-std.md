# Portable builds and API migration

`yaml-sigil-core`, `yaml-sigil-signing`, `yaml-sigil-transcription`,
`yaml-sigil-verification`, and `yaml-sigil-traits` support `no_std`.
Both default paths and `v1alpha1` select the same definitions and features.
The specification version and encoded artifact formats remain unchanged.

## Choose features

| Features with defaults disabled | Available operations | Allocator |
| --- | --- | --- |
| None | Byte decomposition, payload validation, algorithms, resource policy, portable error categories | None |
| `p256-encoding` on core | Bare core with P-256 encoding conversions | None |
| `alloc` | Allocating DTOs, extension traits, provider bindings and qualification; no enabled artifact forms | Required |
| `yaml` | Complete YAML signing, verification, and transcription | Required |
| `protobuf` | Complete protobuf signing, verification, and transcription | Required |
| `yaml,protobuf` | Both forms and signing-crate transcoding | Required |

Defaults enable `std`, `yaml`, and `protobuf` on implementation crates;
signing also enables `system-rng`. Traits defaults enable `std`, which
includes `alloc`. Format features imply `alloc`, independently of `std`.
The `std` feature adds hosted conveniences without selecting a format.
`json-schema-validate` on core requires `std` and `yaml`.

A YAML-only consumer can declare:

```toml
[dependencies]
yaml-sigil-signing = { version = "0.7", default-features = false, features = ["yaml"] }
yaml-sigil-verification = { version = "0.7", default-features = false, features = ["yaml"] }
```

These declarations illustrate the feature selection in this development
branch. Its breaking traits contract needs the paired development checkout
until maintainers select and publish the next compatible crate versions.
For local validation, pass `--traits-path` to the xtask as shown below.

YAML-only normal dependencies omit Buffa, and the core build script omits
protobuf generation. Protobuf-only normal dependencies omit `noyalib` and
the YAML model/parser. Protobuf build tools run on the host and may use `std`;
they are independent of the target's runtime graph. Disabled forms are absent
from capabilities and fail with invocation errors before cryptographic work.

## Supply entropy

Ed25519 signing stays deterministic and requires no RNG. With `system-rng`
disabled, native `sign` advertises Ed25519. Use `sign_with_rng(&request, rng)`
with `rand_core::TryCryptoRng` for P-256, or use the existing provider APIs.
`signer_capabilities_with_rng()` describes the supplied-entropy operation;
provider signer adapters advertise both implemented algorithms.

P-256 samples an independent uniform nonzero nonce, retries invalid scalar
candidates and zero signature components, and aborts on entropy failure.
There is no RFC 6979 fallback. The caller or provider owns its entropy source.
Async callers also own their executor and remote-operation policies.

## Migrate primary operations

The Rust contract changes deliberately improve the primary APIs:

- Add `resource_limits` to `SignRequest`, `ComposeRequest`, and
  `DecomposeRequest`. Select `ArtifactResourceLimits::unbounded()` explicitly
  to keep the former behavior, or `default()` for the 4 MiB policy.
- Use `SignRequest::output_form` with `sign` instead of `sign_yaml` or
  `sign_proto` and their separate parameter types.
- Set `VerifierOptions::resource_limits` and `include_parser_observations` on
  `verify`. Read the state through `VerifyResult::state`.
- Pass `PreVerifyOptions` to `pre_verify` and `can_pre_verify`, and handle their
  `Result`. Defaults are unsigned refusal, no parser observations, and an
  unbounded whole-artifact policy.
- Use these same options on sync/async trait implementations and provider
  operations. Remove `_with_resource_limits`, `_and_resource_limits`, and
  separate metadata calls.
- Pass `&ArtifactResourceLimits` to primary core artifact codecs, outer
  envelope helpers, and signing-crate transcoding functions. Protobuf
  `SignedYamlArtifact` and `SignedYamlArtifactRef` decoding and encoding take
  the policy directly. Inner signature-carrier codecs retain their format
  safeguards independently of the complete-artifact policy.
- Match one typed error result. `SignError`, `ComposeError`, `DecomposeError`,
  `VerifyError`, `TranscodeError`, `ArtifactDecodeError`, and
  `ArtifactEncodeError` distinguish relevant stages. Resource errors retain
  content-free categories, forms, ceilings, and observed/projected lengths.

`ArtifactResourceLimits::default()` selects the explicit deployment policy;
operation options default to `unbounded()`. These limits do not change
conformance or the independent 16,384-octet YAML signature-carrier constraint.
Input admission precedes parsing. Output admission precedes complete-output
allocation; YAML signing can reject either its preflight lower bound or the
final exact serialized size.

## Borrow reads and own writes

`decompose` returns payload and carrier slices into the original artifact.
`pre_verify` retains `source_artifact` and borrowed payload bytes while owning
small metadata and parser observations. Subsequent verification checks the
original encoded length under its own policy, without reconstructing bytes.
Successful `VerifierState::Verified` payloads borrow only that artifact;
temporary request, pre-response, key, and option values may be dropped first.
Signing and composition return owned output vectors. Applications that need
owned verified payloads can explicitly call `to_vec()` at their boundary.

Existing JavaScript operations retain their names and owned result classes;
the hosted binding copies borrowed Rust reads into its existing JavaScript DTOs.

## Validate the matrix

Install the bare-metal target for the MSRV and the selected development
compiler, then run the isolated task:

```shell
rustup target add --toolchain 1.95.0 thumbv7em-none-eabi
rustup target add --toolchain 1.98.0 thumbv7em-none-eabi
cargo xtask --traits-path ../yaml-sigil-traits no-std
cargo xtask --traits-path ../yaml-sigil-traits ci
```

`--traits-path` temporarily patches the traits dependency for nested Cargo
checks, downstream fixtures, and dependency tools, then restores the original
Cargo configuration. Publication manifests retain their registry requirements.
An ordinary feature branch leaves versions and changelogs for release
preparation; activating a breaking coordination line owns its prerelease
safety version separately.

`tests/no-std` is a separate workspace, so hosted workspace dependencies cannot
unify `std` into its graph. The task checks five feature profiles on
`thumbv7em-none-eabi`, runs host tests against those same profiles, inspects
normal dependency features, and links an allocator-free binary. An alloc-enabled
negative control must fail without a global allocator. Compilation output is
temporary and removed when the task returns.
