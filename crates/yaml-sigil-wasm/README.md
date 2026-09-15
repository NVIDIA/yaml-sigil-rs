# yaml-sigil-wasm

> [!IMPORTANT]
> WebAssembly support is currently experimental.

`yaml-sigil-wasm` exposes YAML Sigil compose, decompose, sign, and verify
operations to browser and Node.js JavaScript through
`wasm32-unknown-unknown`. It delegates protocol processing to the Rust
implementation crates in this workspace.

This crate is an unpublished, source-only workspace boundary. The repository
does not publish an npm package, prebuilt WebAssembly, or another executable
artifact. Run `cargo xtask wasm` for local validation. The task puts generated
WebAssembly and JavaScript in a temporary directory and removes that directory
before returning.

## JavaScript API

The generated bindings expose these positional functions:

| Function | Inputs | Result class |
|---------|--------|--------------|
| `compose` | Payload bytes, signature-carrier bytes, and form. | `ComposeResult`. |
| `decompose` | Artifact bytes, form, and optional outer conformance. | `DecomposeResult`. |
| `sign` | Payload bytes, algorithm, private key bytes, optional `keyid`, newline permission, and output form. | `SignResult`. |
| `verify` | Artifact bytes, form, algorithm, and public key bytes. | `VerifyResult`. |

Every byte input and output uses `Uint8Array`. Expected invocation, artifact,
and cryptographic failures return a typed result and do not throw a JavaScript
exception. Each result has a string `status` property and an optional stable
snake-case `code` property. Each byte getter returns a fresh JavaScript-owned
copy.

Use the corresponding presence property before reading an optional byte
getter. `ComposeResult` and `SignResult` provide `hasArtifact`.
`DecomposeResult` provides `hasPayload` and `hasSignatureCarrier`.
`SignResult` provides `hasModifiedPayload`, and `VerifyResult` provides
`hasPayload` and `hasAlgorithm`. An absent byte value reads as an empty
`Uint8Array`.

## Explicit resource limits

The four functions above remain unbounded with respect to complete artifact
size. Their `composeWithResourceLimits`, `decomposeWithResourceLimits`,
`signWithResourceLimits`, and `verifyWithResourceLimits` counterparts take
the same arguments followed by a required `ArtifactResourceLimits` object.
They delegate to the `0.6.0` track's resource-aware Rust APIs and retain the
same result classes.

Create a policy explicitly when processing external input.

```javascript
const limits = new ArtifactResourceLimits();
const result = verifyWithResourceLimits(
  artifact, "yaml", algorithm, publicKey, limits,
);
if (result.status === "verified") {
  consumeAuthenticatedPayload(result.payload);
}
```

| Policy operation | Behavior |
|------------------|----------|
| `new ArtifactResourceLimits()` | Selects the core default of 4,194,304 bytes (4 MiB). |
| `policy.withMaxArtifactBytes(number)` | Returns a new policy with the specified positive integer ceiling. |
| `policy.withoutMaxArtifactByteLimit()` | Returns a new policy with only the complete-artifact ceiling disabled. |
| `ArtifactResourceLimits.unbounded()` | Disables every optional resource dimension known to this version. |
| `policy.maxArtifactBytes` | Reports the ceiling, or `undefined` when disabled. |

Policy builders leave the original policy unchanged. `withMaxArtifactBytes`
requires a JavaScript number from `1` through `4294967295`, inclusive, matching
the WebAssembly 32-bit size range. Non-number, fractional, non-finite, zero,
negative, and out-of-range values throw a configuration `RangeError` before
integer conversion. This configuration exception is separate from operation
results.

Bounded decompose and verify compare the JavaScript input length with the
ceiling before copying artifact bytes, interpreting selectors, validating a
schema, or resolving keys. Bounded compose and sign validate invocation shape
and check component-length output lower bounds before copying large byte
inputs. The Rust operations then account for envelope overhead, YAML newline
repair, and final serialized output. A lower-bound admission alone never
establishes that the output fits. Fixed key lengths are checked before key
bytes are copied.

| Result status | Stable codes |
|---------------|--------------|
| `resource_error` | `input_artifact_too_large`, `output_artifact_too_large`, `size_computation_overflow`, or `other` for a future resource category. |
| `encode_error` | `message_too_large` for the protobuf format ceiling, or `other`. |

These failures return no output bytes. Resource rejection remains separate
from invocation errors, malformed artifacts, and signature mismatch.

The ceiling is optional operational policy. YamlSigil `v1alpha1` defines no
maximum complete artifact size; its 16,384-octet YAML signature-carrier
constraint remains separate. Selecting `unbounded()` disables optional limits
without disabling parser safeguards or protobuf format limits.

The policy does not cap total JavaScript or WebAssembly memory. The caller
already owns the input arrays, string arguments cross the generated binding
before operation admission, and each output getter creates another copy.
Apply appropriate limits when reading external data, and manage result and
input lifetimes. The existing functions require caller-owned whole-artifact
admission when a deployment needs it.

## Rust implementation boundary

The bindings use this workspace's synchronous RustCrypto signing and
verification paths. They do not expose browser crypto-provider adapters or
claim provider qualification. Protobuf processing stays behind the core
facade, with Buffa types and errors private. Signature documents retain the
Serde data-model boundary and the policy-configured YAML parser.

## Selectors and keys

Form selectors are exactly `yaml` and `protobuf`. YAML decompose calls must
omit outer conformance. Protobuf decompose calls must provide exactly `strict`
or `signature_strict`. Selectors are case-sensitive and are not trimmed or
auto-detected.

Algorithm selectors are the canonical `v1alpha1` strings:

- `ED25519_PUREEDDSA_RAW_RS64_CANONICAL`.
- `ECDSA_SECP256R1_SHA256_RAW_RS64`.

Ed25519 signing keys are 32-byte seeds, and Ed25519 verification keys are
32-byte encoded public keys. P-256 signing keys are 32-byte big-endian secret
scalars. P-256 verification keys use the 65-byte uncompressed `0x04 || X || Y`
point encoding from *Standards for Efficient Cryptography 1 (SEC 1)*.
Compressed point encodings are rejected. Invalid key lengths, scalars,
encodings, and points return stable invocation codes without including key
material.

The boundary copies a supplied private key into temporary Rust storage that
uses best-effort zeroization. It cannot clear the caller's JavaScript
`Uint8Array`, copies retained by the JavaScript engine, or historical
WebAssembly linear-memory contents. Clear the caller-owned key array after use.
Browser JIT execution and WebAssembly do not provide the same side-channel
guarantees as a hardened native cryptographic environment.

## Schema feature

The optional `json-schema-validate` feature validates signature documents
against the schema embedded at compile time. Validation does not read the
schema from a browser filesystem or fetch it over a network. The
`browser-tests` feature only selects browser mode for the shared local test
suite.

## Local validation

The validation task requires Rust 1.95.0, Node.js 20 or newer, Firefox, and
`wasm-pack` 0.15.0:

```shell
rustup target add --toolchain 1.95.0 wasm32-unknown-unknown
cargo install --locked wasm-pack --version 0.15.0
cargo xtask wasm
```

The task checks the runtime crates and the boundary for
`wasm32-unknown-unknown`, runs the schema-enabled suite under Node.js and
headless Firefox, and exercises the generated Node.js bindings. It rejects any
`.wasm` file retained in the workspace and reports temporary-directory cleanup
failures. Tests cover exact and exceeded limits, policy configuration, output
overhead, admission precedence, unchanged unbounded behavior above 4 MiB, and
typed failure results.
