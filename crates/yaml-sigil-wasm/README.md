# yaml-sigil-wasm

`yaml-sigil-wasm` exposes YamlSigil v1alpha1 compose, decompose, sign, and
verify operations to browser and Node.js JavaScript through
`wasm32-unknown-unknown`. It delegates protocol processing to the Rust runtime
crates in this workspace.

This crate is a source-only, unpublished workspace boundary. The repository
does not provide an npm package, prebuilt WebAssembly, or another executable
artifact. Use `cargo xtask wasm` for local validation; the task places all
project build output in a temporary directory and removes it before returning.

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
snake-case `code` property. Output bytes remain owned by the Rust result. Each
byte getter returns a fresh JavaScript-owned copy.

Use the corresponding presence property before reading an optional byte
getter. `ComposeResult` and `SignResult` provide `hasArtifact`.
`DecomposeResult` provides `hasPayload` and `hasSignatureCarrier`.
`SignResult` provides `hasModifiedPayload`, and `VerifyResult` provides
`hasPayload` and `hasAlgorithm`. An absent byte value reads as an empty
`Uint8Array`, so the presence property distinguishes absence from valid empty
bytes.

The result statuses are:

| Result class | Status values |
|-------------|---------------|
| `ComposeResult` | `success`, `invocation_error`, and `error`. |
| `DecomposeResult` | `ok`, `unsigned`, `malformed_attempted_signed`, and `invocation_error`. |
| `SignResult` | `success`, `invocation_error`, and `signer_error`. |
| `VerifyResult` | `verified`, `unsigned`, `malformed_attempted_signed`, `signed_but_algorithm_unsupported`, `signed_but_failed_verification`, and `invocation_error`. |

## Selectors and keys

Form selectors are exactly `yaml` and `protobuf`. YAML decompose calls must
omit outer conformance. Protobuf decompose calls must provide exactly `strict`
or `signature_strict`. Selectors are case-sensitive and are not trimmed or
auto-detected.

Algorithm selectors are the canonical v1alpha1 strings:

- `ED25519_PUREEDDSA_RAW_RS64_CANONICAL`.
- `ECDSA_SECP256R1_SHA256_RAW_RS64`.

Ed25519 signing keys are 32-byte seeds, and Ed25519 verification keys are
32-byte encoded public keys. P-256 signing keys are 32-byte big-endian secret
scalars. P-256 verification keys use compressed or uncompressed point
encoding from *Standards for Efficient Cryptography 1 (SEC 1)*. Invalid
lengths, scalars, encodings, and points return stable invocation codes without
including key material.

The boundary copies a supplied private key into temporary Rust storage that
uses best-effort zeroization. It cannot clear the caller's JavaScript
`Uint8Array`, copies retained by the JavaScript engine, or historical WebAssembly
linear-memory contents. Clear the caller-owned key array after use. Browser
JIT execution and WebAssembly do not provide the same side-channel guarantees
as a hardened native cryptographic environment.

## Schema feature

The optional `json-schema-validate` feature validates signature documents
against the schema embedded at compile time. Validation does not read the
schema from a browser filesystem or fetch it over a network. The
`browser-tests` feature only selects the browser mode for the shared local test
suite; downstream applications do not need it.

## Local validation

The validation task requires Rust 1.95.0, Node.js 20 or newer, Firefox, and
`wasm-pack` 0.15.0. Install the Rust target and pinned helper, then run the
task from the workspace root:

```shell
rustup target add --toolchain 1.95.0 wasm32-unknown-unknown
cargo install --locked wasm-pack --version 0.15.0
cargo xtask wasm
```

The task checks all four runtime crates and this boundary for
`wasm32-unknown-unknown`, runs the shared schema-enabled suite under Node.js
and headless Firefox, and creates temporary optimized `web` builds with and
without schema validation. It rejects any `.wasm` file retained in the
workspace.

On 2026-08-18, Rust 1.95.0 and `wasm-pack` 0.15.0 produced these optimized raw
WebAssembly sizes before temporary cleanup:

| Feature set | Raw bytes |
|------------|----------:|
| Default features. | 507,224. |
| `json-schema-validate`. | 3,366,788. |

These measurements describe one toolchain run. They are not a compatibility,
performance, or future size guarantee.
