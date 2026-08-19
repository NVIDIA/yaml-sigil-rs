# yaml-sigil-transcription

`yaml-sigil-transcription` combines document and signature components into
[`yaml-sigil`](https://github.com/NVIDIA/yaml-sigil-spec#tldr) documents and
separates existing documents back into those components. It supports YAML and
protobuf forms.

In the API, the document bytes are the `payload` and the encoded signature
component is the `signature_carrier`. Compose joins them into an artifact,
while decompose returns their byte ranges. These operations change document
structure only. They do not verify a signature or authenticate the payload. Use
[`yaml-sigil-verification`](https://crates.io/crates/yaml-sigil-verification)
for signature verification.

## API Surface

- `compose` and `decompose` perform the byte operations.
- `DefaultTranscriber` and `DefaultAsyncTranscriber` delegate to the free
  functions.
- `Transcriber`, `AsyncTranscriber`, request types, response types, and
  capability types are re-exported from
  [`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits).

This crate does not provide RPC transport. Consumers that need a service
boundary should wire the trait API into their own deployment.
