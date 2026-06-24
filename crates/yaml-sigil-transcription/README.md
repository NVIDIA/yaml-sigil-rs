# yaml-sigil-transcription

`yaml-sigil-transcription` implements YamlSigil v1alpha1 compose and decompose
operations for YAML and protobuf artifact forms.

Use this crate when you need to assemble an artifact from payload bytes plus a
signature carrier, or split an existing artifact back into those byte ranges.
The crate provides free functions for in-process callers and default
`Transcriber` implementations for trait-based code.

## API Surface

- `compose` and `decompose` perform the byte operations.
- `DefaultTranscriber` and `DefaultAsyncTranscriber` delegate to the free
  functions.
- `Transcriber`, `AsyncTranscriber`, request types, response types, and
  capability types are re-exported from `yaml-sigil-traits`.

This crate does not provide RPC transport. Consumers that need a service
boundary should wire the trait API into their own deployment.
