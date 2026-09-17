# YAML facade

Use `yaml-sigil-core` to read and write YAML signature documents without
importing a YAML library. `parse_signature_document` returns the public
`SignatureDocument` data model, and `serialize_signature_document` writes
canonical YAML from that model.

## Run the example

Run this command from the repository root.

```shell
cargo run --package yaml-sigil-examples --example yaml-facade
```

The [example source](../examples/yaml_facade.rs) parses a built-in signature
carrier, serializes it, and parses the output again. It prints the emitted
YAML and checks that the document fields survive the round trip. The sample
`keyid` contains punctuation and quotes to show how the serializer handles
string values.

This is the signature document alone. A complete signed YAML artifact also
contains a payload and document framing. The sample signature encodes the
illustrative bytes `[1, 2, 3]`. The example neither signs nor verifies a
payload. See the [cryptographic provider examples](../examples/README.md#local-cryptographic-providers)
for complete signing and verification flows.

## Public data model

`SignatureDocument` exposes these fields and their Serde representation.

| Field | Representation |
|-------|----------------|
| `schema` | Required string identifying the signature-document schema. |
| `alg` | Required string naming the signature algorithm. |
| `keyid` | Optional string. A missing field becomes `None`; serialization omits `None`. |
| `signature` | Required string carrying the encoded signature. |

Unknown fields are rejected. Serde is a public integration boundary, so an
application can use its own serializer with this model. The concrete YAML
backend remains private to the core crate. Its current Noyalib dependency can
appear transitively in your dependency graph without requiring you to import
Noyalib or select its version directly.

## Parsing and serialization boundaries

Use `parse_signature_document` for untrusted signature carriers. It applies
the 16,384-byte carrier limit and parser resource budgets, rejects duplicate
and unknown fields, anchors, aliases, and custom tags, and requires one YAML
document. Direct Serde deserialization does not apply those parser policies.
The carrier limit is separate from the size of a complete artifact.

Parsing produces unauthenticated field values. The serializer checks the
schema identifier, canonical algorithm spelling, and base64url encoding
before emitting YAML. Neither operation establishes that a signature is
valid for a payload or trusted key.

Compare semantic values after a round trip. Canonical emission can change
quoting and removes input presentation such as comments. Keep the original
carrier bytes when forwarding must preserve those bytes. Treat
`CoreError::SignatureYaml` text as diagnostic output rather than a stable
format to parse.

## Tests

The example tests cover a quoted `keyid` and an absent `keyid`. The
[core-only consumer fixture](../tests/downstream/core-only/Cargo.toml) also
parses and serializes documents while depending directly on only
`yaml-sigil-core`. It checks that using the facade does not require a direct
YAML-backend dependency. The
[downstream Serde fixture](../tests/downstream/noyalib-0-0-35/Cargo.toml) checks
values in both directions between `noyalib` `0.0.35` and the current private
backend.

```shell
cargo test --package yaml-sigil-examples --example yaml-facade
cargo test --manifest-path tests/downstream/Cargo.toml \
  --package yaml-sigil-core-downstream-core-only
```
