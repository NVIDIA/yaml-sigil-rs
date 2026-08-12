# yaml-sigil-conformance

`yaml-sigil-conformance` is a workspace-only test harness that drives local
YamlSigil conformance fixtures through the Rust implementation's public trait
surfaces and byte-level helpers.

## Conformance fixtures

The artifacts under `fixtures/` are curated imports from the
[YamlSigil specification conformance suite][upstream-conformance] at commit
`07d76b3624265af9632568abcb4bac5143af5a8e`. The upstream documentation is
authoritative for the fixture inventory, expected outcomes, provenance,
regeneration process, and deliberately incomplete coverage.

This repository imports the fixture artifacts that the Rust implementation
uses. It does not copy the upstream fixture README files, rebuild generators,
or vendor data. Rust-specific fixture mappings, validation results, and
divergences are recorded in
[`docs/conformance-validation.md`](../../docs/conformance-validation.md).

Exact-byte fixtures cannot carry inline attribution without changing the bytes
under test. Keep the local
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) with distributed copies of
the fixtures. It records the applicable attribution, source terms, warranty
disclaimers, intellectual-property caveats, and non-endorsement language.

## Updating fixtures

Run `cargo xtask update-spec` from the repository root to refresh the imported
artifacts and notices. When the imported specification revision changes,
update the pinned upstream link in this README and add a matching entry to
`docs/conformance-validation.md` in the same commit.

[upstream-conformance]: https://github.com/NVIDIA/yaml-sigil-spec/tree/07d76b3624265af9632568abcb4bac5143af5a8e/conformance
