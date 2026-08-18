---
name: yaml-sigil-rs-spec-update
description: Use when reviewing YamlSigil specification changes for yaml-sigil-rs, importing affected local proto/schema/conformance/notice artifacts, or reconciling this Rust implementation after spec changes.
---

# yaml-sigil-rs Spec Update

## Purpose

`yaml-sigil-rs` owns the Rust implementation crates for YamlSigil. It depends on
the separately published `yaml-sigil-traits` crate for the public trait and DTO
contract, and it owns only the local implementation inputs and distribution
notices needed by this workspace:

- `crates/yaml-sigil-core/spec/proto/yaml_sigil/v1alpha1/yaml_sigil.proto`
- `crates/yaml-sigil-core/spec/schema/YamlSigilSignature.v1alpha1.schema.json`
- `crates/yaml-sigil-conformance/fixtures/`
- `THIRD_PARTY_NOTICES.md`
- `crates/yaml-sigil-conformance/THIRD_PARTY_NOTICES.md`
- `crates/yaml-sigil-core/THIRD_PARTY_NOTICES.md` for the copied JSON Schema
  and related conformance material packaged by core.
- `crates/yaml-sigil-verification/THIRD_PARTY_NOTICES.md` for the locally
  maintained, crate-scoped notice that must remain aligned with imported
  source terms.

Run commands from the repository root. Paths in this skill are relative to that
root.

There is no `source-spec` submodule in this repository. Use this skill when
reviewing a `yaml-sigil-spec` update for impact on this workspace.

## Invariants

- Use the public GitHub URL for spec repository operations:
  `https://github.com/NVIDIA/yaml-sigil-spec.git`.
- Do not add `yaml-sigil-spec` back as a submodule.
- Import only local artifacts this implementation uses: `yaml_sigil.proto`, the
  signature-document JSON Schema, curated conformance fixtures, and the
  third-party notices that accompany those fixtures.
- Do not import service protos, Buf module files, rebuild generators, or vendor
  data unless the implementation starts using them directly.
- Do not edit, generate, or publish `yaml-sigil-traits` from this repository.
- If a spec delta requires trait or DTO contract changes, update
  `yaml-sigil-traits` first, then update this repository's dependency.
- Keep updates scoped to this workspace's crates, tests, docs, CI, and xtask
  helpers.
- Leaving implementation code unchanged is a valid outcome when the spec delta
  only advances source text or does not require Rust implementation changes.
- Do not add gRPC servers, clients, gateways, transport adapters, or generated
  service stubs for signing, verification, or transcription service IDL.

## Workflow

1. Start from a clean worktree:

   ```shell
   git status --short
   ```

2. Refresh this repository's imported local artifacts from the target spec ref.
   The command defaults to `origin/main` and uses the public spec repository
   URL:

   ```shell
   cargo xtask update-spec
   cargo xtask update-spec --ref origin/dev/example-branch
   ```

   This imports only `yaml_sigil.proto`, the signature-document JSON Schema,
   the curated conformance fixture directories, and their third-party notices.
   It does not import service protos, Buf module files, rebuild generators, or
   vendor data.
   It also does not overwrite crate-local notices. Reconcile
   `crates/yaml-sigil-verification/THIRD_PARTY_NOTICES.md` with the imported
   canonical notice whenever the applicable RFC material or terms change.
   Apply the same review to `crates/yaml-sigil-core/THIRD_PARTY_NOTICES.md`
   when the imported JSON Schema or related conformance material changes.

3. Review the spec delta that can affect this implementation. Treat this as a
   starting point, not a closed list. If you need a diff, use the managed
   checkout under `target/spec-update/yaml-sigil-spec` or a separate temporary
   checkout.

   First inspect the full repository diff stat so unlisted spec files are not
   missed:

   ```shell
   git -C target/spec-update/yaml-sigil-spec diff --stat <old-spec-ref>..<new-spec-ref>
   ```

   Then inspect the known implementation-relevant paths:

   ```shell
   git -C target/spec-update/yaml-sigil-spec diff --stat <old-spec-ref>..<new-spec-ref> -- \
     README.md \
     signing-api.md \
     verification-api.md \
     transcription-api.md \
     transcoding.md \
     base64-requirements.md \
     algorithms/ \
     proto/yaml_sigil/v1alpha1/yaml_sigil.proto \
     schema/YamlSigilSignature.v1alpha1.schema.json \
     conformance/
   ```

   Review any unlisted changed files that could affect imported artifacts,
   implementation behavior, conformance expectations, docs, CI, or xtask
   helpers. Update this path list when spec files move, new spec files take
   ownership of implementation behavior this workspace imports, or a spec update
   reveals a cleaner review path.

4. Check the imported artifact diff deliberately:

   ```shell
   git diff -- \
     crates/yaml-sigil-core/spec/ \
     crates/yaml-sigil-conformance/fixtures/ \
     THIRD_PARTY_NOTICES.md \
     crates/yaml-sigil-conformance/THIRD_PARTY_NOTICES.md \
     crates/yaml-sigil-core/THIRD_PARTY_NOTICES.md \
     crates/yaml-sigil-verification/THIRD_PARTY_NOTICES.md
   ```

   Revert an imported artifact only when the spec change is known to be
   irrelevant to this implementation and the omission is recorded in the commit
   or MR description.

5. Map spec changes to the workspace surface. Treat this as a starting point,
   not a closed list:

   - `crates/yaml-sigil-core/src/algorithm.rs`: canonical YAML `alg` strings,
     protobuf enum mapping, algorithm additions, and algorithm deprecations.
   - `crates/yaml-sigil-core/src/signature_doc.rs` and
     `crates/yaml-sigil-core/src/tier_a_schema.rs`: YAML signature document
     parsing, schema validation, and metadata extraction.
   - `crates/yaml-sigil-core/src/proto_outer.rs` and `src/wire.rs`: protobuf
     envelope structure, strictness, and wire encode/decode behavior.
   - `crates/yaml-sigil-signing/`: signing flow, output form behavior,
     canonical envelope generation, key and payload preconditions.
   - `crates/yaml-sigil-transcription/`: YAML/protobuf compose, decompose, and
     signed-artifact transcoding behavior.
   - `crates/yaml-sigil-verification/`: verifier state model, pre-verify paths,
     algorithm checks, key resolution, parser observations, and capability
     advertisement.
   - `crates/yaml-sigil-conformance/` and `docs/conformance-validation.md`:
     fixture coverage, divergence catalog, and API gaps discovered by
     conformance changes.
   - Root, conformance, and crate-local `THIRD_PARTY_NOTICES.md` files:
     imported attribution, independently packaged material, source terms,
     warranty disclaimers, patent/IP caveats, and non-endorsement language.
   - `Cargo.toml` and `Cargo.lock`: update `yaml-sigil-traits` when the public
     trait contract changes.
   - This skill: keep the map current when code moves, new crates take
     ownership of spec behavior, or a spec update reveals a cleaner review path.

   If none of the reviewed spec changes affect these surfaces, record that
   conclusion in the commit or MR description and leave implementation code
   unchanged.

6. Run the quality loop appropriate to the change:

   ```shell
   cargo xtask ci
   ```

   During fixture iteration, use
   `cargo test -p yaml-sigil-conformance --all-features` as a faster focused
   check. The final validation remains `cargo xtask ci`.

7. Coordinate release order after review:

   Publish only the four implementation libraries as crates.io `.crate` source
   packages. Keep conformance, test-key, and xtask packages unpublished. Update
   `yaml-sigil-traits` first when the public contract changes, then update this
   workspace's `yaml-sigil-traits` dependency.
