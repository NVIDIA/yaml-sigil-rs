// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Test harness that drives local `fixtures/` through the workspace's public
//! trait surfaces (`Transcriber`, `Verifier`, `Signer`) and a small set of
//! `yaml-sigil-core` helpers.
//!
//! Audit trail: [`docs/conformance-validation.md`](../../docs/conformance-validation.md).
//! Every conformance-related change to this crate MUST update that document in
//! the same commit (see also [`AGENTS.md`](../../AGENTS.md) § *Conformance
//! testing*).

pub mod alg_ecdsa;
pub mod alg_ed25519;
pub mod base64;
pub mod decomposition;
pub mod fixtures;
pub mod key_id;
pub mod proto_outer;
pub mod schema_alignment;
pub mod yaml_signature;
