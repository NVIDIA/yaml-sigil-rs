// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Native ring signing and verification with the shared YAML example flow.
//!
//! cli-common/ring.rs contains the native key generation and public adapter
//! implementations. cli-common/mod.rs selects qualified signing for both
//! algorithms, qualified P-256 verification, and unqualified Ed25519
//! verification because of ring's mixed-order acceptance difference.

#[path = "cli-common/mod.rs"]
mod cli_common;
#[path = "cli-common/ring.rs"]
mod ring_adapter;

use anyhow::Result;
use cli_common::{KeyType, ProviderExample};
use ring_adapter::{RingFactory, RingSigner};

// Connect the native adapters to the examples' shared CLI driver. This trait
// is example scaffolding; the shared native adapters are the library contracts.
impl ProviderExample for RingFactory {
    type Key = RingSigner;
    const NAME: &'static str = "ring";
    const COMMAND: &'static str = "ring-provider";

    fn generate_key(key_type: KeyType) -> Result<Self::Key> {
        RingSigner::generate(key_type.algorithm())
    }

    fn public_key(key: &Self::Key) -> &[u8] {
        key.public_key()
    }
}

fn main() -> Result<()> {
    cli_common::run_cli::<RingFactory>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_builds() {
        cli_common::tests::cli_builds::<RingFactory>();
    }

    #[test]
    fn default_p256_document() -> Result<()> {
        cli_common::tests::default_p256_document::<RingFactory>()
    }

    #[test]
    fn default_ed25519_document() -> Result<()> {
        cli_common::tests::default_ed25519_document::<RingFactory>()
    }

    #[test]
    fn yaml_file_for_both_key_types() -> Result<()> {
        cli_common::tests::yaml_file_for_both_key_types::<RingFactory>()
    }

    #[test]
    fn standard_input_for_both_key_types() -> Result<()> {
        cli_common::tests::standard_input_for_both_key_types::<RingFactory>()
    }
}
