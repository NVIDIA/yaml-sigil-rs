// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared key selection for CLI examples offering both supported algorithms.

use clap::ValueEnum;
use yaml_sigil_core::AlgorithmId;

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum KeyType {
    Ed25519,
    P256,
}

impl KeyType {
    pub(crate) fn algorithm(self) -> AlgorithmId {
        match self {
            Self::Ed25519 => AlgorithmId::Ed25519,
            Self::P256 => AlgorithmId::EcdsaP256Sha256,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::P256 => "ECDSA P-256 (SHA-256)",
        }
    }
}
