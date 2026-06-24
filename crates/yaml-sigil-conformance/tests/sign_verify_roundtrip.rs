// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign -> verify round-trip for YAML artifacts.

use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{SignYamlParams, SigningKey, sign_yaml};
use yaml_sigil_test_keys::{ed25519_signing_key, ed25519_verifying_key};
use yaml_sigil_verification::{PublicKeys, VerifierOptions, VerifierState, verify_yaml};

const PAYLOAD: &[u8] = b"sign-verify-roundtrip: ed25519\n";

fn keys() -> PublicKeys<'static> {
    let vk = Box::leak(Box::new(ed25519_verifying_key(0)));
    PublicKeys {
        ed25519: Some(vk),
        p256: None,
    }
}

#[test]
fn yaml_roundtrip() {
    let sk = ed25519_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let st = verify_yaml(&artifact, &keys(), VerifierOptions::default()).unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}
