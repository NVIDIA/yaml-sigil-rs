// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protobuf outer-envelope suite — drives the fixtures in
//! `fixtures/protobuf-conformance/` through
//! `Transcriber::decompose` under the two `OuterConformance` modes our IDL
//! defines (`Strict` and `SignatureStrict`).
//!
//! The fixture README also lists a "Permissive outcome" column; see
//! [`docs/conformance-validation.md`](../../docs/conformance-validation.md) § 3a
//! for why we do not exercise it (no `OUTER_CONFORMANCE_PERMISSIVE` exists in
//! `transcription.proto`).

use ed25519_dalek::{SigningKey as EdSk, VerifyingKey as EdVk};
use yaml_sigil_transcription::{
    AsyncTranscriber, DecomposeOutcome, DecomposeRequest, DecomposeResponse, OuterConformance,
    Transcriber, TranscriptionForm,
};
use yaml_sigil_verification::{
    ArtifactForm, AsyncVerifier, PublicKeys, Verifier, VerifierOptions, VerifierState,
};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "protobuf-conformance";

#[derive(Debug, Clone, Copy)]
struct ProtoFixture {
    file: &'static str,
    strict: DecomposeOutcome,
    signature_strict: DecomposeOutcome,
}

const FIXTURES: &[ProtoFixture] = &[
    ProtoFixture {
        file: "valid-baseline.binpb",
        strict: DecomposeOutcome::Ok,
        signature_strict: DecomposeOutcome::Ok,
    },
    ProtoFixture {
        file: "duplicate-outer-payload.binpb",
        strict: DecomposeOutcome::MalformedAttemptedSigned,
        signature_strict: DecomposeOutcome::Ok,
    },
    ProtoFixture {
        file: "duplicate-outer-signature.binpb",
        strict: DecomposeOutcome::MalformedAttemptedSigned,
        signature_strict: DecomposeOutcome::MalformedAttemptedSigned,
    },
    ProtoFixture {
        file: "unknown-outer-field.binpb",
        strict: DecomposeOutcome::MalformedAttemptedSigned,
        signature_strict: DecomposeOutcome::Ok,
    },
    ProtoFixture {
        // Inner duplicate `alg`. The fixture's outcome columns pair
        // (`OuterConformance`, `ConformanceProfile`) (see the upstream
        // README's "Column meaning" sub-table, added in the spec
        // follow-up that resolved §5a). Our `Transcriber::decompose` walks
        // only the outer envelope — the duplicate scalar is invisible to
        // it and the carrier bytes are returned as-is under both outer
        // modes. The verifier's inner-decode path uses stock buffa,
        // which applies last-wins to duplicate scalars — verbatim Permissive
        // behavior. Our `verifier_capabilities()` advertises Permissive
        // unconditionally (see `docs/conformance-validation.md` §3g and
        // §5.r §5a "resolved upstream"); the spec's
        // fixture-profile-targeting rule means the Strict / SignatureStrict
        // columns for this fixture are out-of-profile for us, not
        // conformance failures.
        file: "inner-strict-duplicate-alg.binpb",
        strict: DecomposeOutcome::Ok,
        signature_strict: DecomposeOutcome::Ok,
    },
    ProtoFixture {
        // Decompose succeeds with empty carrier; the empty-signature rule
        // fires later at the verification stage (asserted in alg-* suites).
        file: "present-empty-outer-signature.binpb",
        strict: DecomposeOutcome::Ok,
        signature_strict: DecomposeOutcome::Ok,
    },
    ProtoFixture {
        // Single 0x72 payload byte with a placeholder all-zero 64-byte
        // signature. Per spec commit ce35681
        // (`SignedYamlArtifact.payload` is now arbitrary octets) Decompose
        // MUST succeed under both modes; the YAML-envelope payload rules
        // (UTF-8, no BOM, trailing line terminator) do not apply to the
        // protobuf form. The §5b regression guard against re-introducing
        // those checks lives in `binary_payload_no_yaml_fit_reaches_crypto`
        // below. See docs/conformance-validation.md §3f.
        file: "binary-payload-no-yaml-fit.binpb",
        strict: DecomposeOutcome::Ok,
        signature_strict: DecomposeOutcome::Ok,
    },
];

fn run_one<T: Transcriber>(t: &T, bytes: &[u8], mode: OuterConformance) -> DecomposeOutcome {
    let resp = t.decompose(&DecomposeRequest {
        artifact: bytes,
        form: TranscriptionForm::Protobuf,
        outer_conformance: Some(mode),
    });
    match resp {
        DecomposeResponse::Structural(s) => s.outcome,
        DecomposeResponse::Invocation(e) => {
            panic!("unexpected invocation error from protobuf decompose: {e:?}")
        }
    }
}

pub fn run_protobuf_outer_suite<T: Transcriber, V: Verifier>(t: &T, v: &V) {
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let got_strict = run_one(t, &bytes, OuterConformance::Strict);
        assert_eq!(
            got_strict, fx.strict,
            "{}/{}: Strict outcome mismatch",
            CATEGORY, fx.file
        );
        let got_sig = run_one(t, &bytes, OuterConformance::SignatureStrict);
        assert_eq!(
            got_sig, fx.signature_strict,
            "{}/{}: SignatureStrict outcome mismatch",
            CATEGORY, fx.file
        );
    }
    binary_payload_no_yaml_fit_reaches_crypto(v);
}

/// Verify-stage regression guard for the consumer-side resolution of §5b.
///
/// `binary-payload-no-yaml-fit.binpb` carries a single 0x72 payload byte and a
/// placeholder all-zero signature. After dropping the YAML-envelope payload
/// rules from the protobuf path (proto_verify::pre_verify_proto and
/// lib::verify_extracted_signature), Verify MUST reach the crypto stage
/// rather than rejecting on envelope rules — i.e. the outcome MUST NOT be
/// `MalformedAttemptedSigned`. The placeholder signature won't authenticate
/// against the placeholder key, so the expected outcome is
/// `SignedButFailedVerification`. If a future change re-introduces a YAML
/// envelope check on the protobuf path, this test flips back to
/// `MalformedAttemptedSigned` and fails loudly.
fn binary_payload_no_yaml_fit_reaches_crypto<V: Verifier>(v: &V) {
    let bytes = load_bytes(CATEGORY, "binary-payload-no-yaml-fit.binpb");
    let placeholder_vk: EdVk = EdSk::from_bytes(&[1u8; 32]).verifying_key();
    let keys = PublicKeys {
        ed25519: Some(&placeholder_vk),
        p256: None,
    };
    let state = v
        .verify(
            &bytes,
            ArtifactForm::Proto,
            &keys,
            VerifierOptions::default(),
        )
        .expect("binary-payload-no-yaml-fit verify should not return invocation error");
    assert_ne!(
        state,
        VerifierState::MalformedAttemptedSigned,
        "binary-payload-no-yaml-fit.binpb: expected to reach crypto stage \
         (SignedButFailedVerification), got MalformedAttemptedSigned — \
         likely a re-introduced YAML-envelope payload check on the protobuf \
         path. See docs/conformance-validation.md §3f / §5.r §5b."
    );
    assert_eq!(
        state,
        VerifierState::SignedButFailedVerification,
        "binary-payload-no-yaml-fit.binpb: expected SignedButFailedVerification, got {state:?}"
    );
}

async fn run_one_async<T: AsyncTranscriber>(
    t: &T,
    bytes: &[u8],
    mode: OuterConformance,
) -> DecomposeOutcome {
    let resp = t
        .decompose(&DecomposeRequest {
            artifact: bytes,
            form: TranscriptionForm::Protobuf,
            outer_conformance: Some(mode),
        })
        .await;
    match resp {
        DecomposeResponse::Structural(s) => s.outcome,
        DecomposeResponse::Invocation(e) => {
            panic!("unexpected invocation error from protobuf decompose (async): {e:?}")
        }
    }
}

/// Async sibling of [`run_protobuf_outer_suite`].
pub async fn run_protobuf_outer_suite_async<T: AsyncTranscriber, V: AsyncVerifier>(t: &T, v: &V) {
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let got_strict = run_one_async(t, &bytes, OuterConformance::Strict).await;
        assert_eq!(
            got_strict, fx.strict,
            "{}/{} (async): Strict outcome mismatch",
            CATEGORY, fx.file
        );
        let got_sig = run_one_async(t, &bytes, OuterConformance::SignatureStrict).await;
        assert_eq!(
            got_sig, fx.signature_strict,
            "{}/{} (async): SignatureStrict outcome mismatch",
            CATEGORY, fx.file
        );
    }
    binary_payload_no_yaml_fit_reaches_crypto_async(v).await;
}

async fn binary_payload_no_yaml_fit_reaches_crypto_async<V: AsyncVerifier>(v: &V) {
    let bytes = load_bytes(CATEGORY, "binary-payload-no-yaml-fit.binpb");
    let placeholder_vk: EdVk = EdSk::from_bytes(&[1u8; 32]).verifying_key();
    let keys = PublicKeys {
        ed25519: Some(&placeholder_vk),
        p256: None,
    };
    let state = v
        .verify(
            &bytes,
            ArtifactForm::Proto,
            &keys,
            VerifierOptions::default(),
        )
        .await
        .expect("binary-payload-no-yaml-fit verify (async) should not return invocation error");
    assert_ne!(
        state,
        VerifierState::MalformedAttemptedSigned,
        "binary-payload-no-yaml-fit.binpb (async): expected to reach crypto stage \
         (SignedButFailedVerification), got MalformedAttemptedSigned"
    );
    assert_eq!(
        state,
        VerifierState::SignedButFailedVerification,
        "binary-payload-no-yaml-fit.binpb (async): expected SignedButFailedVerification, got {state:?}"
    );
}
