// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Exchange protobuf bytes through the public core facade and Prost.
//!
//! The facade section uses only yaml-sigil-core. The Prost section represents
//! an application using its own protobuf library and message types. Neither
//! section imports Buffa. The sample signature is illustrative, not verified.

use anyhow::{Context as _, Result, ensure};
use prost::Message as _;
use yaml_sigil_core::{
    AlgorithmId,
    pb::{SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature},
};

fn main() -> Result<()> {
    // Protobuf payloads are opaque bytes. This sample intentionally includes
    // a NUL and an invalid UTF-8 byte, so it cannot be treated as YAML text.
    round_trip(b"\x00\xffexample payload\n", Some("demo-key"))
}

fn round_trip(payload: &[u8], keyid: Option<&str>) -> Result<()> {
    println!("Protobuf envelope with illustrative signature data; no verification.");

    // Core facade only: construct and encode without a protobuf runtime trait.
    // [1, 2, 3] is sample encoding data, not a cryptographic signature.
    let mut signature = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
    signature.set_keyid(keyid.map(str::to_owned));
    let artifact = SignedYamlArtifact::new(payload.to_vec(), Some(signature));
    let wire = artifact.encode_to_vec()?;

    // Owned decoding copies the fields; borrowed decoding keeps byte and
    // string fields in wire. Keep that buffer alive while using the view.
    let owned = SignedYamlArtifact::decode(&wire)?;
    let borrowed = SignedYamlArtifactRef::decode(&wire)?;
    ensure!(owned == artifact, "owned facade round trip changed fields");
    ensure!(borrowed.payload() == payload, "borrowed payload changed");
    let borrowed_signature = borrowed.signature().context("missing borrowed signature")?;
    ensure!(
        borrowed_signature.algorithm() == Some(AlgorithmId::Ed25519)
            && borrowed_signature.keyid() == keyid
            && borrowed_signature.signature() == [1, 2, 3],
        "borrowed signature fields changed"
    );
    println!("Core encode -> owned and borrowed decode preserved the fields.");

    // Build the application's message independently. Matching field tags,
    // types, and presence let the two libraries exchange the same wire format.
    let application = AppArtifact {
        payload: payload.to_vec(),
        signature: Some(AppSignature {
            alg: AppAlgorithm::Ed25519 as i32,
            keyid: keyid.map(str::to_owned),
            signature: vec![1, 2, 3],
        }),
    };

    // Core -> Prost: decode the facade's bytes into application-owned types.
    let decoded_by_prost = AppArtifact::decode(wire.as_slice())?;
    ensure!(
        decoded_by_prost == application,
        "Core -> Prost changed fields"
    );
    println!("Core encode -> Prost decode preserved the fields.");

    // Prost -> Core: encode the independently constructed application message.
    // No generated Rust type or conversion adapter crosses the boundary.
    let application_wire = application.encode_to_vec();
    let decoded_by_core = SignedYamlArtifact::decode(&application_wire)?;
    ensure!(decoded_by_core == artifact, "Prost -> Core changed fields");
    println!("Prost encode -> Core decode preserved the fields.");
    Ok(())
}

// These example-owned declarations follow the field numbers, types, presence,
// and algorithm values in the local v1alpha1 schema at
// crates/yaml-sigil-core/spec/proto/yaml_sigil/v1alpha1/yaml_sigil.proto.
// Prost supports annotated hand-written types, so this example adds no codegen.
#[derive(Clone, PartialEq, prost::Message)]
struct AppArtifact {
    #[prost(bytes = "vec", tag = "1")]
    payload: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    signature: Option<AppSignature>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AppSignature {
    #[prost(enumeration = "AppAlgorithm", tag = "1")]
    alg: i32,
    #[prost(string, optional, tag = "2")]
    keyid: Option<String>,
    #[prost(bytes = "vec", tag = "3")]
    signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum AppAlgorithm {
    Unspecified = 0,
    Ed25519 = 1,
    EcdsaP256Sha256 = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchanges_binary_payload_and_present_keyid() -> Result<()> {
        round_trip(b"\x00\xffexample payload\n", Some("demo-key"))
    }

    #[test]
    fn exchanges_payload_and_absent_keyid() -> Result<()> {
        round_trip(b"message\n", None)
    }
}
