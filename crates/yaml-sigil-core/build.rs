// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_root = manifest_dir.join("spec/proto");
    let proto_file = proto_root.join("yaml_sigil/v1alpha1/yaml_sigil.proto");

    if !proto_file.is_file() {
        panic!(
            "yaml-sigil-core: protobuf IDL not found at {}",
            proto_file.display()
        );
    }

    println!("cargo::rerun-if-changed={}", proto_file.display());

    buffa_build::Config::new()
        .files(std::slice::from_ref(&proto_file))
        .includes(std::slice::from_ref(&proto_root))
        .include_file("yaml_sigil_include.rs")
        .compile()
        .expect("buffa codegen failed");
}
