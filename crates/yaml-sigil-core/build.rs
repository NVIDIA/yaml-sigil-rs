// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_root = manifest_dir.join("spec/proto");
    let proto_relative = PathBuf::from("yaml_sigil/v1alpha1/yaml_sigil.proto");
    let proto_file = proto_root.join(&proto_relative);
    let buf_config = manifest_dir.join("buf.yaml");

    if !proto_file.is_file() {
        panic!(
            "yaml-sigil-core: protobuf IDL not found at {}",
            proto_file.display()
        );
    }
    if !buf_config.is_file() {
        panic!(
            "yaml-sigil-core: Buf configuration not found at {}",
            buf_config.display()
        );
    }

    println!("cargo::rerun-if-changed={}", proto_file.display());
    println!("cargo::rerun-if-changed={}", buf_config.display());

    let descriptor_path =
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("yaml_sigil_descriptor.binpb");
    let status = Command::new(buf_tools::buf_bin_path())
        .current_dir(&manifest_dir)
        .args(["build", "--as-file-descriptor-set", "-o"])
        .arg(&descriptor_path)
        .status()
        .expect("yaml-sigil-core: failed to run Buf");
    assert!(status.success(), "yaml-sigil-core: Buf build failed");

    buffa_build::Config::new()
        .files(std::slice::from_ref(&proto_relative))
        .descriptor_set(descriptor_path)
        .include_file("yaml_sigil_include.rs")
        .compile()
        .expect("buffa codegen failed");
}
