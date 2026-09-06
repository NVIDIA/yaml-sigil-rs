// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_relative = PathBuf::from("compat.proto");
    let proto_file = manifest_dir.join("proto").join(&proto_relative);
    let buf_config = manifest_dir.join("buf.yaml");

    println!("cargo::rerun-if-changed={}", proto_file.display());
    println!("cargo::rerun-if-changed={}", buf_config.display());

    let descriptor_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("compat.binpb");
    let status = Command::new(buf_tools::buf_bin_path())
        .current_dir(&manifest_dir)
        .args(["build", "--as-file-descriptor-set", "-o"])
        .arg(&descriptor_path)
        .status()
        .expect("run the pinned Buf CLI for the Buffa 0.5 fixture");
    assert!(status.success(), "Buffa 0.5 fixture Buf build failed");

    buffa_build::Config::new()
        .files(std::slice::from_ref(&proto_relative))
        .descriptor_set(descriptor_path)
        .include_file("compat_include.rs")
        .compile()
        .expect("Buffa 0.5 fixture code generation failed");
}
