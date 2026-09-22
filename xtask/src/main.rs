// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Process entry point for repository development tasks.

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match xtask::execute(xtask::Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}
