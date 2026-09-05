// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bounded GitHub API transport for typed release operations.

use std::process::Command;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::bounded_process::{self, OutputLimits};

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const API_VERSION: &str = "2026-03-10";

pub(crate) trait Transport {
    fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, String>;
    fn get_optional<T: DeserializeOwned>(&mut self, path: &str) -> Result<Option<T>, String>;
    fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, payload: &P) -> Result<T, String> {
        let _ = payload;
        Err("unexpected GitHub GraphQL query".to_string())
    }
    fn post<T: DeserializeOwned, P: Serialize>(
        &mut self,
        path: &str,
        payload: &P,
    ) -> Result<T, String>;
}

pub(crate) struct GhCli;

impl GhCli {
    pub(crate) fn new() -> Result<Self, String> {
        if std::env::var_os("GH_TOKEN").is_none() {
            return Err("GH_TOKEN is required".to_string());
        }
        let output = bounded_process::output(
            Command::new("gh").arg("--version"),
            OutputLimits {
                stdout: MAX_ERROR_BYTES,
                stderr: MAX_ERROR_BYTES,
            },
        )
        .map_err(|error| format!("run gh: {error}"))?;
        if !output.status.success() {
            return Err("gh is unavailable".to_string());
        }
        Ok(Self)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        payload: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, String> {
        if !matches!(method, "GET" | "POST") || path.is_empty() || path.contains(['\0', '\r', '\n'])
        {
            return Err("invalid GitHub request".to_string());
        }
        let mut command = Command::new("gh");
        command.args([
            "api",
            "--method",
            method,
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            &format!("X-GitHub-Api-Version: {API_VERSION}"),
            path,
        ]);
        if payload.is_some() {
            command.args(["--input", "-"]);
        }
        let limits = OutputLimits {
            stdout: MAX_RESPONSE_BYTES,
            stderr: MAX_ERROR_BYTES,
        };
        let output = match payload {
            Some(body) => bounded_process::output_with_input(&mut command, body, limits),
            None => bounded_process::output(&mut command, limits),
        }
        .map_err(|error| format!("run gh api: {error}"))?;
        if output.status.success() {
            return Ok(Some(output.stdout));
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if method == "GET" && (detail.contains("HTTP 404") || detail.contains("Not Found")) {
            return Ok(None);
        }
        Err(format!(
            "GitHub {method} {path} failed: {}",
            detail.lines().last().unwrap_or("unknown error")
        ))
    }

    fn decode<T: DeserializeOwned>(method: &str, path: &str, body: &[u8]) -> Result<T, String> {
        serde_json::from_slice(body)
            .map_err(|error| format!("GitHub {method} {path} returned invalid JSON: {error}"))
    }
}

impl Transport for GhCli {
    fn get<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, String> {
        let body = self
            .request("GET", path, None)?
            .ok_or_else(|| format!("GitHub GET {path} returned not found"))?;
        Self::decode("GET", path, &body)
    }

    fn get_optional<T: DeserializeOwned>(&mut self, path: &str) -> Result<Option<T>, String> {
        self.request("GET", path, None)?
            .map(|body| Self::decode("GET", path, &body))
            .transpose()
    }

    fn graphql<T: DeserializeOwned, P: Serialize>(&mut self, payload: &P) -> Result<T, String> {
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("encode GitHub GraphQL query: {error}"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("GitHub GraphQL query exceeded its bound".to_string());
        }
        let response = self
            .request("POST", "graphql", Some(&body))?
            .ok_or_else(|| "GitHub GraphQL query returned not found".to_string())?;
        Self::decode("POST", "graphql", &response)
    }

    fn post<T: DeserializeOwned, P: Serialize>(
        &mut self,
        path: &str,
        payload: &P,
    ) -> Result<T, String> {
        let body = serde_json::to_vec(payload)
            .map_err(|error| format!("encode GitHub POST {path}: {error}"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("GitHub request exceeded its bound".to_string());
        }
        let response = self
            .request("POST", path, Some(&body))?
            .ok_or_else(|| format!("GitHub POST {path} returned not found"))?;
        Self::decode("POST", path, &response)
    }
}
