// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Fixture-loading helpers used by all conformance suites.
//!
//! Fixture paths are resolved relative to this crate's vendored fixture tree.
//! Specification updates import new fixture artifacts explicitly instead of
//! depending on a live spec checkout.

use std::path::{Path, PathBuf};

/// Crate-relative root for local conformance fixtures, evaluated at compile time.
pub const FIXTURES_ROOT_LITERAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");

/// Returns the absolute path to the local conformance fixtures as a [`PathBuf`].
pub fn fixtures_root() -> PathBuf {
    PathBuf::from(FIXTURES_ROOT_LITERAL)
}

/// Resolve a fixture path of the form `("alg-ed25519", "rfc8032-vec1-empty-message.binpb")`.
pub fn fixture_path(category: &str, file: &str) -> PathBuf {
    fixtures_root().join(category).join(file)
}

/// Load a fixture file as raw bytes; panics with the path on failure (tests only).
pub fn load_bytes(category: &str, file: &str) -> Vec<u8> {
    let p = fixture_path(category, file);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

/// Load a fixture file as a UTF-8 string; panics on failure.
pub fn load_string(category: &str, file: &str) -> String {
    let p = fixture_path(category, file);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

/// Decode a hex string into bytes, ignoring ASCII whitespace.
///
/// Used to lift hex public keys / signatures out of `.expected.txt` sidecars.
/// Panics on invalid hex; this crate is workspace-only test code.
pub fn hex_decode(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(
        cleaned.len().is_multiple_of(2),
        "hex_decode: odd-length string {cleaned:?}"
    );
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("hex_decode: invalid nibble {:#x}", b),
    }
}

/// Extract the value following a `key:` prefix on any line of a multi-line
/// `.expected.txt` body and hex-decode it.
///
/// Comment lines (`#`-prefixed) are scanned for the prefix; the value is
/// everything after the colon, trimmed. Returns `None` if no match.
pub fn read_hex_field(body: &str, prefix: &str) -> Option<Vec<u8>> {
    for line in body.lines() {
        let trimmed = line.trim_start_matches('#').trim();
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let value = rest.trim_start_matches(':').trim();
            if !value.is_empty() {
                return Some(hex_decode(value));
            }
        }
    }
    None
}

/// Same as [`read_hex_field`] but panics with the prefix on miss (tests only).
pub fn require_hex_field(body: &str, prefix: &str) -> Vec<u8> {
    read_hex_field(body, prefix)
        .unwrap_or_else(|| panic!("no `{prefix}` field in expected.txt body"))
}

/// Yield every nonblank, non-comment line in a `.txt` fixture.
pub fn data_lines(body: &str) -> impl Iterator<Item = &str> {
    body.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Existence smoke check: panics if the path is missing. Useful at the top of
/// per-fixture asserts so test failures point at the offending file.
pub fn must_exist(category: &str, file: &str) -> PathBuf {
    let p = fixture_path(category, file);
    assert!(
        Path::new(&p).is_file(),
        "missing conformance fixture: {}",
        p.display()
    );
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_paths_resolve_under_vendored_root() {
        let root = fixtures_root();
        assert!(root.ends_with("fixtures"));
        let path = fixture_path("base64", "empty.txt");
        assert!(path.starts_with(&root));
        assert!(path.ends_with("base64/empty.txt"));
        assert_eq!(must_exist("base64", "empty.txt"), path);
    }

    #[test]
    fn load_helpers_read_bytes_and_text() {
        assert_eq!(load_bytes("base64", "empty.txt"), b"");
        let valid = load_string("base64", "valid-64-octet.txt");
        assert_eq!(valid.trim().len(), 86);
    }

    #[test]
    fn hex_decode_accepts_whitespace_and_case_variants() {
        assert_eq!(hex_decode("0a FF\n10"), vec![0x0a, 0xff, 0x10]);
    }

    #[test]
    #[should_panic(expected = "odd-length")]
    fn hex_decode_rejects_odd_length_after_whitespace_removal() {
        let _ = hex_decode("abc");
    }

    #[test]
    #[should_panic(expected = "invalid nibble")]
    fn hex_decode_rejects_non_hex_nibble() {
        let _ = hex_decode("0g");
    }

    #[test]
    fn hex_field_helpers_scan_comment_and_plain_lines() {
        let body = "\
# public_key: 0A0b
seed: ff
";
        assert_eq!(read_hex_field(body, "public_key"), Some(vec![0x0a, 0x0b]));
        assert_eq!(read_hex_field(body, "seed"), Some(vec![0xff]));
        assert_eq!(read_hex_field(body, "missing"), None);
        assert_eq!(require_hex_field(body, "seed"), vec![0xff]);
    }

    #[test]
    fn data_lines_filters_blank_and_comment_lines() {
        let lines: Vec<&str> = data_lines("\n# comment\n  alpha  \n\nbeta\n").collect();
        assert_eq!(lines, ["alpha", "beta"]);
    }

    #[test]
    #[should_panic(expected = "missing conformance fixture")]
    fn must_exist_reports_missing_fixture_path() {
        let _ = must_exist("base64", "does-not-exist.txt");
    }
}
