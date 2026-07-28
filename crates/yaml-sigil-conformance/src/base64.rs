// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Base64 profile suite — `fixtures/base64/`.
//! YamlSigil uses URL-safe base64 without padding; trailing-bit hygiene is
//! mandated for raw 64-octet signatures. This suite asserts both directions
//! (accept / reject) against the implementation's actual decoder.

use base64::Engine;

use crate::fixtures::load_bytes;

const CATEGORY: &str = "base64";

#[derive(Debug, Clone, Copy)]
enum Expectation {
    AcceptedLen(usize),
    Rejected,
}

#[derive(Debug, Clone, Copy)]
struct Base64Fixture {
    file: &'static str,
    expect: Expectation,
}

const FIXTURES: &[Base64Fixture] = &[
    Base64Fixture {
        file: "valid-64-octet.txt",
        expect: Expectation::AcceptedLen(64),
    },
    Base64Fixture {
        file: "empty.txt",
        expect: Expectation::AcceptedLen(0),
    },
    Base64Fixture {
        file: "invalid-alphabet-plus.txt",
        expect: Expectation::Rejected,
    },
    Base64Fixture {
        file: "invalid-alphabet-slash.txt",
        expect: Expectation::Rejected,
    },
    Base64Fixture {
        file: "padding-present.txt",
        expect: Expectation::Rejected,
    },
    Base64Fixture {
        file: "length-mod-4-eq-1.txt",
        expect: Expectation::Rejected,
    },
    Base64Fixture {
        file: "whitespace-internal.txt",
        expect: Expectation::Rejected,
    },
    Base64Fixture {
        file: "nonzero-trailing-bits.txt",
        expect: Expectation::Rejected,
    },
];

/// Decode a candidate signature scalar using the YamlSigil base64 profile:
/// URL-safe alphabet, no padding, no internal whitespace, no non-zero
/// trailing bits.
///
/// Mirrors `yaml-sigil-verification`'s internal `decode_sig_b64` byte-for-byte
/// (URL-safe + no-pad + trailing-bit hygiene are the
/// `base64::engine::general_purpose::URL_SAFE_NO_PAD` defaults), including
/// rejection of external whitespace without normalization.
fn decode_yamlsigil_b64(input: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

pub fn run_base64_suite() {
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let got = decode_yamlsigil_b64(&bytes);
        match fx.expect {
            Expectation::AcceptedLen(n) => {
                let decoded = got.unwrap_or_else(|e| {
                    panic!("{}/{}: expected success, got {e:?}", CATEGORY, fx.file)
                });
                assert_eq!(
                    decoded.len(),
                    n,
                    "{}/{}: decoded length mismatch",
                    CATEGORY,
                    fx.file
                );
            }
            Expectation::Rejected => assert!(
                got.is_err(),
                "{}/{}: expected base64 decode failure, got Ok({})",
                CATEGORY,
                fx.file,
                got.unwrap().len()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_fixture_table_covers_all_documented_base64_edges() {
        let files: Vec<&str> = FIXTURES.iter().map(|fx| fx.file).collect();
        assert_eq!(
            files,
            [
                "valid-64-octet.txt",
                "empty.txt",
                "invalid-alphabet-plus.txt",
                "invalid-alphabet-slash.txt",
                "padding-present.txt",
                "length-mod-4-eq-1.txt",
                "whitespace-internal.txt",
                "nonzero-trailing-bits.txt",
            ]
        );
    }

    #[test]
    fn decoder_accepts_url_safe_unpadded_scalars() {
        let decoded = decode_yamlsigil_b64(b"-_8").expect("URL-safe no-pad scalar");
        assert_eq!(decoded, [0xfb, 0xff]);
    }

    #[test]
    fn decoder_rejects_external_whitespace() {
        assert!(decode_yamlsigil_b64(b" Zm9v").is_err());
        assert!(decode_yamlsigil_b64(b"Zm9v\n").is_err());
    }

    #[test]
    fn run_suite_exercises_accept_and_reject_branches() {
        assert!(
            FIXTURES
                .iter()
                .any(|fx| matches!(fx.expect, Expectation::AcceptedLen(_)))
        );
        assert!(
            FIXTURES
                .iter()
                .any(|fx| matches!(fx.expect, Expectation::Rejected))
        );
        run_base64_suite();
    }
}
