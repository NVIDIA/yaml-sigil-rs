// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Shared Cargo feature selection for checks and coverage.

use std::ffi::OsString;

use clap::Args;

#[derive(Args, Clone, Debug, Default)]
pub(crate) struct FeatureArgs {
    /// Enable all workspace features (the default without feature options).
    #[arg(long, conflicts_with_all = ["features", "no_default_features"])]
    all_features: bool,
    /// Enable the listed Cargo features, optionally without default features.
    #[arg(long, value_delimiter = ',', value_name = "FEATURE,...", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    features: Vec<String>,
    /// Disable default features.
    #[arg(long)]
    no_default_features: bool,
}

impl FeatureArgs {
    pub(crate) fn cargo_args(&self) -> Vec<OsString> {
        if self.all_features || (self.features.is_empty() && !self.no_default_features) {
            return vec!["--all-features".into()];
        }
        let mut args = Vec::new();
        if !self.features.is_empty() {
            args.extend(["--features".into(), self.features.join(",").into()]);
        }
        if self.no_default_features {
            args.push("--no-default-features".into());
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Parser)]
    struct Fixture {
        #[command(flatten)]
        features: FeatureArgs,
    }

    #[test]
    fn feature_defaults_and_explicit_combinations_match_cargo() {
        Fixture::command().debug_assert();
        for (input, expected) in [
            (vec![], vec!["--all-features"]),
            (vec!["--all-features"], vec!["--all-features"]),
            (vec!["--no-default-features"], vec!["--no-default-features"]),
            (vec!["--features", "one,two"], vec!["--features", "one,two"]),
            (
                vec![
                    "--features",
                    "one",
                    "--features",
                    "two",
                    "--no-default-features",
                ],
                vec!["--features", "one,two", "--no-default-features"],
            ),
        ] {
            let parsed = Fixture::try_parse_from(std::iter::once("fixture").chain(input)).unwrap();
            assert_eq!(
                parsed.features.cargo_args(),
                expected.iter().map(OsString::from).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn contradictory_and_empty_feature_options_are_rejected() {
        for input in [
            vec!["--all-features", "--features", "one"],
            vec!["--all-features", "--no-default-features"],
            vec!["--features="],
            vec!["--features=one,,two"],
        ] {
            assert!(Fixture::try_parse_from(std::iter::once("fixture").chain(input)).is_err());
        }
    }
}
