// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Exact package, tag, changelog, and toolchain release policy.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackagePolicy {
    pub(crate) package: &'static str,
    pub(crate) tag_prefix: &'static str,
    pub(crate) changelog: &'static str,
    pub(crate) path_in_vcs: &'static str,
    pub(crate) internal_dependencies: &'static [&'static str],
}

pub(crate) const RELEASE_PLZ_VERSION: &str = "0.3.160";

impl PackagePolicy {
    pub(crate) fn tag(&self, version: &str) -> String {
        format!("{}{version}", self.tag_prefix)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleasePolicy {
    pub(crate) packages: &'static [PackagePolicy],
}

const RUST_PACKAGES: &[PackagePolicy] = &[
    PackagePolicy {
        package: "yaml-sigil-core",
        tag_prefix: "yaml-sigil-core-v",
        changelog: "crates/yaml-sigil-core/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-core",
        internal_dependencies: &[],
    },
    PackagePolicy {
        package: "yaml-sigil-transcription",
        tag_prefix: "yaml-sigil-transcription-v",
        changelog: "crates/yaml-sigil-transcription/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-transcription",
        internal_dependencies: &["yaml-sigil-core"],
    },
    PackagePolicy {
        package: "yaml-sigil-signing",
        tag_prefix: "yaml-sigil-signing-v",
        changelog: "crates/yaml-sigil-signing/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-signing",
        internal_dependencies: &["yaml-sigil-core", "yaml-sigil-transcription"],
    },
    PackagePolicy {
        package: "yaml-sigil-verification",
        tag_prefix: "yaml-sigil-verification-v",
        changelog: "crates/yaml-sigil-verification/CHANGELOG.md",
        path_in_vcs: "crates/yaml-sigil-verification",
        internal_dependencies: &[
            "yaml-sigil-core",
            "yaml-sigil-signing",
            "yaml-sigil-transcription",
        ],
    },
];

pub(crate) const RUST_POLICY: ReleasePolicy = ReleasePolicy {
    packages: RUST_PACKAGES,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_policy_is_central_and_ordered() {
        assert_eq!(RUST_POLICY.packages.len(), 4);
        assert_eq!(
            RUST_POLICY.packages[0].tag("0.5.0"),
            "yaml-sigil-core-v0.5.0"
        );
        assert_eq!(RELEASE_PLZ_VERSION, "0.3.160");
    }
}
