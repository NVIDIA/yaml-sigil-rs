// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Repository-specific source-package inventory policy.

use crate::package_content::PackageSpec;

pub(crate) const PACKAGE_SPECS: &[PackageSpec] = &[
    PackageSpec {
        name: "yaml-sigil-core",
        inventory_path: "xtask/package-contents/yaml-sigil-core.txt",
        inventory: include_str!("../package-contents/yaml-sigil-core.txt"),
    },
    PackageSpec {
        name: "yaml-sigil-transcription",
        inventory_path: "xtask/package-contents/yaml-sigil-transcription.txt",
        inventory: include_str!("../package-contents/yaml-sigil-transcription.txt"),
    },
    PackageSpec {
        name: "yaml-sigil-signing",
        inventory_path: "xtask/package-contents/yaml-sigil-signing.txt",
        inventory: include_str!("../package-contents/yaml-sigil-signing.txt"),
    },
    PackageSpec {
        name: "yaml-sigil-verification",
        inventory_path: "xtask/package-contents/yaml-sigil-verification.txt",
        inventory: include_str!("../package-contents/yaml-sigil-verification.txt"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_scope_and_order_are_explicit() {
        assert_eq!(
            PACKAGE_SPECS
                .iter()
                .map(|package| package.name)
                .collect::<Vec<_>>(),
            [
                "yaml-sigil-core",
                "yaml-sigil-transcription",
                "yaml-sigil-signing",
                "yaml-sigil-verification",
            ]
        );
    }
}
