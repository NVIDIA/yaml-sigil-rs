# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0-rc.2](https://github.com/NVIDIA/yaml-sigil-rs/compare/yaml-sigil-core-v0.4.0-rc.1...yaml-sigil-core-v0.4.0-rc.2) - 2026-08-20

### Other

- improve crate discovery and reader guidance

## [0.4.0-rc.1](https://github.com/NVIDIA/yaml-sigil-rs/releases/tag/yaml-sigil-core-v0.4.0-rc.1) - 2026-08-18

### Fixed

- *(core)* prevent YAML field injection during serialization
- *(conformance)* absorb security clarification
- *(core)* scan YAML markers in constant memory
- *(core)* validate protobuf lengths portably
- *(core)* reject invalid protobuf tags
- *(core)* absorb upstream signature parsing updates
- *(core)* remove unreachable marker outcome
- *(core)* enforce signature document EOF
- *(security)* prevent signature carrier marker injection

### Other

- *(release)* add Trusted Publishing workflow
- *(release)* prepare YamlSigil 0.4.0-rc.1 crates
- align crate package contents
- add hosted and local validation
- *(metadata)* add crates.io contact
- *(schema)* import profile clarification
- include compliance docs in crate packages
- normalize packaged license files
- add SPDX metadata to project files
- *(deps)* update noyalib to 0.0.13
- *(porting)* initial porting
