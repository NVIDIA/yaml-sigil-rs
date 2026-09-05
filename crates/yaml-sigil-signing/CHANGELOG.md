# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0-rc.2](https://github.com/NVIDIA/yaml-sigil-rs/compare/yaml-sigil-signing-v0.5.0-rc.1...yaml-sigil-signing-v0.5.0-rc.2) - 2026-09-05

### Other

- consolidate repository history

## [0.5.0-rc.1](https://github.com/NVIDIA/yaml-sigil-rs/compare/yaml-sigil-signing-v0.4.0-rc.2...yaml-sigil-signing-v0.5.0-rc.1) - 2026-08-21

### Fixed

- *(transcoding)* parse markerless carriers
- *(signing)* preserve protobuf payload bytes

## [0.4.0-rc.2](https://github.com/NVIDIA/yaml-sigil-rs/compare/yaml-sigil-signing-v0.4.0-rc.1...yaml-sigil-signing-v0.4.0-rc.2) - 2026-08-20

### Other

- improve crate discovery and reader guidance

## [0.4.0-rc.1](https://github.com/NVIDIA/yaml-sigil-rs/releases/tag/yaml-sigil-signing-v0.4.0-rc.1) - 2026-08-18

### Fixed

- *(core)* prevent YAML field injection during serialization
- *(verification)* reject signature whitespace
- *(security)* prevent signature carrier marker injection

### Other

- *(release)* add Trusted Publishing workflow
- *(release)* prepare YamlSigil 0.4.0-rc.1 crates
- align crate package contents
- add hosted and local validation
- *(metadata)* add crates.io contact
- include compliance docs in crate packages
- normalize packaged license files
- add SPDX metadata to project files
- *(porting)* initial porting
