# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0-rc.1](https://github.com/NVIDIA/yaml-sigil-rs/releases/tag/yaml-sigil-verification-v0.4.0-rc.1) - 2026-08-18

### Fixed

- *(verification)* classify malformed ECDSA components
- *(conformance)* absorb security clarification
- *(verification)* reject weak Ed25519 keys at use
- *(core)* reject invalid protobuf tags
- *(verification)* reject signature whitespace
- *(core)* absorb upstream signature parsing updates
- *(security)* prevent signature carrier marker injection

### Other

- *(release)* add Trusted Publishing workflow
- *(release)* prepare YamlSigil 0.4.0-rc.1 crates
- align crate package contents
- add hosted and local validation
- *(metadata)* add crates.io contact
- *(conformance)* adopt latest specification fixtures
- *(licensing)* absorb upstream attribution update
- *(licensing)* correct RFC and SEC material attribution
- *(verification)* clarify nested signature content
- *(verification)* state authorized key binding
- include compliance docs in crate packages
- normalize packaged license files
- add SPDX metadata to project files
- complete third-party attribution terms
- add third-party licensing notices
- *(porting)* initial porting
