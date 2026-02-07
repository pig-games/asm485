# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Breaking Changes
- Removed `.dsection`. The directive now emits:
  `.dsection has been removed; use .place/.pack with .output`.

### Added
- Linker-region workflow directives and integration:
  `.region`, `.place`, `.pack`, linker `.output`, `.mapfile`, `.exportsections`.
- Contiguous and image output payload generation for linker outputs.
- Mapfile and per-section export payload generation paths.
- Generated-output listing footer coverage in example/reference tests.

### Changed
- Section-based examples now use explicit placement (`.place`/`.pack`) instead
  of legacy `.org + .dsection` injection flow.
- Reference outputs were regenerated for linker-region examples.

### Docs
- Updated `README.md` with v3.1 linker workflow examples.
- Updated reference manual for placement/output rules and common diagnostics.
- Added phase 8 migration notes for `.dsection` removal.
