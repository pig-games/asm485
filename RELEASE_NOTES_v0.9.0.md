# opForge v0.9.0 Release Notes

## Scope

This document summarizes all changes since the last push to `origin/main`, including
the current local documentation updates in this working tree.

Delta summary: `119 files changed, 9559 insertions(+), 6431 deletions(-)`.

## Breaking Changes

- Removed legacy `.dsection`.
- `.dsection` now reports an actionable diagnostic directing migration to
  `.place`/`.pack` with `.output`.

## Added

- Linker-region workflow directives and validation:
  - `.region`, `.place`, `.pack`
  - strict region-bound placement checks
  - deferred placement records with explicit pass-1 layout replay
- Output artifact directives and pass-1 collection:
  - `.output`, `.mapfile`, `.exportsections`
  - contiguous payload validation
  - image payload span/fill behavior
  - mapfile symbol filtering (`all|public|none`)
  - per-section export generation controls (including BSS handling)
- Data/section directive expansion:
  - `.emit`, `.res`, `.fill` (data form), `.long`
  - `.db` alias for `.byte`
  - `.dw` alias for `.word`
  - `.section` options `kind=`, `align=`, `region=`
  - macro/segment closing aliases `.endm` and `.ends`
- CPU coverage additions:
  - missing Z80 CB-prefixed instruction handling
  - missing 65C02 bit-branch instruction support
- New linker-region examples and generated reference outputs, including
  diagnostics fixtures for invalid placement and region scenarios.

## Changed

- Assembler internals were split/refactored for stricter layering:
  - `src/assembler/mod.rs` chunked into focused modules
  - new `src/assembler/bootstrap.rs`, `src/assembler/engine.rs`,
    and `src/assembler/asmline_directives.rs`
- Example programs were migrated to the linker-region workflow and regenerated.
- Listing output includes generated-output footer coverage for examples.
- Documentation tree was reorganized from `docs/` to `documentation/`, and
  a generated reference-manual PDF was added.
- Repository policy change: `AGENTS.md` was removed from tracked sources.

## Fixed

- Section size accounting and end-to-end map references in linker-region flow.
- Unknown-region and related diagnostics coverage.
- Assorted code-review findings (critical/high/medium/low) across assembler,
  parser, and CPU handlers.
- Reference manual correctness and consistency updates:
  - fixed broken quick-reference markdown fence
  - clarified Z80 indexed addressing support as CB-prefix-only
  - documented implemented directives and aliases that were previously missing
  - synchronized CLI details (`-h`, `-V`, repeatable `-b`, `--fill` default,
    `--pp-macro-depth` minimum, multi-input output requirement)
  - aligned architecture appendix details and trait snippets with implementation

## Migration

Replace legacy pattern:

```asm
.section code
  ; bytes
.endsection
.org $2000
.dsection code
```

With:

```asm
.region rom, $2000, $20ff
.section code
  ; bytes
.endsection
.place code in rom
.output "build/code.bin", format=bin, sections=code
```

Or grouped placement:

```asm
.pack in rom : code, data, vectors
```
