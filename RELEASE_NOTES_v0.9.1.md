# opForge v0.9.1 Release Notes

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
- 65816 support (phase-1 instruction set + phase-2 addressing hardening):
  - `.cpu 65816` plus aliases `.cpu 65c816` and `.cpu w65c816`
  - implemented 65816 instruction support:
    - control flow/control: `BRL`, `JML`, `JSL`, `RTL`, `REP`, `SEP`, `XCE`, `XBA`
    - stack/register control: `PHB`, `PLB`, `PHD`, `PLD`, `PHK`, `TCD`, `TDC`, `TCS`, `TSC`
    - memory/control: `PEA`, `PEI`, `PER`, `COP`, `WDM`
    - block move: `MVN`, `MVP`
  - implemented 65816 addressing-form support in MOS-family parsing:
    - stack-relative (`d,S`) and stack-relative indirect indexed (`(d,S),Y`)
    - bracketed indirect forms (`[...]`, `[...,Y]`) for implemented instructions
  - width-sensitive immediate sizing for supported 65816 immediate mnemonics via `REP`/`SEP`
    M/X state tracking (including CPU-switch state reset behavior)
  - explicit runtime-state assumptions via `.assume` for `E/M/X/DBR/PBR/DP`
- New 65816 examples and golden references:
  - `examples/65816_simple.asm`
  - `examples/65816_allmodes.asm`
  - `examples/65816_wide_image.asm`
  - `examples/65816_assume_state.asm`
  - matching `examples/reference/65816_*.hex` and `examples/reference/65816_*.lst`
- Phase-2 wide-address core behavior:
  - `.org`, region placement (`.region`/`.place`/`.pack`), and linker image spans support wide addresses
  - CLI accepts 4-8 hex digit addresses for `-b/--bin` ranges and `-g/--go`
  - HEX start-address emission supports both start-segment (16-bit) and start-linear (wide) records
  - overflow/underflow arithmetic paths in directives/linker/image now report explicit diagnostics

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
- PRG output keeps a 16-bit load address prefix and now reports a directive error
  when `loadaddr` exceeds 16 bits.

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

## Notes on 65816 scope

Current 65816 coverage includes phase-1 instruction support plus phase-2 24-bit addressing hardening:
- wide placement and output workflows are supported (`.org`, regions, wide image spans, wide BIN ranges, HEX ELA/start-linear records)
- long memory encodings are supported for `ORA`, `AND`, `EOR`, `ADC`, `STA`, `LDA`, `CMP`, and `SBC` (`$llhhhh` and `$llhhhh,X`)
- stack-relative forms (`d,S` and `(d,S),Y`) are supported for `ORA`, `AND`, `EOR`, `ADC`, `STA`, `LDA`, `CMP`, and `SBC`
- checked address arithmetic now guards directive/linker/image overflow paths; descending BIN ranges are rejected
- full banked CPU-state semantics are still planned
- width-sensitive immediate sizing via M/X state tracking is implemented for supported immediate mnemonics
