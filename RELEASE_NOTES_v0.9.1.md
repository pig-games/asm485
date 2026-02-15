# opForge v0.9.1 Release Notes

## Scope

This document summarizes all changes since the last push to `origin/main`, including
the current local documentation updates in this working tree.

Delta summary: `119 files changed, 9559 insertions(+), 6431 deletions(-)`.

## Breaking Changes

- Removed legacy `.dsection`.
- `.dsection` now reports an actionable diagnostic directing migration to
  `.place`/`.pack` with `.output`.
- 65816 sequence/provenance inference chains were removed for bank/direct-page
  state (`PHK/PLB`, `LDA #imm ... PHA ... PLB`, `PEA ... PLB`, `PHB ... PLB`,
  and corresponding `... PLD` provenance patterns). Use explicit operand
  overrides and/or `.assume` updates near affected call sites.

## Added

- opThread hierarchy groundwork (in-progress, feature-gated development surface):
  - hierarchy package chunks for `FAMS`/`CPUS`/`DIAL`/`REGS`/`FORM`
  - deterministic metadata canonicalization and stable snapshot coverage
  - host/runtime bridge API for active CPU selection + hierarchy-aware pipeline resolution
  - explicit family rollout modes: MOS6502-family is authoritative package-runtime; Intel8080-family remains staged verification (native default)
  - bounded deterministic dialect rewrite engine (`src/opthread/rewrite.rs`)
  - parity smoke harness behind feature flag (`cargo test --features opthread-parity ...`)
  - draft `.optst` vector corpus under `examples/opthread/vectors/`
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
    - long-indirect jump alias: `JMP [$nnnn]` (same encoding as `JML [$nnnn]`)
    - stack/register control: `PHB`, `PLB`, `PHD`, `PLD`, `PHK`, `TCD`, `TDC`, `TCS`, `TSC`
    - memory/control: `PEA`, `PEI`, `PER`, `COP`, `WDM`
    - block move: `MVN`, `MVP`
  - implemented 65816 addressing-form support in MOS-family parsing:
    - stack-relative (`d,S`) and stack-relative indirect indexed (`(d,S),Y`)
    - bracketed indirect forms (`[...]`, `[...,Y]`) for implemented instructions
  - width-sensitive immediate sizing for supported 65816 immediate mnemonics via `REP`/`SEP`
    M/X state tracking (including CPU-switch state reset behavior)
  - explicit runtime-state assumptions via `.assume` for `E/M/X/DBR/PBR/DP`,
    including bank-aware absolute-vs-long and direct-page mode resolution
  - explicit per-operand mode overrides for ambiguous forms:
    `,d`, `,b`, `,k`, and `,l`
  - deterministic mode-selection precedence:
    explicit override > `.assume` state > automatic fallback
  - automatic `PBR` default inference for `JMP`/`JSR` from current assembly bank
    when `.assume pbr=...` is not explicitly set
  - `.assume dbr=auto` / `.assume pbr=auto` to clear explicit bank overrides
    and return to inferred-bank behavior
  - conservative state invalidation:
    `PLB` invalidates known `DBR`, and `PLD`/`TCD` invalidate known `DP`
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
- README cleanup: detailed 65816 implementation/status notes were moved to these
  release notes so README stays focused on stable overview and usage.

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
- bracketed long-indirect forms (`[...]`, `[...,Y]`) and long absolute operands are implemented for currently supported 65816 instructions
- checked address arithmetic now guards directive/linker/image overflow paths; descending BIN ranges are rejected
- explicit per-operand overrides are supported for ambiguous bank/page forms (`d`, `b`, `k`, `l` suffixes)
- deterministic mode-selection precedence is explicit override > `.assume` > automatic fallback
- `PLB` invalidates known `DBR`; `PLD` and `TCD` invalidate known `DP`
- listing/map formatting renders addresses consistently in 4/6/8-digit hex widths, based on effective address size
- full automatic banked CPU-state inference is not implemented (`.assume` plus explicit overrides remain the control surface)
- width-sensitive immediate sizing via M/X state tracking is implemented for supported immediate mnemonics
- PRG output `loadaddr` must still fit in 16 bits

Migration note: if source previously relied on stack-sequence inference (`PHK/PLB`,
`LDA #imm ... PHA ... PLB`, `PEA ... PLB`, `... PLD` patterns), add local explicit
overrides and/or nearby `.assume` updates at the call sites where mode selection matters.
