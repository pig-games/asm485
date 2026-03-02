# opForge Motorola 68000 Family Extension Spec (v0.1, starting with 68000)

## Goal
Add Motorola 68000-family support to opForge using the existing family/CPU/dialect architecture, with initial delivery focused on `68000`.

This specification defines architecture boundaries, implementation phases, tests, diagnostics, and acceptance criteria for first-class 68k assembly support.

## Scope
In scope:
- new 68000 family module (operand parser + family encoding table)
- new CPU module for canonical `m68000` / alias `68000`
- registry wiring, `.cpu` aliases, `cpusupport`/capabilities reporting
- assembler tests plus examples/reference fixtures for baseline 68000 behavior
- documentation updates for supported CPUs and syntax usage

Out of scope for v0.1:
- non-68000 Motorola lines (already separate family work)
- post-68000 CPUs (for example `68010`, `68EC020`, `68020`) beyond registration placeholders
- macro-language or directive redesign unrelated to CPU support
- broad third-party dialect compatibility layers in first pass

## Baseline Constraints (from current opForge architecture)
1. Shared semantics belong in a family module; CPU-only behavior belongs in CPU modules.
2. Dialects are mapping/rewrite layers and never emit bytes directly.
3. Two-pass assembly behavior is preserved.
4. Validation order remains: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, full tests.
5. Reference outputs update only for intentional behavior changes.

## Target Runtime Matrix (68000 family, initial subset)

| Family | Dialect(s) | CPU (canonical) | Aliases | Notes |
|---|---|---|---|---|
| `motorola68000` | `motorola68k` (initial pass-through) | `m68000` | `68000`, `mc68000` | baseline target for v0.1 |

Design choice:
- Start with one canonical syntax (`motorola68k`) and preserve room for compatibility dialects later.
- Keep CPU identity separate from family parser/encoder ownership.

## Architecture and Layering Plan

### Family ownership (`src/families/m68000/*`)
Family module owns:
- operand parsing for 68000 addressing forms
- instruction table entries common to all future 68000-family CPUs
- branch displacement/range validation shared at family level
- register token parsing (data/address registers, special registers)
- extension seams for future CPUs (`68010`, `68020`) without registry redesign

Proposed files:
- `src/families/m68000/mod.rs`
- `src/families/m68000/module.rs`
- `src/families/m68000/handler.rs`
- `src/families/m68000/operand.rs`
- `src/families/m68000/table.rs`
- `src/families/m68000/dialect.rs`
- `src/families/m68000/formatter.rs` (starter no-op formatter hook)

### CPU ownership (`src/m68000/*`)
`m68000` CPU module owns:
- CPU identity, aliases, and capability metadata
- 68000-only constraints (for example unsupported 68010+ instructions)
- CPU-specific validation if future family table contains wider 68k superset entries

Proposed files:
- `src/m68000/mod.rs`
- `src/m68000/module.rs`
- `src/m68000/instructions.rs` (only if CPU-specific table split is needed)

### Registry and assembler wiring
Update registration and visibility in:
- `src/families/mod.rs`
- `src/lib.rs`
- `src/assembler/mod.rs` (imports)
- `src/assembler/engine.rs` (`register_family`, `register_cpu`)
- `src/assembler/tests.rs` registry test helpers

## 68000 Operand and Encoding Model (v0.1 baseline)

### Required addressing forms
1. Data register direct (`Dn`)
2. Address register direct (`An`)
3. Address register indirect (`(An)`)
4. Postincrement/predecrement (`(An)+`, `-(An)`)
5. Displacement (`d16(An)`)
6. Indexed (`d8(An,Xn)`)
7. Absolute short/long (`(xxx).W`, `(xxx).L`)
8. Program counter relative (`d16(PC)`, `d8(PC,Xn)`)
9. Immediate (`#imm`)

### Baseline instruction class coverage
v0.1 baseline should include representative instructions across core classes:
- data movement: `MOVE`, `MOVEA`, `LEA`, `PEA`
- arithmetic/logic: `ADD`, `ADDA`, `SUB`, `SUBA`, `CMP`, `AND`, `OR`, `EOR`
- control flow: `BRA`, `BSR`, `Bcc`, `JMP`, `JSR`, `RTS`
- shifts/rotates: `ASL`, `ASR`, `LSL`, `LSR`, `ROL`, `ROR`
- quick/immediate forms: `MOVEQ`, `ADDQ`, `SUBQ`

### Size suffix and width policy
- Supported operation sizes for baseline: `.B`, `.W`, `.L` where legal.
- Width legality is instruction-specific and must be validated in encoder tables.
- Missing/implicit size behavior should follow canonical 68000 defaults per instruction and be documented in diagnostics when ambiguous.

### Endianness and address model
- 68000 stores multi-byte values in big-endian order.
- CPU handler target metadata for baseline:
  - `max_program_address() = 0x00FF_FFFF` (24-bit logical address space)
  - `native_word_size_bytes() = 2`
  - `is_little_endian() = false`

This impacts `.word`, `.emit word`, and size-aware emission behavior when `.cpu 68000` is active.

## Syntax and Dialect Policy
- Initial dialect: `motorola68k` as pass-through canonical grammar.
- Source selection remains `.cpu`-driven; no new `.dialect` directive in v0.1.
- Compatibility dialects (for example GNU/vasm style variants) are deferred until baseline stability.

## Error Model and Diagnostics
Required baseline diagnostics:
- unknown register token
- invalid effective-address form for instruction
- invalid size suffix for mnemonic/operand combination
- immediate out-of-range for chosen size
- branch displacement out of range (`BRA/Bcc/BSR` short/word forms)
- CPU-gating errors for non-68000 instructions (if entered through aliases)

Diagnostics should follow current opForge style:
- instruction-context-rich messages
- deterministic wording for fixture stability
- span-aware operand highlighting when available

## Test Plan

### Unit tests (new family and CPU modules)
- operand parser tests for each effective-address class
- encoding tests for representative instruction+mode combinations
- negative tests for illegal mode/size combinations
- branch displacement boundary tests

### Integration tests (`src/assembler/tests.rs`)
- `.cpu 68000` and `.cpu m68000` alias resolution
- `cpusupport_report` and capabilities include family/cpu entries
- `.word`/`.emit word` big-endian behavior under 68000 mode
- unknown CPU error path includes new aliases as candidates

### Examples and references
Add baseline examples:
- `examples/68000_basic_moves.asm`
- `examples/68000_branching.asm`
- `examples/68000_effective_addresses.asm`
- `examples/68000_arithmetic_sizes.asm`

Reference outputs:
- generated under `examples/reference/*` using existing project conventions
- regenerated only after tests pass except intentional output deltas

## Documentation Updates Required
When implementation lands, update:
- `README.md` CPU support list and minimal 68000 sample
- `documentation/opForge-reference-manual.md`
  - supported CPU table
  - `.cpu` aliases
  - 68000 syntax notes and size suffix behavior

Release notes policy:
- create notes only in the next release file for the next tag
- never edit already-tagged release notes

## Phased Delivery Plan

### Phase 0: Scaffolding and registration
- create family/CPU module skeletons
- wire registry and assembler startup paths
- add `cpusupport` visibility tests

Exit criteria:
- `.cpu 68000` resolves cleanly
- deterministic capabilities output includes `motorola68000` and `m68000`

### Phase 1: Baseline operand + encoder path
- implement family operand parser and core instruction tables
- implement baseline CPU handler metadata and validation
- add unit/integration tests and baseline examples

Exit criteria:
- representative 68000 programs assemble correctly
- no regressions in existing families

### Phase 2: Diagnostics hardening and fixture stabilization
- refine diagnostic wording/span anchors
- lock branch/size boundary tests
- generate fixture references for examples

Exit criteria:
- fixture outputs stable across repeated test runs
- negative tests cover major operand/size failure classes

### Phase 3: Docs completion and quality gate
- sync README/manual docs
- run full validation workflow

Exit criteria:
- docs and behavior are consistent
- required quality gates pass

## Risks and Open Decisions
1. Canonical 68k syntax variant for baseline:
   - decide exact accepted punctuation/case and keep it strict in v0.1.

2. Immediate range and default-size policy:
   - require explicit size for ambiguous forms or infer defaults per mnemonic.

3. Address expression width handling:
   - decide when unresolved symbols force `.W` vs `.L` encoding or require explicit suffix.

4. Future CPU layering:
   - reserve extension points for `68010`/`68020` without over-generalizing v0.1.

## Acceptance Criteria
This spec is considered fulfilled when:
1. `m68000` is registered under new `motorola68000` family with documented aliases.
2. Baseline effective-address forms and instruction classes above are assembled with correct bytes.
3. Size/addressing diagnostics are deterministic and covered by negative tests.
4. Examples and reference outputs are present and validated.
5. README/manual updates document shipped 68000 support.
