# opForge Motorola 6800 Family Extension Spec (v0.1, starting with 6809)

## Goal
Add Motorola 6800-family support to opForge using the existing family/CPU/dialect architecture, with initial delivery focused on `6809` and `HD6309`.

This specification defines architecture, module boundaries, implementation phases, tests, and acceptance criteria. It is intentionally implementation-oriented.

## Scope
In scope:
- new 6800 family module (parser + family encoding table)
- new CPU modules for `6809` (baseline) and `HD6309` (extension)
- registry wiring, `.cpu` aliases, capabilities/cpusupport reporting
- assembler tests plus example/reference fixtures for 6800-family behavior
- manual/README updates needed to expose supported CPUs and syntax

Out of scope for v0.1:
- non-6800-line Motorola families (for example 68000)
- additional 6800-line CPUs beyond `6809`/`HD6309` in v0.1 (for example `6800`, `6801`, `6803`)
- macro-language or directive syntax changes unrelated to CPU support
- binary compatibility shims for every third-party 6809 assembler dialect

## Baseline Constraints (from current opForge architecture)
1. Shared semantics belong in a family module; CPU-only behavior belongs in CPU modules.
2. Dialects are rewrite layers and do not emit bytes directly.
3. Two-pass assembly behavior must be preserved.
4. Validation order stays: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, full tests.
5. Reference outputs are regenerated only for intentional deltas, never to hide regressions.

## Target Runtime Matrix (6800 family, initial subset)

| Family | Dialect(s) | CPU (canonical) | Aliases | Notes |
|---|---|---|---|---|
| `motorola6800` | `motorola680x` (initial pass-through) | `m6809` | `6809`, `mc6809` | baseline target for first delivery |
| `motorola6800` | `motorola680x` | `hd6309` | `6309`, `m6309` | CPU extension phase after baseline is stable |

Design choice:
- Keep one canonical syntax first (`motorola680x`).
- Add additional compatibility dialects later only if needed (for example, specific LWASM/ASxxxx quirks).

## Architecture and Layering Plan

### Family ownership (`src/families/m6800/*`)
Family module owns:
- operand parsing for family addressing forms
- family instruction table for instructions shared by `m6809` and `hd6309`
- branch displacement/range validation shared across family CPUs
- register and condition recognition for family-common tokens
- extension seam for later 6800-line CPUs (`6800`/`6801`/`6803`) without reworking the registry model

Proposed files:
- `src/families/m6800/mod.rs`
- `src/families/m6800/module.rs`
- `src/families/m6800/handler.rs`
- `src/families/m6800/operand.rs`
- `src/families/m6800/table.rs`
- `src/families/m6800/dialect.rs`
- `src/families/m6800/formatter.rs` (no-op starter, parity with formatter hooks)

### CPU ownership (`src/m6809/*`, `src/hd6309/*`)
`m6809` CPU module:
- baseline CPU handler (mostly family passthrough)
- CPU identity, aliases, defaults, max address, endianness

`hd6309` CPU module:
- extension instruction table and resolution logic
- optional stricter validation for 6309-only forms

Proposed files:
- `src/m6809/mod.rs`
- `src/m6809/module.rs`
- `src/m6809/instructions.rs` (only if any CPU-only forms exist)
- `src/hd6309/mod.rs`
- `src/hd6309/module.rs`
- `src/hd6309/instructions.rs`

### Registry and assembler wiring
Update registration and visibility in:
- `src/families/mod.rs`
- `src/lib.rs`
- `src/assembler/mod.rs` (imports)
- `src/assembler/engine.rs` (`register_family`, `register_cpu`)
- `src/assembler/tests.rs` registry test setup helpers

## 6809 Operand and Encoding Model

### Required addressing forms (baseline)
1. Inherent (`ABX`, `RTS`, `NOP`)
2. Immediate 8/16 (`LDA #$12`, `LDD #$1234`)
3. Direct (`LDA <$20` style forcing deferred; baseline is address form)
4. Extended (`LDA $1234`)
5. Indexed (core 6809 forms)
6. Relative 8-bit branches (`BEQ`, `BNE`, etc.)
7. Relative 16-bit branches (`LBRA`, `LBSR` and long conditionals if included)
8. Register pair ops (`TFR`, `EXG`)
9. Register list ops (`PSHS`, `PULS`, `PSHU`, `PULU`)

### Indexed-mode coverage target
Baseline parser/encoder should cover canonical 6809 indexed families:
- `,X` / `,Y` / `,U` / `,S`
- `n,X` with 5-bit/8-bit/16-bit offsets (range-driven encoding)
- `A,X`, `B,X`, `D,X`
- auto inc/dec forms like `,X+`, `,--S`
- PCR-relative indexed forms (`n,PCR`)
- indirect bracketed forms where legal (`[,X]`, `[n,X]`, etc.)

### Endianness and width
- `m6809` and `hd6309` are 16-bit address CPUs with big-endian word storage for multi-byte data directives.
- CPU handlers must return:
  - `max_program_address() = 0xFFFF`
  - `native_word_size_bytes() = 2`
  - `is_little_endian() = false`

This impacts `.word`, `.emit word`, and other size-aware directives already wired through CPU mode.

## Syntax and Dialect Policy
- Initial dialect: `motorola680x` with pass-through mapping (no alternate mnemonic rewrite yet).
- Source remains `.cpu`-driven; no `.dialect` directive is introduced.
- If future dialects are added, they map syntax only and preserve family/CPU encoder ownership.

## Error Model and Diagnostics
Required diagnostics for baseline:
- unknown register in indexed/register-list/register-pair context
- invalid register pair for `TFR`/`EXG`
- invalid register-list token for stack ops
- out-of-range branch displacement (8-bit and 16-bit)
- invalid indexed displacement or illegal indirect mode form
- unknown `6309` mnemonic while targeting `m6809`

Diagnostics should match current opForge style:
- clear instruction-context message
- stable wording where possible for reference fixtures
- span-aware reporting for operand errors

## Test Plan

### Unit tests (new family and CPU modules)
- operand parser tests for each addressing class
- encoding tests for representative opcodes per mode
- negative tests for illegal indexed and register forms
- branch displacement boundary tests (`-128/+127`, long-branch bounds)

### Integration tests (`src/assembler/tests.rs`)
- `.cpu 6809` and `.cpu m6809` alias resolution
- `.cpu 6309`/`.cpu hd6309` resolution and extension behavior
- `cpusupport_report` and JSON entries include new CPUs and family
- unknown CPU diagnostic includes new aliases
- `.word`/`.emit word` big-endian behavior under 6809 CPU mode

### Examples and references
Add baseline examples:
- `examples/6809_simple.asm`
- `examples/6809_indexed_modes.asm`
- `examples/6809_branches.asm`
- `examples/6809_register_ops.asm`

Add extension example (phase with `hd6309`):
- `examples/6309_extensions.asm`

Reference outputs:
- generated under `examples/reference/*` per current project conventions
- update only after tests pass except intentional output deltas

## Documentation Updates Required
When implementation lands, update:
- `README.md` supported CPU list and usage samples
- `documentation/opForge-reference-manual.md`
  - introduction CPU list
  - `.cpu` accepted names/aliases
  - appendix architecture matrix

Release notes:
- add only in the next release-notes file for the next version tag
- never rewrite notes for already tagged releases

## Phased Delivery Plan

### Phase 0: Scaffolding and registration
- create family/CPU module skeletons
- wire registry and assembler startup paths
- add cpusupport visibility tests

Exit criteria:
- `.cpu 6809` resolves
- deterministic capabilities/cpusupport output includes new entries

### Phase 1: Baseline 6809 encode path
- implement family operand parser and core instruction table
- implement baseline CPU handler
- add unit/integration tests and baseline examples

Exit criteria:
- representative 6809 programs assemble correctly
- no regressions on existing families

### Phase 2: HD6309 extension layer
- add `hd6309` extension table and handler logic
- add extension-only diagnostics and tests
- add 6309 example/reference fixtures

Exit criteria:
- 6309-only instructions accepted on `hd6309`, rejected on `m6809`

### Phase 3: Docs and fixture completion
- finalize README/manual updates
- regenerate references only for intentional behavior changes
- run full required validation workflow

Exit criteria:
- docs and references match shipped behavior
- all quality gates pass

### Phase 4 (Future): VM encode/runtime support for Motorola 6800 family
- add VM operand-shape mapping for `motorola6800` family modes (`Immediate16`, indexed, register-list, branches)
- add VM instruction selector entries for baseline `m6809` table and `hd6309` extension table
- add runtime/native parity tests for `m6809` and `hd6309` mnemonic/mode coverage
- keep rollout policy staged as non-authoritative until parity checklists pass

Exit criteria:
- VM/native encode parity is demonstrated for baseline 6809 and 6309 extension samples
- tokenizer/parser/expr rollout policies for `motorola6800` are promoted only after checklist completion

## Implementation Progress Checklist

- [x] Register `motorola6800` family and canonical `motorola680x` dialect.
- [x] Register CPUs `m6809` and `hd6309` with aliases (including `h6309` and `hitachi6309`).
- [x] Wire family/CPU modules into assembler, formatter hooks, VM builder/runtime registries.
- [x] Implement baseline 6809 operand resolution for inherent/immediate/direct/extended/relative modes.
- [x] Implement baseline indexed encoding path (`n,R`, `A/B/D,R`, including `PC` displacement forms).
- [x] Implement register-pair (`TFR`/`EXG`) and register-list (`PSHS`/`PULS`/`PSHU`/`PULU`) encoding with diagnostics.
- [x] Add branch range diagnostics and boundaries for short and long branches.
- [x] Add initial HD6309 extension support (`SEXW`) and reject it under `.cpu m6809`.
- [x] Add 6809/6309 example sources and reference `.hex/.lst` fixtures.
- [x] Sync README and reference manual CPU support documentation.
- [x] Add next release-notes draft entry for this feature set (`RELEASE_NOTES_v0.9.4.md`).
- [x] Add canonical 6809 indexed parser forms for auto inc/dec spellings (implemented baseline forms: `,R+`, `,R++`, `,-R`, `,--R` for indexable base registers).
- [x] Add 6809 indirect indexed bracketed forms (baseline complete for `[n,X]`, `[n,PC]`, `[n]`, and register-offset bracket forms) with diagnostics.
- [x] Expand HD6309 instruction coverage beyond seed extensions (inherent extension set now includes `SEXW`, `CLRD`, `CLRW`, `CLRE`, `CLRF`).
- [x] Promote Motorola 6800-family VM encode/runtime parity from staged to complete (Phase 4).

## Risks and Open Decisions
1. Direct vs extended force syntax:
   - Many 6809 assemblers use `<`/`>` forcing conventions.
   - opForge already uses unary `<`/`>` in expression semantics.
   - Decision needed: adopt compatibility aliases, new explicit forcing syntax, or rely on range-based selection only in v0.1.

2. Indexed syntax variants across toolchains:
   - Bracket and auto-inc/dec notation differs between assemblers.
   - Keep v0.1 to one canonical parser and defer compatibility dialects.

3. Long-branch mnemonic set:
   - Some assemblers expose additional long conditional aliases.
   - Start with canonical 6809 set and add aliases only with tests.

## Acceptance Criteria
This spec is considered fulfilled when:
1. `m6809` and `hd6309` are registered CPUs under a new `motorola6800` family.
2. Baseline 6809 addressing/encoding coverage exists with tests.
3. `hd6309` extensions are isolated to CPU layer and test-covered.
4. Examples and reference fixtures are added using project policy.
5. `cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, and full tests pass.
6. README/manual CPU documentation is synchronized with shipped behavior.
