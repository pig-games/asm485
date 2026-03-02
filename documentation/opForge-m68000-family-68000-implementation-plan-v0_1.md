# opForge Motorola 68000 Family Implementation Plan — v0.1 (68000 first)

## Goal
Turn `opForge-m68000-family-68000-cpu-extension-spec-v0_1.md` into an executable implementation plan with:
- ticket-sized work items
- file-level touchpoints
- concrete tests and acceptance gates

Scope for v0.1 is intentionally narrow: ship a stable baseline `68000` implementation with canonical syntax and deterministic diagnostics.

## Non-goals (v0.1)
- no `68010`/`68020` instruction enablement
- no compatibility dialect expansion beyond canonical `motorola68k`
- no directive-language redesign or macro behavior changes
- no VM/runtime execution claims until explicit parity work is scheduled

## Operating principles
1. Keep family/CPU ownership boundaries strict.
2. Prefer deterministic diagnostics and fixture stability over broad syntax acceptance.
3. Avoid widening syntax scope until baseline encoding correctness is validated.
4. Never update references to hide regressions.

## Deliverable boundary
Done when:
- `.cpu 68000` and `.cpu m68000` resolve and assemble baseline programs.
- baseline effective-address and size rules are encoded with deterministic diagnostics.
- examples + references are added for positive and negative paths.
- full quality gates pass (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`).

---

## Workstream A — Foundation and registration

### Ticket M68K-001: Create 68000 family and CPU scaffolding
Objective:
- introduce `motorola68000` family and `m68000` CPU modules with compile-safe skeletons

Primary files:
- `src/families/m68000/mod.rs` (new)
- `src/families/m68000/module.rs` (new)
- `src/families/m68000/handler.rs` (new)
- `src/families/m68000/operand.rs` (new)
- `src/families/m68000/table.rs` (new)
- `src/families/m68000/dialect.rs` (new)
- `src/families/m68000/formatter.rs` (new)
- `src/m68000/mod.rs` (new)
- `src/m68000/module.rs` (new)

Implementation notes:
- start with minimal no-op/placeholder encode path returning well-scoped “not yet implemented” diagnostics.
- add family and CPU identity metadata early to unblock registry and capability tests.

Tests:
- unit smoke tests for module construction and registration metadata.

Acceptance:
- build succeeds with new modules wired but baseline encoding still stubbed.

---

### Ticket M68K-002: Wire registry, CLI CPU resolution, and capability reporting
Objective:
- expose `.cpu 68000` support and include family/cpu in support reporting

Primary files:
- `src/families/mod.rs`
- `src/lib.rs`
- `src/assembler/mod.rs`
- `src/assembler/engine.rs`
- `src/assembler/tests.rs`

Implementation notes:
- register canonical cpu name `m68000` with aliases `68000`, `mc68000`.
- set default dialect to `motorola68k`.

Tests:
- integration tests for `.cpu` alias resolution.
- `cpusupport_report` assertions include `motorola68000` + `m68000` entries.

Acceptance:
- CPU selection works end-to-end and reporting is deterministic.

---

## Workstream B — Operand parser and encoding baseline

### Ticket M68K-003: Implement effective-address parser (v0.1 set)
Objective:
- parse baseline 68000 effective-address forms used by initial instruction set

Primary files:
- `src/families/m68000/operand.rs`
- `src/families/m68000/handler.rs`

Implementation notes:
- implement parser support for:
  - `Dn`, `An`, `(An)`, `(An)+`, `-(An)`
  - `d16(An)`, `d8(An,Xn)`
  - `d16(PC)`, `d8(PC,Xn)`
  - absolute `.W` / `.L`
  - immediate `#imm`
- use structured operand enums to keep encoding deterministic.

Tests:
- unit parser tests for valid + invalid spelling per mode.
- negative tests for malformed indexed/PC-relative expressions.

Acceptance:
- parser coverage exists for all baseline addressing classes.

---

### Ticket M68K-004: Implement core encoding tables and mode validation
Objective:
- emit bytes for representative baseline instruction classes

Primary files:
- `src/families/m68000/table.rs`
- `src/families/m68000/handler.rs`
- optional `src/m68000/instructions.rs`

Implementation notes:
- implement instruction coverage in vertical slices:
  1. moves/addressing (`MOVE`, `MOVEA`, `LEA`, `PEA`)
  2. arithmetic/logic (`ADD/SUB/CMP/AND/OR/EOR`)
  3. branches/control (`BRA/BSR/Bcc/JMP/JSR/RTS`)
  4. quick/size-sensitive forms (`MOVEQ`, `ADDQ`, `SUBQ`)
- enforce legal mode + size matrix in encoder, not ad hoc parser checks.

Tests:
- table-driven encode tests by mnemonic/mode/size.
- negative tests for illegal mode combinations.

Acceptance:
- representative programs assemble with expected machine code.

---

### Ticket M68K-005: Add size suffix and immediate-range diagnostics
Objective:
- harden error behavior for `.B/.W/.L` and immediate width constraints

Primary files:
- `src/families/m68000/handler.rs`
- `src/families/m68000/table.rs`

Implementation notes:
- add explicit diagnostics for:
  - invalid size for mnemonic
  - immediate value overflow/underflow for selected size
  - ambiguous width requiring explicit suffix

Tests:
- boundary tests around min/max immediate ranges by size.
- golden diagnostic text tests for deterministic wording.

Acceptance:
- diagnostic output is stable and span-anchored where feasible.

---

## Workstream C — Integration, examples, and references

### Ticket M68K-006: Add integration tests for `.cpu 68000` behavior
Objective:
- validate assembler-level behavior from parser to emission

Primary files:
- `src/assembler/tests.rs`

Implementation notes:
- verify:
  - `.cpu` switching into 68000 mode
  - big-endian `.word` emission under 68000
  - unknown-CPU diagnostics still coherent with new aliases

Tests:
- integration tests in existing assembler test harness.

Acceptance:
- new tests pass without affecting existing CPU family assertions.

---

### Ticket M68K-007: Add example programs and reference outputs
Objective:
- provide practical baseline corpus and lock expected output

Primary files:
- `examples/68000_basic_moves.asm` (new)
- `examples/68000_branching.asm` (new)
- `examples/68000_effective_addresses.asm` (new)
- `examples/68000_arithmetic_sizes.asm` (new)
- `examples/reference/*` (generated)

Implementation notes:
- run tests before reference updates.
- update references only for intentional behavior deltas.

Tests:
- `make test` then reference comparison lane.

Acceptance:
- examples assemble and generated fixtures are stable.

---

## Workstream D — Documentation and release readiness

### Ticket M68K-008: Update README and reference manual
Objective:
- document supported 68000 CPU, aliases, and syntax baseline

Primary files:
- `README.md`
- `documentation/opForge-reference-manual.md`

Implementation notes:
- add concise “getting started” snippet with `.cpu 68000`.
- document baseline supported addressing forms and size suffix rules.

Tests:
- docs consistency pass via manual review and sample assembly smoke test.

Acceptance:
- docs match implemented behavior and examples.

---

### Ticket M68K-009: Final quality gate and release-note prep
Objective:
- complete validation and prep release-note entry in next version file only

Primary files:
- next release-notes file (created only when releasing)

Implementation notes:
- run:
  - `cargo fmt`
  - `cargo clippy -- -D warnings`
  - `cargo audit`
  - `make test`
- if behavior changed intentionally, regenerate references only after tests except fixture deltas pass.

Acceptance:
- all required checks pass; release-note content is ready for next tag file.

---

## Milestones and Exit Gates

### Milestone 0: Registration complete
- `M68K-001`, `M68K-002` complete.
- Exit gate: `.cpu 68000` resolves and appears in support reporting.

### Milestone 1: Baseline encoding complete
- `M68K-003`, `M68K-004`, `M68K-005` complete.
- Exit gate: baseline 68000 instruction corpus assembles with deterministic diagnostics.

### Milestone 2: Integration + fixtures complete
- `M68K-006`, `M68K-007` complete.
- Exit gate: examples and references validated in CI-equivalent test run.

### Milestone 3: Documentation + quality gate complete
- `M68K-008`, `M68K-009` complete.
- Exit gate: docs synced, full quality gate passes.

---

## Risk Register
- **Syntax ambiguity risk:** Different 68k assemblers use different EA spellings and defaults.
  - Mitigation: keep canonical syntax strict in v0.1; add dialect layer later.

- **Width inference risk:** Implicit size defaults can create unexpected encodings.
  - Mitigation: prefer explicit suffix diagnostics where ambiguity exists.

- **Address-size risk:** 24-bit address model may collide with existing assumptions in generic helpers.
  - Mitigation: add focused integration tests for max-address and absolute mode encoding.

- **Scope creep risk:** broad instruction coverage may delay delivery.
  - Mitigation: implement by instruction-class slices with hard milestone gates.

---

## Definition of Done (v0.1)
- `motorola68000` family + `m68000` CPU are fully registered and selectable.
- Baseline EA forms and instruction classes from the spec are encoded with tests.
- Negative diagnostics for mode/size/range issues are deterministic.
- Example corpus + reference outputs exist and pass validation.
- README and reference manual reflect shipped 68000 support.
