# opThread v0.3 Parse/Resolve Realization Plan (MOS6502 First)

Status: draft execution checklist  
Last updated: 2026-02-15  
Scope: package/vm-driven operand parsing + operand resolution, with host-native tokenization and expression evaluation

## Objective

Move instruction operand parsing/resolution responsibility into the package/vm runtime path (starting with `m6502`), while keeping host-owned:

- tokenization,
- expression parsing/evaluation,
- directives/macros/link/output pipeline.

## Non-goals (this plan)

- Replacing host tokenizer/parser.
- Removing native fallback for unsupported parse/resolve cases in early phases.
- Multi-family rollout in this plan.

## Exit criteria for this iteration

- Runtime path can parse/resolve `m6502` operand forms from host `Expr` AST and encode through package `TABL` VM programs.
- Existing `m6502` runtime parity gates stay green (bytes + diagnostics).
- Full validation is green: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`.

## Phase checklist

### Phase 0 - Plan lock

- [x] Add this v0.3 execution checklist.
- [x] Link rollout criteria to this plan.
- [x] Lock first implementation slice to `m6502` only.

### Phase 1 - Runtime parse/resolve surface

- [x] Add runtime API that accepts mnemonic + host `Expr` operands + context and attempts package-driven parse/resolve/encode.
- [x] Keep deterministic error plumbing and avoid changing non-MOS families.

### Phase 2 - `m6502` parse/resolve implementation

- [x] Implement `m6502` operand shape parsing from host `Expr` AST.
- [x] Implement candidate mode/operand-byte resolution and package `TABL` lookup.
- [x] Preserve pass behavior for branch-relative and unresolved symbol cases.

### Phase 3 - Assembler wiring and fallback policy

- [x] Prefer package parse/resolve path for `m6502` in runtime mode.
- [x] Fall back to existing native parse/resolve path only when runtime parse/resolve reports unsupported shape.

### Phase 4 - Validation and parity hardening

- [x] Add targeted tests proving package parse/resolve path is exercised for `m6502`.
- [x] Keep parity corpus and example-program parity green.
- [x] Run full validation clean.



### Phase 5 - Mode-selection metadata schema (MSEL)

- [x] Add package-level selector metadata descriptor and chunk (`MSEL`).
- [x] Keep chunk decode backward-compatible (missing `MSEL` => empty selector set).
- [x] Keep canonical ordering/dedup deterministic for selector records.

### Phase 6 - Builder realization for MOS family

- [x] Emit selector metadata for MOS family/family-CPU instruction tables.
- [x] Add selector emission for 65C02 bit-branch forms and 65816 block-move/immediate-width forms.
- [x] Keep package build deterministic with selector metadata included.

### Phase 7 - Runtime selector execution across MOS CPUs

- [x] Replace m6502-specific hardcoded selector path with generic `MSEL` execution.
- [x] Enable selector-driven Expr parse/resolve candidate generation for `m6502`, `65c02`, and `65816`.
- [x] Preserve safe fallback to native parse/resolve when selector evaluation is unsupported for an input form.

### Phase 8 - Parity and validation gates

- [x] Keep opthread-runtime parity tests green across MOS family corpora.
- [x] Add runtime-unit coverage for selector-driven 65C02/65816 Expr encode cases.
- [x] Run full validation clean (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`).

## Residual follow-up after Phase 8

- Extend selector handling for explicit 65816 force-suffix edge semantics currently routed through native fallback.
- Evaluate removing remaining native parse/resolve fallback once selector coverage is complete and parity-gated.
