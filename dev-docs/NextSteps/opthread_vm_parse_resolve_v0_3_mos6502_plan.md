# opThread v0.3 Parse/Resolve Realization Plan (MOS6502 First)

Status: draft execution checklist  
Last updated: 2026-02-14  
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

- [ ] Add runtime API that accepts mnemonic + host `Expr` operands + context and attempts package-driven parse/resolve/encode.
- [ ] Keep deterministic error plumbing and avoid changing non-MOS families.

### Phase 2 - `m6502` parse/resolve implementation

- [ ] Implement `m6502` operand shape parsing from host `Expr` AST.
- [ ] Implement candidate mode/operand-byte resolution and package `TABL` lookup.
- [ ] Preserve pass behavior for branch-relative and unresolved symbol cases.

### Phase 3 - Assembler wiring and fallback policy

- [ ] Prefer package parse/resolve path for `m6502` in runtime mode.
- [ ] Fall back to existing native parse/resolve path only when runtime parse/resolve reports unsupported shape.

### Phase 4 - Validation and parity hardening

- [ ] Add targeted tests proving package parse/resolve path is exercised for `m6502`.
- [ ] Keep parity corpus and example-program parity green.
- [ ] Run full validation clean.

## Follow-up after this iteration

- Extend parse/resolve realization to `65c02`, then `65816` (stateful width/bank semantics).
- Move remaining MOS-specific mode-selection heuristics into package-executable metadata.
