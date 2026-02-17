# opThread VM Retro-Native Balance Plan (v0.1)

Status: draft  
Last updated: 2026-02-17  
Primary target: stable VM/host contract boundary suitable for retro/vintage native ports (first target: Ultimate64-class environment)

## Goal

Reach a pragmatic VM-first architecture where the assembler hot path is VM-native, while keeping high-complexity orchestration host-side.  
This is intended to maximize deterministic runtime behavior on constrained native targets without over-VM-ifying tooling features.

## Target balance

### VM-native (required)
- Tokenization in assembler-owned paths.
- Parser statement-envelope execution (via parser VM contract/program).
- Expression parse/eval path used by assembler hot loop.
- Mode selection and instruction emission.

### Host-native (intentionally retained)
- Preprocessor + macro orchestration.
- Module/import graph resolution.
- Linker/output orchestration, map/listing generation, file I/O.
- High-level directive orchestration that is not hot-path-critical for native emission.

## Scope boundary for this plan

### In scope
- Remove host expression parsing from parser bridge in assembler pass1/pass2 hot paths.
- Extend parser VM only enough to keep statement-envelope parsing contract-driven and deterministic.
- Freeze and harden VM contracts for retro-native portability.
- Add retro-profile budget enforcement and determinism tests.
- Define Ultimate64-facing ABI/contract expectations.

### Out of scope
- Full VM migration of all directives/macros/module system.
- Replacing host orchestration for project-wide assembly graph management.
- UI/CLI feature changes not needed for VM contract hardening.

## Phase R0: Contract checkpoint

- [ ] Confirm and document current parser VM contract/version assumptions (`PARS` + `PRVM`).
- [ ] Record current “VM vs host” execution split as a baseline.
- [ ] Lock diagnostics invariants required for parity.

Acceptance criteria:
- A documented baseline exists for what is VM-authoritative vs host-side.
- Parser/tokenizer contract versions and diagnostics mappings are explicit.

## Phase R1: Expression path off host parser (next critical step)

- [ ] Introduce/enable a VM-authoritative expression parse contract entrypoint for assembler bridge usage.
- [ ] Replace all `Parser::parse_expr_from_tokens(...)` usage in `src/opthread/token_bridge.rs` with VM contract calls.
- [ ] Keep span/diagnostic behavior deterministic and parity-checked.
- [ ] Add tests proving assembler hot path does not rely on host expression parser.

Acceptance criteria:
- No host expression parser calls in assembler line hot paths.
- Regression tests fail when expression VM contract/program is intentionally broken (proving no silent host fallback).

## Phase R2: Minimal parser VM envelope completion

- [ ] Extend parser VM envelope op coverage only where needed for hot-path parse semantics.
- [ ] Keep bridge logic contract-driven; avoid broad directive-system VM migration.
- [ ] Preserve existing AST shapes consumed by assembler host execution.

Acceptance criteria:
- Statement-envelope parsing is contract-led and deterministic for supported paths.
- No regression in instruction/directive parity corpus.

## Phase R3: Retro-hardening

- [ ] Define strict limits for parser/expression/tokenizer execution (steps, nodes, depth, bytes).
- [ ] Enforce bounded memory behavior and deterministic failures under budget caps.
- [ ] Add retro profile tests and deterministic re-run tests.

Acceptance criteria:
- Retro profile reliably enforces limits with stable diagnostics.
- Repeated runs produce identical bytes and diagnostics for fixed input.

## Phase R4: Ultimate64 portability contract

- [ ] Specify ABI-level contract requirements (data layout, endianness assumptions, buffer ownership, error code catalog).
- [ ] Define minimum runtime footprint expectations for native target profile.
- [ ] Add host-side conformance tests that emulate constrained target behavior.

Acceptance criteria:
- Contract document is sufficient to implement/validate a native Ultimate64-side runtime counterpart.
- Conformance tests demonstrate no hidden host assumptions in hot-path VM contracts.

## Validation workflow (for each implementation batch)

- [ ] `cargo fmt`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo audit`
- [ ] `make test`
- [ ] `make reference-test`

## “Good enough for native-first” exit criteria

- Assembler hot path is VM-driven for tokenize -> envelope parse -> expression parse/eval -> mode select -> emit.
- Host-side responsibilities remain orchestration/tooling-focused.
- Contracts are versioned, deterministic, bounded, and tested under retro constraints.
- Ultimate64 portability contract is explicit and implementable without hidden parser/host dependencies.

