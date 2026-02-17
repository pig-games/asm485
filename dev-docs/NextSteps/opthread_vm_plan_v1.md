# opThread VM Unified Execution Plan (v1.0)

Status: active canonical plan  
Last updated: 2026-02-17

## 1. Goal

Reach the minimum complete VM-authoritative hot path needed for robust retro/vintage-native implementations, while intentionally keeping host-side orchestration for non-hot-path tooling features.

## 2. Definition of Done

All items below are true:
- Tokenization in assembler-owned hot paths is VM-authoritative.
- Parser VM is authoritative for line statement-envelope execution in assembler hot paths.
- Host parser expression parsing is removed from assembler hot paths.
- Mode selection and instruction emission remain package/runtime-authoritative.
- Runtime contracts are deterministic, bounded, versioned, and validated.
- Ultimate64-focused ABI/contract constraints are documented and test-backed.

## 3. Current Status Snapshot

### 3.1 Completed
- Assembler line tokenization routed through VM-authoritative runtime entrypoints.
- Parser VM contract/program resolution in bridge path is active.
- Assembler runtime parsing now routes through parser VM bridge path (not direct host `Parser::parse_line()` in runtime lane).
- Strict tokenization gates for authoritative families are in place and tested.
- VM-authoritative expression parse contract path is active in bridge hot paths.
- Expression diagnostic shape/span parity corpus is covered by regression tests.
- Parser VM envelope now includes dedicated staged primitives for dot-directive, star-org, assignment, and instruction forms.
- Default parser VM sequencing now uses primitive envelopes plus deterministic terminal parser diagnostics (no default statement-envelope fallback dependency).

### 3.2 In progress / pending
- Phase P3 contract freeze/validation hardening is complete.
- Phase P4 bounded-allocation hot-path hardening is still in progress.
- Retro-native ABI hardening/conformance is not yet finalized.

## 4. Workstream Phases

## Phase P0: Plan/Spec Lock
- [x] Establish one canonical spec document.
- [x] Establish one canonical plan document.
- [x] Remove superseded tracked planning/spec docs from active `NextSteps` set.

Acceptance:
- Only this plan and the unified spec are canonical references for opThread VM work.

## Phase P1: Expression Path Off Host Parser (highest priority)
- [x] Introduce/enable VM-authoritative expression parse contract entrypoint for bridge usage.
- [x] Replace all `Parser::parse_expr_from_tokens(...)` usages in `src/opthread/token_bridge.rs`.
- [x] Preserve diagnostic code shape/span parity for representative corpus.
- [x] Add regression tests proving no silent host expression parser fallback in assembler hot paths.

Acceptance:
- No host expression parser calls remain in assembler hot path bridge code.
- Intentional expression-contract breakage causes deterministic runtime errors (not fallback).

## Phase P2: Minimal Parser VM Envelope Completion
- [x] Move remaining statement-envelope primitives to contract-driven parser VM behavior.
- [x] Keep scope narrow: do not migrate full directive orchestration.
- [x] Preserve AST shape compatibility consumed by assembler execution.

Acceptance:
- Statement-envelope parse behavior for hot-path forms is parser-VM contract-led and deterministic.

## Phase P3: Contract Freeze and Validation Hardening
- [x] Freeze tokenizer/parser/expression contract payloads and version checks.
- [x] Add explicit compatibility/error behavior for version mismatches.
- [x] Ensure diagnostics mappings are stable and package-scoped.

Acceptance:
- Contract and version mismatch behavior is deterministic and fully test-covered.

## Phase P4: Retro Profile Enforcement
- [x] Define and enforce strict retro runtime budgets for tokenizer/parser/expression.
- [ ] Ensure bounded allocation behavior on hot path.
- [x] Add determinism and budget-exhaustion test suites.

Acceptance:
- Retro profile consistently enforces limits with stable outputs and diagnostics.

## Phase P5: Ultimate64 Portability Contract
- [ ] Produce ABI-facing contract note for Ultimate64-class native runtime integration.
- [ ] Define byte-order/layout/ownership/error-code expectations.
- [ ] Add host-side conformance tests to emulate constrained native integration assumptions.

Acceptance:
- Native implementers can build to one stable contract without relying on hidden host behavior.

## 5. Non-goals for this plan iteration

- Full VM migration of macro/preprocessor/module/linker orchestration.
- Removal of host tooling/output features.
- Broad CLI behavior redesign.

## 6. Execution Rules

- Ship in small commits with green validation gates.
- Prefer hard failures over silent fallback in authoritative VM paths.
- Keep VM/host split explicit in code and docs.

## 7. Validation Gates (every implementation batch)

- [ ] `cargo fmt`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo audit`
- [ ] `make test`
- [ ] `make reference-test`

## 8. Immediate Next Step

Phase P3: freeze parser/tokenizer/expression contract payload/version behavior and add explicit mismatch compatibility tests.
