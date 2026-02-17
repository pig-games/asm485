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
- 6502-native host ABI envelope (control-block layout + entrypoint ordinals) is versioned and test-backed.

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
- Native 6502 host harness v1 envelope is implemented with ordinal-driven entrypoints and control-block status/length reporting.
- Native harness shakeout fixtures now cover deterministic success flow and `OPC`/`OTR`/`ott`/`otp` failure namespaces through the harness boundary.

### 3.2 In progress / pending
- Phase P3 contract freeze/validation hardening is complete.
- Phase P4 retro profile enforcement is complete.
- Phase P5 Ultimate64 portability contract hardening is complete.
- Phase P6 6502-native host ABI shakeout is complete.

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
- [x] Ensure bounded allocation behavior on hot path.
- [x] Add determinism and budget-exhaustion test suites.

Acceptance:
- Retro profile consistently enforces limits with stable outputs and diagnostics.

## Phase P5: Ultimate64 Portability Contract
- [x] Produce ABI-facing contract note for Ultimate64-class native runtime integration.
- [x] Define byte-order/layout/ownership/error-code expectations.
- [x] Add host-side conformance tests to emulate constrained native integration assumptions.

Acceptance:
- Native implementers can build to one stable contract without relying on hidden host behavior.

## Phase P6: 6502-Native Host ABI Envelope and Harness
- [x] Define and freeze a 6502-native host control-block envelope with fixed offsets/widths.
- [x] Define and freeze stable native entrypoint ordinals for v1 jump-table integration.
- [x] Reserve capability bits for forward-compatible `.struct`/`.enum` ABI growth.
- [x] Build external harness smoke flow (`load package -> set pipeline -> tokenize/parse/encode`) against the frozen envelope.
- [x] Add fixture-backed shakeout cases for deterministic success and failure (`OPC`, `OTR`, `ott`, `otp`) through the harness boundary.

Acceptance:
- A 6502 assembler/machine-language host can integrate against one stable v1 in-memory envelope without relying on C ABI assumptions.
- Harness smoke coverage proves deterministic end-to-end behavior through the native interface boundary.

## 5. Non-goals for this plan iteration

- Full VM migration of macro/preprocessor/module/linker orchestration.
- Removal of host tooling/output features.
- Broad CLI behavior redesign.

## 6. Execution Rules

- Ship in small commits with green validation gates.
- Prefer hard failures over silent fallback in authoritative VM paths.
- Keep VM/host split explicit in code and docs.

## 7. Validation Gates (every implementation batch)

- [x] `cargo fmt`
- [x] `cargo clippy -- -D warnings`
- [x] `cargo audit`
- [x] `make test`
- [x] `make reference-test`

## 8. Immediate Next Step

Bridge the Rust native harness envelope to a real external Ultimate64-class host harness and validate identical fixture outcomes across the process boundary.
