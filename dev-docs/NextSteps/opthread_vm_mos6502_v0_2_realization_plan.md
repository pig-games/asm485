# opThread MOS6502 Family v0.2 Realization Plan

Status: draft execution checklist  
Last updated: 2026-02-14  
Scope: MOS6502 family only (`m6502`, `65c02`, `65816`)

## Objective

Deliver a MOS6502-family runtime path where opThread package execution is authoritative for instruction encoding under runtime mode, while preserving byte/diagnostic parity with the current native Rust path.

## Non-goals (this plan)

- Multi-family v0.2 rollout beyond MOS6502.
- Feature-flag removal for non-MOS families.
- Host/linker/macro behavior changes outside instruction encode flow.

## Exit Criteria

- Runtime mode for MOS6502 family does not use native instruction encode fallback when VM metadata exists.
- MOS6502 family parity remains green for bytes and diagnostics across:
  - line-level parity corpus,
  - table-mode sweep corpus,
  - example-program corpus.
- Validation is clean: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`.

## Phase Checklist

## Phase 0 - Plan lock and rollout alignment

- [x] Add this v0.2 MOS execution checklist.
- [x] Link rollout criteria to this checklist and MOS-only scope.
- [x] Freeze VM-only runtime behavior target for MOS family under `opthread-runtime`.

## Phase 1 - MOS runtime VM-only enforcement

- [x] In runtime mode, enforce MOS-family VM encode path as authoritative.
- [x] For MOS-family instructions, remove native encode fallback when VM program lookup fails.
- [x] Add deterministic diagnostics for missing VM programs in MOS runtime mode.
- [x] Add regression tests proving missing TABL entries fail instead of silently falling back.

## Phase 2 - Package metadata completeness gates (MOS)

- [x] Add checks/tests that MOS scoped `FORM` metadata and `TABL` programs stay coherent.
- [x] Ensure CPU-extension mnemonics (including 65C02 bit-branch mnemonics) are represented in both dispatch metadata and VM program tables.
- [x] Keep metadata ordering deterministic and snapshot-stable.

## Phase 3 - Parity expansion and hardening (MOS)

- [x] Expand/refresh parity corpus coverage for MOS family stateful and ambiguous operand cases.
- [x] Add additional unresolved/reloc and boundary diagnostics parity checks for MOS runtime mode.
- [x] Keep example-program parity green for MOS family examples.

## Phase 4 - Runtime bridge cleanup (MOS)

- [ ] Remove remaining MOS-specific assumptions that are no longer required in assembler/runtime glue.
- [ ] Keep VM core generic (`src/opthread/vm.rs`) and MOS logic package-driven.
- [ ] Document residual native dependencies that remain intentionally host-side for v0.2.

## Phase 5 - Readiness gate

- [ ] Run full validation workflow clean.
- [ ] Confirm feature-flag behavior and regression expectations in docs.
- [ ] Record known follow-up items for post-MOS multi-family rollout.
