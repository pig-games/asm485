# opThread VM Tokenization Plan v0.1

Status: phase 1 complete
Last updated: 2026-02-15
Scope: full VM-based tokenization, family/cpu independent behavior

## Objective

Deliver a production-grade VM tokenizer path where tokenization behavior is data-driven by package policy/chunks and not hardcoded by family/cpu.

## Invariants

- Tokenization runtime logic must not branch on concrete family/cpu ids.
- Family/cpu/dialect differences are represented as package data and owner precedence.
- Owner precedence for token policy selection is dialect, then cpu, then family.
- Behavior is deterministic under bounded runtime budgets.
- Host tokenizer remains compatibility fallback during staged rollout.

## Phase 0 - Contract lock (runtime interface freeze)

- [x] Freeze portable token data model for tokenizer host/runtime boundary.
- [x] Freeze delegated tokenizer adapter ABI and request/response structure.
- [x] Freeze policy resolution contract (`dialect -> cpu -> family`).
- [x] Add interface-level tests for stability and deterministic behavior.

Acceptance criteria:
- Runtime exposes a portable token model independent from core parser internals.
- Delegated tokenizer adapter does not depend on family/cpu-specific logic.
- Contract tests verify owner-precedence policy selection and deterministic token mapping.

Phase 0 completion artifacts:
- `src/opthread/runtime.rs` adds `PortableToken`, `PortableTokenKind`, `PortableOperatorKind`, and `PortableSpan`.
- `src/opthread/runtime.rs` freezes tokenizer ABI as `PortableTokenizerAdapter` + `PortableTokenizeRequest` returning `Vec<PortableToken>`.
- `src/opthread/runtime.rs` keeps owner-precedence token policy resolution in `resolve_token_policy(..)` and `token_policy_for_resolved(..)`.
- `src/opthread/runtime.rs` tests lock the contract:
  - `portable_token_contract_round_trips_core_token_model`
  - `execution_model_token_policy_resolution_prefers_dialect_then_cpu_then_family`
  - token parity tests for delegated mode vs host baseline.

## Phase 1 - TOKS schema closure

- [x] Extend `TOKS` from hints to complete lexical policy (comment, quote, escape, number policy, operators).
- [x] Preserve decode compatibility for existing packages.
- [x] Add schema/canonicalization tests for all new fields.

Phase 1 completion artifacts:
- `src/opthread/package.rs` extends `TokenPolicyDescriptor` with full lexical policy fields.
- `src/opthread/package.rs` encodes extended `TOKS` entries with a backward-compatible extension marker and defaults legacy entries when fields are absent.
- `src/opthread/package.rs` canonicalizes and deduplicates lexical policy fields deterministically.
- `src/opthread/builder.rs` emits default lexical policy closures for family-scoped token policies.
- `src/opthread/runtime.rs` carries extended lexical fields in `RuntimeTokenPolicy` and `PortableTokenizeRequest`.
- Tests cover extended round-trip and legacy `TOKS` compatibility defaults.

## Phase 2 - Tokenizer VM ISA

- [ ] Define compact lexical VM instruction set and state-machine model.
- [ ] Define hard limits (steps, tokens/line, lexeme length, error count).
- [ ] Map tokenizer diagnostics to package-driven catalog.

## Phase 3 - Builder compiler path

- [ ] Compile tokenizer VM programs/tables from Rust-authored lexical specs.
- [ ] Keep Rust table/spec authoring path for onboarding new families/cpus.
- [ ] Emit deterministic package bytes from identical inputs.

## Phase 4 - Runtime VM tokenizer engine

- [ ] Add VM tokenizer executor in runtime.
- [ ] Add runtime modes: host, delegated-core, vm.
- [ ] Keep host tokenizer fallback for staged rollout.

## Phase 5 - Parity gates

- [ ] Add token-stream parity corpus across examples and edge cases.
- [ ] Add host-vs-vm token parity tests (kind, content, spans, diagnostics).
- [ ] Add deterministic fuzz/property tokenization checks.

## Phase 6 - Retro readiness

- [ ] Add tokenizer budget profiles for constrained native targets.
- [ ] Minimize hot-path allocations and enforce bounded buffers.
- [ ] Add runtime memory and step budget tests for retro profiles.

## Phase 7 - Rollout

- [ ] Enable VM tokenizer by default for MOS6502 family after parity gates.
- [ ] Keep non-certified families on staged verification mode.
- [ ] Document authoritative vs staged tokenizer families.

## Phase 8 - Finalization

- [ ] Promote VM tokenizer as authoritative for all certified families.
- [ ] Keep host tokenizer as optional compatibility/debug path.
- [ ] Require tokenizer parity checklist for onboarding new families/cpus.

## Delivery map

- `src/opthread/runtime.rs`: tokenizer ABI, policy resolution, runtime mode dispatch, VM executor.
- `src/opthread/package.rs`: TOKS schema/chunk extensions and canonicalization.
- `src/opthread/builder.rs`: tokenizer VM data emission from authoring specs.
- `src/core/parser.rs`: consume stable token contract with no behavior regressions.
- `src/assembler/mod.rs`: mode wiring and rollout controls.
- `src/assembler/tests.rs` and `src/opthread/runtime.rs`: parity and determinism coverage.
