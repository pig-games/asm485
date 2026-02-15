# opThread VM Tokenization Plan v0.1

Status: phase 8 complete
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

- [x] Define compact lexical VM instruction set and state-machine model.
- [x] Define hard limits (steps, tokens/line, lexeme length, error count).
- [x] Map tokenizer diagnostics to package-driven catalog.

Phase 2 completion artifacts:
- `src/opthread/package.rs` adds optional `TKVM` chunk support with owner-scoped tokenizer VM descriptors (`TokenizerVmProgramDescriptor`) including opcode version, state entry table, limits, and diagnostics map.
- `src/opthread/package.rs` freezes the lexical opcode contract via `TokenizerVmOpcode` and `TOKENIZER_VM_OPCODE_VERSION_V1`.
- `src/opthread/package.rs` adds deterministic tokenizer limits (`TokenizerVmLimits`) and package diagnostic-code mapping (`TokenizerVmDiagnosticMap`) with runtime catalog defaults.
- `src/opthread/runtime.rs` loads `TKVM` descriptors into runtime-owned maps and resolves them with owner precedence (`dialect -> cpu -> family`) via `resolve_tokenizer_vm_program(..)` / `resolve_tokenizer_vm_limits(..)`.
- `src/opthread/builder.rs` emits minimal family-scoped `TKVM` descriptors so generated `.opcpu` artifacts carry phase-2 tokenizer VM contracts.
- Tests cover `TKVM` canonicalization/round-trip and invalid-shape rejection in `src/opthread/package.rs`, plus runtime owner-precedence resolution in `src/opthread/runtime.rs`.

## Phase 3 - Builder compiler path

- [x] Compile tokenizer VM programs/tables from Rust-authored lexical specs.
- [x] Keep Rust table/spec authoring path for onboarding new families/cpus.
- [x] Emit deterministic package bytes from identical inputs.

Phase 3 completion artifacts:
- `src/opthread/builder.rs` adds Rust-authored lexical spec structures (`TokenizerVmProgramSpec`, `TokenizerVmStateSpec`, `TokenizerVmInstructionSpec`) plus compiler path (`compile_tokenizer_vm_program_spec(..)`) that lowers specs into `TKVM` bytecode and state tables.
- `src/opthread/builder.rs` routes default family `TKVM` emission through the new spec compiler (`default_family_tokenizer_vm_spec(..)` -> `compile_tokenizer_vm_program_spec(..)`), preserving package-driven builder ownership semantics.
- `src/opthread/builder.rs` tests lock the authoring path and determinism (`builder_compiles_tokenizer_vm_program_from_rust_authored_spec` and `builder_encoding_is_deterministic`).

## Phase 4 - Runtime VM tokenizer engine

- [x] Add VM tokenizer executor in runtime.
- [x] Add runtime modes: host, delegated-core, vm.
- [x] Keep host tokenizer fallback for staged rollout.

Phase 4 completion artifacts:
- `src/opthread/runtime.rs` adds tokenizer runtime mode controls (`RuntimeTokenizerMode`, `tokenizer_mode()`, `set_tokenizer_mode(..)`) and mode-aware dispatch in `tokenize_portable_statement(..)`.
- `src/opthread/runtime.rs` adds bounded `TKVM` opcode execution for tokenization (`tokenize_with_vm_core(..)`) with deterministic limit enforcement and opcode decoding helpers.
- `src/opthread/runtime.rs` keeps staged rollout safety by preserving host tokenizer fallback when VM programs are missing, emit no tokens, or fail.
- `src/opthread/runtime.rs` adds tests for host/delegated-core/vm dispatch and VM execution/fallback behavior.

## Phase 5 - Parity gates

- [x] Add token-stream parity corpus across examples and edge cases.
- [x] Add host-vs-vm token parity tests (kind, content, spans, diagnostics).
- [x] Add deterministic fuzz/property tokenization checks.

Phase 5 completion artifacts:
- `src/opthread/runtime.rs` adds a tokenizer parity corpus test (`execution_model_tokenizer_parity_corpus_examples_and_edge_cases_host_vs_vm`) that validates host-vs-vm parity across `examples/*.asm` source lines plus explicit edge-case lines.
- `src/opthread/runtime.rs` adds deterministic fuzz/property tokenizer parity coverage (`execution_model_tokenizer_parity_deterministic_fuzz_host_vs_vm`) using a fixed-seed generator.
- `src/opthread/runtime.rs` adds deterministic-repeatability coverage for VM mode (`execution_model_tokenizer_vm_mode_is_deterministic_for_same_input`), ensuring repeated tokenization is stable for identical inputs.

## Phase 6 - Retro readiness

- [x] Add tokenizer budget profiles for constrained native targets.
- [x] Minimize hot-path allocations and enforce bounded buffers.
- [x] Add runtime memory and step budget tests for retro profiles.

Phase 6 completion artifacts:
- `src/opthread/runtime.rs` extends `RuntimeBudgetLimits` with tokenizer-specific runtime caps (steps/tokens/lexeme/errors) and defines constrained values for `RuntimeBudgetProfile::RetroConstrained`.
- `src/opthread/runtime.rs` enforces effective tokenizer VM limits as `min(package TKVM limits, runtime profile limits)` in `tokenize_with_vm_core(..)`, including bounded preallocation for token and lexeme buffers.
- `src/opthread/runtime.rs` reduces avoidable hot-path allocations in `vm_build_token(..)` by allocating lexeme strings only for token kinds that require textual payloads.
- `src/opthread/runtime.rs` adds retro-profile budget tests:
  - `execution_model_tokenizer_vm_retro_profile_enforces_step_budget`
  - `execution_model_tokenizer_vm_retro_profile_enforces_lexeme_budget`
  - `execution_model_tokenizer_vm_retro_profile_enforces_token_budget`

## Phase 7 - Rollout

- [x] Enable VM tokenizer by default for MOS6502 family after parity gates.
- [x] Keep non-certified families on staged verification mode.
- [x] Document authoritative vs staged tokenizer families.

Phase 7 completion artifacts:
- `src/opthread/runtime.rs` adds `RuntimeTokenizerMode::Auto` and sets it as the default tokenizer mode for new `HierarchyExecutionModel` instances.
- `src/opthread/runtime.rs` resolves `Auto` per active hierarchy in `effective_tokenizer_mode_for_resolved(..)`, routing MOS6502-family tokenization to VM mode and non-certified families to delegated-core staged mode.
- `src/opthread/runtime.rs` documents and centralizes the authoritative-family decision in `tokenizer_vm_authoritative_for_family(..)`.
- `src/opthread/runtime.rs` adds rollout tests:
  - `execution_model_defaults_to_auto_tokenizer_rollout_mode`
  - `execution_model_tokenizer_auto_mode_uses_vm_for_mos6502_family`
  - `execution_model_tokenizer_auto_mode_uses_vm_for_intel8080_family`

## Phase 8 - Finalization
- [x] Promote VM tokenizer as authoritative for all certified families.
- [x] Keep host tokenizer as optional compatibility/debug path.
- [x] Require tokenizer parity checklist for onboarding new families/cpus.

Phase 8 completion artifacts:
- `src/opthread/runtime.rs` defines explicit tokenizer VM certification metadata (`TOKENIZER_VM_CERTIFICATIONS`) for authoritative families and promotes all certified families to VM authority in auto mode.
- `src/opthread/runtime.rs` keeps host tokenizer as an explicit compatibility/debug path via `RuntimeTokenizerMode::Host` override while `RuntimeTokenizerMode::Auto` remains the default rollout mode.
- `src/opthread/runtime.rs` adds parity-checklist resolution and enforcement hooks (`resolve_tokenizer_vm_parity_checklist(..)`, `tokenizer_vm_parity_checklist_for_family(..)`), making onboarding certification dependent on explicit parity checklist text.
- `src/opthread/runtime.rs` adds finalization tests:
  - `execution_model_tokenizer_vm_parity_checklist_resolves_for_certified_families`
  - `tokenizer_vm_certification_entries_require_parity_checklist_text`
  - `execution_model_tokenizer_auto_mode_uses_vm_for_intel8080_family`
- [ ] Require tokenizer parity checklist for onboarding new families/cpus.

## Delivery map

- `src/opthread/runtime.rs`: tokenizer ABI, policy resolution, runtime mode dispatch, VM executor.
- `src/opthread/package.rs`: TOKS schema/chunk extensions and canonicalization.
- `src/opthread/builder.rs`: tokenizer VM data emission from authoring specs.
- `src/core/parser.rs`: consume stable token contract with no behavior regressions.
- `src/assembler/mod.rs`: mode wiring and rollout controls.
- `src/assembler/tests.rs` and `src/opthread/runtime.rs`: parity and determinism coverage.
