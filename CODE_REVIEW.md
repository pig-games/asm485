# Code Review — opForge `opthread-vm-family-impl` branch

**Reviewer:** Oz (AI)
**Date:** 2026-02-15
**Scope:** Full codebase (49.5 kLOC across 71 `.rs` files), not limited to branch delta
**Build status:** `cargo clippy --all-features` clean, 568 tests pass, 0 failures

---

## 1. Rust Idiom

### 1.1 Strengths

- **Error types are well-structured.** Every subsystem defines its own error enum
  (`VmError`, `OpcpuCodecError`, `RuntimeBridgeError`, `HierarchyError`,
  `RewriteError`, `HierarchyBuildError`) with `Display`, `Error`, and `From`
  impls. Error propagation via `?` flows naturally.
- **Trait-object layering is idiomatic.** The `FamilyHandlerDyn` / `CpuHandlerDyn`
  / `DialectModule` trait-object registry uses `Box<dyn …>` with `Send + Sync`
  bounds. `FamilyOperandSet` provides `clone_box()` for type-erased cloning —
  textbook Rust.
- **Feature flags are used appropriately.** `opthread-runtime`,
  `opthread-runtime-intel8080-scaffold`, and `opthread-runtime-opcpu-artifact`
  progressively gate WIP code behind stable compilation units.
- **`#[must_use]` on `Tokenizer::new`**, `Span` derives, and `RegisterChecker`
  via `Arc` are all good practice.

### 1.2 Concerns

**R-1. `EncodeResult<T>` is not `Result`.** `EncodeResult::NotFound` /
`EncodeResult::Ok` / `EncodeResult::Error` (in `core/family.rs`) is a custom
three-way enum that looks like `Result` but isn't. This pattern also exists
for `FamilyEncodeResult`. Callers cannot use `?`. Consider whether
`Result<Option<T>, EncodeError>` would work (`None` = not found), reducing
boilerplate in the assembler pipeline. **Severity: low** — the current pattern
works and is used consistently.

**R-2. `PortableOperatorKind` / `OperatorKind` mirror enums.**
`runtime.rs` (228–310) defines `PortableOperatorKind` and provides two
bidirectional `From` impls that are 44-line mechanical 1:1 maps. Since they are
identical, consider a shared enum with a newtype wrapper, or a macro to generate
the mirror and conversions. The same applies to `PortableTokenKind` ↔ `TokenKind`
(lines 312–402). **Severity: medium** — high maintenance cost for zero semantic
divergence.

**R-3. `to_core_token` is `#[cfg(test)]`-only.**
`PortableToken::to_core_token()` (lines 372–402) is gated behind `#[cfg(test)]`.
If the round-trip guarantee is important, consider making this part of the public
API or at least documenting why it is test-only. **Severity: info.**

**R-4. `unreachable!()` in `from_core_token`.**
Line 363 uses `unreachable!("end token is not representable as portable token")`
for `TokenKind::End`. If the caller ever passes an end token, this panics at
runtime. A safer pattern is returning `Result` or filtering before the call.
**Severity: low** — the caller currently filters correctly.

---

## 2. DRYness

### 2.1 `ScopedOwner` sort/dedup boilerplate

`package.rs` `canonicalize_hierarchy_metadata()` (lines 612–783) contains
**six near-identical blocks** that:
1. Lowercase-mutate `ScopedOwner` fields via a `match`.
2. Sort by `(owner_kind, owner_id, …)` using the same `match` → `0u8/1u8/2u8`
   pattern.
3. Dedup by matching owner variant pairs.

This pattern appears ~8 times in total. Extracting a helper:

```rust path=null start=null
impl ScopedOwner {
    fn kind_tag(&self) -> u8 { … }
    fn id(&self) -> &str { … }
    fn canonicalize(&mut self) { … }
    fn eq_variant(&self, other: &Self) -> bool { … }
}
```

…would eliminate roughly 100 lines of repetitive match arms.

### 2.2 `encode_expr_*` family in `runtime.rs`

`encode_expr_u8`, `encode_expr_u16`, `encode_expr_u24` (lines 1893–1924) share
the same shape: evaluate, range-check, return little-endian bytes. These could be
unified into a single `encode_expr_le(expr, ctx, byte_count, max)` helper.
Similarly, `encode_expr_force_abs16` and `encode_expr_abs16_bank_fold` share
substantial bank-lookup logic. **Severity: medium.**

### 2.3 Builder instruction table iteration

`builder.rs` (190–302) has four structurally identical loops over
`INTEL8080_FAMILY_INSTRUCTION_TABLE`, `I8085_EXTENSION_TABLE`,
`Z80_EXTENSION_TABLE`, and the MOS tables. Each loop follows the same
pattern: filter by registered IDs, compile VM program, push descriptor.
A helper `fn emit_intel_table_programs(table, owner, tables)` would halve
the repetition.

### 2.4 `token_policy_for_test` / `default_family_token_policy`

`builder.rs` `default_family_token_policy()` (335–361) and
`runtime.rs` test helper `token_policy_for_test()` (2303–2328) both
construct `TokenPolicyDescriptor` with the same `default_token_policy_lexical_defaults()`
fill pattern. Consider a `TokenPolicyDescriptor::with_defaults(owner, case_rule, …)`
constructor.

### 2.5 `Operand::span()` and `Operand::value_bytes()` match arms

`families/mos6502/operand.rs` — both `span()` (317–344) and `value_bytes()`
(348–382) enumerate every variant of the 27-variant `Operand` enum. If a new
variant is added and one of these is missed, Rust's exhaustiveness check will
catch it, but the maintenance burden is high. Consider storing `Span` as a
common field via a struct-of-enum pattern or `#[derive]`-based approach.

---

## 3. Code/Spec Alignment

### 3.1 Spec vs. implementation: VM instruction set

The spec (`opthread_vm_cpu_package_spec_v0_1.md` §5.3) defines a rich
stack-based VM with opcodes like `PUSH_I`, `TOK_PEEK`, `EXPR_PARSE`,
`EMIT8`, etc. The actual `vm.rs` implements a much simpler emit-only VM
with only three opcodes (`OP_EMIT_U8`, `OP_EMIT_OPERAND`, `OP_END`).
**This is not a conflict** — the spec is labeled "planned" and the code
is phased — but the gap is substantial. The `TokenizerVmOpcode` enum in
`package.rs` (153–167) introduces a separate opcode set for tokenizer VM
programs that is closer to the spec's vision but not connected to the
encode VM. **Recommendation:** The dev-docs should explicitly track which
spec sections are realized vs. planned. Currently the boundary is implicit.

### 3.2 Spec: hierarchy pipeline resolution — aligned

The spec (§3.3–3.4) defines family→CPU→dialect resolution with explicit
override → CPU default → family canonical fallback. `HierarchyPackage::resolve_pipeline()`
in `hierarchy.rs` implements exactly this chain. The `resolve_pipeline`
in `registry.rs` mirrors the same logic. **No conflict.**

### 3.3 Spec: deterministic execution — aligned

Spec §2.1 requires bounded deterministic execution. `RuntimeBudgetLimits`
(runtime.rs 138–145), `RewriteLimits` (rewrite.rs 28–43), and
`TokenizerVmLimits` (package.rs 243–259) all enforce configurable ceilings.
**No conflict.**

### 3.4 Rollout criteria vs. code state

`opthread_rollout_criteria_v0_1.md` requires "Pilot family parity smoke
passes for bytes + diagnostics." The test
`opthread_runtime_mos6502_example_programs_match_native_mode` (in
`assembler/tests.rs`) directly implements this gate. The criteria also
require clippy clean + cargo audit + make test, all of which pass.
**Aligned.**

### 3.5 Rollout module `FamilyRuntimeMode::Authoritative` for MOS but `StagedVerification` for Intel

`rollout.rs` marks MOS6502 as `Authoritative` and Intel8080 as
`StagedVerification`. This is consistent with the dev-docs' MOS-first
strategy. However, the rollout module is only compiled under
`#[cfg(feature = "opthread-runtime")]` but the feature flag is not
documented in `Cargo.toml` feature table comments. **Minor doc gap.**

---

## 4. Test Coverage

### 4.1 Overall

568 tests across the codebase. Distribution by module:
- `assembler/tests.rs`: 286 (integration/reference tests)
- `opthread/runtime.rs`: 49 (unit tests for runtime model)
- `core/parser.rs`: 32
- `assembler/cli.rs`: 26
- `opthread/package.rs`: 15
- `core/macro_processor.rs`: 13
- `core/expr.rs`: 13
- `opthread/rewrite.rs`: 5
- `opthread/rollout.rs`: 4
- `opthread/vm.rs`: 2
- `core/registry.rs`: 10
- Others: tokenizer, operand, hierarchy, symbol_table, preprocess, etc.

### 4.2 Gaps

**T-1. `intel8080_vm.rs` has zero unit tests.** The `mode_key_for_instruction_entry`
and `compile_vm_program_for_instruction_entry` functions are only
exercised indirectly through builder round-trip tests. Direct unit tests
for edge cases (DdCb/FdCb rejection, Im rejection, prefix_bytes
exhaustiveness) would improve confidence.

**T-2. `builder.rs` has tests only for encode round-trips.** The builder's
`compile_mode_selector`, `compile_m65816_force_selectors`, and
`compile_m65816_long_mode_selectors` functions produce complex
`ModeSelectorDescriptor` trees that are only tested via end-to-end
integration. Unit tests for individual selector shape/priority/plan
correctness would catch regressions faster.

**T-3. `hierarchy.rs` has no direct test for `resolve_pipeline_context`.** The
`ResolvedHierarchyContext` variant (returning descriptor references) is exercised
only through `runtime.rs` callers.

**T-4. `rewrite.rs` has only 5 tests.** Missing coverage for:
- Multi-pass convergence (rules that stabilize after >1 pass)
- Empty input
- Growth limit exactly at boundary
- Case sensitivity edge cases across `eq_ignore_ascii_case`

**T-5. `opthread/package.rs` — no fuzz or property-based testing for the binary
codec.** The encode/decode round-trip tests are deterministic fixtures.
Malformed-input robustness is only tested for known error variants, not for
arbitrary byte streams. Consider `proptest` or `cargo fuzz` for the decode path.

---

## 5. General Code Quality

### 5.1 Strengths

- **Clean module boundaries.** `core` has zero knowledge of specific CPUs.
  Families are isolated. The opthread module depends on families but not the
  assembler engine.
- **Consistent formatting.** All files follow `rustfmt` conventions with
  consistent SPDX headers and `//!` module docs.
- **Error messages are user-friendly.** Diagnostic codes (`OPC001`–`OPC011`,
  `OTR001`–`OTR004`, `OTT001`–`OTT006`) are structured and template-renderable.
- **Feature-flag discipline is strong.** The Intel8080 scaffold is fully gated
  behind `opthread-runtime-intel8080-scaffold`. No dead code leaks into the
  default build.

### 5.2 Concerns

**Q-1. `runtime.rs` is 3639 lines.** This single file contains:
- Type definitions (Portable{Span,OperatorKind,TokenKind,Token})
- Bridge/adapter structs and traits
- The full `HierarchyExecutionModel` with encode + tokenizer + selector logic
- All MOS6502 expr-resolution and 65816 bank-resolution logic
- All Intel8080 scaffold resolver (behind feature flag)
- Private helpers (encode_expr_*, parse_mode_key, selector_to_candidate, etc.)
- 49 unit tests

This file should be split. Natural fracture lines:
1. `portable_token.rs` — Portable{Span,OperatorKind,TokenKind,Token} + conversions
2. `bridge.rs` — HierarchyRuntimeBridge, PortableInstructionAdapter, PortableTokenizerAdapter
3. `model.rs` — HierarchyExecutionModel core (from_chunks, encode, budget)
4. `mos6502_resolver.rs` — MOS6502 expr resolution, selector logic, encode helpers
5. `intel8080_resolver.rs` — Intel8080 scaffold resolver (feature-gated)

**Q-2. `package.rs` is 2843 lines.** Similar to Q-1, the binary codec
(encode + decode for 12 chunk types) and the canonicalization logic are all in
one file. Consider splitting into `package/encode.rs`, `package/decode.rs`,
`package/canonicalize.rs`.

**Q-3. Magic numbers in `owner_key_parts`.** The `0u8/1u8/2u8` tags for
Family/Cpu/Dialect are used in both `owner_key_parts` (runtime.rs:2251) and the
`canonicalize_*` functions (package.rs). These should be named constants or part
of `ScopedOwner` itself.

**Q-4. `to_ascii_lowercase()` allocation frequency.**
`runtime.rs` calls `.to_ascii_lowercase()` on mnemonic, family_id, cpu_id, and
dialect_id strings on virtually every encode/lookup path. For hot-path
performance, consider normalizing once at model construction and storing
normalized keys. The interner (`LowercaseIdInterner`) partially addresses this
for TABL/MSEL keys, but `encode_candidates()` still lowercases on every call
(line 1150, 1154–1156, 1164).

**Q-5. `selector_to_candidate` operand plan dispatch (runtime.rs 1723–1851).**
The 20+ string-matched operand plans (`"u8"`, `"u16"`, `"force_d_u8"`, etc.)
are stringly-typed. A typo in builder or selector code would silently produce
`Ok(None)` at the `_ => return Ok(None)` catch-all. Consider an enum for
operand plans with a `FromStr` impl that can fail loudly.

**Q-6. `Cargo.toml` feature dependencies are not visible in this review.** The
feature flags `opthread-runtime`, `opthread-runtime-intel8080-scaffold`, and
`opthread-runtime-opcpu-artifact` are referenced in code but their Cargo.toml
definitions and dependency chains were not inspected. Worth auditing that
feature combinations are tested in CI.

---

## 6. Summary of Recommendations

| ID | Area | Severity | Recommendation |
|---|---|---|---|
| R-1 | Idiom | Low | Consider `Result<Option<T>>` over custom `EncodeResult` |
| R-2 | DRY | Medium | Eliminate mirror enums for Portable↔Core tokens/operators |
| R-4 | Idiom | Low | Replace `unreachable!()` with fallible conversion |
| D-1 | DRY | Medium | Extract `ScopedOwner` helpers for sort/dedup boilerplate |
| D-2 | DRY | Medium | Unify `encode_expr_*` LE-byte helpers |
| D-3 | DRY | Low | Deduplicate builder instruction-table iteration |
| Q-1 | Quality | High | Split `runtime.rs` (~3.6 kLOC) into focused submodules |
| Q-2 | Quality | Medium | Split `package.rs` (~2.8 kLOC) into encode/decode/canonicalize |
| Q-3 | Quality | Low | Name magic `0u8/1u8/2u8` owner-kind tags |
| Q-4 | Quality | Low | Reduce per-call `to_ascii_lowercase()` allocations |
| Q-5 | Quality | Medium | Replace stringly-typed operand plans with an enum |
| T-1 | Coverage | Medium | Add unit tests for `intel8080_vm.rs` |
| T-2 | Coverage | Medium | Add unit tests for builder selector compilation |
| T-3 | Coverage | Low | Add direct `resolve_pipeline_context` tests |
| T-4 | Coverage | Low | Expand rewrite engine test coverage |
| T-5 | Coverage | Medium | Add fuzz/property-based testing for binary codec |
| S-1 | Spec | Info | Track realized vs. planned spec sections in dev-docs |
| S-2 | Spec | Low | Document feature flags in Cargo.toml |
