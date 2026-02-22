# Code Review — opForge main

**Reviewer:** Oz (AI)
**Date:** 2026-02-20 (revision 2; prior review 2026-02-15)
**Scope:** Full codebase (64.6 kLOC across 75 `.rs` files), not limited to branch delta
**Build status:** `cargo clippy -- -D warnings` clean, 792 tests pass, 0 failures

### Changes since prior review (2026-02-15)

| Metric | Prior | Current | Delta |
|---|---|---|---|
| `.rs` files | 71 | 75 | +4 |
| Lines of code | 49.5 kLOC | 64.6 kLOC | +15.1 kLOC (+30%) |
| Tests | 568 | 743 | +175 (+31%) |
| `runtime.rs` | 3,639 | 9,367 | +5,728 |
| `package.rs` | 2,843 | 4,025 | +1,182 |
| `token_bridge.rs` | — | 3,124 | new |
| `builder.rs` | ~1,200 | 1,659 | +~459 |

Key additions: `RuntimeExpressionParser`, Intel 8080 full resolver, portable
AST/expression types, expression VM rollout infrastructure, portable expression
evaluation, parser VM interpreter, and native 6502 ABI + wire protocol.

Both MOS 6502 and Intel 8080 families now default to `Authoritative` for all
three rollout gates (runtime, expr eval, expr parser).

---

## 1. Rust Idiom

### 1.1 Strengths (unchanged + new)

- **Error types are well-structured.** Every subsystem defines its own error enum
  with `Display`, `Error`, and `From` impls. Error propagation via `?` flows naturally.
- **Zero `unwrap()` in production code** across the opthread module and
  conditional-stack handling in `assembler/mod.rs` — error paths are now
  consistently `Result`-based (Q-10 addressed).
- **Feature flags are used appropriately.** `opthread-runtime-opcpu-artifact` and
  `opthread-parity` gate optional code paths. The prior `opthread-runtime` and
  `opthread-runtime-intel8080-scaffold` flags have been removed; all opthread code
  is now unconditionally compiled.
- **`#[must_use]`**, `Arc`-wrapped shared state, and `Span` derives continue to
  follow best practice.

### 1.2 Concerns

**R-1. `EncodeResult<T>` is not `Result`.** (Carried forward, unchanged.)
`EncodeResult::NotFound`/`Ok`/`Error` in `core/family.rs` is a custom three-way
enum. Consider `Result<Option<T>, EncodeError>`. **Severity: low.**

**R-2. `PortableOperatorKind` / `OperatorKind` mirror enums.** (Carried forward,
now worse.) The portable mirror types have expanded to include
`PortableAstBinaryOp` (20 variants, ~100-line bidirectional `From` impls) and
`PortableAstExpr` in addition to the original token/operator mirrors. Total
mechanical mapping boilerplate is now ~400 lines. A macro or `strum`-style derive
would eliminate this. **Severity: medium.**

**R-3. `to_core_token` is `#[cfg(test)]`-only.** (Carried forward, unchanged.)
**Severity: info.**

**R-4. `unreachable!()` in production code.** (Carried forward, now expanded.)

| Location | Guard | Risk |
|---|---|---|
| `runtime.rs` L465 | `TokenKind::End` in `from_core_token` | **Medium** — unguarded; panics if caller passes End token |
| `runtime.rs` L4269, L4295, L4432, L4455 | Inside Z80 CB-prefix byte calculation | Low — structurally guarded by outer match |
| `intel8080_vm.rs` L319 | `z80_cb_opcode_with_reg` inner match | Medium — guarded by outer match but breaks if refactored |

**Recommendation:** Replace with `return None` / `return Err(…)` for
defense-in-depth. **Severity: medium** (for the unguarded L465 case).

**R-5. `saturating_add` / `saturating_sub` overuse.** `token_bridge.rs` has 54
`saturating_add` and 13 `saturating_sub` calls for index arithmetic on valid
`usize` values. For index math, plain `+= 1` is idiomatic; `saturating_*`
silently masks overflow bugs that should panic in debug builds. Reserve
`saturating_*` for depth counters where underflow is legitimate. **Severity: low.**

---

## 2. DRYness

### 2.1 `ScopedOwner` boilerplate — **Critical** (prior D-1, now significantly worse)

The `ScopedOwner` match pattern (kind tag → `0u8/1u8/2u8`, id extraction,
lowercase canonicalization, variant equality) has grown from ~30 to **~70
repetitions** across `package.rs`, `runtime.rs`, and `builder.rs`. Each new chunk
type adds 4–6 copies.

**In `runtime.rs`:** The scoped-lookup pattern (lowercase 3 IDs, build
`owner_order` array, iterate map with `(owner_tag, interned_id)`) is
copy-pasted **8 times** across `token_policy_for_resolved`,
`tokenizer_vm_program_for_resolved`, `parser_contract_for_resolved`, etc.

**In `package.rs`:** 16 encode-side `kind_tag` matches + 10 decode-side
`from_tag` matches + 12 dedup `eq_variant` matches.

**Fix:** Extract `ScopedOwner::kind_tag()`, `::id()`, `::from_tag()`,
`::canonicalize_id()`, `::eq_variant()` methods and a `lookup_scoped<V>()`
helper on `HierarchyExecutionModel`. This would eliminate ~300 lines.
**Severity: high.**

### 2.2 Canonicalize function shape duplication

`package.rs` contains 7 `canonicalize_*` functions (lines 1000–1477, 477 lines)
that all follow the same 3-step pattern: lowercase owner IDs → sort by
owner_kind + owner_id → dedup by owner variant. A generic
`canonicalize_scoped_descriptors<T>()` with a key extractor would collapse this.
Shared `canonicalize_scoped_owner_id()` and `compare_scoped_owner()` helpers
now remove duplicated owner normalization/sort-key logic in these canonicalize
paths, but the full generic descriptor canonicalizer is still pending.
**Severity: partially addressed.**

### 2.3 Encode/decode owner-tag pattern

Every `encode_*_chunk` (10 functions) and `decode_*_chunk` (10 functions)
repeated the same owner-tag marshal/unmarshal block. `package.rs` now uses
shared `encode_scoped_owner()` / `decode_scoped_owner()` helpers across TOKS,
REGS, FORM, TABL, MSEL, TKVM, PARS, PRVM, EXPR, and EXPP chunk codecs.
**Severity: closed.**

### 2.4 Comma-separated operand splitter in `token_bridge.rs`

The same ~30-line block (init depth counters, match open/close braces, split on
comma at depth 0) appears 4 times at L667, L834, L902, and L1208.
**Severity: medium.**

### 2.5 `encode_expr_*` family in `runtime.rs`

`encode_expr_u8`, `encode_expr_u16`, `encode_expr_u24` (plus `rel8`, `rel16`)
share the same evaluate → range-check → LE-bytes shape. Unify into
`encode_expr_le(expr, ctx, byte_count, max)`. **Severity: medium.**

### 2.6 Test registry setup boilerplate

The pattern `ModuleRegistry::new()` + register family/CPUs + `from_registry()`
appears **~40 times** in `runtime.rs` tests. A `fn mos6502_model()` or
`fn parity_model()` helper would save ~200 lines. **Severity: medium.**

### 2.7 Builder instruction table iteration

(Carried forward.) Four structurally identical loops over instruction tables in
`builder.rs`. A helper `fn emit_table_programs(table, owner, tables)` would halve
repetition. **Severity: low.**

### 2.8 Intel 8080 handler dual encode path

`handler.rs` has `encode_instruction` (resolved `Operand`) and
`encode_family_operands` (pre-resolve `FamilyOperand`) with substantially
duplicated Z80-deferral logic (~40 mirrored lines). MOS 6502 only uses
`encode_instruction`. **Severity: low-medium.**

### 2.9 `intel8080_vm.rs` key/prefix/byte helper pairs

Multiple pairs of near-identical functions (`indexed_cb_prefix()` /
`indexed_cb_base_key()`, `z80_cb_register_code()` / `z80_cb_register_key()`,
`z80_half_index_prefix_byte()` / `z80_half_index_prefix_key()`) differ only in
return type. Each could be unified into a single function returning
`(key, value)`. **Severity: low.**

### 2.10 Rollout gate triplication

`rollout.rs` defines three near-identical rollout gate subsystems (Runtime,
ExprEval, ExprParser) as structural clones (~130 lines × 3 = ~390 lines). A
generic `RolloutGate<Mode>` pattern or macro would reduce to ~150 lines.
**Severity: high** (maintenance cost grows with each new gate).

---

## 3. Code/Spec Alignment

### 3.1 VM spec boundary document — now aligned

The `dev-docs/NextSteps/opthread_vm_spec_v1.md` was rewritten as a detailed
host↔VM boundary specification with:
- Boundary matrix table
- Architecture flowchart (Mermaid)
- Bootstrap + hot-path protocol sequence diagrams
- Rollout defaults + override controls
- Compliance criteria
- Appendix A: Boundary Traceability Map (rule → code entrypoint)

The spec accurately reflects the current implementation. **No conflict.**

### 3.2 Rollout state — both families authoritative

`rollout.rs` now marks both MOS 6502 and Intel 8080 as `Authoritative` for all
three gates (runtime, expr eval, expr parser). The `StagedVerification` variant
exists but is unused in the default tables. Env-var overrides
(`OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES`, `OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES`)
still function for testing. **Aligned with spec.**

### 3.3 Feature flag audit

Two feature flags are defined in `Cargo.toml`:
- `opthread-runtime-opcpu-artifact` — gates binary artifact caching (6 `#[cfg]` sites)
- `opthread-parity` — gates one parity test in `assembler/tests.rs`

The prior flags `opthread-runtime` and `opthread-runtime-intel8080-scaffold` are
**gone** — all opthread code is now unconditionally compiled. This is consistent
with both families being authoritative. **The Cargo.toml features section has no
documentation comments** — see S-2.

### 3.4 Spec: deterministic execution — aligned

`RuntimeBudgetLimits`, `RewriteLimits`, and `TokenizerVmLimits` all enforce
configurable ceilings. The expression VM adds `max_program_size`,
`max_stack_depth`, `max_symbol_refs`, and `max_eval_steps`. **No conflict.**

### 3.5 Hardcoded family/CPU identity checks in generic engine

Three policy checks in `assembler/mod.rs` break the generic family abstraction:
- `opthread_runtime_expr_operands_from_mapped()` hard-codes
  `intel8080::FAMILY_ID` for operand reconstruction (L2042)
- `defer_to_native_diagnostics` checks `intel8080::FAMILY_ID` (L3539)
- `runtime_expr_selector_gate_only` checks `m65816::CPU_ID` (L3466)

These are rollout-policy leaks, not interface violations. The host↔VM boundary
through `HierarchyExecutionModel` is clean. **Severity: medium** — should be
refactored into family/CPU capabilities or rollout queries.

---

## 4. Test Coverage

### 4.1 Overall

743 tests across the codebase. Distribution by top-level module:

| Module | Tests | % |
|---|---|---|
| `assembler` | 353 | 47.5 |
| `opthread` | 216 | 29.1 |
| `core` | 129 | 17.4 |
| `families` | 23 | 3.1 |
| `z80` | 12 | 1.6 |
| `i8085` | 5 | 0.7 |
| `m65c02` | 4 | 0.5 |
| `m65816` | 1 | 0.1 |

opthread submodule breakdown:

| Submodule | Tests |
|---|---|
| `runtime` | 119 |
| `token_bridge` | 24 |
| `package` | 24 |
| `rollout` | 20 |
| `hierarchy` | 9 |
| `builder` | 7 |
| `native6502` | 6 |
| `rewrite` | 5 |
| `vm` | 2 |

### 4.2 Improvements since prior review

- `runtime.rs` tests grew from 49 to **119** (+143%). Covers Z80 half-index, CB
  prefix, indexed memory, LD indirect, interrupt modes, ABI stability,
  expression parser parity corpus, budget enforcement, contract validation.
- `rollout.rs` tests grew from 4 to **20** (+400%). Full coverage of both
  families × all three gates × case sensitivity.
- `package.rs` tests grew from 15 to **24** (+60%). New EXPR/EXPP/MSEL chunk
  round-trip and validation tests.
- `token_bridge.rs` is new with **24** tests covering parser VM opcodes,
  contract validation, budget enforcement.

### 4.3 Remaining gaps

**T-1. `intel8080_vm.rs` direct unit coverage was added.**
The module now includes direct tests for interrupt-mode bounds, CB register
bit bounds, invalid register-code rejection, IM exclusion in generic instruction
VM compilation, and indexed-memory operand-count bounds.
**Severity: closed.**

**T-2. Builder selector helper coverage is now direct and targeted.**
Tests now explicitly cover `compile_mode_selector`, `selector_priority`, and
`selector_width_rank` in addition to existing M65816 force/long selector and
MOS forms coverage. **Severity: closed.**

**T-3. `hierarchy.rs` — no tests for `DuplicateCpuId`, `DuplicateFamilyId`,
`UnknownCpuInDialectAllowList` error paths.** The happy-path and cross-family
dialect tests are good, but construction-error coverage has gaps. **Severity: low.**

**T-4. `rewrite.rs` rewrite-error coverage expanded with direct tests.**
Coverage now includes targeted checks for `RuleHasEmptyMatch`,
`GrowthLimitExceeded`, and `TokenLimitExceeded` in addition to prior
deterministic mapping, filtering, overflow, and invalid-output paths.
**Severity: closed.**

**T-5. Binary codec now has deterministic mutation-fuzz decode coverage.**
`opthread/package.rs` now includes a seeded mutation-fuzz regression test that
bit-flips/truncates encoded container bytes and asserts deterministic decode
outcomes without panics across 256 malformed inputs.
`proptest`/`cargo fuzz` harnessing is still not present.
**Severity: partially addressed.**

**T-6. `token_bridge.rs` directive parser coverage is now direct and targeted.**
Direct tests now exercise `.use` selective+alias+with parsing, wildcard-alias
rejection, `.place` unknown-option rejection, `.pack` missing-section rejection,
and `.statement` envelope definition parsing.
**Severity: closed.**

**T-7. `RuntimeExpressionParser` now has direct negative/precedence tests.**
Direct tests now cover malformed ternary expressions (missing `:`), unexpected
primary-token failures, and explicit precedence shape (`1+2*3`) through the
runtime parser itself in addition to execution-model rejection tests.
**Severity: closed.**

**T-8. `vm.rs` now includes direct edge-case coverage for VM execution errors.**
Tests now cover empty/truncated program input, invalid opcode reporting, and
`OP_END`-only execution behavior. **Severity: closed.**

**T-9. Intel 8080 `handler.rs` now has direct unit tests for family encode behavior.**
Coverage now includes Z80 deferral paths (`JP IX` and two-operand I/O) plus
baseline family-table encoding (`MOV A,B`) in addition to existing RST tests,
half-index deferral (`IXH`/`IYH`) and indexed-memory deferral (`(IX+d)/(IY+d)`).
**Severity: closed.**

**T-10. Expression VM now has direct coverage for ternary and indirect behavior.**
`core::expr_vm` tests now include explicit coverage for `SelectTernary` branch
selection and `Expr::Indirect` / `Expr::IndirectLong` compile unwrapping parity.
**Severity: closed.**

**T-11. Wire codec edge cases now have targeted tests (native6502.rs).**
Direct tests now verify NUL rejection in `encode_wire_set_pipeline_payload`
and explicit trailing-byte decode rejection for wire encode payloads.
**Severity: closed.**

**T-12. MSEL chunk decode-rejection coverage is now explicit.**
Targeted tests now cover invalid `unstable_widen` flags, truncated MSEL payload
decoding, and invalid owner-tag rejection paths.
**Severity: closed.**

---

## 5. General Code Quality

### 5.1 Strengths

- **Clean module boundaries.** `core` has zero CPU knowledge. Families are
  isolated. The opthread module depends on families but not the assembler engine.
- **Consistent formatting.** All files follow `rustfmt` with SPDX headers and
  `//!` module docs.
- **Error messages are user-friendly.** Diagnostic codes (`OPC001`–`OPC011`,
  `OTR001`–`OTR004`, `OTT001`–`OTT006`, `DIAG_EXPR_*`) are structured.
- **Zero TODO/FIXME/HACK markers** in the entire codebase (the one `XXX` is a
  test mnemonic string, not a work marker).
- **Budget enforcement is comprehensive.** Every VM interpreter
  (encode VM, tokenizer VM, parser VM, expression VM) has configurable
  step/depth/size limits with clean error propagation.
- **Expression VM design is solid.** Compile-time stack-depth tracking,
  versioned opcodes, deduplicating symbol interner.
- **Binary codec is well-hardened.** The `Decoder` struct systematically checks
  bounds, rejects trailing bytes, and validates string lengths before allocation.
- **Zero `unwrap()` in opthread production code** — the entire module uses
  `Result`-based error propagation throughout.

### 5.2 Concerns — File Size

**Q-1. `runtime.rs` is 9,367 lines.** (Carried forward, now critical.)
This file grew 157% from 3,639 lines. It contains 5 independent subsystems
that should be extracted:

| Proposed module | Lines | Content |
|---|---|---|
| `portable_types.rs` | ~770 | PortableSpan, PortableOperatorKind, PortableTokenKind, PortableToken, PortableAstExpr, PortableLineAst, etc. |
| `runtime_expr_parser.rs` | ~560 | RuntimeExpressionParser (standalone precedence-climbing parser) |
| `intel8080_resolver.rs` | ~600 | select_candidates_from_exprs_intel8080, half-index/CB/indexed memory helpers |
| `mos6502_selector.rs` | ~1,400 | selector_input_from_family_operands, selector_to_candidate, encode_expr_*, M65816 bank-aware encoding |
| `tokenizer_vm_interp.rs` | ~380 | tokenize_with_vm_core, vm_read_*, vm_build_token, vm_char_class_matches |

Splitting these would reduce `runtime.rs` from 9,367 to ~3,200 lines (tests
remain in `runtime.rs` or move to per-module test files). **Severity: high.**

**Q-2. `package.rs` is 4,025 lines.** (Carried forward, now urgent.)
Grew 41% from 2,843 lines. Natural split into `package/types.rs`,
`package/encode.rs`, `package/decode.rs`, `package/canonicalize.rs`,
`package/validate.rs`, `package/tests.rs`. **Severity: high.**

**Q-3. `token_bridge.rs` is 3,124 lines** (new file, born large).
Split candidates: parser VM interpreter (~200 lines), directive parsers
(`parse_use_directive`, `parse_place_directive`, etc., ~400 lines), and
expression bridge (~200 lines). **Severity: medium.**

### 5.3 Concerns — API & Visibility

**Q-4. `runtime.rs` has 54 `pub fn` but only 2 `pub(crate) fn`.** Many methods
on `HierarchyExecutionModel` (`encode_portable_instruction`,
`resolve_tokenizer_vm_program`, `resolve_parser_vm_program`,
`resolve_expr_contract`, etc.) appear to be called only within the `opthread`
module. These should be `pub(crate)`. **Severity: low.**

**Q-5. `token_bridge.rs` entry-point docs are now present.**
The `pub(crate)` tokenizer/parser bridge entry points now have direct `///`
documentation describing runtime-model behavior and conversion boundaries.
**Severity: closed.**

**Q-6. Native 6502 ABI constants are now grouped in a dedicated submodule.**
`runtime.rs` now places the native ABI constants in `native6502_abi` and
re-exports them, reducing top-level clutter while preserving existing external
call sites.
**Severity: closed.**

### 5.4 Concerns — Performance

**Q-7. `vm_scan_next_core_token()` now reuses tokenizer state linearly.**
The VM scan path carries a persistent `Tokenizer` across `ScanCoreToken`
opcodes, so tokenization advances incrementally instead of reconstructing and
rescanning from the beginning of the line each step.
**Severity: closed.**

**Q-8. `to_ascii_lowercase()` called ~67 times** in `runtime.rs`, often
redundantly on the same identifiers across nested call chains. The interner
normalizes on insert, but call sites still lowercase before lookup.
**Severity: low.**

**Q-9. Scoped-lookup helpers now return borrowed entries.**
Resolved lookup helpers in `runtime.rs` return `Option<&T>` for tokenizer/parser
programs and contracts, avoiding per-call cloning; cloning is now explicit only
where ownership is required.
**Severity: closed.**

### 5.5 Concerns — Error Handling

**Q-10. Conditional-stack access now avoids `.unwrap()` in production paths.**
The guarded `last_mut().unwrap()` sites in `assembler/mod.rs` were converted to
explicit `let Some(ctx) = ... else { ... }` handling, preserving diagnostics and
making the safety invariant local to each use site.
**Severity: closed.**

**Q-11. `token_bridge.rs` `EmitDiag` handler does not advance `pc` past its
slot operand.** Because `EmitDiag` always returns `Err(…)` this is currently
benign, but the adjacent `EmitDiagIfNoAst` correctly advances `pc` — the
inconsistency is a maintenance hazard. **Severity: low** (latent).

**Q-12. Fragile string comparison for error reclassification.** `token_bridge.rs`
L1607: `err.message == "Unexpected end of expression"` — if the upstream message
changes, this silently stops working. Use a constant or structured error kind.
**Severity: low.**

**Q-13. `parse_error_at_end` always points to end-of-line.** Every parser VM
error uses this helper, losing the actual problem location. Consider passing
the relevant token span when available. **Severity: low.**

### 5.6 Concerns — Security (binary codec)

**Q-14. Decode count hardening now rejects pathological allocation requests.**
The decode path now applies bounded-count checks (including a hard maximum)
before allocation, and malformed-count regression tests verify deterministic
erroring instead of oversized allocation attempts.
**Severity: closed.**

### 5.7 Concerns — Assembler Integration

**Q-15. Runtime-expression gate coupling is now explicitly documented.**
`assembler/mod.rs` keeps separate booleans for authoritative-bytes behavior and
VM-path enabling, with an explicit comment that they are intentionally coupled
today and may diverge under future rollout policy changes.
**Severity: closed.**

**Q-16. Label-definition logic is already centralized.**
`assembler/mod.rs` uses the shared `define_statement_label` helper for both
label-only and label+mnemonic statement paths, removing the prior duplicated
symbol-definition flow.
**Severity: closed.**

**Q-17. Authoritative-runtime model guard deduplicated.**
The duplicate "runtime model unavailable for authoritative family" check in the
same instruction path was reduced to a single early guard, removing redundant
logic while preserving the existing diagnostic behavior.
**Severity: closed.**

### 5.8 Concerns — Family Modules

**Q-18. MOS 6502 `Operand` enum (27 variants)** with three exhaustive match
implementations (`mode()`, `span()`, `value_bytes()`). Consider a struct-based
design with `(AddressMode, value, span)` tuple to reduce per-variant
maintenance. **Severity: low.**

**Q-19. Intel 8080 `handler.rs` RST validation no longer uses production `unwrap()`.**
RST validation now uses fallible branches (`if let`/pattern matching), and the
family handler has direct tests for vector bounds, extra-argument rejection, and
Z80 deferral paths. **Severity: closed.**

**Q-20. MOS 6502 ZP/Absolute ambiguity** in multi-pass assembly: when
`expr_has_unstable_symbols` is true and the value fits 0–255, the handler
pessimistically promotes to `Absolute` mode. If the symbol stabilizes to ZP in
pass 2, the instruction shrinks (3→2 bytes), potentially invalidating downstream
addresses. This relies entirely on multi-pass convergence — no explicit cap on
promotion depth. **Severity: info** (correct for the current assembler design).

---

## 6. Rollout System Assessment

### 6.1 Architecture

Three independent rollout gates (runtime, expr eval, expr parser) each with
const rollout tables, case-insensitive family lookup, and env-var override
support. The expr eval and expr parser gates support opt-in and force-host
overrides. The runtime gate has no override mechanism — this appears intentional
but is undocumented.

### 6.2 Concerns

**RO-1.** Rollout gate triplication — see D-10 in §2.

**RO-2. force_host + opt_in precedence is now tested.**
Both expr-eval and expr-parser rollout paths include explicit tests that
`force_host` wins when both lists include the same family id; expr-eval now
also includes an unknown-family precedence test.
**Severity: closed.**

**RO-3. `pub` fields on `pub(crate)` structs.** The rollout table entry structs
expose `pub` fields but are themselves `pub(crate)`. Either make fields
`pub(crate)` or document the convention. **Severity: info.**

---

## 7. Summary of Recommendations

### Status key
- **New** — first identified in this review
- **Open** — carried forward from prior review, unchanged
- **Worse** — carried forward, severity increased
- **Partial** — partially addressed since prior review
- **Closed** — resolved since prior review

| ID | Area | Severity | Status | Recommendation |
|---|---|---|---|---|
| **D-1** | DRY | **High** | Closed | Completed shared ScopedOwner helper extraction: package canonicalization now uses generic `canonicalize_scoped_descriptors<T>()` plus `ScopedOwner::normalize_owner_id_ascii_lowercase()` / `cmp_scope_key()` from hierarchy |
| **D-1a** | DRY | Med-High | Closed | Implemented shared generic `canonicalize_scoped_descriptors<T>()` helper and applied it across scoped package canonicalization paths |
| **D-1b** | DRY | Medium | Closed | Shared `encode_scoped_owner` / `decode_scoped_owner` helpers now cover owner-tag marshal/unmarshal across scoped chunk codecs |
| **D-10** | DRY | High | Closed | Introduced generic rollout gate plumbing (`RolloutGate<Mode>` + shared mode lookup) and removed structural triplication across Runtime / ExprEval / ExprParser rollout subsystems |
| **D-4** | DRY | Medium | Closed | Extract comma-operand splitter in `token_bridge.rs` |
| **D-2** | DRY | Medium | Closed | Unify `encode_expr_*` LE-byte helpers |
| **D-6** | DRY | Medium | Closed | Runtime test registry setup now consistently uses shared helpers (`mos6502_family_registry()` / `parity_registry()`), removing repeated `ModuleRegistry::new()` + MOS CPU registration boilerplate |
| **R-2** | Idiom | Medium | Closed | Replaced manual mirror-enum `From` boilerplate with shared macro-based bidirectional mappings for runtime/operator AST mirror enums |
| **R-4** | Idiom | Medium | Closed | Replace `unreachable!()` with fallible return |
| **Q-1** | Quality | **High** | Partial | Ongoing `runtime.rs` modularization: extracted portable token/AST contract conversions (`runtime/portable_contract.rs`), assembler expression parse/eval bridge (`runtime/expression_bridge.rs`), tokenizer VM bridge (`runtime/tokenizer_bridge.rs`), instruction encoding/expr-resolver bridge (`runtime/encoding_bridge.rs`), parser/expr contract lookup+compatibility helpers (`runtime/contract_bridge.rs`), shared scoped-lookup/encoding-budget model helpers (`runtime/model_core_helpers.rs`), standalone runtime expression parser (`runtime/runtime_expr_parser.rs`), selector/candidate bridge scaffolding (`runtime/selector_bridge.rs`) including MOS/Intel candidate-resolution entry paths plus Intel-specific candidate helpers, and selector-addressing/relative/bank-fold encoding helpers (`runtime/selector_encoding.rs`); `runtime.rs` reduced to 5,018 lines, with remaining orchestration/runtime-tests sections still to split |
| **Q-2** | Quality | **High** | Worse | Split `package.rs` (4.0 kLOC → 6 submodules) |
| **Q-3** | Quality | Medium | New | Split `token_bridge.rs` (3.1 kLOC) |
| **Q-5** | Quality | Medium | Closed | Added doc comments for token-bridge `pub(crate)` entry points |
| **Q-7** | Perf | Medium | Closed | `vm_scan_next_core_token()` now reuses tokenizer state and scans incrementally |
| **Q-14** | Security | Medium | Closed | Added bounded + hard-capped decode count checks to prevent malformed-input OOM |
| **Q-15** | Quality | Low-Med | Closed | Clarified intentional coupling between runtime expression authority and VM-path gate |
| **Q-16** | Quality | Medium | Closed | Label-definition flow is centralized via `define_statement_label` |
| **S-1** | Spec | Medium | New | Hardcoded family/CPU checks should use capabilities |
| **T-1** | Coverage | **High** | Closed | Added direct `intel8080_vm.rs` unit tests for CB/IM/operand-count edge cases |
| **T-9** | Coverage | Medium | Closed | Added direct Intel 8080 handler tests for RST validation plus Z80 deferral branches (`JP IX`, two-op I/O, half-index, indexed-memory) and baseline `MOV A,B` encode |
| **T-5** | Coverage | Medium | Partial | Added deterministic mutation-fuzz decode coverage for binary codec; dedicated `cargo fuzz`/property harness still pending |
| **T-6** | Coverage | Medium | Closed | Added direct tests for `.use/.place/.pack/.statement` directive parser paths |
| **T-7** | Coverage | Medium | Closed | Added direct RuntimeExpressionParser negative + precedence tests |
| **RO-2** | Coverage | Medium | Closed | Added force_host-vs-opt_in priority tests for expr-eval and expr-parser rollout |
| **T-2** | Coverage | Low | Closed | Added direct tests for `compile_mode_selector`, `selector_priority`, and `selector_width_rank` |
| **T-3** | Coverage | Low | Closed | Add hierarchy construction error-path tests |
| **T-4** | Coverage | Low | Closed | Added rewrite error-path tests for empty-match, growth-limit, and token-limit failures |
| **R-1** | Idiom | Low | Open | Consider `Result<Option<T>>` over `EncodeResult` |
| **Q-4** | Quality | Low | Partial | Tighten `pub fn` → `pub(crate) fn` on model methods |
| **Q-6** | Quality | Low | Closed | Grouped native 6502 ABI constants in `runtime::native6502_abi` and kept compatibility via re-export |
| **Q-8** | Perf | Low | Partial | Reduced allocation-heavy lowercase sort keys in package canonicalization via allocation-free case-insensitive comparators; additional call-site cleanup remains |
| **Q-9** | Perf | Low | Closed | Scoped resolved-lookup helpers now return borrowed entries (`Option<&T>`) |
| **Q-10** | Quality | Low | Closed | Replaced conditional-stack `last_mut().unwrap()` with explicit `let Some(...) else` handling |
| **Q-19** | Quality | Low | Closed | Intel 8080 RST validation now uses fallible matching without production `unwrap()` |
| **S-2** | Spec | Low | Closed | Document feature flags in `Cargo.toml` |

### Closed items from prior review

| ID | Prior rec | Resolution |
|---|---|---|
| S-1 (prior) | Track realized vs. planned spec sections | **Closed** — spec rewritten with boundary matrix + traceability appendix |
| R-3.5 (prior) | Intel8080 `StagedVerification` vs docs | **Closed** — both families now `Authoritative` |
| Q-6 (prior) | Feature flag auditing | **Closed** — prior feature flags removed; all opthread code unconditionally compiled |
| D-3 (prior) | Builder table iteration boilerplate | **Open** — not addressed but lower priority now |
| D-4 (prior) | `token_policy_for_test` / `default_family_token_policy` dup | Subsumed by D-6 |

---

## 8. Architecture Assessment

The codebase has matured substantially since the prior review. The core
architecture — family registry → hierarchy resolution → runtime execution
model — is sound and well-layered. Both families running in authoritative mode
validates the VM pipeline end-to-end.

**Primary concern:** The growth rate. The project added 15.1 kLOC (+30%) since
the prior review 5 days ago. `runtime.rs` alone absorbed 5,728 new lines.
Without the recommended file splits, the largest files will become increasingly
difficult to navigate and review. Splitting `runtime.rs`, `package.rs`, and
`token_bridge.rs` into focused submodules is the single highest-impact
improvement for long-term maintainability.

**Positive trajectory:** Test count grew proportionally (+31%), error handling
quality is excellent (zero production unwraps in opthread), and the boundary
specification is now formalized. The rollout system provides a clean migration
path for future family additions.
