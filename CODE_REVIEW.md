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
- **Zero `unwrap()` in production code** across the opthread module — all error
  handling is `Result`-based. The only production `.unwrap()` is a guarded
  conditional-stack access in `assembler/mod.rs` (5 occurrences, all behind
  `is_empty()` checks — see Q-10).
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
**Severity: medium-high.**

### 2.3 Encode/decode owner-tag pattern

Every `encode_*_chunk` (10 functions) and `decode_*_chunk` (10 functions)
repeats the same 6-line owner-tag marshal/unmarshal block. Extract as
`fn encode_owner()` / `ScopedOwner::from_tag()`. **Severity: medium.**

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

**T-2. Builder selector compilation partially tested.** (Partially addressed.)
New tests cover M65816 force/long selectors and MOS forms shape, but individual
`compile_mode_selector`, `selector_priority`, and `selector_width_rank` remain
untested. **Severity: medium.**

**T-3. `hierarchy.rs` — no tests for `DuplicateCpuId`, `DuplicateFamilyId`,
`UnknownCpuInDialectAllowList` error paths.** The happy-path and cross-family
dialect tests are good, but construction-error coverage has gaps. **Severity: low.**

**T-4. `rewrite.rs` has only 5 tests.** (Carried forward, unchanged.)
**Severity: low.**

**T-5. No fuzz/property-based testing for binary codec.** (Carried forward,
unchanged.) The 24 package tests are deterministic fixtures. `proptest` or
`cargo fuzz` for the decode path would catch malformed-input edge cases.
**Severity: medium.**

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

**T-8. `vm.rs` has only 2 tests for 3 opcodes + 3 error paths.** No test for
empty program, invalid opcode, or `OP_END`-only program. **Severity: low.**

**T-9. Intel 8080 `handler.rs` now has direct unit tests for family encode behavior.**
Coverage now includes Z80 deferral paths (`JP IX` and two-operand I/O) plus
baseline family-table encoding (`MOV A,B`) in addition to existing RST tests.
**Severity: partially addressed.**

**T-10. Expression VM: no test for `SelectTernary` opcode or `Expr::Indirect`
unwrapping behavior.** **Severity: low.**

**T-11. Wire codec edge cases (native6502.rs).** NUL-rejection for
`encode_wire_set_pipeline_payload` and trailing-byte rejection for decode are
tested implicitly but not with targeted edge-case tests. **Severity: low.**

**T-12. No MSEL chunk decode-rejection tests.** TOKS and DIAG chunks have
dedicated malformed-input rejection tests; MSEL does not. **Severity: low.**

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

**Q-5. `token_bridge.rs` has zero `///` doc comments** on its 5 `pub(crate)`
entry points. Key concepts (`VmExprParseContext`, `ParserVmExecContext`,
`DEFAULT_TOKENIZER_CPU_ID`) are undocumented. **Severity: medium.**

**Q-6. Native 6502 ABI constants** (30+ `pub const` in `runtime.rs` L1331–1470)
should be grouped in a `native_abi` submodule since they're irrelevant to the
general assembler. **Severity: low.**

### 5.4 Concerns — Performance

**Q-7. `vm_scan_next_core_token()` is O(n²).** Creates a new `Tokenizer` on
every call and scans from the beginning of the line, skipping past `cursor`
position. For lines with many tokens, this is quadratic. Cache the tokenizer
or track its position. **Severity: medium.**

**Q-8. `to_ascii_lowercase()` called ~67 times** in `runtime.rs`, often
redundantly on the same identifiers across nested call chains. The interner
normalizes on insert, but call sites still lowercase before lookup.
**Severity: low.**

**Q-9. Scoped-lookup methods clone returned values.** All `*_for_resolved()`
methods call `.clone()` on stored `Vec<u8>` programs and contract structs.
Returning `Option<&T>` would avoid allocation; callers that need ownership can
clone explicitly. **Severity: low.**

### 5.5 Concerns — Error Handling

**Q-10. 5× `.unwrap()` on conditional-stack `last_mut()`.** In
`assembler/mod.rs` (L2990, L3109, L3156, L3185, L3216), the conditional-block
stack is accessed via `.unwrap()` after an `is_empty()` guard 5–20 lines above.
These are logically safe but fragile if the conditional logic changes. Use
`let Some(ctx) = stack.last_mut() else { … }` for documentation and safety.
**Severity: low.**

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

**Q-14. Potential OOM via crafted `count` field in decode.** Every
`decode_*_chunk` reads a `u32` count field and calls
`Vec::with_capacity(count as usize)`. A malicious package with
`count = 0xFFFF_FFFF` triggers a 4-billion-element allocation attempt. Add a
cap: `min(count, remaining_bytes / min_record_size)`. **Severity: medium** for
untrusted input; low if packages are always self-generated.

### 5.7 Concerns — Assembler Integration

**Q-15. Identical boolean expressions.** `assembler/mod.rs` L3460–3465:
`runtime_expr_bytes_authoritative` and `runtime_expr_vm_path_enabled` are
assigned the exact same expression
`(strict || family_authoritative) && !force_host`. Either this is a copy-paste
error or intentional future-proofing — add a comment or unify.
**Severity: low-medium.**

**Q-16. Duplicate label-definition logic.** `assembler/mod.rs` L2772–2810 (label
only) vs L2816–2851 (label + mnemonic) contain ~40 duplicated lines. Extract
a `define_label_symbol()` helper. **Severity: medium.**

**Q-17. Duplicate "model unavailable for authoritative family" guard** at L3444
and L3634 in the same function. Extract a common guard. **Severity: low.**

### 5.8 Concerns — Family Modules

**Q-18. MOS 6502 `Operand` enum (27 variants)** with three exhaustive match
implementations (`mode()`, `span()`, `value_bytes()`). Consider a struct-based
design with `(AddressMode, value, span)` tuple to reduce per-variant
maintenance. **Severity: low.**

**Q-19. Intel 8080 `handler.rs` RST validation** (L590) uses a single `.unwrap()`
— the only non-test `unwrap()` in family handlers. It's reachable via a
`len() > 1` guard but would be more robust as `if let`. **Severity: low.**

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
| **D-1** | DRY | **High** | Worse | Extract `ScopedOwner` helper methods (~300 lines saved) |
| **D-1a** | DRY | Med-High | New | Generic `canonicalize_scoped_descriptors<T>()` helper |
| **D-1b** | DRY | Medium | New | Extract encode/decode owner-tag marshal helpers |
| **D-10** | DRY | High | New | Deduplicate triple rollout gate pattern |
| **D-4** | DRY | Medium | Closed | Extract comma-operand splitter in `token_bridge.rs` |
| **D-2** | DRY | Medium | Closed | Unify `encode_expr_*` LE-byte helpers |
| **D-6** | DRY | Medium | New | Test registry setup boilerplate (~40 repetitions) |
| **R-2** | Idiom | Medium | Worse | Eliminate mirror enums with macro/derive (~400 lines) |
| **R-4** | Idiom | Medium | Closed | Replace `unreachable!()` with fallible return |
| **Q-1** | Quality | **High** | Worse | Split `runtime.rs` (9.4 kLOC → ~3.2 kLOC + 5 modules) |
| **Q-2** | Quality | **High** | Worse | Split `package.rs` (4.0 kLOC → 6 submodules) |
| **Q-3** | Quality | Medium | New | Split `token_bridge.rs` (3.1 kLOC) |
| **Q-5** | Quality | Medium | New | Add doc comments to `token_bridge.rs` entry points |
| **Q-7** | Perf | Medium | New | Fix O(n²) `vm_scan_next_core_token()` |
| **Q-14** | Security | Medium | New | Cap decode count to prevent OOM on malformed input |
| **Q-15** | Quality | Low-Med | New | Clarify identical boolean expressions in assembler |
| **Q-16** | Quality | Medium | New | Extract duplicate label-definition logic |
| **S-1** | Spec | Medium | New | Hardcoded family/CPU checks should use capabilities |
| **T-1** | Coverage | **High** | Closed | Added direct `intel8080_vm.rs` unit tests for CB/IM/operand-count edge cases |
| **T-9** | Coverage | Medium | Partial | Added direct Intel 8080 handler tests for Z80 deferral + baseline MOV encode |
| **T-5** | Coverage | Medium | Open | Add fuzz/property-based testing for binary codec |
| **T-6** | Coverage | Medium | Closed | Added direct tests for `.use/.place/.pack/.statement` directive parser paths |
| **T-7** | Coverage | Medium | Closed | Added direct RuntimeExpressionParser negative + precedence tests |
| **RO-2** | Coverage | Medium | Closed | Added force_host-vs-opt_in priority tests for expr-eval and expr-parser rollout |
| **T-2** | Coverage | Low | Partial | Complete unit tests for builder selector helpers |
| **T-3** | Coverage | Low | Closed | Add hierarchy construction error-path tests |
| **T-4** | Coverage | Low | Open | Expand rewrite engine coverage |
| **R-1** | Idiom | Low | Open | Consider `Result<Option<T>>` over `EncodeResult` |
| **Q-4** | Quality | Low | New | Tighten `pub fn` → `pub(crate) fn` on model methods |
| **Q-6** | Quality | Low | Open | Group native 6502 ABI constants in submodule |
| **Q-8** | Perf | Low | Partial | Reduce redundant `to_ascii_lowercase()` calls |
| **Q-9** | Perf | Low | New | Return `&T` from scoped-lookup methods instead of cloning |
| **Q-10** | Quality | Low | New | Replace conditional-stack `.unwrap()` with `let Some` |
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
