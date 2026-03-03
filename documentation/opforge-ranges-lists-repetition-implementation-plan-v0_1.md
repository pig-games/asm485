# opForge Ranges, Lists, and Repetition Implementation Plan v0.1

Status: Implemented (all phases completed on branch `codex/ranges-lists-repetition-plan-v0_1`)  
Date: 2026-03-03  
Source design: `documentation/opforge-ranges-lists-repetition-design-v0_1.md`
Latest implementation commit: `fc25a30`

## 1. Purpose

This plan converts the v0.1 feature proposal into an implementation sequence that an autonomous coding agent can execute without additional product decisions.

It covers:

1. Ranges (`..`, `..=`, optional `:step`)
2. Lists (`{...}`)
3. Index/member expressions (`value[n]`, `value.field`)
4. `.for/.bfor/.while/.bwhile` with `.endfor/.endwhile`
5. `.struct/.endstruct`
6. Labeled repetition outputs (`label[n]`, optional struct annotation)
7. `.len(...)` builtin
8. Tests, examples, references, and docs sync
9. Formatter and LSP support for new notation and semantics
10. Typed literal struct instances assignable to symbols

## 2. Locked Scope and Decisions

These are resolved now to avoid blocking implementation:

1. Defer `.break` and `.continue` to a later version.
2. Defer string-valued lists to a later version; list elements are integer expressions only.
3. Defer nested structs; include standalone typed struct literal instances in this plan.
4. Keep scope labels and struct fields as distinct concepts:
`scope.label` is an address, `Struct.field` is an offset.
5. Keep unscoped loop label prohibition:
labels inside `.for/.while` bodies and on `.endfor/.endwhile` are errors.
6. Keep structured directives implemented in assembler passes (not macro preprocessor).
7. Keep two-pass stability requirements strict:
if pass1 vs pass2 iteration counts differ, error out.
8. Introduce `--max-loop-iterations` CLI option with default `65536`.
9. Keep current reference-update policy:
only regenerate references after behavior changes are intentional and all non-reference tests pass.
10. Struct literal syntax is typed and explicit:
`StructName { field: expr, ... }`.
11. Struct literals require exact field coverage:
all declared fields exactly once, no unknown fields.

## 3. Skill Routing and Workstream Order

Use workflow routing from `$opforge-workflow-router`:

1. Code and tests: `$opforge-cpu-extension-pack`
2. Reference fixtures: `$opforge-golden-reference-maintainer`
3. Docs/changelog sync: `$opforge-doc-sync-and-release-notes`

Do not reorder unless a blocking dependency is discovered.

## 4. Execution Contract for Autonomous Agent

## 4.1 Branch and Commit Rules

1. Create a branch prefixed with `codex/` (example: `codex/ranges-lists-repetition-v0_1`).
2. Make phase-scoped commits (one commit per phase or sub-phase).
3. Commit messages must contain:
title line + summary body.

## 4.2 Validation Rules (mandatory)

After each major phase and before final completion run:

1. `cargo fmt --all`
2. `cargo clippy -- -D warnings`
3. `cargo audit`
4. `make test`

Reference workflow:

1. Run tests first without updating references.
2. If only expected fixture deltas remain, run `make reference`.
3. Re-run `make reference-test` and `make test`.

## 4.3 Stop Conditions

Stop and ask for guidance only if:

1. A required semantic choice is not covered by Section 2.
2. A design requirement cannot be implemented without breaking existing architecture guarantees.
3. Validation failures cannot be resolved without changing locked scope.

Otherwise continue autonomously.

## 5. Architecture Touchpoints (must be updated)

Primary files:

1. `src/core/tokenizer.rs`
2. `src/core/parser.rs`
3. `src/vm/runtime/runtime_expr_parser.rs`
4. `src/core/expr.rs`
5. `src/core/assembler/expression.rs`
6. `src/assembler/asmline_eval.rs`
7. `src/core/expr_vm.rs`
8. `src/core/assembler/scope.rs`
9. `src/assembler/asmline_directives.rs`
10. `src/assembler/asmline_directives_scope.rs`
11. `src/assembler/mod.rs`
12. `src/assembler/engine.rs`
13. `src/assembler/cli.rs`
14. `src/assembler/tests.rs`
15. `documentation/opForge-reference-manual.md`
16. `README.md`
17. `CHANGELOG.md`
18. `examples/*.asm` and `examples/reference/*`
19. `src/formatter/surface_tokenizer.rs`
20. `src/formatter/surface_parser.rs`
21. `src/formatter/planner.rs`
22. `src/formatter/renderer.rs`
23. `src/formatter/fixture_tests.rs`
24. `src/lsp/document_symbols.rs`
25. `src/lsp/definition.rs`
26. `src/lsp/hover.rs`
27. `src/lsp/completion.rs`
28. `src/lsp/diagnostics.rs`
29. `src/lsp/validation_runner.rs`

Expected new files:

1. `src/core/asm_value.rs` (value model + helpers)
2. `src/core/struct_table.rs` (struct definitions)
3. `src/assembler/repetition.rs` (repeat block collection/execution helpers)

If file naming differs, keep equivalent separation of concerns.

## 6. Implementation Phases

## Phase 0: Spec-to-Code Prep and Safety Net

Objectives:

1. Create implementation scaffolding and test placeholders.
2. Ensure no ambiguity remains before parser changes.

Tasks:

1. Add this plan file and a short implementation checklist in `dev-docs/NextSteps/` (optional but recommended).
2. Add test stubs in `src/core/parser.rs` tests and `src/assembler/tests.rs` for:
range parsing, list parsing, `.for` parsing, `.while` parsing, `.struct` parsing.
3. Add TODO markers for all upcoming diagnostic strings from the design doc.

Exit criteria:

1. Baseline tests still pass.
2. New stubs compile and fail only where expected.

Suggested commit:
`chore(plan): scaffold ranges/lists/repetition implementation checkpoints`

## Phase 1: Tokenizer + AST + Parser Foundation

Objectives:

1. Parse all new expression forms and directive heads.
2. Keep existing syntax behavior unchanged.

Tasks:

1. Extend tokenizer operators:
`OperatorKind::Range` for `..`,
`OperatorKind::RangeInclusive` for `..=`.
2. Ensure lexing order prefers `..=` over `..`, and `..` over `.`.
3. Extend `Expr` with:
`Range`, `List`, `Index`, `Member`, `Call`, and `Placeholder` (`?`).
4. Add parser precedence level for range expressions:
between compare and comma handling.
5. Add postfix parser loop for chained index/member:
`base[n].field`.
6. Add builtin-call parser for dot-prefixed functions:
`.len(expr)`.
7. Add list literal parser for `{}` and `{expr,...}`.
8. Add dedicated parse paths for directives with non-comma grammar:
`.for`, `.bfor`, `.while`, `.bwhile`, `.struct`, `.endstruct`, `.endfor`, `.endwhile`.
9. Mirror expression parser changes in `src/vm/runtime/runtime_expr_parser.rs`.
10. Update parser and tokenizer tests for:
`0..8`, `0..=7`, `0..16:2`, `10..=0:-1`, `{1,2,3}`, `table[2]`, `table[2].x`, `.len(table)`, `0...len(a)`.

Exit criteria:

1. Parser can produce AST for all new syntax forms.
2. Existing parser tests remain green.
3. VM runtime expression parser contract tests remain green.

Suggested commit:
`feat(parser): add range/list/index/member/call syntax and repetition directive parsing`

## Phase 2: Value Model and Expression Evaluation

Objectives:

1. Add compile-time compound value support without breaking scalar paths.
2. Provide unified evaluation for scalar, range, list, and struct values.

Tasks:

1. Introduce `AsmValue`, `StructDef`, `StructField` in `src/core/asm_value.rs`.
2. Add assembler-side value storage:
`HashMap<String, AsmValue>` for non-scalar symbols and scalar wrappers where needed.
3. Add helper APIs:
`len`, `iter`, `get`, `to_list`, `field_offset`, scalar conversion.
4. Refactor `eval_expr_ast` path:
add `eval_value_ast` returning `AsmValue`,
retain scalar-only wrapper for instruction/data directives.
5. Implement range normalization/validation:
non-zero step, direction compatibility, inclusive-end rewrite.
6. Implement list operators:
`list + list` concat,
`list * n` repetition.
7. Implement index evaluation for list/range with bounds checks.
8. Implement `.len(...)` builtin in expression evaluator.
9. Implement member evaluation path:
only valid when a struct context exists.
10. Update VM expression compiler behavior:
for unsupported compound-only expressions in VM path, fail cleanly and force host evaluation where applicable.

Exit criteria:

1. Scalar legacy expressions behave exactly as before.
2. New expression unit tests pass.
3. Error diagnostics match required messages for step/bounds/type errors.

Suggested commit:
`feat(expr): introduce AsmValue and evaluate ranges/lists/index/member/len`

## Phase 3: `.struct` and Struct Table

Objectives:

1. Support struct type definitions with field offsets and size.
2. Emit no bytes during struct definition.

Tasks:

1. Add `StructTable` module and wire it into assembler state.
2. Add `.struct/.endstruct` directive handling and state machine.
3. Inside struct mode, accept field declarations with `.byte/.word/.long/.res N` and placeholder `?`.
4. Record field offsets and total size.
5. Define scalar symbols:
`StructName` as size,
`StructName.field` as offset.
6. Register struct definition in value/struct table for member/index typing.
7. Add diagnostics:
unmatched `.endstruct`,
unterminated `.struct`,
invalid field directive in struct body.

Exit criteria:

1. Struct definitions parse and register correctly.
2. No program bytes emitted inside struct blocks.
3. Existing non-struct directives unaffected.

Suggested commit:
`feat(directives): add .struct/.endstruct with struct symbol and offset resolution`

## Phase 4: `.for` and `.endfor` Core Loop Engine

Objectives:

1. Implement counted and collection-based `.for`.
2. Execute loops in both passes with stable iteration enforcement.

Tasks:

1. Add repetition execution module (`src/assembler/repetition.rs`) with:
`RepeatBlock`, `RepeatKind`, runtime loop context.
2. Refactor pass engine loop traversal (`src/assembler/engine.rs`) to support block collection and recursive execution.
3. Implement `.for <count>` expansion (`0..count-1` semantics).
4. Implement `.for <var> in <iterable>` expansion for list/range values.
5. Implement loop variable scoping for unscoped `.for` (variable visible only in body execution context, no block scope).
6. Enforce label prohibition in unscoped `.for` body and on `.endfor`.
7. Add pass1/pass2 iteration count stability check and diagnostic.
8. Add loop iteration safety ceiling integration (temp constant until CLI option lands in Phase 6).

Exit criteria:

1. Nested `.for` works.
2. Unscoped label prohibition errors trigger correctly.
3. Loop body emits expected bytes and listing lines.

Suggested commit:
`feat(loop): implement .for/.endfor with two-pass stability and unscoped label guard`

## Phase 5: `.bfor` and Labeled Repetition

Objectives:

1. Add scoped repetition semantics.
2. Support labeled repetition output indexing.

Tasks:

1. Extend `ScopeKind` with `Repeat` and integrate pop/push behavior.
2. Implement `.bfor` as `.for` + per-iteration implicit repeat scope.
3. Add labeled repetition behavior:
collect base addresses per iteration into `AsmValue::List`.
4. Implement implicit struct inference from sub-label layout for labeled `.bfor`.
5. Implement explicit struct annotation:
`.bfor ... : StructName`
with per-iteration size checks.
6. Wire `Expr::Index` + `Expr::Member` for struct-typed labeled repetition lists.
7. Add diagnostics:
missing struct type for member access,
unknown struct field,
annotated size mismatch.

Exit criteria:

1. `label[n]` returns iteration base addresses.
2. `label[n].field` resolves correctly with implicit and explicit struct metadata.
3. Scoped labels no longer collide across iterations.

Suggested commit:
`feat(loop): add .bfor scoped repetition and labeled list/struct access`

## Phase 6: `.while` and `.bwhile` + CLI Safety Limit

Objectives:

1. Implement condition-driven loops.
2. Make loop limit configurable from CLI.

Tasks:

1. Implement `.while/.endwhile` execution in repetition engine.
2. Implement `.bwhile` per-iteration repeat scope.
3. Enforce unscoped label prohibition in `.while`.
4. Add CLI option `--max-loop-iterations` with default `65536` in `src/assembler/cli.rs`.
5. Add env override (optional) if following existing CLI env pattern.
6. Propagate configured max-iterations into assembler/engine state.
7. Add diagnostics for exceeded loop limit and unmatched `.endwhile`.

Exit criteria:

1. `.while` loops terminate and emit expected output.
2. Infinite loop protection works and is test-covered.
3. CLI parse/validate tests cover new flag and invalid values.

Suggested commit:
`feat(loop): add .while/.bwhile and configurable max loop iteration guard`

## Phase 7: Integration Details and Compatibility

Objectives:

1. Ensure macro/segment parameter paths work with ranges/lists.
2. Keep formatter, VM bridge, and diagnostics parity stable.

Tasks:

1. Verify macro text substitution path accepts range/list literals without macro processor rewrites.
2. Verify `.segment` parameter parsing behavior with new expressions.
3. Update `src/formatter/surface_parser.rs` operator handling if range operators affect parsing/splitting.
4. Update `is_scope_directive`/top-level checks to include new block directives where needed.
5. Ensure diagnostic/fixit behavior remains deterministic under VM/native parity tests.

Exit criteria:

1. No regressions in macro/segment tests.
2. Formatter tests pass.
3. VM/native contract tests pass for impacted expression paths.

Suggested commit:
`fix(integration): wire repetition/value features through macro/formatter/runtime compatibility paths`

## Phase 8: Examples, References, Docs, and Final Validation

Objectives:

1. Ship user-facing examples and synchronized docs.
2. Regenerate references only for intentional deltas.

Tasks:

1. Add new success examples (suggested names):
`examples/ranges_lists_basic.asm`,
`examples/for_counter_basic.asm`,
`examples/for_collection_basic.asm`,
`examples/bfor_labeled_struct_basic.asm`,
`examples/while_basic.asm`.
2. Add new explicit error examples (must include `error` in filename):
`examples/for_unscoped_label_error.asm`,
`examples/while_unscoped_label_error.asm`,
`examples/range_step_direction_error.asm`,
`examples/range_step_zero_error.asm`,
`examples/index_out_of_bounds_error.asm`,
`examples/loop_pass_instability_error.asm`.
3. Run tests before reference regeneration.
4. If expected deltas only, regenerate references and re-test.
5. Update docs:
`documentation/opForge-reference-manual.md`,
`README.md`,
`CHANGELOG.md`.
6. Do not create or edit release notes unless releasing a new tag.

Exit criteria:

1. New examples pass and references are synchronized.
2. Manual and README syntax/docs match implementation.
3. Changelog includes feature summary and migration notes.

Suggested commit:
`docs/examples: add ranges-lists-repetition examples, references, and manual updates`

## Phase 9: Formatter and LSP Parity for New Syntax and Semantics

Objectives:

1. Ensure formatter understands and preserves/normalizes the new syntax safely.
2. Ensure LSP semantic features resolve the new constructs consistently with assembler behavior.

Tasks:

1. Update formatter surface tokenization/parsing for:
`..`, `..=`, `:step`, list literals, index/member chains, and `.for/.bfor/.while/.bwhile/.struct` block directives.
2. Update formatter planner/renderer so formatting remains idempotent for new constructs and block layout remains stable.
3. Add/extend formatter fixtures for:
range/list expressions, `.len(...)`, index/member expressions, nested repetition directives, and struct blocks.
4. Verify formatter semantic token projection preservation tests for range/list/repetition/member notation.
5. Extend LSP diagnostics path so parse/eval diagnostics for new notation are surfaced with stable spans.
6. Extend LSP hover/definition/symbol extraction behavior for:
loop variables, indexed labeled repetition symbols (`label[n]`), and struct field member access (`label[n].field`).
7. Extend LSP completion context handling for `.for/.while/.struct` and member/index expression contexts where supported.
8. Add LSP regression/integration tests covering dialect-sensitive and VM-only execution combinations for impacted semantics.
9. Confirm formatter and LSP behavior parity against assembler diagnostics on the same source fixtures.

Exit criteria:

1. Formatter fixture snapshots and idempotence tests pass with intentional outputs only.
2. LSP validation/integration tests for new notation pass.
3. Assembler vs LSP diagnostics are consistent for the new syntax on shared fixtures.
4. No regressions in existing formatter/LSP scenarios.

Suggested commit:
`feat(tooling): add formatter and lsp support for ranges/lists/repetition semantics`

## Phase 10: Typed Literal Struct Instances

Objectives:

1. Support typed struct literal expressions assignable to `.const/.var/.set` and assignment forms.
2. Define member semantics clearly for struct type symbols vs struct instance values.

Tasks:

1. Extend parser/AST with a typed struct literal expression form:
`StructName { field: expr, ... }`.
2. Implement parser validation for field initializer grammar:
identifier field names + colon + expression + comma separation.
3. Extend `AsmValue` with a struct-instance variant storing:
resolved struct type and per-field scalar values.
4. Implement evaluator validation:
unknown field, duplicate field, missing required field, and unknown struct type diagnostics.
5. Preserve existing semantics:
`StructName.field` resolves to field offset,
`instance.field` resolves to field value.
6. Keep a single symbol namespace/scope across scalar/set/struct symbols:
resolve exact dotted symbols first, then typed member access fallback (`base.field`) when no exact symbol exists.
7. Integrate literal struct instances in symbol assignment paths:
`.const/.var/.set`, `=`, `:=`, and value-symbol storage.
8. Keep assignment operator constraints explicit:
scalar operators (`+=`, etc.) reject struct-instance symbols.
9. Add parser/evaluator/integration tests and example fixtures for:
literal declaration, field access, validation failures, and scalar/non-scalar transitions.
10. Update formatter/LSP expectations for the new typed-literal syntax where needed.

Exit criteria:

1. Typed struct literals parse and evaluate deterministically across passes.
2. Assigned struct-instance symbols can be referenced via member expressions.
3. Existing struct type offset behavior remains unchanged.
4. Diagnostics for invalid literals are stable and covered by tests.

Suggested commit:
`feat(struct): add typed struct literal instances and member value access`

## 7. Required Test Matrix

Minimum required tests to add or update:

1. Tokenizer tests:
`..`, `..=`, `...len` tokenization, list braces with existing bracket behavior.
2. Parser tests:
range/list/index/member/call/placeholder parsing,
`.for/.bfor/.while/.bwhile/.struct` heads and block terminators.
3. Expression evaluator tests:
range normalization,
list operations,
`.len`,
index bounds,
member access type errors.
4. Struct tests:
field offset calculation and size symbol definition.
5. Loop tests:
counted loops,
iterable loops,
nested loops,
pass stability mismatch,
max iteration guard,
label prohibition.
6. Scoped loop tests:
per-iteration label isolation and labeled repetition indexing.
7. CLI tests:
`--max-loop-iterations` parse/validation.
8. Example/reference tests:
`examples_match_reference_outputs`,
`project_root_example_matches_reference_outputs`.
9. Formatter tests:
fixture snapshots, idempotence, and semantic token projection for range/list/repetition/member syntax.
10. LSP tests:
diagnostics, hover, definition, completion, and document symbols for new syntax/semantics.
11. Struct literal tests:
typed literal parsing, exact field coverage validation, symbol assignment, and instance member value access.

## 8. Diagnostics Contract (must match)

Implement and test these messages (exact text or stable equivalent):

1. `error: range step must be non-zero`
2. `error: range step direction conflicts with start..end`
3. `error: loop iteration count changed between passes (pass1: N, pass2: M)`
4. `error: loop exceeded maximum iteration limit (65536)` (or configured value)
5. `error: .endfor without matching .for`
6. `error: unterminated .for (opened at line N)`
7. `error: index X out of bounds for 'name' (0..Y)`
8. `error: label 'X' not allowed inside .for (use .bfor for scoped repetition)`
9. `error: label 'X' not allowed inside .while (use .bwhile for scoped repetition)`
10. `error: label not allowed on .endfor / .endwhile`
11. `error: expected range or list after 'in', found scalar`
12. `error: .endstruct without matching .struct`
13. `error: unterminated .struct (opened at line N)`
14. `error: no struct type associated with 'name' for field access`
15. `error: struct 'S' has no field 'f'`
16. `error: iteration body size (N) does not match struct 'S' size (M)`
17. `error: unknown field 'f' in struct literal for 'S'`
18. `error: duplicate field 'f' in struct literal for 'S'`
19. `error: missing required field 'f' in struct literal for 'S'`
20. `error: unknown struct type 'S' for struct literal`

## 9. Final Definition of Done

All must be true:

1. All Phase 1-10 objectives are completed.
2. `cargo fmt --all`, `cargo clippy -- -D warnings`, `cargo audit`, and `make test` pass.
3. CI matrix succeeds for all supported build/runtime combinations, including VM-only variants, by passing:
`make ci-core`,
`make ci-vm-mos6502`,
`make ci-vm-intel8080`,
`make test-vm-opcpu-modes`,
`make test-build-profile-matrix`,
`make test-build-combo-smoke`.
4. `make reference-test` passes after any intentional reference updates.
5. New docs/examples are aligned with implemented behavior.
6. No open ambiguity remains for v0.1 scope.

Validation snapshot (executed on 2026-03-03):

1. `cargo fmt --all` passed.
2. `cargo clippy -- -D warnings` passed.
3. `cargo audit` passed.
4. `cargo test` passed.
5. `make ci-core` passed.
6. `make ci-vm-mos6502` passed.
7. `make ci-vm-intel8080` passed.
8. `make test-vm-opcpu-modes` passed.
9. `make test-build-profile-matrix` passed.
10. `make test-build-combo-smoke` passed.
11. `make reference-test` passed.

## 10. Final Squash-Free Commit Sequence (executed)

1. `20eabdc` `docs(plan): add executable implementation plan for ranges/lists/repetition v0.1`
2. `c080e53` `feat(parser): add range tokenization and Expr::Range parsing foundation`
3. `9f692f4` `feat(parser): parse list/index/member/call/placeholder expression forms`
4. `d1fe47b` `feat(parser): add dedicated repetition/struct directive head parsing`
5. `2ca9627` `feat(expr): add AsmValue foundation for ranges/lists/struct metadata`
6. `ed85dd6` `feat(struct): add StructTable registry foundation`
7. `cac9e92` `feat(directives): implement .struct/.endstruct with field offset symbols`
8. `c4eb9a1` `feat(expr): evaluate range/list/index and .len in host expression path`
9. `43282e6` `feat(loop): implement .for/.endfor engine with pass-stability checks`
10. `9ae23e7` `feat(loop): implement .bfor scoped repetition and label indexing`
11. `2e2a701` `feat(loop): add .while/.bwhile with iteration guard`
12. `0b2d6e9` `fix(integration): stabilize range/list/repetition compatibility paths`
13. `6dafed5` `docs/examples: add ranges-lists-repetition examples and manual sync`
14. `1448542` `docs(plan): add formatter and lsp implementation phase`
15. `605292b` `fix(expr): allow non-scalar const/var symbol values`
16. `c35ccea` `examples: add struct variable assignment example`
17. `168456b` `docs(plan): add struct-literal phase and spec semantics`
18. `507bdf3` `feat(struct): implement typed struct literal instances`
19. `3fa1dfc` `feat(struct): unify typed symbol member access with dotted identifiers`
20. `fc25a30` `feat(tooling): extend formatter and LSP for struct member contexts`
