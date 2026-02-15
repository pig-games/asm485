# opThread VM Line Pipeline Phase A Plan (v0.1)

## Problem statement
Phase A makes assembly-line processing consume tokenization through the opThread runtime tokenizer path while preserving current parser semantics and current hybrid instruction emission behavior.  
Immediate target: replace line-local host tokenization in `AsmLine::process` without parser/AST regressions.

## Current state (validated)
- `AsmLine::process` still tokenizes through `Parser::from_line_with_registers(...)` (`src/assembler/mod.rs:2448`).
- `Parser` only exposes line-based constructors that tokenize internally (`src/core/parser.rs:198`, `src/core/parser.rs:207`).
- Runtime already has tokenization mode dispatch and owner-precedence token policy (`src/opthread/runtime.rs:933`, `src/opthread/runtime.rs:1083`, `src/opthread/runtime.rs:1168`).
- Instruction emission is already VM-first with native fallback (`src/assembler/mod.rs:3330`, `src/assembler/mod.rs:3472`, `src/assembler/mod.rs:3539`).
- Bootstrap and macro pre-scan parsing still parse directly from raw lines (`src/assembler/bootstrap.rs:345`, `src/core/macro_processor.rs:553`, `src/core/macro_processor.rs:661`).

## Scope boundaries
### In scope (Phase A)
- Assembly-line tokenization path in `AsmLine::process` (pass1/pass2).
- Parser intake extension for externally tokenized input.
- Compatibility behavior for diagnostics and AST outcomes.

### Out of scope (Phase A)
- Removing native instruction emission fallback.
- Replacing parser grammar/AST with a VM parser.
- Full migration of bootstrap/macro pre-scan tokenization.

## Design approach
Introduce a parser constructor that accepts pre-tokenized core tokens, then route `AsmLine::process` through runtime tokenizer output mapped into parser-compatible token structures. Keep parse behavior identical by reusing existing parse logic after token-vector initialization.

## Phase A execution checklist
### 1) Token bridge: runtime tokens -> parser tokens
- [x] Add an internal conversion layer from runtime token output to `core::tokenizer::Token`/`TokenKind`.
- [x] Preserve span fidelity (`line`, `col_start`, `col_end`) and casing assumptions used by parser/expression code.
- [x] Map all operators and punctuation 1:1 to parser token categories.
- [x] Add deterministic conversion failure diagnostics for impossible token mappings.

### 2) Parser constructor for externally supplied tokens
- [x] Add parser entrypoint (e.g. `Parser::from_tokens(...)`) initialized from token vector + end-of-line metadata.
- [x] Reuse existing `parse_line` implementation unchanged.
- [x] Keep `from_line`/`from_line_with_registers` intact for compatibility callers.

### 3) Wire `AsmLine::process` to runtime tokenizer path
- [x] In runtime-enabled path with active execution model, tokenize via runtime before parser construction.
- [x] Resolve tokenization mode/policy through runtime using active CPU pipeline context.
- [x] Build parser from mapped token stream and preserve parser error plumbing (`last_parser_error`, `last_error_column`, `line_end_span`, `line_end_token`).
- [x] Define deterministic runtime-tokenization failure behavior (no panics; usable diagnostics).

### 4) Preserve non-runtime and staged-runtime behavior
- [x] Keep existing host parser construction when runtime is disabled or model is absent.
- [x] Preserve staged-family behavior unless runtime is explicitly injected/enabled by tests.

### 5) Add/expand tests
- [x] Add assembler-level parity tests for VM-tokenized `AsmLine::process` vs existing host path on representative directives/instructions.
- [x] Add parser tests for `from_tokens(...)` (label at column 1, comments/end-span handling, column-accurate errors).
- [x] Add token-bridge unit tests (operators, strings, register ids, malformed token rejection).
- [x] Re-run existing runtime/assembler parity suites to verify no regression.

### 6) Validation and gate
- [x] Run `cargo fmt`.
- [x] Run `cargo clippy`.
- [x] Run `cargo audit`.
- [x] Run full tests (`make test` or `cargo test`).
- [x] Run `make reference-test` to verify no unintended fixture drift.
- [x] If only diagnostic text differs, follow reference update policy after passing behavior checks (not needed in this pass; no reference drift observed).

## Acceptance criteria
- `AsmLine::process` uses runtime-tokenized input (not line-local host tokenizer) when runtime model is active.
- AST outcomes and emitted bytes remain parity-equivalent for covered corpus.
- Parser diagnostics remain stable or intentionally improved with explicit test updates.
- Existing runtime parity and staged-family behavior remain green.

## Risks and mitigations
- Token-shape mismatch with parser expectations  
  - [x] Mitigate with strict conversion tests and span-rich deterministic failures.
- End-span / comment drift vs current parser behavior  
  - [x] Mitigate by carrying explicit end-of-line metadata and targeted tests.
- Hidden dependencies in bootstrap/macro pre-scan paths  
  - [x] Mitigate by keeping those call sites unchanged in Phase A and scheduling later migration.

## Following phases
### Phase B (post-Phase A): VM-authoritative emission
- [ ] Expand strict expr-resolver coverage and VM program completeness per family/CPU.
- [ ] Tighten/replace native fallback chain for authoritative families (`src/assembler/mod.rs:3472`, `src/assembler/mod.rs:3539`).
- [ ] Align rollout policy/model availability as needed (`src/opthread/rollout.rs:22`).

### Phase C (post-Phase B): VM parser/AST pipeline
- [ ] Define package-level parser grammar/AST contract and chunk schema.
- [ ] Implement parser VM execution + diagnostics contract.
- [ ] Migrate assembler, macro, and bootstrap parse call sites to VM parser path with compatibility gates.

### Optional Phase D: full pre-assembly parse-path unification
- [ ] Migrate bootstrap and macro statement pre-scan parsing to shared runtime tokenization/parser abstractions (`src/assembler/bootstrap.rs:345`, `src/core/macro_processor.rs:553`, `src/core/macro_processor.rs:661`).
- [ ] Remove duplicate line-tokenization paths where safe.

## Recommended execution order
Run Phase A steps 1 -> 6 in order, then hold a checkpoint review before Phase B strictness/rollout changes.
