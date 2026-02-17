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
### Phase B (post-Phase A): VM-authoritative emission and tokenizer ubiquity

Status: in progress (refreshed 2026-02-17, post Intel8080 tokenizer authority expansion)

Requested target: all assembler tokenization in opForge runs through VM tokenization paths, with authoritative VM behavior for certified families.
Current note: tokenizer authority now covers MOS6502 + Intel8080 families; Intel instruction-emission runtime rollout policy remains staged.

#### B1) Replace placeholder tokenizer VM programs with real bytecode
- [x] Replace `TokenizerVmOpcode::End` placeholder programs emitted by builder with bootstrap tokenizer VM bytecode per rollout family (deterministic line-walk, non-emitting).
- [x] Keep policy ownership and precedence unchanged (`dialect -> cpu -> family`), but ensure authoritative families have runnable tokenizer VM programs.
- [x] Add tokenizer VM parity corpus gates for each rollout family before enabling strict authority.

#### B2) Switch assembler-owned tokenization calls to strict VM for authoritative families
- [x] Move assembler-owned call sites to strict VM tokenization entrypoints for authoritative families (`tokenize_portable_statement_vm_authoritative` path).
- [x] Remove implicit host fallback from authoritative-family assembler tokenization call paths.
- [x] Keep host/delegated fallback only for staged families and explicit debug/compatibility modes.

#### B3) Prove host tokenizer is not used for authoritative families
- [x] Add tests that fail if authoritative-family tokenization silently falls back to host path.
- [x] Add regression tests for empty-token, invalid-opcode, and malformed-state failure behavior under strict authoritative mode.
- [x] Keep deterministic diagnostics and span behavior in strict mode.

#### B4) Rollout and expansion sequence
- [x] Enable authoritative strict VM tokenization for one family lane first (MOS6502 family).
- [x] Re-run full validation gates (`cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`, runtime-feature suites).
- [x] Expand the same strict-authoritative tokenizer gate to Intel8080 family after parity/diagnostic gates are green.

### Phase C (post-Phase B): VM parser/AST pipeline
- [ ] Define package-level parser grammar/AST contract and chunk schema.
- [ ] Implement parser VM execution + diagnostics contract.
- [ ] Migrate assembler, macro, and bootstrap parse call sites to VM parser path with compatibility gates.

### Optional Phase D: full pre-assembly parse-path unification
- [ ] Migrate bootstrap and macro statement pre-scan parsing to shared runtime tokenization/parser abstractions (`src/assembler/bootstrap.rs:345`, `src/core/macro_processor.rs:553`, `src/core/macro_processor.rs:661`).
- [ ] Remove duplicate line-tokenization paths where safe.

## Recommended execution order
Run Phase A steps 1 -> 6 in order, then hold a checkpoint review before Phase B strictness/rollout changes.

## Phase B extension (requested outcome)
Requested target: all assembler tokenization in opForge runs through opThread VM tokenization paths.

Implementation intent in this pass:
- Route assembly-line parsing, bootstrap pre-scan parsing, and macro statement tokenization through a shared VM token bridge.
- Keep host tokenization as compatibility/debug mode only, not as the authoritative path for assembler-owned tokenization call sites.
