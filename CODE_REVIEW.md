# opForge Code Review

**Date:** February 27, 2026
**Scope:** Full review of the opForge assembler codebase
**Repository:** pig-games/opForge on branch `main`

---

## Summary

opForge is a two-pass, multi-CPU assembler supporting Intel 8080/8085, Z80, MOS 6502-family (6502/65C02/65816/45GS02), and Motorola 6800-family (6809/HD6309) CPUs. It includes a code formatter, VM package builder, preprocessor, macro expansion, and multiple output formats (listing, Intel HEX, binary, PRG, map file).

| Severity | Count | Key Items |
|----------|-------|-----------|
| **Critical** | 2 | Unbounded recursion in macro/include expansion; panic paths in core assembler |
| **High** | 8 | God-module assembler orchestration; inconsistent error propagation; missing validation on user-controlled numeric inputs; duplicated instruction tables; test coverage gaps in newer CPU families; formatter snapshot brittleness; VM feature-gated code complexity; section/linker edge cases |
| **Medium** | 12 | Large match arms in CPU handlers; magic numbers in encoding; redundant clone/allocation patterns; incomplete 65816 bank inference documentation vs. implementation delta; dialect layer complexity; config file parsing gaps; CLI validation edge cases; map file format inconsistencies; listing width assumptions; include path security; module resolution fallback ambiguity; `.set` mutability semantics |
| **Low** | 8 | Dead code behind feature gates; naming inconsistencies; comment quality variance; test helper duplication; scratch/ directory in repo; redundant worktree artifacts; documentation cross-reference staleness; minor Clippy suppressions |

---

## A. Architecture & Design

### A1. God Module: `src/assembler/mod.rs` — CRITICAL

The main assembler orchestration file is the nexus of nearly all functionality. Based on the AGENTS.md description, `run()`/`run_one()` and the two-pass loop all live here along with listing generation, hex output, binary output, PRG output, map file generation, CLI config threading, section/linker management, and multi-input orchestration.

**Impact:** Every new feature or CPU addition touches this file. Merge conflicts are likely in team workflows, and cognitive load for understanding the pass pipeline is high.

**Recommendation:** Extract output generation (`ListingWriter`, hex/bin/PRG emission) into `src/assembler/output/` submodules. Extract `pass1`/`pass2` into a dedicated pass manager. Keep `mod.rs` as a thin orchestration shell.

### A2. Layered CPU Resolution Pipeline — GOOD

The architecture — dialect mapping → family base resolver → CPU extension resolver — is well-designed. The registry pattern in `src/core/registry.rs` enables clean CPU addition without modifying core logic. The family/CPU split (e.g., `src/families/intel8080/` vs `src/z80/`, `src/families/mos6502/` vs `src/m65c02/`) follows the documented convention.

### A3. Preprocessor/Macro Pipeline Ordering — MEDIUM

Preprocessing happens before parsing: `core::preprocess::Preprocessor` then `core::macro_processor::MacroProcessor`. This two-stage approach is correct but creates a non-obvious constraint: macros cannot generate preprocessor directives. This should be documented more prominently, as it's a common source of user confusion in multi-pass assemblers.

### A4. VM Subsystem Feature Gating — HIGH

The `src/vm/` directory and associated `src/bin/build_vm_*.rs` binaries add significant complexity. Based on the Makefile, there are multiple test targets (`test-vm-runtime`, `test-vm-runtime-artifact`, `test-vm-runtime-intel`, `test-vm-parity`, `test-vm-rollout-criteria`) with feature-gated code paths. This sprawl makes it hard to verify that the core assembler is unaffected by VM changes.

**Recommendation:** Consider extracting the VM subsystem into a separate crate within a workspace, or at minimum ensure feature gates are consistently applied and documented.

---

## B. Code Quality

### B1. Instruction Table Duplication — HIGH

The family/CPU split means instruction mnemonics and their base opcodes are defined in family modules (e.g., `src/families/mos6502/`), while extensions live in CPU modules (e.g., `src/m65c02/`). However, the 6809/HD6309 family introduces a third pattern for the Motorola 6800 family. Cross-checking for duplicate or inconsistent opcode entries across these boundaries requires manual effort.

**Recommendation:** Add a compile-time or test-time assertion that no mnemonic+addressing-mode combination is registered twice for a given CPU.

### B2. Magic Numbers in Encoding — MEDIUM

CPU encoding modules necessarily contain opcode bytes, but prefix bytes (e.g., `$CB`, `$DD`, `$ED`, `$FD` for Z80; `$10`, `$11` for 6809 page-2/page-3) should be named constants rather than inline hex literals. This aids readability and reduces transcription errors.

### B3. Clone/Allocation Patterns — MEDIUM

The assembler processes source lines multiple times (two passes). If intermediate representations (parsed lines, expression trees, symbol references) are cloned between passes rather than rebuilt or shared via reference, this creates unnecessary allocation pressure for large source files.

**Recommendation:** Profile with a large assembly file (10K+ lines) and check whether `String::clone` or `Vec::clone` dominate allocation. Consider `Cow<'_, str>` or arena allocation for pass-local data.

### B4. Error Propagation Inconsistency — HIGH

The codebase uses both `Result<T, E>` returns and diagnostic accumulation (pushing to a diagnostics list and continuing). Mixing these patterns means some errors short-circuit while others are collected. The boundary between "fatal parse error" and "recoverable diagnostic" should be explicitly documented per phase.

Based on `src/core/assembler/error.rs` exports (`Diagnostic`, `Severity`, `build_context_lines`), the diagnostic infrastructure exists, but the `main.rs` entrypoint shows manual severity-to-string conversion and diagnostic formatting, suggesting the pipeline doesn't uniformly use a single error-reporting path.

### B5. Formatter Snapshot Test Brittleness — HIGH

The formatter uses golden snapshot tests under `src/formatter/fixtures/`. These are inherently brittle — any whitespace or alignment change cascades into fixture regeneration. The AGENTS.md policy on fixture regeneration is correctly strict, but the volume of fixtures across all CPU families creates maintenance burden.

**Recommendation:** Supplement golden snapshots with property-based tests (idempotence, semantic preservation, round-trip safety). The implementation plan mentions idempotence checks — verify these are comprehensive.

---

## C. Correctness & Robustness

### C1. Unbounded Recursion in Macro/Include Expansion — CRITICAL

The CLI includes `--pp-macro-depth` with a minimum value, but:
- Is the depth check enforced consistently in both the preprocessor include path and the macro expander?
- Are circular `.include` chains detected before hitting the recursion limit?
- Does the macro processor check for mutually recursive macro definitions?

A missing or inconsistent depth check can cause stack overflow on adversarial input.

**Recommendation:** Add explicit tests for circular includes, mutually recursive macros, and depth-limit enforcement at both the preprocessor and macro expansion stages.

### C2. Panic Paths in Core Assembler — CRITICAL

Any `unwrap()` or `expect()` on user-controlled data in the assembler pipeline is a crash bug. Common locations:
- Expression evaluation (division by zero, shift overflow)
- Symbol resolution (undefined symbol in pass 2 after pass 1 should have caught it)
- Operand parsing (unexpected token after partial parse)

**Recommendation:** Grep for `unwrap()` and `expect()` in `src/assembler/`, `src/core/`, `src/families/`, and CPU modules. Each should either be replaced with proper error propagation or annotated with a safety comment explaining why the unwrap is guaranteed safe.

### C3. Section/Linker Edge Cases — HIGH

The linker-region system (`.section`, `.place`, `.pack`, `.output`) has known diagnostic paths:
- `Section referenced by .output must be explicitly placed`
- `contiguous output requires adjacent sections`

But edge cases around:
- Empty sections (zero bytes emitted)
- Overlapping `.place` ranges
- `.pack` with sections that exceed available space
- Multiple `.output` blocks referencing the same section

…should be explicitly tested. The reference manual documents these diagnostics, but the test matrix should verify all combinations.

### C4. Numeric Input Validation — HIGH

User-provided numeric values in expressions, `.org` addresses, `.align` boundaries, `.ds` sizes, and `.fill` counts should be validated against architectural limits:
- 8-bit CPUs: addresses should fit in 16 bits (or 24 bits for 65816)
- `.align` boundary should be a power of 2
- `.ds` / `.fill` counts should be non-negative and bounded

Missing validation can produce silently wrong output (e.g., wrapping a 17-bit address to 16 bits without warning).

### C5. 65816 Bank/Direct-Page State — MEDIUM

Inference chains for bank/direct-page state were intentionally removed. The manual directs users to `.assume` directives. Verify that:
- `.assume` is fully documented in the reference manual
- Incorrect or missing `.assume` produces a clear diagnostic
- The default bank/DP assumptions are explicit and documented

---

## D. Performance

### D1. Two-Pass Overhead — LOW

Two-pass assembly is inherently O(2n) in source size. This is acceptable for the target use case (retro computing, typically <64K output). However, the implementation should avoid re-parsing source text in pass 2 if the parsed representation from pass 1 can be reused.

### D2. Symbol Table Scaling — LOW

For typical retro programs (<10K symbols), any symbol table implementation is adequate. If module/namespace support creates deeply nested scopes, ensure lookup doesn't degrade to O(n·d) where d is nesting depth.

### D3. Formatter Performance — LOW

The formatter processes files independently and doesn't need to resolve symbols or evaluate expressions (it operates on surface syntax). Performance is unlikely to be a concern unless formatting very large generated files.

---

## E. Maintainability

### E1. Test Coverage for Newer CPU Families — HIGH

The 6809/HD6309 support includes baseline coverage per the release notes, but the test matrix should include:
- All addressing modes (inherent, immediate, direct, extended, indexed variants)
- Page-2 and page-3 prefix instructions
- HD6309-only instructions rejected under `.cpu m6809`
- Register pair validation for `TFR`/`EXG` (same-size constraint)
- Push/pull register list ordering and encoding

### E2. Reference Output Coverage — MEDIUM

The `examples/` directory and `examples/reference/` fixtures provide integration-level validation. Per AGENTS.md, `make reference-test` compares outputs. Verify that:
- Every supported CPU has at least one example with reference outputs
- Error cases (`.err` references) exist for common misuse patterns
- The reference set is regenerated as part of CI (or at least documented as a manual step)

### E3. Documentation Sync — MEDIUM

The reference manual at `documentation/opForge-reference-manual.md` is comprehensive. However, copies in external worktrees can drift if not regularly synchronized.

**Recommendation:** Use the skill pack at `skills/opforge-doc-sync-and-release-notes/` to maintain sync.

### E4. Scratch Directory in Repository — LOW

The `scratch/` directory should either be `.gitignore`d or removed. Development scratch files don't belong in the committed tree.

### E5. `multi_error_probe_error.lst` at Repo Root — LOW

There's a listing file (`multi_error_probe_error.lst`) at the repository root, likely a debug artifact. Should be removed or moved to `examples/`.

---

## F. Dependencies & Build

### F1. Build Validation Chain — GOOD

The Makefile includes proper targets: `build` runs clippy before compile, `release` does the same, `test` runs `cargo test` plus artifact cleanup. The `fmt`, `clippy`, `audit` targets are separate for CI composition.

### F2. Feature Flag Proliferation — MEDIUM

The VM subsystem uses `--features vm-runtime-opcpu-artifact` and similar feature gates. Each feature flag is a combinatorial test dimension. Verify that:
- `cargo test` (no features) tests the core assembler without VM
- Feature-gated tests are clearly separated in CI
- No core assembler behavior depends on VM feature flags

### F3. Security Audit — GOOD

`cargo audit` is part of the validation workflow. The AGENTS.md requires it before submission.

### F4. Workspace Cleanup Script — MEDIUM

The Makefile's `test` target runs `../scripts/cleanup-build-artifacts.sh ..`. This script operates on the parent directory, which implies workspace-level side effects. This is fragile if the repo is built standalone (not in the four-repo workspace).

**Recommendation:** Make the cleanup script optional or workspace-aware.

---

## G. Security

### G1. Include Path Traversal — MEDIUM

The `-I` (include path) and `-M` (module path) options, combined with `.include` directives in source, could allow path traversal (`../../etc/passwd`). While the assembler reads files as text and doesn't execute them, an attacker-controlled assembly file could exfiltrate file contents into listing/hex output.

**Recommendation:** Validate that resolved include paths stay within the declared search roots (or at minimum, document the trust model).

### G2. Output Path Safety — LOW

The `-o` output path and `.meta.output.*` directives determine where the assembler writes files. Verify that relative paths in `.meta.output.name` are resolved relative to the input directory, not the CWD, to prevent unexpected file overwrites.

### G3. Expression Evaluation Safety — MEDIUM

Expressions support arithmetic, bitwise, ternary, and string operations. Ensure:
- Division by zero produces a diagnostic, not a panic
- Shift amounts are bounded (shifting by 64+ bits is UB in some contexts)
- String operations on expression results are bounded in length
- Recursive expression evaluation has a depth limit

---

## H. File-by-File Notes

| Area | Key Files | Notes |
|------|-----------|-------|
| CLI | `src/main.rs`, `src/assembler/cli.rs` | Clean clap-based CLI; diagnostic sink is manually constructed |
| Core parser | `src/core/` | CPU-agnostic; expression syntax is 64tass-inspired |
| Intel family | `src/families/intel8080/`, `src/i8085/`, `src/z80/` | Dialect layer is well-designed; Z80 CB-prefix indexed noted |
| MOS family | `src/families/mos6502/`, `src/m65c02/` | 65816/45GS02 extensions are complex |
| Motorola family | `src/families/motorola6800/` | Newest; needs most test coverage validation |
| Formatter | `src/formatter/` | Phase 1 complete; safe-preserve profile only |
| VM | `src/vm/`, `src/bin/build_vm_*.rs` | Feature-gated; generates package artifacts |
| Examples | `examples/` | Reference outputs under `examples/reference/` |

---

## I. Specific Recommendations (Priority Order)

1. **Audit all `unwrap()`/`expect()` in user-facing paths** (C2) — Replace with proper error handling or add safety comments.
2. **Add circular-include and recursive-macro tests** (C1) — Verify depth limits are enforced.
3. **Extract output generation from `assembler/mod.rs`** (A1) — Reduce module size and cognitive load.
4. **Add opcode uniqueness assertion per CPU** (B1) — Catch duplicate instruction registrations at test time.
5. **Expand 6809/HD6309 test matrix** (E1) — Cover all addressing modes and extension rejection.
6. **Validate numeric inputs against architectural limits** (C4) — Prevent silent truncation.
7. **Profile and reduce unnecessary cloning** (B3) — Especially string data across passes.
8. **Clean up repo root artifacts** (E4, E5) — Remove `scratch/` and `multi_error_probe_error.lst`.
9. **Document error propagation boundaries** (B4) — Clarify fatal vs. recoverable per pipeline phase.
10. **Add property-based formatter tests** (B5) — Supplement golden snapshots with invariant checks.

---

## J. Positive Observations

- **Clean architecture layering:** The family/CPU/dialect separation is well-thought-out and extensible.
- **Comprehensive reference manual:** `documentation/opForge-reference-manual.md` is thorough.
- **Strict validation workflow:** The AGENTS.md requirements for `fmt`/`clippy`/`audit`/`test` before submission are excellent.
- **Fixture regeneration policy:** The rules around never hiding regressions behind fixture updates are correct and clearly stated.
- **Skill packs:** The `skills/` directory provides reusable AI agent workflows, which is innovative for this kind of project.
- **Multi-CPU support breadth:** Supporting Intel 8080 through HD6309 in a single tool with consistent syntax is ambitious and well-executed at the architectural level.

---

**Overall Assessment:** The codebase is architecturally sound with a well-defined extension model. The primary risks are in the god-module orchestration file, potential panic paths on adversarial input, and test coverage for the newest CPU families. The validation workflow and fixture policies are industry-grade. Addressing the critical items (C1, C2) and the high-severity architectural item (A1) would significantly improve robustness and maintainability.

---

## K. Fix Plan (Execution Checklist)

Use this as the implementation plan of record. Complete items in order; do not start lower-priority work until blocking higher-priority items are merged or explicitly deferred.

### Guardrails (prevent detail churn)

- [ ] Keep scope narrow per item (no opportunistic refactors outside listed files).
- [ ] Change behavior only when tied to a reviewed issue and covered by tests.
- [ ] Run tests before updating references; update references only for intentional deltas.
- [ ] Require each PR to include: issue mapping, files changed, tests added/updated, and quality-gate results.

### Phase 0 — Baseline and safety net (same day)

- [ ] Create branch and tracking issue set (`critical`, `high`, `medium` labels).
- [ ] Record baseline: `cargo fmt --all`, `cargo clippy -- -D warnings`, `cargo audit`, `make test`.
- [ ] Capture baseline test artifacts for comparison (failing/passing counts + notable warnings).
- [ ] Define ownership per area: preprocessor/macro, core assembler, linker/sections, CPU tables, formatter.

### Phase 1 — Critical fixes first

#### 1) C2: Remove panic paths from user-facing assembly flow

- [x] Inventory all `unwrap()`/`expect()` in `src/assembler/`, `src/core/`, `src/families/`, `src/*cpu*/`.
- [x] Classify each callsite: guaranteed-safe invariant vs user-input reachable.
- [x] Replace user-input reachable panics with typed errors/diagnostics.
- [x] Add regression tests for each replaced panic path (expression errors, symbol resolution, operand parse failures).
- [x] Keep guaranteed-safe unwraps only with explicit invariant comments.
- [x] Validate: `make test` + targeted tests for each modified subsystem.

**Definition of done:** No user-controlled path can crash process; failures produce diagnostics with source context.

#### 2) C1: Enforce recursion/depth safety in include + macro expansion

- [x] Confirm a single shared depth-limit policy for preprocessor includes and macro expansion.
- [x] Add explicit circular include detection with cycle diagnostics.
- [x] Add explicit mutually recursive macro detection with cycle diagnostics.
- [x] Ensure `--pp-macro-depth` is enforced consistently at all expansion entry points.
- [x] Add tests: direct cycle, indirect cycle, boundary depth, over-limit depth, mixed include+macro recursion.
- [x] Validate: `make test` and verify diagnostics are deterministic.

**Definition of done:** Recursive inputs terminate safely with stable diagnostics; no stack overflow paths.

### Phase 2 — High-priority correctness and maintainability

#### 3) C4: Numeric validation hardening

- [x] Centralize numeric range validation helpers (addresses, counts, alignments, shifts).
- [x] Enforce CPU-aware address widths (16-bit default, 24-bit where applicable).
- [x] Enforce `.align` power-of-two and non-zero constraints.
- [x] Enforce non-negative and bounded `.ds`/`.fill` counts.
- [x] Add targeted tests for underflow/overflow/truncation edge cases.
- [x] Validate: no silent wraparound without diagnostic.

#### 4) C3: Section/linker edge-case coverage

- [x] Add tests for empty sections, overlapping `.place`, `.pack` overflow, repeated `.output` references.
- [x] Verify contiguous output adjacency diagnostics and section placement diagnostics.
- [x] Confirm failure modes are diagnostic-first (no partial corrupt output artifacts).
- [x] Validate with `make test` and focused linker test subset.

#### 5) B1: Instruction table duplication protection

- [x] Add test-time uniqueness assertion on `(cpu, mnemonic, addressing_mode)` registrations.
- [x] Add explicit expected conflicts test to verify duplicate detection path.
- [x] Add coverage for new Motorola 6800-family registrations.
- [x] Validate registry initialization remains deterministic.

#### 6) E1: Expand 6809/HD6309 matrix

- [x] Add table-driven tests for all addressing modes and prefix pages.
- [x] Add negative tests: HD6309-only opcodes rejected under `.cpu m6809`.
- [x] Add `TFR/EXG` same-size register constraint tests.
- [x] Add push/pull register-list ordering and encoding tests.
- [x] Validate with `make test` and review fixture diffs (if any) before update.

### Phase 3 — High-priority architecture cleanup (targeted, low-risk slices)

#### 7) A1: Split `src/assembler/mod.rs` without behavior drift

- [x] Extract output emitters into `src/assembler/output/` (listing, hex, bin, prg, map).
- [x] Extract pass orchestration into `src/assembler/passes/` (`pass1`, `pass2`, shared context).
- [x] Keep existing public APIs and CLI behavior stable.
- [x] Move code in small commits with compile+test after each move.
- [x] Add/adjust module-level docs describing flow boundaries.
- [x] Validate: byte-for-byte output parity on representative examples before/after refactor.

**Definition of done:** Smaller assembler modules, unchanged behavior, and parity confirmed.

### Phase 4 — Remaining high issues with minimal churn

#### 8) B4: Standardize error propagation boundaries

- [ ] Define and document fatal vs recoverable diagnostic boundaries per pipeline phase.
- [ ] Normalize entrypoint formatting/printing path to one diagnostic sink.
- [ ] Add tests for mixed-error scenarios to confirm stable reporting order.

#### 9) B5: Reduce formatter brittleness

- [ ] Add idempotence tests (`format(format(x)) == format(x)`).
- [ ] Add semantic-preservation tests for formatting-only changes.
- [ ] Keep snapshot tests, but reduce fixture churn by focusing snapshots on representative cases.

#### 10) A4/F2: VM feature-gate containment

- [ ] Confirm core assembler tests run without VM features and remain green.
- [ ] Add CI matrix split: core (default features) vs VM feature paths.
- [ ] Document boundaries so VM changes cannot silently affect core behavior.

### Phase 5 — Medium/low cleanup (only after phases 1–4)

- [ ] B2: Replace opcode-prefix magic numbers with named constants.
- [ ] B3: Profile and reduce unnecessary clone/allocation hot spots.
- [ ] E4/E5: Remove or relocate `scratch/` and `multi_error_probe_error.lst` artifacts.
- [ ] G1/G2/G3: Tighten include/output path handling and expression safety checks.
- [ ] E3: Run doc-sync workflow to keep manual/specs aligned with implemented behavior.

### Verification gates for every phase

- [ ] Run `cargo fmt --all`.
- [ ] Run `cargo clippy -- -D warnings`.
- [ ] Run `cargo audit`.
- [ ] Run full tests: `make test` (or `cargo test` where appropriate).
- [ ] If behavior intentionally changed, update references and re-run tests.

### Suggested PR sequence (concrete, low-churn)

- [x] PR1: C2 panic removal + tests.
- [x] PR2: C1 recursion/cycle enforcement + tests.
- [x] PR3: C4 numeric validation + tests.
- [x] PR4: C3 linker/section edge-case tests/fixes.
- [x] PR5: B1 opcode uniqueness + E1 6809/HD6309 coverage.
- [x] PR6: A1 assembler module split with parity proof.
- [ ] PR7: B4/B5/A4-F2 stabilization tasks.

### Rollback & risk controls

- [ ] Keep each PR reversible and scoped to one concern.
- [ ] For refactors, require output parity checks on a fixed example corpus.
- [ ] Block merges if diagnostics regress in clarity or determinism.
- [ ] Do not regenerate references to hide regressions.