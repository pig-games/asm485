# opForge code formatter implementation plan — v0.1 (Phase 1 focused)

## Goal
Turn `opforge_code_formatter_spec_v0_1.md` into an executable Phase 1 implementation plan with:
- ticket-sized work items
- file-level targets
- concrete tests and acceptance criteria

Phase 1 scope is the safe formatter profile only (`safe-preserve`):
- deterministic whitespace/layout normalization
- CPU/family/dialect-aware classification
- no semantic rewrites

## Non-goals (Phase 1)
- no dialect canonicalization rewrites
- no numeric literal style conversion
- no macro expansion rewrites
- no cross-file refactors

## Operating principles
1. Keep behavior semantic-equivalent by default.
2. Prefer narrow commits with one conceptual change each.
3. Keep formatter layering aligned with assembler layering (family -> dialect -> CPU hooks).
4. Never update references to hide regressions.

## Deliverable boundary (Phase 1)
Done when:
- `opforge fmt --check` and `opforge fmt --write` exist and work on single/multi-file input.
- formatter is idempotent.
- formatter tracks `.cpu` changes line-by-line and uses resolved pipeline metadata.
- fallback-on-unsafe-parse behavior preserves original lines and reports diagnostics.
- quality gates pass: `cargo fmt`, `cargo clippy`, `cargo audit`, `make test`.

---

## [x] Workstream A — Foundation and wiring

### [x] Ticket FMT-001: Create formatter module skeleton
Objective:
- establish formatter package layout and public API without behavior changes outside formatter paths

Primary files:
- `src/formatter/mod.rs` (new)
- `src/formatter/engine.rs` (new)
- `src/formatter/config.rs` (new)
- `src/core/mod.rs` (wire module export if needed)

Implementation notes:
- define top-level `FormatterEngine`, `FormatterConfig`, `FormatMode`.
- keep API CPU-agnostic at outer boundary; pipeline resolution happens inside engine.

Tests:
- smoke unit test for default config creation.
- smoke unit test creating engine with default registry-backed context.

Acceptance:
- code compiles with formatter module present and unused by CLI.

Progress update:
- Added `src/formatter/` skeleton (`mod.rs`, `config.rs`, `engine.rs`) with no-op Phase 1 engine and unit tests.
- Exported formatter module from `src/lib.rs`.

---

### [x] Ticket FMT-002: Add CLI entrypoint for formatter
Objective:
- expose formatter invocation mode with explicit check/write/stdout behaviors

Primary files:
- `src/assembler/cli.rs`
- `src/main.rs` and/or `src/assembler/mod.rs` (where command dispatch is handled)

Implementation notes:
- add formatter options:
  - `--fmt-check`
  - `--fmt-write`
  - `--fmt-stdout`
  - `--fmt-config <FILE>`
  - `--fmt-line-range <start:end>` (parse only; limited behavior can be deferred with clear diagnostics)
- if subcommands are not feasible yet, use top-level flags with strict conflict validation.

Tests:
- CLI validation tests for incompatible combinations (`check + write`, stdout + multi-input).
- CLI parsing tests for config and line-range syntax.

Acceptance:
- user can invoke formatter mode from CLI and receive deterministic exit codes.

Progress update:
- Added `--fmt` (shorthand for write mode), `--fmt-check`, `--fmt-write`, `--fmt-stdout`, and `--fmt-config`.
- Added formatter-mode CLI validation (conflicts, stdout single-input restriction, config flag requirement).
- Wired formatter-mode execution path in `src/main.rs` to short-circuit assembler execution.

---

## [x] Workstream B — Source-preserving analysis layer

### [x] Ticket FMT-003: Implement surface tokenizer with trivia retention
Objective:
- tokenize each line while preserving code/comment/whitespace trivia needed for re-render

Primary files:
- `src/formatter/surface_tokenizer.rs` (new)
- optional reuse helpers from `src/core/text_utils.rs`

Implementation notes:
- preserve:
  - leading indentation
  - inter-token spacing
  - inline comment text (including exact comment bytes)
  - end-of-line state
- do not replace existing `core::tokenizer`; this layer is formatter-only.

Tests:
- comment edge cases (semicolon inside single/double quoted strings).
- mixed tabs/spaces retention.
- empty line and whitespace-only line coverage.

Acceptance:
- tokenizer round-trip reconstruction test passes for untouched mode.

Progress update:
- Added `src/formatter/surface_tokenizer.rs` with trivia-preserving line model (`SurfaceDocument`, `SurfaceLine`).
- Implemented line ending retention (`LF`/`CRLF`/none), quote-aware comment splitting via shared core helper, and full source round-trip rendering.
- Added tests for semicolon-in-string comment parsing, mixed tabs/spaces retention, and empty/whitespace-only lines.

---

### [x] Ticket FMT-004: Implement surface line parser
Objective:
- parse line envelopes for formatting decisions while retaining original lexemes

Primary files:
- `src/formatter/surface_parser.rs` (new)
- `src/formatter/types.rs` (new, optional)

Implementation notes:
- parse line categories:
  - empty/comment-only
  - label-only
  - directive
  - instruction
  - assignment
- optionally reuse `core::parser` expression parse where safe; never discard original lexeme strings.

Tests:
- label forms (with and without trailing colon).
- directive and instruction line classification.
- unparsable line fallback marker.

Acceptance:
- parser classifies representative lines from each CPU family test corpus.

Progress update:
- Added `src/formatter/surface_parser.rs` with `SurfaceLineKind` classification and `SurfaceParsedLine` fallback marker support.
- Implemented parser envelope classification for empty/comment-only/label-only/directive/instruction/assignment/unparsed lines while retaining raw code lexemes.
- Added tests for label-with-colon, label-without-colon, directive/instruction classification, fallback marking, and document-level parsing.

---

## [x] Workstream C — Pipeline-aware formatting behavior

### [x] Ticket FMT-005: CPU/dialect state tracker
Objective:
- track active CPU pipeline per line and expose resolved family/cpu/dialect metadata

Primary files:
- `src/formatter/state_tracker.rs` (new)
- integration with `src/core/registry.rs` usage (read-only)

Implementation notes:
- initial CPU selection mirrors assembler behavior (`--cpu` override then default).
- `.cpu` directive updates state using `resolve_cpu_name`.
- derive active dialect from `cpu_default_dialect`.

Tests:
- mixed `.cpu` blocks:
  - `8085 -> z80 -> m6502 -> 65816`
- unknown `.cpu` handling:
  - preserve line
  - record formatter warning

Acceptance:
- per-line resolved state snapshot tests are deterministic.

Progress update:
- Added `src/formatter/state_tracker.rs` with per-line pipeline tracking (`before`/`after` state snapshots) based on `.cpu` directives.
- Implemented default formatter registry bootstrap aligned with current family/cpu registrations and CPU-default dialect lookup.
- Added deterministic tests for mixed `.cpu` transitions, quoted CPU operands, unknown `.cpu` warnings with state preservation, and invalid initial CPU override errors.

---

### [x] Ticket FMT-006: Formatting hook registry (family/dialect/cpu)
Objective:
- provide modular extension points aligned with assembler layering

Primary files:
- `src/formatter/hooks.rs` (new)
- `src/formatter/hook_registry.rs` (new)
- starter adapters near:
  - `src/families/intel8080/` (formatter adapter module new)
  - `src/families/mos6502/` (formatter adapter module new)
  - optional CPU adapter modules for `src/i8085/`, `src/z80/`, `src/m65c02/`, `src/m65816/`, `src/m45gs02/`

Implementation notes:
- start with no-op adapters that expose casing/spacing hints only.
- hook dispatch order for Phase 1:
  1. dialect
  2. family
  3. cpu
  4. global fallback

Tests:
- hook resolution tests for each registered CPU.
- order-of-application tests using synthetic hook outputs.

Acceptance:
- all current registry CPUs resolve to formatter hook context without panic.

Progress update:
- Added `src/formatter/hooks.rs` and `src/formatter/hook_registry.rs` with explicit dialect/family/cpu/global hook traits and ordered dispatch.
- Added no-op starter formatter adapters in family/CPU modules:
  - `src/families/intel8080/formatter.rs`
  - `src/families/mos6502/formatter.rs`
  - `src/i8085/formatter.rs`
  - `src/z80/formatter.rs`
  - `src/m65c02/formatter.rs`
  - `src/m65816/formatter.rs`
  - `src/m45gs02/formatter.rs`
- Added hook registry tests for all registered CPUs and deterministic dispatch ordering (`dialect -> family -> cpu -> global`).

---

## [x] Workstream D — Planner/renderer and safe profile

### [x] Ticket FMT-007: Planner for safe-preserve normalization
Objective:
- compute normalized line formatting plan under safe constraints

Primary files:
- `src/formatter/planner.rs` (new)

Implementation notes:
- Phase 1 normalization:
  - directive/mnemonic column alignment when label exists
  - single space before operand list
  - `, ` comma spacing
  - minimum two spaces before inline comment
  - blank-line collapsing (configurable max)
- keep mnemonic/register lexeme casing unchanged by default.

Tests:
- representative line rewrite snapshots (one file per family).
- no-op tests where input already matches policy.

Acceptance:
- planner produces deterministic edit plans for mixed-family fixture files.

Progress update:
- Added `src/formatter/planner.rs` with a deterministic planning layer (`plan_document`) and explicit `FormatPlan`/`PlannedLine` output model.
- Implemented Phase 1-safe normalization for directive/instruction lines:
  - label-head alignment via config
  - single-space head/tail separation
  - `, ` operand comma spacing outside quoted strings
  - minimum two spaces before inline comments
  - configurable consecutive blank-line collapsing
- Preserved fallback behavior for unparsed lines by passing original source through unchanged.
- Added planner tests covering Intel-style and MOS-style lines, fallback preservation, blank-line collapsing, and no-op/idempotent inputs.

---

### [x] Ticket FMT-008: Renderer and idempotence contract
Objective:
- render planned output with stable newline and spacing policy

Primary files:
- `src/formatter/renderer.rs` (new)
- `src/formatter/engine.rs`

Implementation notes:
- preserve existing newline flavor if possible (`\n` vs `\r\n`) or normalize per config default.
- preserve final newline policy with explicit config control.

Tests:
- idempotence: `format(format(input)) == format(input)` on fixture corpus.
- line-ending handling tests.

Acceptance:
- idempotence property tests pass for all Phase 1 fixtures.

Progress update:
- Added `src/formatter/renderer.rs` and integrated renderer flow into `FormatterEngine::format_source`.
- Formatter engine now runs `tokenize -> parse -> plan -> render` in Phase 1 safe profile mode.
- Implemented renderer line-ending behavior:
  - preserve per-line endings by default
  - optional normalization to `LF` when configured
  - final newline policy controlled by config
- Added idempotence and newline-behavior tests across `engine` and `renderer`.

---

## [x] Workstream E — Diagnostics, fallback, and reporting

### [x] Ticket FMT-009: Formatter diagnostics and fallback path
Objective:
- fail safely per line, never destroy ambiguous source

Primary files:
- `src/formatter/diagnostics.rs` (new)
- `src/formatter/engine.rs`

Implementation notes:
- on unsafe parse:
  - emit warning diagnostic with file:line
  - pass original line through unchanged
- aggregate summary counts for CLI exit/report decisions.

Tests:
- malformed line fixture: unchanged output + warning count.
- mixed valid/invalid lines continue through full file.

Acceptance:
- formatter never drops lines on parse ambiguity.

Progress update:
- Added `src/formatter/diagnostics.rs` with fallback diagnostic collection for unparsed lines.
- Extended formatter engine APIs with per-source and per-file diagnostics (`FormatterOutput`, `FormatterRunReport`).
- `run_paths_with_report` now tracks warning counts and file-level warning presence while continuing formatting for mixed valid/invalid files.
- Formatter CLI mode now emits fallback warnings with `file:line` context and includes warning counters in text/JSON summaries.

---

### [x] Ticket FMT-010: Check/write/stdout modes and report output
Objective:
- finalize operational UX for local/editor/CI use

Primary files:
- `src/formatter/engine.rs`
- CLI dispatch files (`src/main.rs`, `src/assembler/mod.rs`, `src/assembler/cli.rs`)

Implementation notes:
- `--fmt-check`: non-zero on diff required.
- `--fmt-write`: writes in place.
- `--fmt-stdout`: single-input stdout output.
- optional JSON summary output in Phase 1 if low effort; otherwise stable text summary.

Tests:
- mode behavior integration tests:
  - check on clean file -> zero
  - check on unformatted file -> non-zero
  - write updates file content
  - stdout mode rejects multi-input

Acceptance:
- deterministic mode behavior and exit status across tests.

Progress update:
- Integrated formatter run reporting into CLI mode with stable text/JSON summary fields:
  - `files_seen`
  - `files_changed`
  - `warnings`
  - `files_with_warnings`
- Confirmed formatter mode exit behavior:
  - `--fmt-check` returns non-zero when formatting changes are required
  - `--fmt-write` writes normalized output in place
  - `--fmt-stdout` single-input guard remains enforced via CLI validation tests
- Implemented `--fmt-config` runtime loading with strict validation and Phase 1-safe keys
  (`profile`, line-ending/newline toggles, alignment, blank-line limits) plus alias support.
- Added main-entrypoint formatter mode tests for clean check mode, dirty check mode, and write mode file updates.

---

## Cross-cutting test matrix (Phase 1)
Minimum fixture coverage:
- Intel family:
  - `8085` in `intel8080` dialect style
  - `z80` in `zilog` style
- MOS family:
  - `m6502`
  - `65c02`
  - `65816`
  - `45gs02`
- directive-heavy file (`.module`, `.section`, `.place`, `.pack`, `.cpu`)
- macro/preprocessor-heavy file (`.macro`, `.segment`, `.statement`, `.ifdef`/`.endif`)

Test types:
1. Golden formatter snapshots (input -> expected output).
2. Idempotence checks on formatted output.
3. Safety fallback tests for malformed/partial lines.
4. CLI behavior tests for mode and conflict handling.

Progress update:
- Added fixture corpus under `src/formatter/fixtures/` covering:
  - `8085` (`intel8085_intel`)
  - `z80` (`z80_zilog`)
  - `m6502` (`m6502_basic`)
  - `65c02` (`m65c02_basic`)
  - `65816` (`m65816_basic`)
  - `45gs02` (`m45gs02_basic`)
  - directive-heavy and macro/preprocessor-heavy files
  - malformed fallback fixture
- Added fixture-driven formatter tests in `src/formatter/fixture_tests.rs`:
  - golden snapshot comparisons (`input -> expected`)
  - corpus idempotence checks (`fmt(fmt(x)) == fmt(x)`)
  - fallback warning verification

---

## Suggested commit sequence (Phase 1)
1. FMT-001 formatter skeleton.
2. FMT-003 tokenizer.
3. FMT-004 surface parser.
4. FMT-005 state tracker.
5. FMT-006 hook registry + no-op adapters.
6. FMT-007 planner.
7. FMT-008 renderer + idempotence.
8. FMT-009 diagnostics/fallback.
9. FMT-002 CLI flags/entrypoint (can be earlier if desired).
10. FMT-010 mode/report integration hardening.

Rationale:
- build internals first, expose CLI when behavior is already stable.

---

## Phase 1 completion gate
Required final verification run:
- [x] `cargo fmt --all`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo audit`
- [x] `make test`

If any formatter snapshots are intentionally updated:
1. run tests first without snapshot updates
2. update expected outputs only for intentional formatter behavior changes
3. re-run full gate

---

## Deferred to Phase 2+
- additional style transforms beyond current opt-in label/mnemonic/hex casing and label-colon controls
- advanced alignment profiles
- dialect canonicalization rewrite modes
- shared fixit plumbing integration
