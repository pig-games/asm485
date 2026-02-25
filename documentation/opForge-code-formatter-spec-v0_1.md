# opForge Code Formatter Specification (v0.1)

## Goal
Define a deterministic source formatter for opForge assembly that:
- supports all registered CPU families, CPUs, and dialects
- preserves assembly semantics by default
- follows the same family/CPU/dialect modularity model used by the assembler

This is a design specification, not an implementation.

## Scope
In scope:
- formatter architecture and module boundaries
- CPU/family/dialect integration model
- safe default formatting rules
- CLI/config surface proposal
- validation and rollout plan

Out of scope (v0.1):
- automatic semantic rewrites that can change behavior
- mass canonicalization of numeric literal styles
- cross-file refactoring or macro expansion rewriting

## Current Runtime Matrix (Baseline)
Formatter support is required for every pipeline currently registered in opForge:

| Family | Dialects | CPUs (canonical IDs) | Notable aliases |
|---|---|---|---|
| `intel8080` | `intel8080`, `zilog` | `8085`, `z80` | `8080` (maps to `8085`) |
| `mos6502` | `transparent` | `m6502`, `65c02`, `65816`, `45gs02` | `6502`, `65c816`, `w65c816`, `m45gs02`, `mega65`, `4510`, `csg4510` |

Source still has no `.dialect` directive; dialect selection follows CPU defaults unless a host override is used. Formatter behavior must respect this.

## Design Principles
1. Semantic safety first: default mode must not change assembled bytes or diagnostics meaning.
2. Deterministic and idempotent: formatting a file twice yields byte-identical output.
3. Modular layering parity: formatter extension points mirror family/CPU/dialect layers.
4. Graceful fallback: on uncertain parsing, preserve original text for affected lines.
5. Incremental adoption: start with whitespace/layout normalization, add optional rewrites later.

## Semantic Invariants
The formatter must preserve, by default:
- token sequence meaning (mnemonics, operands, directives, labels)
- CPU-selection flow (`.cpu` state changes by line order)
- macro/preprocessor behavior (`.macro`, `.segment`, `.statement`, conditional directives)
- comment text and relative attachment to lines
- string literal and char literal contents

The formatter must not:
- insert or remove directives
- infer or emit a `.dialect` directive
- reorder lines
- fold lines across preprocessor/macro boundaries

## Architecture
Add a new formatting subsystem under `src/formatter/`:

1. `surface_tokenizer.rs`
- Produces trivia-preserving tokens (whitespace, comments, code spans).
- Unlike `core::tokenizer`, it does not discard comments.

2. `surface_parser.rs`
- Builds a lightweight per-line `SurfaceLineAst` for formatting decisions.
- Reuses core expression parsing where safe, but retains original lexeme text.

3. `state_tracker.rs`
- Tracks active CPU pipeline while scanning lines.
- Uses same CPU resolution rules as `.cpu` handling in assembler.

4. `planner.rs`
- Applies formatting policy to `SurfaceLineAst`.
- Delegates family/CPU/dialect-specific decisions to formatter hooks.

5. `renderer.rs`
- Emits normalized source text with configurable indentation/alignment.
- Preserves line endings and final newline policy.

6. `engine.rs`
- Orchestrates tokenize -> parse -> state tracking -> plan -> render.
- Supports write/check/stdout modes.

7. `config.rs`
- Defines formatter options and profile loading (`.toml` + CLI overrides).

## Modularity Model (Family/CPU/Dialect)
Formatter extension points should mirror assembler registry layering:

1. Family formatter hook
- Family-wide operand/punctuation conventions.
- Family-shared mnemonic/register casing hints.

2. CPU formatter hook
- CPU-specific register forms and extension mnemonic handling.
- CPU-specific formatting constraints (for example wide-address notations).

3. Dialect formatter hook
- Dialect-specific mnemonic/operand surface style preferences.
- Optional canonicalization mapping (opt-in, never default in v0.1).

Proposed traits:

```rust
pub trait FamilyFormatterModule: Send + Sync {
    fn family_id(&self) -> CpuFamily;
    fn format_statement(&self, input: FamilyFormatInput<'_>) -> FamilyFormatDecision;
}

pub trait CpuFormatterModule: Send + Sync {
    fn cpu_id(&self) -> CpuType;
    fn family_id(&self) -> CpuFamily;
    fn format_statement(&self, input: CpuFormatInput<'_>) -> CpuFormatDecision;
}

pub trait DialectFormatterModule: Send + Sync {
    fn dialect_id(&self) -> &'static str;
    fn family_id(&self) -> CpuFamily;
    fn format_statement(&self, input: DialectFormatInput<'_>) -> DialectFormatDecision;
}
```

Resolution order for a statement:
1. Dialect hook (surface preference)
2. Family hook (shared rules)
3. CPU hook (extensions/overrides)
4. Global fallback formatter

This keeps ownership consistent with current architecture:
- dialect = rewrite/style surface
- family = shared syntax conventions
- CPU = extensions and edge behavior

## Formatting Policy (Default Safe Profile)
Default profile: `safe-preserve`

Rules:
- labels remain in column 1
- mnemonic/directive token starts at configured code column if line has label
- single space after mnemonic/directive before first operand
- comma spacing normalized to `", "`
- binary operators normalized with surrounding spaces where unambiguous
- inline comments preserved and aligned with minimum two spaces before `;`
- consecutive blank lines collapsed to a configurable max (default: 1)
- directive keyword casing normalized to lowercase with dot prefix preserved
- mnemonic/register casing default: keep original lexeme text

Not normalized by default:
- numeric base style (`$10` vs `16` vs `%00010000`)
- quote style (`'A'` vs `"A"`)
- operand canonicalization across dialects

## CPU and Dialect State Tracking
Formatter must compute active pipeline per line:

1. Initial CPU = CLI/config override or assembler default (`8085`) when absent.
2. On `.cpu <name>`, resolve using `ModuleRegistry::resolve_cpu_name`.
3. Active dialect = `registry.cpu_default_dialect(cpu)` unless host override is explicitly set by formatter invocation.
4. Family = `registry.cpu_family_id(cpu)`.

This state decides token classification (registers/mnemonics) and hook selection per line.

## Error Handling and Fallback
Per-line fallback policy:
- if line cannot be parsed safely, emit original line unchanged
- emit formatter diagnostic in check/report output with file:line
- continue formatting remaining lines

Global failure policy:
- malformed config -> hard error
- unknown explicit CPU override -> hard error
- unknown `.cpu` in source -> preserve line and report warning in formatter output (matches assembler behavior expectations)

## CLI Surface Proposal
Preferred surface: new subcommand

```bash
opforge fmt [OPTIONS] [INPUT]...
```

Options:
- `--check`: do not write files; non-zero exit if changes needed
- `--write`: apply edits in place
- `--stdout`: emit formatted output to stdout (single input)
- `--config <FILE>`: formatter config file
- `--cpu <ID>`: initial CPU override (same semantics as assembler)
- `--line-range <start:end>`: partial formatting (editor integration)
- `--report-format <text|json>`: formatter report output

If subcommands are deferred, equivalent `--fmt-*` top-level flags are acceptable, but must avoid conflict with existing `--format` (diagnostic/report mode).

## Config File Proposal
Default file: `.opforgefmt.toml` at workspace root.

Example:

```toml
profile = "safe-preserve"
indent_width = 4
label_column = 1
code_column = 9
comment_column = 41
max_blank_lines = 1
mnemonic_case = "keep"   # keep|upper|lower
register_case = "keep"   # keep|upper|lower
directive_case = "lower" # keep|upper|lower
dialect_rewrite = "off"  # off|canonical|preferred
```

Precedence:
1. built-in defaults
2. config file
3. CLI flags

## Testing and Validation Requirements
Implementation must include:

1. Unit tests
- surface tokenizer trivia retention
- line parser classification
- state tracking across mixed `.cpu` blocks
- formatter hook dispatch order

2. Snapshot/integration tests
- representative examples per CPU and family
- mixed-dialect Intel examples (8085 and Z80)
- macro/preprocessor heavy files

3. Property tests
- idempotence (`fmt(fmt(file)) == fmt(file)`)
- no-change safety for unparsable lines

4. Repo gates after implementation
- `cargo fmt`
- `cargo clippy`
- `cargo audit`
- `make test` (or full `cargo test`)

Reference fixtures are only updated when formatter behavior changes intentionally.

## Rollout Plan
Phase 1: Core safe formatter
- whitespace/layout normalization only
- no mnemonic/operand rewrites
- full CPU/family/dialect-aware classification

Phase 2: Optional style controls
- casing controls for mnemonics/registers/directives
- comment/alignment profiles

Phase 3: Opt-in dialect canonicalization
- explicit rewrite mode with preview/check support
- strict test coverage for rewrite correctness

## Open Questions
1. CLI shape decision: `opforge fmt` subcommand vs top-level `--fmt-*` flags.
2. Default behavior for unknown `.cpu` in formatter-only runs: warn+preserve vs hard fail.
3. Partial formatting semantics around macro/statement boundaries.
4. Whether formatter should share fixit infrastructure for edit application/reporting.

## Deliverables for Implementation Kickoff
1. `src/formatter/` skeleton with engine/config/surface tokenizer/parser.
2. Formatter registry/hook traits and initial adapters for current families/CPUs/dialects.
3. CLI entrypoint with `check/write/stdout` modes.
4. Initial safe-profile test suite across existing example corpus.
