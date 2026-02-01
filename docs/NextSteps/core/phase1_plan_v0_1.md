# Phase 1 Plan (v0.1)

## Scope
Phase 1 focuses on **macro syntax updates**, **adding `.segment`**, and **`.statement` patterned signatures**. It explicitly **excludes sections/dsection/relocation** work.

## Goals
1) Solidify concepts into full specifications (syntax, semantics, errors, precedence).
2) Define AST/data model changes and mapping to existing pipeline phases.
3) Produce an implementation checklist per module.

---

## Track A — Macro syntax updates + `.segment`

### A1. Macro definition surface
**Spec targets**
- Definition notations:
  - Name-first: `mymacro .macro a, b`
  - Directive-first: `.macro mymacro(a, b)`
- Call notations:
  - Space-arg: `.mymacro 10, 20`
  - Paren-arg: `.mymacro(10, 20)`
- Normalization rules: all forms lower to the same internal AST.

**Decisions**
- Zero-arg forms like `.mymacro()` and `.mymacro` are both valid (also for `.segment`).
- Trailing commas and empty argument lists are not allowed.
- Name-first `.macro` is only valid when the definition is the only statement on the line.
  - The macro name must be the first token on the line.
  - The last argument must be the last token on the line, except for comments.

**Acceptance criteria**
- All four surface forms parse to the same macro definition/call structure.
- Diagnostics clearly identify invalid macro syntax and mixed forms.

### A2. `.segment` directive
**Spec targets**
- `.segment <name>` / `.endsegment`
- Scoping: creates a compile-time scope but **does not** imply `.block` (per core spec).
- Segment symbol resolution/visibility matches `.macro` rules.
- `.segment` is module-local unless exported.

**Decisions**
- `.segment` follows the exact same surface structure as `.macro`.
- The only semantic difference: `.segment` does **not** define an implicit `.block` scope.
- No nested `.macro` nor `.segment` definitions for now.

**Acceptance criteria**
- `.segment` parses, scopes correctly, and is discoverable for later injection mechanics.
- No effect on output placement (sections are later-phase).

### A3. Macro/segment expansion order
**Spec targets**
- Clarify expansion phase: macros/segments expand in Phase 2 before parsing.
- State expansion precedence when multiple macro/segment names overlap.

**Acceptance criteria**
- Deterministic expansion order defined (and documented) with error on ambiguity.

---

## Track B — `.statement` + patterned signatures

### B1. Statement definition + invocation
**Spec targets**
- `.statement <keyword> <signature...>` / `.endstatement`
- Statements invoked without leading dot (keyword in statement position).
- Keyword parameterization (e.g. `move.[{char size}] ...`).

**Decisions**
- Local `.statement` definitions override built-in instructions and less-local `.statement` definitions.
- Statement position: tokens are matched against `.statement` definitions during parsing; on match, the `.statement` output is emitted at the same location in the output stream as the original token span.

**Acceptance criteria**
- Patterned statements match deterministically and bind captures into the body scope.

### B2. Signature atoms
**Spec targets**
- Literal tokens (quoted strings) match exactly.
- Typed captures: `<Type> <name>`
- Boundary-controlled spans: `[{ ... }]` enforce adjacency/whitespace rules.

**Decisions**
- Literal tokens support escapes, e.g. `\"` to include `"` in the literal.
- Literal token matching is case-insensitive by default.
  - Optional future extension: a prefix to force case-sensitive matching (regex-style prefix).
- Boundary spans `[{ ... }]` cannot be nested in v0.2.

**Acceptance criteria**
- Matching succeeds/fails strictly per literals/typed captures/boundary spans.

### B3. Capture types
**Spec targets**
- Built-in capture types: `byte`, `word`, `char`, `str`.
- ADT variants can be used as capture types.
- Dialect/user-defined capture types can be registered.

**Decisions**
- Phase 1 supports only built-in capture types (`byte`, `word`, `char`, `str`) plus ADT variants when `.type` is supported.
- Dialect/user-defined capture type registration is deferred.
- Capture results must be type-checked (e.g., `byte` vs `word`).
- Any argument to `.statement`, `.macro`, or `.segment` can use explicit types; call sites may use expressions to derive values.

**Acceptance criteria**
- Capture binding types are validated at match-time; failures are non-fatal unless ambiguous.

### B4. Matching precedence rules
**Spec targets**
1. More literal tokens wins.
2. Longer signatures win.
3. First declared wins.
4. Ambiguous matches produce error.

**Acceptance criteria**
- A deterministic tie-breaking strategy is documented and enforced.

---

## Phase 1 Implementation Checklist (Draft)

### Parser & Tokenizer
- [ ] Extend tokenization for quoted literal tokens in signatures if needed.
- [ ] Add `.segment` directive parsing.
- [ ] Add `.statement` definition parsing and signature AST.
- [ ] Allow macro and segment definition/call alternate syntax forms.

### Macro Processor
- [x] Normalize macro definition forms to a single internal representation.
- [x] Normalize macro call forms to a single internal representation.
- [x] Ensure `.segment` participates in the same expansion pipeline as `.macro`.

### AST / Core Structures
- [ ] Add `StatementSignature` node with atoms (literal/capture/boundary span).
- [ ] Add built-in capture type handling + ADT variant capture when `.type` is available.
- [ ] Add `Segment` scope node, consistent with `.macro` visibility rules.

### Matching & Validation
- [ ] Implement signature matching engine with precedence rules.
- [ ] Bind typed captures into `.statement` body scope.
- [ ] Add diagnostics for ambiguous or invalid signatures.

### Documentation
- [ ] Update core spec + patterned signature doc with final decisions.
- [x] Add syntax examples for `.segment` and macro surface forms.

---

## Phase 1 Task Breakdown (Per-Module, Staged)

### Stage 1 — Macro/segment surface syntax (fast feedback)
- [x] Add token support for quoted literal tokens and escapes in [src/core/tokenizer.rs](src/core/tokenizer.rs).
- [x] Extend token kinds/values for literal-token nodes in [src/core/token_value.rs](src/core/token_value.rs).
- [x] Parse name-first `.macro` definitions in [src/core/parser.rs](src/core/parser.rs).
- [x] Parse directive-first `.macro` definitions in [src/core/parser.rs](src/core/parser.rs).
- [x] Parse `.segment` definitions using macro-like surface syntax in [src/core/parser.rs](src/core/parser.rs).
- [x] Normalize macro/segment definitions and calls in [src/core/macro_processor.rs](src/core/macro_processor.rs).
- [x] Enforce “no nested `.macro`/`.segment`” in [src/core/parser.rs](src/core/parser.rs).

### Stage 2 — `.statement` signature parsing
- [x] Define `StatementSignature` atoms (literal/capture/boundary span) in [src/core/parser.rs](src/core/parser.rs).
- [x] Parse `.statement` headers and body in [src/core/parser.rs](src/core/parser.rs).
- [x] Represent boundary spans `[{ ... }]` in [src/core/parser.rs](src/core/parser.rs).

### Stage 3 — Signature matching + precedence
- [x] Implement signature matching and precedence rules in [src/core/parser.rs](src/core/parser.rs).
- [x] Bind typed captures into `.statement` scope in [src/core/parser.rs](src/core/parser.rs).
- [ ] Add diagnostics for ambiguous/non-matching signatures in [src/core/parser_reporter.rs](src/core/parser_reporter.rs).

### Stage 4 — Capture type handling (phase 1 subset)
- [ ] Implement built-in capture types (`byte`, `word`, `char`, `str`) in [src/core/parser.rs](src/core/parser.rs).
- [ ] Add type-checking for captured values in [src/core/expr.rs](src/core/expr.rs).

### Stage 5 — Documentation updates
- [ ] Apply decisions to [docs/NextSteps/core/opforge_core_spec_v0_3b.md](docs/NextSteps/core/opforge_core_spec_v0_3b.md).
- [ ] Apply decisions to [docs/NextSteps/core/opforge_patterned_statement_signatures_v0_2b.md](docs/NextSteps/core/opforge_patterned_statement_signatures_v0_2b.md).
- [ ] Add syntax examples to [docs/NextSteps/core/opforge_patterned_statement_signatures_v0_2b.md](docs/NextSteps/core/opforge_patterned_statement_signatures_v0_2b.md).

---

## Next Steps
1) [x] Convert decisions into per-module tasks with file pointers and a staging order.
2) [ ] Start with parser/macro syntax changes (lowest risk, fastest feedback).
