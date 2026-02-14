# opThread VM and CPU Package Specification (v0.1)

Author: Erik + ChatGPT  
Status: Draft for implementation planning (not implemented in opForge v0.9.1)  
Last updated: 2026-02-14

## 1. Purpose

This specification defines **opThread**, a small, deterministic, stack-based virtual machine (VM) and a **CPU Package** binary format that together enable:

- A **single semantic core** for assembly (instruction matching, operand parsing hooks, encoding, relocation emission, diagnostics).
- **Portable “native” assembler runtimes** across many CPU families/platforms by implementing only:
  1) the opThread VM interpreter, and  
  2) a small host adapter for tokens/expressions/symbols/emission/diagnostics.

Rust opForge (the "Foundry") acts as the primary authoring tool.
In opForge v0.9.1, assembly is still performed directly by native Rust family/CPU handlers
without an opThread interpreter or `.opcpu` package loader.

## 2. Goals

### 2.1 Goals
- **One truth**: identical assembler semantics across all targets that run the same package bytecode.
- **Small VM**: feasible on 8-bit systems (6502/Z80/8085), yet expressive enough for instruction forms and structured diagnostics.
- **Table-driven CPU definition**: instruction sets, registers, dialect rewrites, and pseudo-ops live in packages.
- **Deterministic execution**: bounded, repeatable behavior suitable for offline/air-gapped environments.
- **Testability**: portable test vectors runnable on modern and native targets.

### 2.2 Non-goals (v0.1)
- Full general-purpose programming language (no unbounded loops, no dynamic allocation requirements).
- Full macro system parity with the Rust host on day one (macros are staged).
- Full expression parsing inside VM (expression parsing is host-provided in v0.1).
- Replacing opForge parser/directive/linker pipelines in v0.1.

### 2.3 Current opForge feature baseline (compatibility target)
The v0.1 opThread package model must preserve behavior that is already implemented in opForge v0.9.1:
- CPU coverage: 8085 (with `.cpu 8080` alias), Z80, 6502, 65C02, 65816.
- Two-pass assembly with preprocessing and macro expansion before parsing.
- Module system (`.module`/`.endmodule`, `.use`, visibility controls, root metadata).
- Section/region linker workflow (`.section`, `.region`, `.place`, `.pack`) and output directives
  (`.output`, `.mapfile`, `.exportsections`), including wide-address image flows.
- Current expression semantics and diagnostics behavior (including 65816 `.assume` / override flows).
- Built-in dialect selection via opForge hierarchy:
  - Family defines available dialects
  - CPU selects the default dialect within its family
  - Dialect mapping runs in the resolved pipeline
  (there is no user `.dialect` directive).

### 2.4 Package schema/version policy (normative)
- Container `version` identifies schema compatibility (`0x0001` for this spec).
- Minor additive evolution in v0.1.x MUST preserve decode compatibility for existing required chunks.
- New optional behavior MUST use new optional chunks or capability flags; existing required chunk semantics are stable in v0.1.
- Breaking schema changes MUST increment package version and MAY introduce a new required chunk set.
- Hosts MUST reject unknown major/breaking versions with deterministic diagnostics.

## 3. Concepts and Architecture

### 3.1 Components
1) **opForge (Rust)**: authoring + package builder + reference runtime.
2) **CPU Package (`*.opcpu`)**: binary artifact containing:
   - metadata, string pool
   - diagnostics catalog
   - explicit **Family / CPU / Dialect** hierarchy descriptors
   - registers/tokens configuration
   - bytecode for mnemonic dispatch + instruction forms
   - optional per-CPU and per-dialect overlays
3) **Test Vector Package (`*.optst`)**: golden tests for package verification.
4) **Runtime**: implements opThread VM + host adapter.

Implementation note (current state): only (1) exists today. Items (2)-(4) are planned work.

### 3.2 Separation of responsibilities
- **Host**: preprocessing, macro expansion, generic parsing, tokenization, expression parsing (to ExprRef),
  symbol table/module scopes, section/region layout, output writing, diagnostics presentation.
- **VM**: instruction-line form matching and encoding only (token consumption + expression hooks + emission requests).

### 3.3 Hierarchy model (normative)
The package model MUST represent and preserve opForge's three-layer target model:

1) **Family**
   - Owns canonical operand model and shared instruction forms.
   - Declares canonical dialect id.
   - Owns the dialect namespace for all CPUs in that family.

2) **CPU**
   - Belongs to exactly one family.
   - Declares default dialect id.
   - May add/override forms, registers, validators, and capability flags.

3) **Dialect**
   - Belongs to exactly one family.
   - May optionally constrain compatibility to specific CPUs in that family.
   - Performs mnemonic/operand/token rewrites into canonical family-facing form.

Design rule: dialects never encode instructions directly; encoding is always family/CPU form execution after dialect mapping.

### 3.4 Pipeline resolution (normative)
Runtime selection MUST mirror `ModuleRegistry::resolve_pipeline` in opForge:

1) Resolve selected CPU id to its CPU descriptor.
2) Resolve the owning family descriptor from that CPU.
3) Select dialect:
   - if host provides explicit override: use it, else error if missing in owning family.
   - else try CPU default dialect.
   - else fall back to family canonical dialect.
4) Build execution pipeline: `family handler -> dialect mapper -> CPU resolver/validator -> encoder`.

Notes:
- There is no source-level `.dialect` directive in opForge v0.9.1 compatibility mode.
- Dialect override, if any, is host policy (CLI/config/API), not assembly-source syntax.

## 4. Data Model

### 4.1 Core types
- `Value` (tagged):
  - `Int` (signed 32-bit conceptual; runtimes may implement smaller with defined overflow rules)
  - `UInt`
  - `Bool`
  - `SymId` (u16/u32)
  - `Tok` (token kind + payload id)
  - `ExprRef` (opaque handle from host)
  - `SpanId` (opaque handle from host, for diagnostics)
  - `SecId` (section identifier)
  - `RegId` (register identifier)

### 4.2 Token model
Host produces a token stream per statement (line or semicolon-delimited). Tokens have:
- kind (enum)
- payload (string id, integer literal, punctuation id, etc.)
- span (start/end byte offsets or SpanId mapping)

Token kinds (minimum set):
- `EOL`
- `Ident`
- `IntLit`
- `StrLit` (optional)
- `Punct` (`,`, `(`, `)`, `+`, `-`, etc.)
- `DotIdent` (optional convenience: `.foo` tokenization) or host can emit `Punct('.') + Ident`.

## 5. opThread VM

### 5.0 Scope boundary in opForge integration
In opForge integration, v0.1 opThread executes only for instruction resolution/encoding.
Directives, module metadata, preprocessing, macros, linker/output directives, and final artifact writing remain host-owned.

### 5.1 VM execution model
- **Data stack** (LIFO) for `Value`s.
- **Return stack** for calls (optional but recommended).
- **Token cursor** points into the current host token list.
- **Probe mode flag** (boolean) controls whether diagnostics are suppressed during form probing.
- **Span context** holds current `SpanId` to attach to diags when not explicit.
- Execution is bounded by:
  - max stack depth (configurable)
  - max instruction steps per statement (configurable)

### 5.2 Form matching model
Each mnemonic resolves to a list of **forms**. A form is bytecode that:
1) Optionally saves token cursor (`TOK_SAVE`)
2) Matches a pattern (tokens, registers, expressions)
3) Emits bytes/relocs
4) Commits by simply not restoring cursor and returning success.

To avoid noisy diagnostics during backtracking:
- Forms run under `PROBE_ON` until a “commit point” is reached, after which `PROBE_OFF` is executed.

A failure can be:
- **silent**: backtrack to next form
- **diagnostic**: emit error and abort statement

### 5.3 Instruction set (v0.1)

#### 5.3.1 Stack and control
- `PUSH_I <sleb>`: push signed literal.
- `PUSH_U <uleb>`: push unsigned literal.
- `PUSH_K <k>`: push small constant (0..31) embedded in opcode.
- `DUP`, `DROP`, `SWAP`, `OVER`
- `EQ`, `LT`, `GT` → push Bool
- `JMP <rel>`, `JZ <rel>`, `JNZ <rel>` (relative branch)
- `CALL <addr>`, `RET`

#### 5.3.2 Token stream
- `TOK_PEEK` → push next `Tok` (or `Tok:EOL`)
- `TOK_NEXT` → consume next token, push it
- `TOK_IS <kind>` → (tok -- bool)
- `TOK_EXPECT <kind> <diagId>` → consume or DIAG
- `TOK_MATCH_LIT <strId>` → consume Ident matching exact string (case rules from package)
- `TOK_MATCH_ID` → consume Ident, push `SymId` (interned via host)
- `TOK_MATCH_REG <regId>` → consume token matching register
- `TOK_SAVE`, `TOK_RESTORE`

#### 5.3.3 Expression hooks (host-provided in v0.1)
- `EXPR_PARSE` → host parses expression at cursor, advances cursor, pushes `ExprRef`
- `EXPR_EVAL` → (ExprRef -- Int/UInt/Addr/...) according to host rules
- `EXPR_NEEDS_RELOC` → (ExprRef -- Bool)
- `EXPR_SPAN` → (ExprRef -- SpanId)
- `EXPR_FREE` → free temp handle (may be no-op)

#### 5.3.4 Emission and relocation
- `EMIT8` → (Int --)
- `EMIT16_LE`, `EMIT16_BE` → (Int --)
- `EMIT24_LE` (optional) → (Int --)
- `EMIT_PAD <n>` → emit `n` zero bytes
- `EMIT_ALIGN <pow2> <fillByte>` → aligns location counter by emitting fill bytes
- `RELOC_ADD <kind>` → (ExprRef --) create relocation record at current emission offset
- `SECTION_SET <secId>`
- `ORG_SET` → (Addr --) optional; may be restricted or unsupported per package capabilities

#### 5.3.5 Diagnostics
- `DIAG <diagId>` → emit error and abort statement (suppressed in probe mode)
- `WARN <diagId>` → warning (suppressed in probe mode)
- `NOTE <diagId>` → informational note (suppressed in probe mode)
- `FIXIT <fixId>` → attach fix suggestion (suppressed in probe mode)
- `SPAN_SET <spanId>` → set default span context
- `PROBE_ON`, `PROBE_OFF`
- `FAIL` → fail current form silently (jump to next form)
- `FAIL_DIAG <diagId>` → fail and emit diagnostic (unless in probe mode; then behaves like FAIL)

### 5.4 Numeric rules
- Integers are conceptually 32-bit signed for semantics.
- Runtimes may implement narrower integers but must define:
  - wrapping vs saturating vs error on overflow per package capability flag.
- `EMIT*` instructions must validate range and emit `FAIL_DIAG` (or DIAG) with a standard code on out-of-range.

## 6. CPU Package Format (`*.opcpu`) v0.1

### 6.1 Container
Chunked binary container:

**Header**
- magic: `OPCP`
- version: u16 (0x0001 for v0.1)
- endianness marker: u16 (0x1234)
- toc_count: u16
- reserved: u16
- TOC entries:
  - `chunk_id` (u32, ASCII packed, e.g., `META`, `STRS`)
  - `offset` (u32)
  - `length` (u32)

All offsets are from start of file.

### 6.2 Required chunks
1) `META` (metadata + package identity/version)
2) `STRS` (string pool)
3) `DIAG` (diagnostics catalog)
4) `FAMS` (family descriptors)
5) `CPUS` (CPU descriptors)
6) `DIAL` (dialect descriptors)
7) `REGS` (register definitions, with scope/owner)
8) `FORM` (mnemonic dispatch + bytecode, with scope/owner)
9) `TABL` (aux tables: opcode masks, tries, index tables)

Chunk ids above are frozen for v0.1 compatibility.

### 6.3 Optional chunks
- `TOKS` tokenization/case rules and identifier character class hints (family/CPU scoped)
- `TEST` embedded minimal self-test vectors

Hierarchy compatibility note: package resolution MUST follow Section 3.4 and preserve the
opForge rule that source code has no `.dialect` directive.

### 6.4 String pool (`STRS`)
- contiguous UTF-8 blob + index table
- ids are u32 indices

### 6.5 Diagnostics catalog (`DIAG`)
Defines:
- `diagId` (u16/u32)
- severity: error/warn/note
- message template: stringId
- optional fixit templates: fixId → template stringId

Templates support placeholder args (host may render):
- `{expected}`, `{found}`, `{token}`, `{span}`, `{hint}`

### 6.6 Families (`FAMS`)
Each family entry defines:
- `family_id` (stable id stringId; e.g., `intel8080`, `mos6502`)
- display name stringId (optional)
- `canonical_dialect_id` (stringId referencing `DIAL`)
- capability flags (endianness class, word-size defaults, optional feature bits)
- optional `family_cpu_id` / alias metadata for compatibility with registry conventions

### 6.7 CPUs (`CPUS`)
Each CPU entry defines:
- `cpu_id` (stable id stringId; e.g., `8085`, `z80`, `6502`, `65c02`, `65816`)
- owning `family_id` reference
- display name + aliases (stringId list)
- `default_dialect_id` (stringId referencing `DIAL`)
- capability flags and runtime defaults (max address, native word size, endianness, runtime state keys)
- optional validator id / policy flags

Each CPU MUST reference an existing family. `default_dialect_id` SHOULD resolve in the owning family;
if not present, runtime MUST fall back to family canonical dialect per Section 3.4.

### 6.8 Dialects (`DIAL`)
Each dialect entry defines:
- `dialect_id` (stable id stringId; normalized case-insensitive key)
- owning `family_id` reference
- compatibility mode:
  - all CPUs in family, or
  - explicit CPU allow-list
- rewrite rules table (mnemonic/operand/token mapping)
- optional overlay `FORM` additions or replacements for that dialect context

Dialect validation rule: a dialect may only be selected for CPUs in the same family and permitted by
its compatibility policy.

### 6.9 Registers (`REGS`)
- register bank entries with explicit owner scope:
  - family-scoped bank (shared by all CPUs in family)
  - CPU-scoped bank (extensions/overrides)
- list of `RegId` → name stringId
- optional aliases (stringId → RegId)

### 6.10 Forms and bytecode (`FORM`)
Contains:
- scoped form sets:
  - family base forms (shared canonical instruction set)
  - CPU extension/override forms
  - optional dialect overlay forms
- mnemonic table:
  - mnemonic stringId
  - owning scope (`family_id`, `cpu_id`, optional `dialect_id`)
  - list of form entry points (u32 bytecode offsets)
- bytecode blob(s)
- Optional dispatch accelerators:
  - hash table from mnemonic to index
  - or trie encoded in `TABL`

Bytecode encoding:
- 1-byte opcodes
- immediates encoded as:
  - uleb/sleb varints, or
  - u16/u32 depending on op

### 6.11 Dialect rewrite rule model (token-level)
- LHS: token pattern (sequence)
- RHS: token expansion (sequence) including optional `VIRT_OP <id>` tokens
- Matching is deterministic and must be bounded.

## 7. Host Adapter Interface (normative)

A runtime host MUST provide:

### 7.0 Active target and hierarchy resolution
- `set_active_cpu(cpuNameOrId)` (or equivalent) to choose active CPU profile.
- `resolve_pipeline(cpuId, dialectOverride?) -> { familyId, cpuId, dialectId }`.
- Dialect overrides are host-policy only and MUST be validated with Section 3.4 rules.
- If no override is provided, host MUST apply CPU default dialect fallback to family canonical dialect.
- In opForge compatibility mode, source syntax does not include `.dialect`.

### 7.1 Token stream
- `next_statement() -> TokenBuffer` (or equivalent callback)
- `TokenBuffer` provides:
  - `len`
  - `get(i) -> Tok`
  - cursor movement

### 7.2 Symbol interning + resolution
- `intern_ident(bytes) -> SymId`
- `resolve_sym(symId) -> SymResolve`
  - `known: bool`
  - `value: optional Int/Addr`
  - `section: optional SecId`
  - `relocatable: bool`

### 7.3 Expressions (v0.1)
- `parse_expr(cursor) -> (ExprRef, newCursor, SpanId)`
- `eval_expr(exprRef) -> (Value, flags)`
- `expr_needs_reloc(exprRef) -> bool`
- `free_expr(exprRef)`

Flags include:
- `unresolved`
- `relocatable`
- `pc_relative` (optional)
- `depends_on_section`

### 7.4 Emission and layout
- `emit8(byte)`
- `emit16_le(word)` (and other supported widths)
- `add_reloc(kind, exprMeta, atOffset, secId)`
- `get_lc(secId) -> Addr`
- `set_section(secId)`

### 7.5 Diagnostics sink
- `emit_diag(severity, diagId, spanId, args[])`
The host is responsible for rendering templates and presenting fixits.

## 8. Test Vector Package (`*.optst`) v0.1

### 8.1 Container
Chunked container with header magic `OPTS`.

### 8.2 Test case model
Each test case includes:
- source input (string or token stream encoding)
- expected bytes
- expected relocation records
- expected diagnostics (codes + spans)
- optional “notes” for human readability

### 8.3 Execution
Runtimes MUST be able to:
- load `.opcpu`
- load `.optst` (or embedded `TEST`)
- run tests and report:
  - pass/fail counts
  - for failures: first N diffs (bytes/relocs/diags)

## 9. Security and Determinism Constraints

- VM must have **step limit** per statement.
- Stack depth must have a **hard max**.
- Dialect rewrite application must be bounded:
  - max rewrite passes per statement
  - max output token growth factor
- No unbounded loops in v0.1 (only conditional branches used for bounded parsing logic).
- Package is treated as trusted code by default; optionally support signature verification later.

## 10. Implementation Roadmap (recommended)

Precondition: do not switch existing CPUs to package execution until parity is demonstrated against
the current Rust handlers and reference fixtures.

### Phase 0: Parity harness in opForge (before VM adoption)
- Add differential checks that run existing Rust encoding path and candidate opThread path side-by-side
  on the same parsed instruction inputs.
- Compare emitted bytes and diagnostics for supported CPUs.
- Keep package path opt-in behind a feature flag until parity gates pass.

### Phase 1: Rust reference VM
- Implement opThread VM interpreter in Rust with full opcode set.
- Implement host adapter atop existing opForge tokenization and expression engine.
- Implement a minimal `*.opcpu` loader.

### Phase 2: Package generation
- Build a hierarchical CPU package builder in Rust:
  - string pool
  - diagnostics catalog
  - family/CPU/dialect descriptor tables
  - scoped register banks
  - mnemonic/form bytecode generation for family base + CPU extensions + dialect overlays
- Convert one full family (with at least two CPUs and at least two dialects) to package-driven as pilot.

### Phase 3: Embedded runtime #1
- Implement opThread interpreter on 6502 target (see Section 11).
- Implement minimal host adapter:
  - tokenization for a statement
  - expression parse/eval subset
  - byte emission to memory/file
  - diags to console/log

### Phase 4: Dialect overlays
- Implement token rewrite engine
- Ship at least one dialect overlay that:
  - introduces a pseudo-op via `VIRT_OP`
  - rewrites a convenience syntax into canonical tokens

### Phase 5: Expand CPU families and fuzzing
- Add differential testing harnesses on modern host
- Grow `.optst` coverage, including randomized operand tests

## 11. Host-specific Translation Plan (Ultimate64 / 6502) — Requirements Stub

This section defines target-specific planning constraints for a 6502/Ultimate64 runtime.

### 11.1 Platform assumptions
- CPU: 6502-compatible (Ultimate64)
- Acceleration: up to 64 MHz (configurable)
- REU available (up to typical sizes; plan assumes large REU possible)
- Storage: disk/SD access via Ultimate firmware environment (exact IO API TBD)

### 11.2 Runtime memory strategy
- Core opThread interpreter stays in main RAM.
- Use REU for:
  - token buffers (per statement)
  - string pool pages
  - bytecode pages
  - symbol table pages (hash buckets + entries)
  - emitted binary staging (if large)

### 11.3 Recommended integer model
- Implement `Int` as 32-bit signed using 4-byte little-endian on stack (fast enough at 64 MHz).
- Provide fast paths for 16-bit where possible (optional).

### 11.4 Tokenization approach
- Line-based tokenizer:
  - store line in RAM
  - produce token list with spans (byte offsets in line)
- Option: store token list in REU to reduce RAM pressure.

### 11.5 Expression engine (v0.1)
- Implement host-side expression parsing using a shunting-yard algorithm to a compact ExprIR:
  - postfix bytecode (stack machine) is recommended for easy eval
- `ExprRef` indexes into ExprIR arena (RAM or REU).

### 11.6 Emission approach
- Output bytes into a growing buffer (RAM or REU).
- Relocation records into parallel buffer.
- If full linker not present on target, support a “flat binary” mode first.

### 11.7 Diagnostics
- Emit structured diag codes + span offsets.
- Render messages using string templates from `DIAG` with minimal formatting.

### 11.8 Self-test support
- Implement `.optst` runner for smoke tests:
  - report to console
  - optionally write a report file

---

## Appendix A: Minimal opcode count target
For v0.1 portability, aim to keep the interpreter to:
- ≤ 50 opcodes
- ≤ ~4–8 KB code on 6502 (initial target; refine during implementation)

## Appendix B: Standard diagnostics (suggested reserved codes)
- `E_RANGE_IMM8`, `E_RANGE_IMM16`
- `E_EXPECT_TOKEN`
- `E_NO_MATCHING_FORM`
- `E_UNRESOLVED_SYMBOL`
- `E_RELOC_NOT_ALLOWED_HERE`
- `E_DIALECT_REWRITE_OVERFLOW`

(Exact numeric assignments are package-defined, but keep a shared catalog for consistency.)

## Appendix C: Feature ownership matrix (v0.1 integration target)

| Feature area | Host-owned in v0.1 | VM/package-owned in v0.1 |
|---|---|---|
| Preprocessor and macro expansion | Yes | No |
| Generic parser + directive handling | Yes | No |
| Module system and visibility | Yes | No |
| Section/region placement + linker output directives | Yes | No |
| Instruction mnemonic/form matching | No | Yes |
| CPU-family dialect mapping for instruction syntax | Host resolves `Family -> CPU -> Dialect` and may apply policy overrides | Package provides dialect definitions/mappings |
| Operand expression parsing/evaluation | Yes (via host hooks) | VM consumes `ExprRef` results |
| Byte emission and relocation requests | Host performs physical write/record | VM issues semantic requests |
| Diagnostic catalog/messages for instruction forms | Host renders | Package provides IDs/templates |
