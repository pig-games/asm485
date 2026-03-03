# opForge Design: Ranges, Lists, and Repetition Constructs — v0.1

**Status:** Proposal  
**Date:** 2026-03-02

---

## 1. Overview

This document proposes adding **ranges**, **lists**, and **repetition constructs** to opForge. These features introduce structured iteration at assembly time, enabling concise generation of repeated data, code patterns, and lookup tables without resorting to manual duplication or external tooling.

### Goals

1. First-class **range** literals with inclusive/exclusive bounds and optional step.
2. First-class **list** literals for arbitrary value sequences.
3. **`.for` / `.endfor`** — counted and collection-based repetition.
4. **`.while` / `.endwhile`** — condition-based repetition.
5. **`.bfor` / `.bwhile`** — scoped variants that open an implicit `.block`.
6. **Labeled repetition** with `[n]` indexing into generated iterations.
7. Ranges and lists as valid parameters for macros, segments, etc.
8. Typed literal struct instances assignable to symbols.

### Design Principles

- **Minimal surface area.** Reuse existing expression, scope, and macro infrastructure.
- **Predictable two-pass behavior.** Loop counts must stabilize in pass 1; all iterations execute in both passes.
- **No runtime semantics.** Everything resolves at assembly time.

---

## 2. Value Model Extension

### 2.1 Current State

Expressions evaluate to scalar `i64` (CPU handlers) or `u32` (assembler pipeline). There is no compound value type.

### 2.2 Proposed: `AsmValue` enum

Introduce a first-class value enum that generalizes scalar, range, list, and struct:

```rust
/// Assembly-time value: scalar, range, list, struct type, or struct instance.
#[derive(Clone, Debug, PartialEq)]
pub enum AsmValue {
    /// Single integer value (backwards compatible with all existing code).
    Scalar(i64),

    /// Range with start, end, step.
    /// Inclusive/exclusive is encoded by adjusting `end` at construction.
    Range {
        start: i64,
        end: i64,      // *exclusive* upper bound (always normalized)
        step: i64,      // non-zero; sign must agree with direction
    },

    /// Ordered list of scalar values. Indexable with [n].
    List(Vec<i64>),

    /// Struct type definition: named fields with byte offsets and sizes.
    Struct(StructDef),

    /// Struct instance value: typed field-value map.
    StructInstance(StructInstance),
}

/// A compile-time struct layout (field names → offsets).
#[derive(Clone, Debug, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<StructField>,
    pub size: u32,               // total byte size of one instance
}

#[derive(Clone, Debug, PartialEq)]
pub struct StructField {
    pub name: String,
    pub offset: u32,             // byte offset from struct start
    pub size: u32,               // byte size of this field
}

#[derive(Clone, Debug, PartialEq)]
pub struct StructInstance {
    pub type_name: String,
    pub fields: HashMap<String, i64>,
}
```

Every existing code path that produces/consumes a plain integer continues to operate on `AsmValue::Scalar`. Range, list, struct type, and struct instance are explicit variants that appear only where explicitly constructed.

### 2.3 Type Relationships

The five value types compose naturally:

| Type       | Indexable `[n]` | Has fields `.f` | Iterable     | Description                       |
|------------|-----------------|-----------------|--------------|-----------------------------------|
| `Scalar`   | No              | No              | No           | Plain integer                     |
| `Range`    | Yes (→ scalar)  | No              | Yes          | Lazy arithmetic sequence          |
| `List`     | Yes (→ scalar)  | No              | Yes          | Materialized value sequence       |
| `Struct`   | No              | Yes (→ offset)  | No           | Layout type with named fields     |
| `StructInstance` | No        | Yes (→ scalar)  | No           | Typed field-value object          |

A **list of struct instances** is not a new type — it is a `List` whose elements are base addresses, combined with a `Struct` that defines the field layout. Indexing `name[k]` returns the address; `.field` adds the field offset.

`AsmValue` supports the following derived operations:

| Operation           | Returns             |
|---------------------|---------------------|
| `.len()`            | Number of elements  |
| `.iter()`           | Iterator over `i64` |
| `.get(index)`       | `Option<i64>`       |
| `.to_list()`        | Materializes a list |
| `Scalar` → `i64`   | Direct unwrap       |
| `.field_offset(n)`  | `Option<u32>` (struct type only) |
| `.field_value(n)`   | `Option<i64>` (struct instance only) |
| `.size()`           | Struct type/instance size |

---

## 3. Range Literals

### 3.1 Syntax

```
range = expr '..' expr              ; exclusive end
      | expr '..=' expr             ; inclusive end
      | expr '..' expr ':' expr     ; exclusive end + step
      | expr '..=' expr ':' expr    ; inclusive end + step
```

The `..` and `..=` operators are new binary operators at a precedence level below comparison, parsed only in contexts that expect a value expression (operand position, assignment RHS, macro argument).

### 3.2 Examples

| Literal         | Expansion                     | Notes                         |
|-----------------|-------------------------------|-------------------------------|
| `0..8`          | 0, 1, 2, 3, 4, 5, 6, 7       | Exclusive (8 not included)    |
| `0..=7`         | 0, 1, 2, 3, 4, 5, 6, 7       | Inclusive                     |
| `0..16:2`       | 0, 2, 4, 6, 8, 10, 12, 14    | Step 2, exclusive             |
| `10..=0:-1`     | 10, 9, 8, …, 1, 0            | Descending, inclusive         |
| `0..0`          | *(empty)*                     | Zero iterations               |

### 3.3 Normalization

Internally the range is always stored with an **exclusive** upper bound:
- `a..=b` → `Range { start: a, end: b + step.signum(), step }` (adjusts `end` by one step unit in the direction of iteration)
- `a..b` → stored as-is.
- Default step = 1 when ascending (start < end), -1 when descending (start > end).
- Error if step direction disagrees with start/end direction (e.g. `0..10:-1`).

### 3.4 Tokenizer Changes

Two new composite operators:

| Token           | Kind                    |
|-----------------|-------------------------|
| `..`            | `OperatorKind::Range`   |
| `..=`           | `OperatorKind::RangeInclusive` |

The step separator reuses the existing colon token (already `TokenKind::Colon`).

### 3.5 Parser / `Expr` Changes

New `Expr` variant:

```rust
Expr::Range {
    start: Box<Expr>,
    end: Box<Expr>,
    step: Option<Box<Expr>>,
    inclusive: bool,
    span: Span,
}
```

Parsed as a binary/ternary expression at a new low-precedence level (below `..` below comparison, above comma):

```
range_expr  = add_expr ('..' | '..=') add_expr (':' add_expr)?
```

---

## 4. List Literals

### 4.1 Syntax

List literals use curly braces to avoid ambiguity with existing parenthesized tuples ``(a, b)`` (used for indirect addressing) and brackets `[a]` (used for `IndirectLong`):

```
list = '{' expr (',' expr)* '}'
     | '{' range '}'               ; range expansion into list
     | '{' '}'                      ; empty list
```

### 4.2 Examples

```asm
sprites  = {0, 4, 8, 12, 16}
evens    = {0..20:2}                ; {0, 2, 4, …, 18}
combined = {1, 2, 3} + {4, 5, 6}   ; concatenation → {1,2,3,4,5,6}
```

### 4.3 Parser / `Expr` Changes

New `Expr` variant:

```rust
Expr::List(Vec<Expr>, Span)
```

Parsed when `{` is encountered in expression position. This is unambiguous because `{` is not currently used as an expression-start token.

### 4.4 List Indexing with `[n]`

All lists (and ranges) are generically indexable with `[n]`:

```asm
colors = {$00, $06, $0E, $01}
    lda #colors[2]           ; → $0E

offsets = 0..8:2
    lda #offsets[1]          ; → 2
```

The `[n]` postfix operator works identically whether the list was created via a literal, a range, or generated by a labeled repetition. There is one unified indexing mechanism.

### 4.5 List Operations (expressions)

| Expression                | Result        | Description               |
|---------------------------|---------------|---------------------------|
| `list + list`             | list          | Concatenation             |
| `list * n`                | list          | Repeat n times            |
| `list[n]`                 | scalar        | Element at index n        |
| `range[n]`                | scalar        | Element at index n        |
| `.len(list)` or `.len(range)` | scalar    | Element count             |

These are evaluated in the expression evaluator. `.len()` is a built-in function, dot-prefixed to match the calling convention of future user-defined `.function` directives.

---

## 5. Repetition: `.for` / `.endfor`

### 5.1 Collection-based for

```
[label] .for <var> in <range|list>
          <body>
        .endfor
```

- `<var>` is a compile-time variable, automatically declared as `.var`-style (read-write) and scoped to the loop body.
- The body is expanded once per element. Inside the body, `<var>` holds the current element value.
- The loop variable is **not** visible after `.endfor`.

### 5.1.1 Label Prohibition in Unscoped `.for`

Because `.for` (without the `b` prefix) does **not** open a per-iteration scope, any label defined inside the body or on the `.endfor` line would be defined multiple times — once per iteration — producing duplicate-symbol errors. To prevent confusing diagnostics and make the intent explicit, **labels are prohibited** inside an unscoped `.for` body and on the `.endfor` directive:

```asm
; ERROR — labels not allowed in unscoped .for
.for i in 0..4
entry   .byte i          ; ← error: label 'entry' not allowed inside .for
.endfor

; OK — use .bfor instead
.bfor i in 0..4
entry   .byte i          ; each 'entry' is scoped to its iteration
.endfor
```

The assembler enforces this by scanning for a label field on every line inside a `.for` body and on the `.endfor` line itself. If a label is found, an error is emitted immediately, before any iteration begins.

This rule applies equally to all `.for` forms (collection-based, counter-based, and named-counter).

```asm
.for i in 0..8
    .byte i * 2         ; emits: 0, 2, 4, 6, 8, 10, 12, 14
.endfor

.for val in {$10, $20, $40, $80}
    .byte val
.endfor
```

### 5.2 Counter-based for

```
[label] .for <counter>
          <body>
        .endfor
```

When only a counter expression is given (no `in`), the loop runs from 0 to counter-1:

```asm
.for 4
    nop                  ; emits 4 NOPs
.endfor
```

Equivalent to `.for __anon in 0..<counter>`.

### 5.3 Nested for

Nesting is fully supported:

```asm
.for row in 0..25
    .for col in 0..40
        .byte row * 40 + col
    .endfor
.endfor
```

### 5.4 Implementation Strategy

Repetition is handled **in the assembler passes**, not in the macro preprocessor. This is critical because:

1. Loop ranges/counts may depend on symbols defined in pass 1.
2. The two-pass model requires that pass 1 and pass 2 expand the same iterations.
3. Text-level macro expansion cannot cleanly handle symbol-dependent loop bounds.

**Mechanism:**

- When `.for` is encountered, the assembler records the current source position and evaluates the range/list/count.
- The body lines (up to `.endfor`) are collected into a `RepeatBlock`.
- For each iteration, the assembler:
  1. Pushes a new scope frame (for `.bfor`) or just sets the loop variable (for `.for`).
  2. Processes the body lines as if they were inline source.
  3. Pops the scope (for `.bfor`).
- In pass 1, iteration must converge: if a loop bound depends on a symbol that changes between pass 1 and pass 2, the assembler emits an error ("loop bound not stable across passes").

**Data structures:**

```rust
struct RepeatBlock {
    kind: RepeatKind,
    label: Option<String>,          // labeled repetition
    var_name: Option<String>,       // loop variable name
    source: Range<usize>,          // or Vec<String> — the body lines  
    values: Vec<i64>,               // materialized iteration values
    scope_each: bool,               // true for .bfor/.bwhile
}

enum RepeatKind {
    For,
    While,
}
```

---

## 6. Repetition: `.while` / `.endwhile`

### 6.1 Syntax

```
[label] .while <condition>
          <body>
        .endwhile
```

- The condition is evaluated before each iteration. If falsy (zero), the loop exits.
- The body **must** modify state (via `.var`/`.set` assignments) to eventually make the condition false or hit an iteration ceiling, otherwise it is an infinite loop.

### 6.1.1 Label Prohibition in Unscoped `.while`

The same restriction as for `.for` applies: **labels are prohibited** inside an unscoped `.while` body and on the `.endwhile` directive. Since the body executes multiple times without per-iteration scoping, any label would be multiply defined.

```asm
; ERROR — labels not allowed in unscoped .while
addr .set $C000
.while addr < $C100
row     .word addr       ; ← error: label 'row' not allowed inside .while
        addr .set addr + 8
.endwhile

; OK — use .bwhile instead
addr .set $C000
.bwhile addr < $C100
row     .word addr       ; 'row' is scoped per-iteration
        addr .set addr + 8
.endwhile
```

Use `.bwhile` when labels inside the loop body are needed.

```asm
addr .set $C000
.while addr < $C100
    .word addr
    addr .set addr + 8
.endwhile
```

### 6.2 Safety Limit

A compile-time maximum iteration count (default: 65536, configurable via `--max-loop-iterations`) prevents runaway assembly. Exceeding it produces an error.

---

## 7. Scoped Variants: `.bfor` / `.bwhile`

### 7.1 Syntax

Identical to `.for`/`.while` but with a `b` prefix:

```
[label] .bfor <var> in <range|list>     ... .endfor
[label] .bfor <counter>                 ... .endfor
[label] .bwhile <condition>             ... .endwhile
```

### 7.2 Behavior

Each iteration opens an implicit `.block` / `.endblock` scope. Labels defined inside the body are local to that iteration's block, preventing name clashes:

```asm
.bfor i in 0..4
retry   lda buffer,x       ; 'retry' is scoped per-iteration
        beq retry
        sta output+i
.endfor
```

Without the `b` prefix, all iterations share the enclosing scope, which means labels inside the body would collide (and produce duplicate-symbol errors if defined more than once).

The `b` scoped variants add a new `ScopeKind`:

```rust
pub enum ScopeKind {
    Module,
    Block,
    Namespace,
    Repeat,       // NEW — used by .bfor/.bwhile iterations
}
```

---

## 8. Structs: `.struct` / `.endstruct`

Structs define reusable, named field layouts with byte offsets — analogous to C structs. They describe a **type**, not data; no bytes are emitted by a struct definition itself.

### 8.1 Syntax

```
name .struct
  field1  .byte ?          ; 1 byte,  offset 0
  field2  .word ?          ; 2 bytes, offset 1
  field3  .byte ?          ; 1 byte,  offset 3
.endstruct                 ; total size: 4 bytes
```

- Each line inside the struct defines a **field** with a name, a data-size directive (`.byte`, `.word`, `.long`, `.res N`), and a placeholder `?` value.
- The `?` indicates that no bytes are emitted — the directive only contributes to offset/size computation.
- Fields are laid out sequentially. Each field's offset is the cumulative size of all preceding fields.
- The struct name becomes a symbol whose value is the **total size** of one instance.
- Each field name becomes a symbol whose value is its **byte offset** within the struct.

### 8.2 Examples

```asm
SpriteData .struct
x           .byte ?         ; offset 0
y           .byte ?         ; offset 1
color       .byte ?         ; offset 2
flags       .byte ?         ; offset 3
.endstruct                  ; SpriteData = 4 (size)

; SpriteData.x     = 0
; SpriteData.y     = 1
; SpriteData.color = 2
; SpriteData.flags = 3

Vec2 .struct
x           .word ?         ; offset 0
y           .word ?         ; offset 2
.endstruct                  ; Vec2 = 4
```

### 8.3 Using Structs

Structs are used in three ways:

1. **As a type for labeled repetition** (see Section 9) — the struct defines the layout of each iteration.
2. **For manual field access** with address arithmetic:
   ```asm
   base = $0400
       lda base + SpriteData.color   ; base + 2
   ```
3. **As a size constant** for `.res`, loops, etc.:
   ```asm
       .res SpriteData * 8            ; reserve space for 8 sprites
   ```

### 8.4 Typed Literal Struct Instances

Typed struct literals create field-value instances of a previously defined struct type:

```asm
player0 .const SpriteData { x: 24, y: 50, color: 1, flags: $00 }
player1 .var   SpriteData { x: 40, y: 50, color: 2, flags: $00 }
```

Syntax:

```
struct_literal = identifier '{' field_init (',' field_init)* '}'
field_init     = identifier ':' expr
```

Rules:

- The leading identifier must resolve to a known struct type.
- Every declared field in the struct must be initialized exactly once.
- Unknown fields, duplicate fields, and missing fields are errors.
- The literal evaluates to `AsmValue::StructInstance`.
- Struct instances are assignable using `.const`, `.var`, `.set`, `=`, and `:=`.
- Member access is type-sensitive:
  - `SpriteData.color` resolves to field offset.
  - `player0.color` resolves to the instance field value.
- Scalar compound assignment operators (`+=`, `-=`, etc.) reject struct-instance symbols.

### 8.5 Struct Nesting (Future)

Struct nesting (embedding one struct inside another) is deferred to a future version. For v0.1, fields are limited to scalar data directives.

### 8.6 Parser / `Expr` Changes

New `Expr` variant for struct field access (member operator):

```rust
Expr::Member {
    base: Box<Expr>,
    field: String,
    span: Span,
}
```

New `Expr` variant for typed struct literal expressions:

```rust
Expr::StructLiteral {
    type_name: String,
    fields: Vec<(String, Expr)>,
    span: Span,
}
```

The `.` member operator already exists conceptually in the scope system (for namespace-qualified identifiers). The `Member` expression reuses this syntax but resolves through the struct field table rather than the scope stack when the base is a struct type or a struct-typed list index.

### 8.7 Implementation

The assembler maintains a `StructTable` alongside the `SymbolTable`:

```rust
pub struct StructTable {
    defs: HashMap<String, StructDef>,
}
```

When `.struct` is encountered, the assembler enters a struct-definition mode where data directives contribute to field offset computation instead of emitting bytes. On `.endstruct`, the `StructDef` is registered and the struct name is defined as a symbol with value = total size.

---

## 9. Labeled Repetition & `[n]` Indexing

A labeled repetition produces a **list of addresses** — each element is the start address of one iteration's emitted content. This is just a regular `List`, indexable with `[n]` like any other list.

### 9.1 Basic Labeled Repetition

```asm
table .bfor i in 0..4
        .word handler_base + i * 2
      .endfor
```

This defines:
- `table` — a **list** value: `{addr0, addr1, addr2, addr3}`, where each `addrN` is the address of that iteration's `.word`.
- `table[0]` — address of iteration 0's content.
- `table[2]` — address of iteration 2's content.
- `.len(table)` — `4`.

Because `table` is a `List`, it uses the same `[n]` indexing as any list literal or range — no special mechanism needed.

### 9.2 Labeled Repetition with Sub-labels → List of Structs

When a labeled `.bfor` body contains sub-labels, the repetition implicitly defines a struct layout and produces a list of struct instances:

```asm
sprites .bfor i in 0..=3
x           .byte 24 + i * 24
y           .byte 50 + i * 16
color       .byte i + 1
        .endfor
```

This is equivalent to:

1. **Implicitly defining a struct** from the sub-label layout:
   ```
   sprites.__struct = { x: offset 0, y: offset 1, color: offset 2 } ; size 3
   ```
2. **Producing a list** of base addresses: `sprites = {addr0, addr1, addr2, addr3}`.
3. **`sprites[k].field`** resolves as `sprites[k] + sprites.__struct.field_offset`.

Access:
```asm
    lda sprites[3].x       ; address of sprite 3's x byte
    lda sprites[3].color   ; address of sprite 3's color byte
    lda sprites[0]         ; address of sprite 0's start
```

### 9.3 Explicit Struct Annotation

For clarity and validation, a labeled repetition can explicitly reference a struct type:

```asm
SpriteData .struct
x           .byte ?
y           .byte ?
color       .byte ?
.endstruct

sprites .bfor i in 0..=3 : SpriteData
            .byte 24 + i * 24       ; field: x
            .byte 50 + i * 16       ; field: y
            .byte i + 1             ; field: color
        .endfor
```

With the explicit `: StructName` annotation:
- The assembler verifies that each iteration's emitted size matches `StructDef.size`.
- Field access `sprites[k].x` uses the struct's field offsets.
- Sub-labels inside the body are optional (the struct already defines the layout).

### 9.4 Expression Grammar for `[n]`

The index operator `[n]` is a **postfix** on an identifier:

```
postfix_expr = primary_expr ('[' expr ']')*
             | postfix_expr '.' identifier
```

This is **unambiguous** with the existing `[expr]` (`IndirectLong`) syntax because:
- `IndirectLong` occurs as a **standalone** primary: `[addr]` as an operand, e.g., `lda [dp]`
- Index `[n]` is always **preceded** by an identifier: `table[3]`
- The parser distinguishes by checking whether `[` follows an identifier token or appears at operand-start position.

New `Expr` variant:

```rust
Expr::Index {
    base: Box<Expr>,
    index: Box<Expr>,
    span: Span,
}
```

Parse rule integrated into the existing `parse_primary()` / postfix chain:

```
After parsing an Identifier:
    if peek == OpenBracket AND context is postfix (not operand-start):
        consume '['
        index = parse_expr()
        consume ']'
        → Expr::Index { base: Identifier, index }
        // allow chaining: result.field via existing dot-member logic
```

### 9.5 Expression Evaluation (Unified)

All `[n]` indexing resolves through a single path:

1. Evaluate `base` to an `AsmValue`.
2. If `AsmValue::List(vec)` → return `vec[n]` as `Scalar`.
3. If `AsmValue::Range { start, end, step }` → return `start + n * step` as `Scalar` (with bounds check).
4. Otherwise → error: "cannot index a scalar or struct".

Field access (`.field`) after indexing:

1. Evaluate `base`.
2. If `base` is `AsmValue::StructInstance`, return the stored field value.
3. Otherwise, for indexed list-of-struct access, evaluate `base[n]` to scalar address `addr`, look up the struct type associated with `base`, and return `addr + struct.field_offset(field_name)`.
4. If no struct type or field is available → emit the corresponding struct/member diagnostic.

Out-of-bounds index produces an assembly error with a clear diagnostic.

---

## 10. Interaction with Macros, Segments, and Parameters

### 10.1 Ranges and Lists as Macro Parameters

Ranges and lists can be passed as arguments to `.macro` and `.segment`:

```asm
fill_table .macro data
    .for val in .data
        .byte val
    .endfor
.endmacro

    .fill_table {10, 20, 30}
    .fill_table 0..=255
```

**Implementation:** Because macro expansion is text-level (pre-parser), the range/list literal text is substituted as-is into the macro body. The parser in the assembler pass then parses the substituted `0..=255` or `{10, 20, 30}` as a range or list expression.

This works transparently — no special macro-processor changes are needed. The macro system already does textual substitution of argument values.

### 10.2 Ranges and Lists as Segment Parameters

Same mechanism — `.segment` parameters receive the text, which is parsed during assembly.

### 10.3 Type Checking (Optional, Future)

The macro parameter `type_name` field (`MacroParam::type_name`) could be extended to accept `"range"`, `"list"`, or `"iterable"` as type annotations for validation, but this is not required for v0.1.

---

## 11. Directive Summary

| Directive                           | Description                                         | Scoped |
|-------------------------------------|-----------------------------------------------------|--------|
| `.struct`                           | Begin struct type definition                        | —      |
| `.endstruct`                        | End struct type definition                          | —      |
| `.for <var> in <range\|list>`       | Iterate over range or list                          | No     |
| `.for <count>`                      | Repeat body `count` times                           | No     |
| `.endfor`                           | End of `.for` / `.bfor` block                       | —      |
| `.bfor <var> in <range\|list>`      | Iterate with per-iteration `.block` scope           | Yes    |
| `.bfor <count>`                     | Counted repetition with scope                       | Yes    |
| `.while <cond>`                     | Condition-based repetition                          | No     |
| `.endwhile`                         | End of `.while` / `.bwhile` block                   | —      |
| `.bwhile <cond>`                    | Condition-based repetition with scope               | Yes    |

---

## 12. Two-Pass Considerations

### 12.1 Pass 1 Behavior

- Loop ranges, lists, and counts are evaluated using pass-1 symbol values.
- Each iteration processes the body as normal, defining symbols and advancing addresses.
- The total iteration count and body size must be deterministic for address computation.

### 12.2 Pass 2 Behavior

- Loop bounds are re-evaluated. If the iteration count differs from pass 1, an error is emitted ("loop iteration count changed between passes").
- Bytes are emitted, listing lines are generated.

### 12.3 Stability Requirement

Because the two-pass model depends on pass 1 producing correct sizes, any loop whose bound depends on a forward reference is an error. The assembler detects this by comparing pass 1 and pass 2 iteration counts.

---

## 13. Error Diagnostics

| Condition                                 | Diagnostic                                                    |
|-------------------------------------------|---------------------------------------------------------------|
| Step is zero                              | `error: range step must be non-zero`                          |
| Step direction disagrees with bounds      | `error: range step direction conflicts with start..end`       |
| Loop bound not stable across passes       | `error: loop iteration count changed between passes (pass1: N, pass2: M)` |
| Max iterations exceeded                   | `error: loop exceeded maximum iteration limit (65536)`        |
| `.endfor` without `.for`                  | `error: .endfor without matching .for`                        |
| `.for` without `.endfor`                  | `error: unterminated .for (opened at line N)`                 |
| Index out of bounds: `table[5]` (4 items) | `error: index 5 out of bounds for 'table' (0..3)`            |
| Label inside unscoped `.for` body         | `error: label 'X' not allowed inside .for (use .bfor for scoped repetition)` |
| Label inside unscoped `.while` body       | `error: label 'X' not allowed inside .while (use .bwhile for scoped repetition)` |
| Label on `.endfor` / `.endwhile`          | `error: label not allowed on .endfor / .endwhile`            |
| Duplicate loop variable name              | `error: loop variable 'i' shadows existing symbol`           |
| Non-iterable in `.for ... in`             | `error: expected range or list after 'in', found scalar`      |
| `.while` condition never becomes false    | `error: loop exceeded maximum iteration limit (65536)`        |
| Empty list in `.for ... in {}`            | *(no error — zero iterations, zero bytes emitted)*            |
| `.endstruct` without `.struct`            | `error: .endstruct without matching .struct`                  |
| `.struct` without `.endstruct`            | `error: unterminated .struct (opened at line N)`              |
| Field access on non-struct list           | `error: no struct type associated with 'name' for field access` |
| Unknown struct field                      | `error: struct 'S' has no field 'f'`                          |
| Struct size mismatch in annotated `.bfor` | `error: iteration body size (N) does not match struct 'S' size (M)` |
| Unknown field in struct literal           | `error: unknown field 'f' in struct literal for 'S'`          |
| Duplicate field in struct literal         | `error: duplicate field 'f' in struct literal for 'S'`        |
| Missing required field in struct literal  | `error: missing required field 'f' in struct literal for 'S'` |
| Unknown struct type in literal            | `error: unknown struct type 'S' for struct literal`           |
| Scalar operator on struct instance        | `error: operator '+=' requires scalar symbol, found struct instance 'X'` |

---

## 14. Example Programs

### 14.1 Jump Table Generation

```asm
        .cpu "6502"
        .org $C000

handlers = {do_move, do_fire, do_pause, do_quit}

jump_table .bfor i in 0...len(handlers)
    .word handlers[i]       ; note: indexing the list, not a labeled repetition
.endfor

do_move     rts
do_fire     rts
do_pause    rts
do_quit     rts

; dispatch:
dispatch    asl a
            tax
            lda jump_table+1,x
            pha
            lda jump_table,x
            pha
            rts
```

### 14.2 Sprite Coordinate Table (Implicit Struct)

```asm
sprites .bfor i in 0..=7
x           .byte 24 + i * 24
y           .byte 50 + i * 16
color       .byte i + 1
        .endfor

; later:
        lda sprites[3].x       ; x-coordinate of sprite 3
        lda sprites[3].color   ; color of sprite 3
```

### 14.3 Unrolled Memory Copy

```asm
        .bfor i in 0..=15
            lda src+i
            sta dst+i
        .endfor
        ; 16 LDA/STA pairs emitted, fully unrolled
```

### 14.4 Pattern Fill with While

```asm
addr .var $0400
.while addr < $0800
    .org addr
    .byte $A0             ; fill screen RAM with spaces
    addr .set addr + 1
.endwhile
```

### 14.5 Lookup Table with Step

```asm
sin_indices .bfor i in 0..256:4
    .byte sin_table + i
.endfor
; 64 entries: sin+0, sin+4, sin+8, …, sin+252
```

### 14.6 Explicit Struct with Labeled Repetition

```asm
; Define the struct type
SpriteData .struct
x           .byte ?
y           .byte ?
color       .byte ?
flags       .byte ?
.endstruct              ; SpriteData = 4

; Generate 8 sprite instances using the struct layout
sprites .bfor i in 0..8 : SpriteData
            .byte 24 + i * 24       ; x
            .byte 50 + i * 16       ; y
            .byte i + 1             ; color
            .byte $00               ; flags
        .endfor

; Access fields by struct offset:
        lda sprites[3] + SpriteData.color   ; equivalent to sprites[3].color
        lda sprites[0] + SpriteData.flags   ; flags of sprite 0

; The list itself:
        ldx #.len(sprites)                   ; 8
```

### 14.7 Standalone List Indexing

```asm
palette = {$00, $06, $0E, $01, $03, $07, $0F, $0A}

; Direct indexing — no repetition needed
        lda #palette[0]          ; $00 (black)
        lda #palette[3]          ; $01 (white)
        ldx #.len(palette)       ; 8
```

### 14.8 Typed Literal Struct Instance

```asm
SpriteData .struct
x           .byte ?
y           .byte ?
color       .byte ?
flags       .byte ?
.endstruct

player0 .const SpriteData { x: 24, y: 50, color: 1, flags: $00 }
player1 .var   SpriteData { x: 40, y: 50, color: 2, flags: $00 }

        lda #player0.x       ; 24 (instance value)
        lda #player1.color   ; 2  (instance value)
        lda sprites[3].x     ; address + struct offset (existing behavior)
```

---

## 15. Implementation Phases

### Phase 1: Value Model + Range/List Parsing
- Add `AsmValue` enum (Scalar, Range, List, Struct).
- Add `..` / `..=` tokens to tokenizer.
- Add `Expr::Range`, `Expr::List`, `Expr::Index`, `Expr::Member` to parser.
- Generic `[n]` indexing for all lists and ranges in expression evaluator.
- Unit tests for all expression forms.

### Phase 2: `.struct` / `.endstruct`
- Add `StructDef`, `StructField`, `StructTable`.
- Implement struct-definition mode in assembler (offset accumulation, no byte emission).
- Define struct name as size symbol, field names as offset symbols.
- `.member` resolution through `StructTable`.
- Unit tests for struct definitions and field access.

### Phase 3: `.for` / `.endfor`
- Add `RepeatBlock` collection in the assembler.
- Implement body-line buffering (`.for` … `.endfor` detection).
- Implement iteration expansion in pass 1 and pass 2.
- Implement counter-based and collection-based `.for`.
- Pass stability checking.
- Safety limit enforcement.
- Unit tests + example programs.

### Phase 4: `.bfor` + Labeled Repetition
- Add `ScopeKind::Repeat`.
- Implement per-iteration block scoping for `.bfor`.
- Labeled repetition producing a `List` of addresses.
- Implicit struct inference from sub-labels.
- Explicit struct annotation (`: StructName`).
- Wire `Expr::Index` + `Expr::Member` evaluation for struct-typed lists.
- Unit tests + example programs.

### Phase 5: `.while` / `.bwhile`
- Implement condition-based loop.
- Same scoping rules as `.for` / `.bfor`.
- Safety limit enforcement.
- Unit tests + example programs.

### Phase 6: Integration + Polish
- Range/list as macro and segment parameters (verify text-substitution path works).
- `.len()` built-in function.
- List concatenation and repeat operators.
- Inline list indexing: `{1,2,3}[1]` → `2`.
- Listing output for loop iterations (indented / annotated).
- Map file entries for list and struct symbols.
- Documentation update (reference manual).
- Full example suite + reference outputs.

### Phase 7: Typed Literal Struct Instances
- Add `Expr::StructLiteral` parser support (`StructName { field: expr, ... }`).
- Add `AsmValue::StructInstance` evaluator/runtime support.
- Validate unknown/duplicate/missing fields and unknown struct types.
- Support `.const/.var/.set`, `=`, and `:=` assignment paths for struct instances.
- Keep member semantics stable:
  - `StructName.field` = offset.
  - `instance.field` = field value.
- Reject scalar compound assignments (`+=`, etc.) on struct-instance symbols.
- Add unit tests and integration examples for valid/invalid struct literals.

---

## 16. Open Questions

1. **`.break` / `.continue`:** Should loops support early exit or skip? *Proposed: defer to a future version; keep v0.1 simple.*

2. **Nested labeled repetition:** Should `outer .bfor ... inner .bfor ... .endfor .endfor` allow `outer[0].inner[1]`? *Proposed: yes, naturally falls out of recursive scoping + list-of-lists.*

3. **String lists:** Should lists support string elements (for text tables)? *Proposed: defer — current lists are integer-only, matching the scalar value model.*

4. **Built-in function prefix:** `.len()` uses a dot prefix (`.len(x)`) to match the calling convention of future user-defined functions (`.function` directive). This ensures all assembly-time function calls share a consistent syntax and avoids collision with user-defined labels.

5. **Struct nesting:** Should structs embed other structs as fields? *Proposed: defer to a future version. For v0.1, use `.res StructName` to reserve space and manual offset arithmetic.*

6. **Standalone struct instances:** Resolved for v0.1 — support typed literal struct instances with expression syntax `StructName { field: value, ... }`, requiring exact field coverage (all fields exactly once).

---

## 17. Discussion: Unifying Scopes and Structs

This section is speculative. It explores whether the scope system (`.block`, `.namespace`, `.module`) and the struct system (`.struct`) should share a common underlying model, and what the consequences would be.

### 17.1 The Observation

Today, scopes and structs serve parallel roles:

| Concept              | Scope (`.block` / `.namespace`)          | Struct (`.struct`)                    |
|----------------------|------------------------------------------|---------------------------------------|
| Contains named items | Yes — labels with absolute addresses     | Yes — fields with byte offsets        |
| Hierarchical         | Yes — scopes nest                        | Not yet (v0.1 is flat)               |
| Dot access           | `module.block.label`                     | `StructName.field`                    |
| Address meaning      | Absolute (in memory)                     | Relative (offset from base)           |
| Emits bytes          | Yes                                      | No (type definition only)             |

A scope is effectively a "struct that has been placed at a concrete address." A struct is a "scope where addresses are relative to zero." The `.` member access syntax is identical in both cases. This suggests they could be two views of the same abstraction.

### 17.2 What Unification Would Look Like

If scopes and structs shared a model, every `.block` / `.namespace` would implicitly define a struct-like layout alongside its absolute addresses:

```asm
player .block
    .org $0400
x       .byte $00       ; player.x = $0400, offset 0
y       .byte $00       ; player.y = $0401, offset 1
hp      .byte $64       ; player.hp = $0402, offset 2
    .endblock           ; player = $0400, player.__size = 3
```

Here `player.x` resolves to `$0400` as it does today, but the block also records that `x` is at offset 0, `y` at offset 1, etc. The block itself could then be used as a struct type:

```asm
; Use 'player' as a struct to define an NPC with the same layout
npc_base = $0500
    lda npc_base + player.x     ; $0500 + 0 — works if .x is both absolute and offset
```

This breaks down immediately: `player.x` is `$0400` (absolute), not `0` (offset). For this to work, the meaning of `.field` would need to be context-dependent — absolute when used standalone, relative when used in an offset expression. That is fragile and confusing.

### 17.3 A Cleaner Variant: Scopes *Generate* Structs

Instead of making scopes *be* structs, a scope could optionally *generate* a companion struct from its label layout:

```asm
player .block : .exportstruct
x       .byte $00
y       .byte $00
hp      .byte $64
    .endblock
; player = $0400 (absolute, as today)
; player.__struct = StructDef { x: 0, y: 1, hp: 2, size: 3 }  (auto-generated)
```

This preserves the existing absolute-address semantics, but gives you a reusable layout type derived from the block's shape. The generated struct could then be used with repetition:

```asm
enemies .bfor i in 0..4 : player.__struct
    .byte $00, $00, $32
.endfor
    lda enemies[2].hp       ; uses the auto-generated struct
```

This is more honest than pretending scopes *are* structs — it acknowledges they serve different purposes but provides a bridge.

### 17.4 Nested Structs as a Prerequisite

Unification (in either form) requires nested structs, since scopes already nest:

```asm
Entity .struct
pos .struct             ; nested struct
x       .word ?
y       .word ?
    .endstruct          ; pos.size = 4, pos.x = 0, pos.y = 2
hp      .byte ?
.endstruct              ; Entity.pos = 0, Entity.pos.x = 0, Entity.pos.y = 2, Entity.hp = 4
```

Without nesting, a scope's sub-blocks have no struct equivalent, and the mapping breaks for anything deeper than one level.

### 17.5 Arguments For Unification

- **Orthogonality.** One mechanism for "named collection of sub-items," whether they describe memory layout or code organization. Fewer concepts to learn.
- **Reuse.** A well-structured `.block` automatically becomes a reusable type without redundant `.struct` definitions.
- **Consistency.** The `.` access syntax already looks the same; making the underlying model the same removes a conceptual seam.
- **Labeled repetition fit.** If a `.bfor` body is a scope, and scopes are struct-like, the "implicit struct from sub-labels" behavior (§9.2) falls out naturally.

### 17.6 Arguments Against

- **Complexity.** Scopes carry runtime concerns (address allocation, conditional assembly, `.org` changes mid-block) that structs don't. Cramming both into one model means the struct representation must handle gaps, non-contiguous regions, and address-dependent fields. This makes `StructDef` significantly heavier than a simple `Vec<StructField>`.
- **Ambiguous semantics.** `player.x` meaning `$0400` or `0` depending on context is a source of subtle bugs. Users would need to learn when a name resolves to an absolute address vs. an offset, which is the exact kind of confusion good design avoids.
- **Not all scopes are uniform.** A `.block` might contain instructions, conditional assembly, macros, and `.org` directives that change the address non-linearly. These don't map to a struct layout — there is no single linear sequence of fields. A struct derived from such a block would be meaningless.
- **Two-pass burden.** Struct layouts must be known in pass 1 for size computation. If structs are derived from scopes, the scope must be fully processed before its struct is available, creating ordering dependencies that don't exist today.
- **Implementation cost.** The existing `ScopeStack` is a lightweight name-qualification mechanism (a stack of string segments). Making it also track field offsets, sizes, and type information turns it into a much heavier data structure, affecting every line of every assembly file — even those that never use structs.

### 17.7 Recommendation

**Keep scopes and structs separate in v0.1.** They serve different purposes (code organization vs. data layout), and forcing them into one model introduces ambiguity and weight without clear payoff for the common case.

However, the "scopes *generate* structs" variant (§17.3) is worth revisiting once nested structs exist. If a clean opt-in mechanism (e.g., `: .exportstruct`) can be designed without polluting the default scope path, it could provide the best of both worlds: orthogonality for users who want it, zero cost for those who don't.

The key design invariant to preserve: **a struct field is always an offset, a scope label is always an address.** Any future unification must respect this distinction rather than blur it.
