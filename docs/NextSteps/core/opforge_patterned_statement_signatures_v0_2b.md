# opForge --- Patterned Statement Signatures & Typed Captures


## Related documents

- **Core spec** (directives, modules, injection): [opforge_core_spec_v0_3b.md](opforge_core_spec_v0_3b.md)
- **Executable mental model** (matching walkthrough): [opforge_executable_mental_model_v0_2b.md](opforge_executable_mental_model_v0_2b.md)
- **45GS02 worked example** (real patterns): [opforge_45gs02_statement_dialect_example_v0_2.md](opforge_45gs02_statement_dialect_example_v0_2.md)

---
*v0.2b*

## Purpose

This document specifies **patterned statement signatures** in opForge.

The mechanism allows language and dialect authors to define new
statements (keywords) whose **surface syntax**, **operand forms**, and
**parameter types** are declared directly in the statement signature.

This enables:

-   custom mnemonics
-   new addressing modes
-   keyword parameterization
-   DSL-like syntax extensions
-   precise whitespace control
-   strong static validation via ADTs

without introducing a separate grammar language.

------------------------------------------------------------------------

## Core Concept

A `.statement` definition introduces a **statement keyword** together
with a **signature pattern**.

The signature pattern is matched against the token stream when the
keyword appears in statement position.

If the pattern matches: - parameters are bound - the statement body is
executed - the body expands to instructions, statements, or backend
operations

------------------------------------------------------------------------

## Signature Atoms

A statement signature consists of a sequence of **signature atoms**:

1.  **Literal tokens**
2.  **Typed captures**
3.  **Boundary-controlled spans** (`[{ ... }]`)

### Literal Tokens

Literal tokens are written as quoted strings:

``` asm
"["
"],y"
","
```

They must match exactly.

------------------------------------------------------------------------

### Typed Captures

Typed captures bind values from the input stream to named parameters.

Syntax:

``` asm
<Type>:<name>
```

Examples:

``` asm
byte:a
word:addr
char:reg
str:label
```

Semantics: - the capture consumes input according to its type - the
captured value is bound to `<name>` - failure to capture means the
signature does not match.

Literal commas **must be quoted** in signatures (use `","`). Unquoted
commas are rejected.

------------------------------------------------------------------------

### Boundary-Controlled Spans (`[{ ... }]`)

`[{ ... }]` may appear **inside statement signatures**.

They indicate: - exact boundary control - no implicit whitespace -
literal token adjacency

Example:

``` asm
.statement sta "[" byte:a ","[{char:reg}]
```

Matches:

    sta [$30],y
    sta [$30],x

Outside `[{ ... }]`, optional whitespace is allowed.

Inside `[{ ... }]`, whitespace is literal.

`[{ ... }]` is **purely positional/whitespace boundary control**. It does not introduce a secondary language mode; it only defines exact output/parse boundaries.


------------------------------------------------------------------------

## Statement Definition Examples

### Basic Addressing Mode

``` asm
.statement sta "[" byte:a "]"
  encode STA_PTR32 .a
.endstatement
```

Matches:

    sta [$30]

------------------------------------------------------------------------

### Addressing Mode with Register Suffix

``` asm
.statement sta "[" byte:a ","[{char:reg}]
  .match .reg
    'x' => { encode STA_PTR32_X .a }
    'y' => { encode STA_PTR32_Y .a }
    _   => { .error "invalid register" }
  .endmatch
.endstatement
```

Matches:

    sta [$30],y

------------------------------------------------------------------------

## Statement Labels With Dots

The statement label may include dots (e.g. `move.b`, `move.l`).

Example:

``` asm
.statement move.b char:dst[{byte:dstnum}] "," char:src[{byte:srcnum}]
```
Matches:

  move.b d0, d1

The captured parameters are available inside the body.

------------------------------------------------------------------------

## ADT-Based Typed Captures

ADT variants automatically act as capture types (later phase).

``` asm
.type Size = | b | w | l

.statement move.b char:dst "," char:src
```

Semantics: - only `b`, `w`, or `l` will match - invalid sizes fail
signature matching - no runtime validation required

------------------------------------------------------------------------

## Capture Type Extensibility

Capture types are pluggable.

Built-in capture types (Phase 1): - `byte` --- 8-bit value (may be derived from an expression at call site) - `word` --- 16-bit value (may be derived from an expression at call site) - `char` --- single character token or literal - `str` --- string literal

Dialect- or user-defined capture types may be added later (e.g. `reg`, `addr`, `type_name`).

This allows dialects to define their own operand grammars.

------------------------------------------------------------------------

## Matching Precedence Rules

When multiple statement signatures share the same keyword:

1.  More literal tokens win over fewer
2.  Longer signatures win over shorter
3.  First declared wins if ambiguity remains
4.  Ambiguous matches produce an error

This guarantees deterministic parsing.

------------------------------------------------------------------------

## Expansion Semantics

Inside the `.statement` body: - captured parameters are in scope -
`.match` may be used for semantic validation - output may be generated
via normal opForge rules - expansion may emit instructions, statements,
or backend operations

------------------------------------------------------------------------

## Relationship to Macros and Segments

-   `.statement` defines **grammar-level constructs**
-   `.macro` and `.segment` define **callable symbols**
-   statements are invoked *without* a leading dot
-   macros/segments are invoked *with* a leading dot

These mechanisms are complementary.

------------------------------------------------------------------------

## Strategic Value

Patterned statement signatures enable:

-   clean definition of complex addressing modes
-   expressive DSL creation
-   syntax-level extensibility
-   reuse of ADTs and matching
-   strong static validation
-   readable, assembler-native syntax

This elevates opForge from a macro system to a **language construction
toolkit**.

------------------------------------------------------------------------

------------------------------------------------------------------------

## Definition and Invocation Notations

For assembler-native ergonomics, opForge may allow both definition notations:

- Name-first: `mymacro .macro a, b`
- Directive-first: `.macro mymacro(a, b)`

And both call notations:

- Space-arg: `.mymacro 10, 20`
- Paren-arg: `.mymacro(10,20)`

These are surface-level conveniences; internally they normalize to the same AST.

## Summary

`.statement` with patterned signatures and typed captures provides:

-   declarative grammar extension
-   precise syntax control
-   minimal verbosity
-   maximum expressive power

It allows opForge users to define *new statements that feel native*.

------------------------------------------------------------------------

## Dialect token mapping

In typical usage, `.statement` patterns defined by a **dialect** map syntax to **CPU-defined tokens**:

``` asm
.statement sta "["[{byte:zp}]"],y"
  emit TOK_STA_ZP_PTR32_Y(zp)
.endstatement
```

Token lowering to bytes is performed by the active CPU backend (opForge or Rust). Note that emit itself
is also just a .statement.
