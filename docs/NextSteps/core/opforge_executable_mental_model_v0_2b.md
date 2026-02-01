# opForge --- Executable Mental Model


## Related documents

- **Core spec** (definitions): [opforge_core_spec_v0_3b.md](opforge_core_spec_v0_3b.md)
- **Patterned signatures** (the feature): [opforge_patterned_statement_signatures_v0_2b.md](opforge_patterned_statement_signatures_v0_2b.md)
- **45GS02 example** (apply the model): [opforge_45gs02_statement_dialect_example_v0_2b.md](opforge_45gs02_statement_dialect_example_v0_2b.md)

---
## How the Parser Walks a Line and Matches Statement Signatures

*v0.2b*

This document explains **how opForge parses a single line**, step by
step, and how it matches that line against `.statement` definitions with
patterned signatures and typed captures.

This is written as an **executable mental model**: you should be able to
mentally simulate the parser while reading code.

------------------------------------------------------------------------

## Key invariants

- `.use` imports symbols for resolution; it never emits content.
- Content injection is explicit via segment/macro references (block injection) or `[{ ... }]` (inline boundary control).
- `[{ ... }]` is purely positional/whitespace control.

------------------------------------------------------------------------

## High-level phases

For each source line, opForge proceeds in these phases:

1.  **Lexical scan**
2.  **Line classification**
3.  **Statement dispatch**
4.  **Signature matching**
5.  **Parameter binding**
6.  **Expansion / execution**

No backtracking parser, no global grammar --- just deterministic
matching.

------------------------------------------------------------------------

## 1. Lexical scan

The lexer produces a flat token stream:

-   identifiers
-   literals
-   operators
-   quoted literals (used verbatim in signatures)
-   punctuation tokens

Example:

    sta [$30],y

Token stream:

    IDENT(sta)
    LBRACKET([)
    INT(0x30)
    RBRACKET(])
    COMMA(,)
    IDENT(y)

Whitespace is preserved *only* for boundary decisions.

------------------------------------------------------------------------

## 2. Line classification

The first non-whitespace token determines the line class:

-   `.` → directive / symbol-processing line
-   identifier → statement candidate
-   otherwise → error or dialect-specific handling

Example:

    sta [$30],y

→ **statement candidate** with keyword `sta`.

------------------------------------------------------------------------

## 3. Statement dispatch

opForge gathers all `.statement` definitions with keyword `sta` that are
visible in the current scope (module + imports).

These definitions form the **candidate signature set**.

------------------------------------------------------------------------

## 4. Signature matching

Each candidate signature is matched left-to-right against the token
stream.

Signature atoms may be:

-   literal tokens
-   typed captures
-   boundary-controlled spans (`[{ ... }]`)

### Example signature

``` asm
.statement sta "[" byte:a ","[{char:reg}]
```

Matching proceeds atom-by-atom:

  Signature atom   Input tokens   Result
  ---------------- -------------- ---------------------
  `sta`            `sta`          match
  `"["`            `[`            match
  `byte:a`         `0x30`         capture `a = 0x30`
  `"]"`            `]`            match
  `","`            `,`            match
  `[{char:reg}]`   `y`            capture `reg = 'y'`

If all atoms match and the input is fully consumed → **signature
matches**.

------------------------------------------------------------------------

## 5. Precedence and ambiguity resolution

If multiple signatures match:

1.  Prefer signatures with **more literal atoms**
2.  Prefer **longer signatures**
3.  Prefer earlier declarations
4.  Otherwise → ambiguity error

This guarantees deterministic behavior.

------------------------------------------------------------------------

## 6. Parameter binding

Captured parameters are bound into a **statement execution frame**:

    a   = 0x30
    reg = 'y'

These bindings are available inside the `.statement` body.

------------------------------------------------------------------------

## 7. Expansion / execution

The statement body executes:

-   may emit instructions
-   may emit other statements
-   may perform `.match` for semantic validation
-   may error

Example body:

``` asm
.match .reg
  'x' => { encode STA_PTR32_X .a }
  'y' => { encode STA_PTR32_Y .a }
  _   => { .error "invalid register" }
.endmatch
```

Execution produces backend operations or expanded statements.

------------------------------------------------------------------------

## What this model deliberately avoids

-   No global grammar
-   No parser generators
-   No implicit textual inclusion
-   No whitespace-sensitive hacks

Everything is explicit, local, and composable.

------------------------------------------------------------------------

------------------------------------------------------------------------

## Token stream vs byte emission

In the standard pipeline:

- **Dialect statements** execute first and build a **token stream** via `emit TOK_...(...)`.
- The active **CPU backend** lowers tokens to `.byte/.word/...` output and creates relocations as needed (section-driven).

Dialects therefore map syntax to tokens; CPUs own encoding.

## Summary

-   Each statement line is parsed independently
-   Matching is deterministic and local
-   `.statement` signatures *are the grammar*
-   Typed captures + ADTs provide static guarantees
-   `[{ ... }]` only affects boundary precision

If you can walk through this document line-by-line, you understand
opForge's parsing model.