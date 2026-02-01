# opForge --- Family, CPU, Dialect Packs and Encoding via Statements


## Related documents

- **Core spec** (registry DSL overview): [opforge_core_spec_v0_3b.md](opforge_core_spec_v0_3b.md)
- **Patterned signatures** (dialect grammar mechanism): [opforge_patterned_statement_signatures_v0_2b.md](opforge_patterned_statement_signatures_v0_2b.md)
- **Sections & relocation** (layout/link story): [opforge_sections_and_relocation_v0_2a.md](opforge_sections_and_relocation_v0_2a.md)

---
*v0.2b*

This document specifies how **processor families, CPUs, and dialects**
are defined, registered, and activated in opForge, and how **instruction
encoding** can be expressed purely using `.statement` definitions.

The goal is to allow: - new CPUs and dialects to be added without
touching core code - full instruction sets to be bootstrapped in opForge
itself - optional coexistence with Rust-based backends for performance
or complexity

------------------------------------------------------------------------

## Conceptual Overview

opForge separates concerns into three layers:

-   **Family** --- architectural lineage and shared properties
-   **CPU** --- concrete processor variant and feature set
-   **Dialect** --- syntax, addressing modes, and statement grammar

All three are defined declaratively and may be registered into the
global module registry.

------------------------------------------------------------------------

## Definitions vs Activation

Definitions create symbols. Activation selects the active compilation
context.

-   `.deffamily`, `.defcpu`, `.defdialect` → define
-   `.register` → add definition to registry
-   `.cpu`, `.dialect` → activate / select

`.use` only imports definitions; it never activates or emits content.

------------------------------------------------------------------------

## Family Definition

``` asm
.deffamily m6502
  ; shared properties, defaults, metadata
.endfamily
```

A family may be referenced by CPUs.

------------------------------------------------------------------------

## CPU Definition

``` asm
.defcpu 45gs02 : m6502
  ; ensure dependencies
  .register family m6502

  ; define dialect(s)
  .defdialect mega65 : 45gs02
    ; statement grammar and encoders live here
  .enddialect

  .register dialect mega65
.endcpu
```

### Semantics

-   `.defcpu` bodies are **not executed** at parse time
-   The body executes when `.register cpu <id>` occurs
-   Registration is idempotent

A `.defcpu` may: - register other CPUs (dependencies) - define and
register dialects - install instruction encoders and features

------------------------------------------------------------------------

## Dialect Definition

------------------------------------------------------------------------

## Dialects as token mappers

A **dialect** is specifically a mapping from *surface statements* to **CPU-defined tokens**.

- The CPU (or family) defines a set of **tokens** (a structured, assembler-facing IR): e.g. `TOK_STA_ZP_PTR32_Y(zp)`.
- The dialect defines `.statement` patterns that **emit tokens** instead of emitting bytes directly.
- A CPU backend (implemented in opForge or Rust) **lowers tokens to bytes** (and may create relocations via `.section` rules).

Roles:

- **Dialect**: syntax + addressing-mode selection → tokens
- **CPU**: legality + encoding (tokens → bytes/relocs)
- **Sections**: placement + linking → final image

`[{ ... }]` remains purely boundary/whitespace control and is unrelated to token emission.

A dialect defines the **surface language**.

``` asm
.defdialect mega65 : 45gs02
  ; statement patterns
  ; operand forms
  ; macros / segments for syntax sugar
.enddialect
```

Dialects typically define `.statement` patterns for instructions.

------------------------------------------------------------------------

## Registration

``` asm
.register cpu 45gs02
.register dialect mega65
```

Registration: - validates the definition exists - installs it into the
registry - executes its definition body once

Registration may occur: - from startup packs - from project-local
source - implicitly when `.cpu` / `.dialect` activates an unregistered
definition

------------------------------------------------------------------------

## Activation

``` asm
.cpu 45gs02
.dialect mega65
```

-   `.cpu` selects the active CPU
-   `.dialect` selects the active grammar
-   dialect defaults may be inferred from CPU

------------------------------------------------------------------------

## Token Lowering and Encoding via `.statement`

There is no special encoder API.

Encoding is expressed by lowering CPU-defined tokens to bytes (and relocations) using normal statements.

### Encoder statements

``` asm
.statement encode TOK_STA_ZP_PTR32(byte:zp)
  .byte 0xAB
  .byte .zp
.endstatement
```

### Syntax statements call encoders

``` asm
.statement sta "[" byte:zp "]"
  emit TOK_STA_ZP_PTR32(.zp)
.endstatement
```

This cleanly separates: - **syntax** (statement pattern) - **encoding**
(byte emission)

Both are defined in opForge.

------------------------------------------------------------------------

## Expressions and Matching in Encoders

Encoders may use: - expressions - `.match` over ADTs or values -
computed opcodes

``` asm
.statement encode MOVE Size:size char:dst char:src
  .match .size
    b => { opcode = 0x10 }
    w => { opcode = 0x11 }
    l => { opcode = 0x12 }
  .endmatch

  .byte opcode
  .byte .dst
  .byte .src
.endstatement
```

------------------------------------------------------------------------

## Coexistence with Rust Backends

Pure opForge encoders: - ideal for bootstrapping - portable - easy to
extend

Rust-based implementations may still be used for: - performance -
complex instruction selection - advanced relocation / optimization

Resolution strategy: 1. Use Rust encoder if available 2. Otherwise fall
back to opForge `.statement` encoders

------------------------------------------------------------------------

------------------------------------------------------------------------

## Auto-register on activation (optional ergonomics)

For convenience, `.cpu <id>` and `.dialect <id>` may auto-register the corresponding definition **if it is in scope** (e.g. imported via `.use`).

If no in-scope definition exists and the id is not registered, activation fails with an error.

------------------------------------------------------------------------

## Modules, `.use`, and content injection

`.use` imports target pack symbols (definitions and helper segments/macros). It never emits content.
Any boilerplate or generated text is injected explicitly by invoking segments/macros, with `[{ ... }]` used only for boundary control.

## Summary

-   Families, CPUs, and dialects are data-driven
-   `.defcpu` acts as an executable registration recipe
-   Dialects define syntax via `.statement`
-   Encoding is just code that emits bytes
-   Rust backends remain optional, not mandatory

This turns opForge into a **self-extending assembler framework**.