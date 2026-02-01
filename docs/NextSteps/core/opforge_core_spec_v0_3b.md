# opForge Core Specification


## Related documents

- **Core spec**: [opforge_core_spec_v0_3b.md](opforge_core_spec_v0_3b.md)
- **Executable mental model**: [opforge_executable_mental_model_v0_2b.md](opforge_executable_mental_model_v0_2b.md)
- **Patterned `.statement` signatures**: [opforge_patterned_statement_signatures_v0_2b.md](opforge_patterned_statement_signatures_v0_2b.md)
- **Family/CPU/Dialect packs + `encode`**: [opforge_family_cpu_dialect_and_encoding_v0_2b.md](opforge_family_cpu_dialect_and_encoding_v0_2b.md)
- **Sections & relocation**: [opforge_sections_and_relocation_v0_2a.md](opforge_sections_and_relocation_v0_2a.md)
- **45GS02 worked example**: [opforge_45gs02_statement_dialect_example_v0_2b.md](opforge_45gs02_statement_dialect_example_v0_2b.md)

---
## Purpose

opForge originated as a multi‑target assembler core with a clean
separation between: - generic assembler infrastructure -
macro/conditional/expression systems - and delegated target logic via
registries of **Family**, **CPU**, and **Dialect** modules.

This document formalizes the evolution of opForge into a broader
framework:

> **opForge becomes a reusable compilation framework** --- a reusable, scalable
> compilation kernel that provides language structure, modularity,
> compile‑time semantics, and extensibility --- while specific
> assemblers (such as asm465) become implementations built on top of
> this framework.

This direction explicitly separates: - **opForge layer** → language
kernel, modules, macros, expressions, types, matching, scopes - **Target
packs** → Family/CPU/Dialect registries and encoding logic - **Assembler
products** → concrete assembler implementations using opForge + target
packs - **Ecosystems (e.g. asm465)** → cross‑dev runtimes, platform
mapping, MMIO, tooling, build/test

Non‑goals: - Becoming a general-purpose scripting language - Embedding a
"second language" inside assembly - Requiring OS services, heap
allocation, or heavy runtime infrastructure - Breaking assembler‑native
mental models

------------------------------------------------------------------------

## Design Principles

### Assembler‑native surface

All features must be expressed in directive/scoping form: `.use`,
`.pub`, `.namespace`, `.section`, `.type`, `.match`, `.macro`, `.block`

No secondary syntax modes or embedded programming languages.

### Staged compilation

Compilation is always structured as explicit phases: tokens → macros →
parsing → evaluation/lowering → emission

### Profile scalability

Same architecture from microcontrollers to modern OSes: - **nano** -
**tiny** - **small** - **full**

Features scale by capability sets, not different languages.

### Determinism

No textual inclusion‑based modularity. No include‑order semantics. No
hidden global state. Module graphs and symbol visibility are explicit.
For some usecases it is still useful to support: 
- .include <file>; injects the text contents of the file
- .binclude <file>; injects the binary contents of a file
These should however not primarily be used to modularize a program, as .use is better solution for that.

------------------------------------------------------------------------

## Core Architecture Layers

### 1. opForge Language Kernel

Provides: - tokenization - scopes - macro system - conditional logic -
expression engine - module graph - compile‑time value system - pattern
matching - diagnostics - staged pipeline

Target‑agnostic by design.

### 2. Target Registry Layer (existing architecture)

Already present in opForge:

-   **Family registry**
-   **CPU registry**
-   **Dialect registry**

Assembler delegates instruction parsing, encoding, and operand handling
to these modules. This layer remains responsible for **instruction
semantics and encoding**, not language structure.

### 3. Assembler Implementation Layer

One consumer of opForge + target registry: - orchestrates passes -
resolves symbols - drives backend emission - coordinates target modules

### 4. External Ecosystems (e.g. asm465)

Separate systems that may embed opForge: - cross‑development
frameworks - platform mapping (MMIO personalities) - runtime
abstraction - build/test automation - tooling integration

------------------------------------------------------------------------

## Modules and Scopes

### Source Files

A source file is a container and may contain: - one implicit module -
multiple explicit modules

### Module

A module is a **root scope with identity and export surface**.

Properties: - `module_id` - import list - export table - root lexical
scope

Modules are semantic units, not textual inclusion units.

### Scope Types

-   `.module`
-   `.namespace`
-   `.block`
-   `.macro`
-   `.segment`

Scopes control visibility and resolution, not packaging.

------------------------------------------------------------------------

## Module Identity, Imports, and Visibility (Consolidated Spec)

### Grammar (informal)

- **Identifiers** are alphanumeric with `_`, starting with a letter or `_`.
- **Module ids** are dotted paths of identifiers (e.g. `std.math`, `app.core.io`).
- **`.module <module-id>`** starts a module block; **`.endmodule`** ends it.
- **`.use <module-id>`** may include:
  - **Alias**: `as <ident>` (tiny+)
  - **Selective list**: `(item [, item]...)` where each item is `name` or `name as alias` (small+)
  - **Parameters**: `with (k=v [, k=v]...)` (small+), where values are expressions.
- **`.pub`** and **`.priv`** are standalone directives that change the default visibility for subsequent declarations in the current scope.

Notes:
- `expr` is any core expression (see Expressions section).

### Module Identity and File Rules

- A **module** is a root scope with identity and export surface.
- A **source file** may contain either:
  - **one implicit module** (no `.module` directives present), or
  - **one or more explicit modules** delimited by `.module`/`.endmodule`.
- If any explicit `.module` appears, **all** top‑level content must be inside an explicit module.

**Implicit module id**:
- The assembler assigns a module id from the source unit name (default: file basename without extension).
- Build tooling may override or prefix the implicit id.

**Explicit module id**:
- The id is defined by `.module <module-id>` and must be unique in the compilation unit.
- Nested modules are illegal.

### Scope Rules

- `.module` establishes the **root lexical scope** for the module.
- `.namespace` and `.block` are lexical scopes inside a module.
- `.macro` and `.segment` introduce named symbols that live in the module namespace.

### Name Resolution Order

For an **unqualified** reference `name` in a module:
1. **Local lexical scopes** from innermost to module root.
2. **Selective imports** that introduce `name` into the current module scope.

For a **qualified** reference `Mod.name` or `Alias.name`:
1. Resolve `Mod` as either a module id or an import alias.
2. Lookup `name` in the target module’s **export table**.

**Shadowing and conflicts**:
- A local definition **may not** reuse a name introduced by selective import in the same scope (diagnostic).
- Import aliases must be unique in the module.
- Duplicate selective imports of the same local name are diagnostics.

### Visibility Rules (`.pub` / `.priv`)

- **Default** visibility is **private**.
- `.pub` and `.priv` change the **current default visibility** for subsequent declarations in the **current scope**.
- Visibility state is **lexically scoped**: entering a scope inherits the parent’s default and changes do not leak outward.
- The visibility at the **point of declaration** is stored on the symbol.

**Exportable symbol kinds**:
- Runtime symbols (labels, constants, variables, data labels).
- Macros (`.macro`) and segments (`.segment`).
- Types (`.type`).

**Non‑exportable** (by default): anonymous/local labels and unnamed scopes.

### Import Forms

- **Basic (qualified)**: `.use std.math`
  - Use as `std.math.add16`.
- **Alias**: `.use std.math as M` (tiny+)
  - Use as `M.add16`.
- **Selective**: `.use std.math (add16, sub16 as sub)` (small+)
  - Introduces `add16` and `sub` as unqualified names.
- **Parameters**: `.use foo with (FEATURE=1, MODE="fast")` (small+)
  - Parameters are visible to the imported module’s profile gates.

### Diagnostics (non‑exhaustive)

- **E‑MOD‑001**: nested `.module`.
- **E‑MOD‑002**: duplicate module id.
- **E‑MOD‑003**: `.endmodule` without matching `.module`.
- **E‑MOD‑004**: top‑level content outside explicit module when explicit modules exist.
- **E‑USE‑001**: missing module id.
- **E‑USE‑002**: import alias collision.
- **E‑USE‑003**: selective import collision.
- **E‑USE‑004**: missing imported symbol.
- **E‑USE‑005**: import cycle detected.
- **E‑VIS‑001**: access to non‑exported symbol.
- **E‑VIS‑002**: selective import of non‑exported symbol.

### Examples

**Basic module + exports**

```
.module math.core
.pub
add16   .macro (a, b)
    ; ...
.endmacro
.priv
tmp     .const 0
.endmodule
```

**Use with alias + selective**

```
.module app.main
.use math.core as M
.use math.core (add16 as add)

    add16  .word 0      ; ok: selective import
    M.add16            ; ok: qualified via alias
.endmodule
```

**Negative cases (illustrative)**

```
.module a
.module b      ; error: nested module (E‑MOD‑001)
.endmodule

.module c
.use missing.mod      ; error: missing module (E‑USE‑001)
.endmodule

.module d
.use math.core (tmp)  ; error: tmp is private (E‑VIS‑002)
.endmodule
```

------------------------------------------------------------------------

## Directives (Core Set)

### `.module <id>` / `.endmodule`

Defines a module scope with identity.

If absent, file becomes one implicit module.

**Profile:** nano+

------------------------------------------------------------------------

### `.use <module-id> [as <alias>] [(items...)] [with (k=v,...)]`

Declares semantic dependency.

No textual injection.


Importing a module never emits content. Content injection is explicit via segments/macros (e.g. a standalone `.doc.intro` line) and inline via `[{.doc.version()}]` for boundary control.

Import forms: - qualified: `Mod.symbol` - alias: `.use std.math as M` -
selective: `.use std.math (add16)` (tiny+) - parameters:
`.use foo with (FEATURE=1)` (small+)

**Profile:** - nano: basic `.use` - tiny: alias - small: selective +
params

------------------------------------------------------------------------

### `.pub` / `.priv`

Controls export visibility.

Exportable: - runtime symbols - macros - types

Default: private.

**Profile:** nano+

------------------------------------------------------------------------

### `.namespace <name>` / `.endnamespace`

Lexical scoping and namespacing only.

**Profile:** nano+

------------------------------------------------------------------------

### `.block` / `.endblock`

Local lexical scope.

**Profile:** nano+

------------------------------------------------------------------------

### `.macro` / `.endmacro`

Compile‑time token transformers.

Macros: - are scoped - are module‑local unless exported - cannot perform
module loading

**Profile:** nano+

------------------------------------------------------------------------

### `.segment` / `.endsegment`

Compile‑time token transformers, does not include an implicit .block scope.

Segments: - are module‑local unless exported - cannot perform
module loading

**Profile:** nano+

------------------------------------------------------------------------

### `.if` / `.elseif` / `.else` / `.endif`

Compile‑time conditional evaluation.

**Profile:** nano+

------------------------------------------------------------------------

### `.dsection <name>` / `.section <name>` / `.endsection`

Output placement control (backend mapping).

`.dsection` declares a section and constraints; `.section` selects the current output target. Relocations and linking are section-driven: relocation records belong to sections and are resolved when sections are placed.

**Profile:** nano+

------------------------------------------------------------------------

## Expressions

Core expression system: - integer literals - symbol references -
arithmetic/bitwise ops - comparisons - precedence - parentheses

Deterministic semantics: - explicit integer width - explicit overflow
behavior

**Profile:** nano+

------------------------------------------------------------------------

## Compile‑Time Values

Compile‑time value types: - integers (always, with `byte`/`word` typed capture support) - strings (tiny+
optional) - tuples/records (small+) - ADTs (small+) - token/AST
fragments (full+ optional future)

------------------------------------------------------------------------

## Algebraic Data Types (ADTs)

### `.type`

``` asm
.type Operand =
  | Imm(value)
  | Zp(addr)
  | Abs(addr)
  | Sym(name)
```

Defines tagged compile‑time values. Compile‑time only. No runtime
footprint.

------------------------------------------------------------------------

## Pattern Matching

### `.match <expr>` / `.endmatch`

Pattern matching over compile‑time values.

Primary early use: - instruction encoding selection - operand
classification - declarative backend logic

Initial strategy: - builtin `Operand` ADT first - user‑defined `.type`
later

------------------------------------------------------------------------

## Compilation Pipeline

### Phase 0 --- Module Graph Resolution

-   resolve `.use`
-   build dependency graph
-   detect cycles (nano/tiny: forbidden)

### Phase 1 --- Lexing

-   byte stream → tokens

### Phase 2 --- Macro Expansion

-   macro expansion
-   conditional evaluation

### Phase 3 --- Parsing

-   nano/tiny: streaming statements
-   small/full: core AST

### Phase 4 --- Evaluation & Lowering

-   expression evaluation
-   symbol resolution
-   match/type lowering
-   backend IR generation

### Phase 5 --- Backend Emission

-   byte emission
-   relocations
-   symbols
-   diagnostics

------------------------------------------------------------------------

## Backend Contract (Conceptual)

Minimal interface:

-   `set_section(name)`
-   `define_symbol(name, value|reloc)`
-   `emit_byte(value|expr|reloc)`
-   `emit_word(value|expr|reloc, endian)`
-   `reloc(kind, symbol, addend)`
-   `diagnostic(level, span?, message)`

Assembler backend is one implementation.

------------------------------------------------------------------------

## Profile Model

### nano

-   modules
-   `.use/.pub`
-   scopes
-   macros
-   conditionals
-   expressions
-   backend emission

### tiny

-   alias imports
-   better diagnostics
-   builtin operand matching

### small

-   `.type`
-   `.match`
-   selective imports
-   module parameters
-   richer compile‑time values

### full

-   AST tooling
-   incremental builds
-   caching
-   hygienic macros
-   tooling/LSP hooks

------------------------------------------------------------------------

## Relationship to asm465

asm465 is **not** a backend of opForge --- it is a separate ecosystem
that may embed opForge:

-   cross‑dev framework
-   platform mapping
-   MMIO personalities
-   runtime abstraction
-   build/test orchestration
-   tooling pipelines

opForge remains: - small - embeddable - deterministic -
framework‑grade

asm465 remains: - application ecosystem - platform/runtime system -
tooling and workflows

------------------------------------------------------------------------

## Strategic Direction

opForge evolves from: \> "multi‑target assembler"

into: \> "assembler‑native language and compilation framework (framework)"

with assemblers becoming products built on it, not the framework itself.
------------------------------------------------------------------------

## Content Injection and Output Boundaries

opForge does not support preprocessor-style textual inclusion. Modules are imported for **symbol resolution** only.

- **Block injection:** a standalone dot-symbol on its own line injects the output of a segment/macro (no `[{ ... }]` needed).
- **Inline injection:** use `[{ ... }]` to splice expansions into surrounding text with exact positional/whitespace control.

`[{ ... }]` is **purely boundary control**. It does not introduce a separate templating language.

------------------------------------------------------------------------

## Target Packs (Family/CPU/Dialect)

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

opForge can load targets via a registry of **Family**, **CPU**, and **Dialect** entries. Targets may be implemented in Rust or defined in opForge source.

Definitions vs activation:

- `.deffamily`, `.defcpu`, `.defdialect` define target entries as symbols.
- `.register` installs a definition into the runtime registry (idempotent).
- `.cpu <id>` selects the active CPU (activation).
- `.dialect <id>` optionally selects the active dialect (dialect selection).

A `.defcpu` body may act as an executable pack recipe: it can register dependencies, define and register dialects, and install `.statement` patterns and encoders.
