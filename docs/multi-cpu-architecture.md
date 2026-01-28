# asm485 Multi-CPU Architecture

This document describes the modular architecture that allows asm485 to support multiple CPU targets (8085, Z80, 6502, 65C02, and potentially 68000, etc.) through a common framework.

## Overview

The assembler is organized into layers with hierarchical parsing and encoding:

```
┌─────────────────────────────────────────────────────────────┐
│                    Assembler Core                           │
│  (preprocessing, macro expansion, symbol table, output)     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Generic Parser                           │
│  Handles: labels, directives, macros, scopes, expressions   │
│  Extracts: mnemonic + raw operand tokens for instructions   │
│  Does NOT interpret addressing mode syntax                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Syntax Dialect (optional)                │
│  Maps dialect-specific mnemonics to instruction encoding    │
│  Transparent for families with uniform syntax (e.g., 6502)  │
│  Active for families with mnemonic variants (e.g., Z80)     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    CPU Family Layer                         │
│  - Parses operands into family addressing modes             │
│  - Uses generic expression parser for operand values        │
│  - Encodes instructions common to all family members        │
│  - Falls through to CPU-specific for extensions             │
└─────────────────────────────────────────────────────────────┘
          │                               │
          ▼                               ▼
┌───────────────────┐           ┌───────────────────┐
│   Intel8080       │           │    MOS6502        │
│   Family          │           │    Family         │
│                   │           │                   │
│ Dialects:         │           │ Dialect:          │
│  • Intel (8085)   │           │  • Transparent    │
│  • Zilog (Z80)    │           │                   │
└───────────────────┘           └───────────────────┘
          │                               │
    ┌─────┴─────┐                   ┌─────┴─────┐
    ▼           ▼                   ▼           ▼
┌───────┐  ┌───────┐           ┌───────┐  ┌───────┐
│ 8085  │  │  Z80  │           │ 6502  │  │ 65C02 │
│ CPU   │  │  CPU  │           │ CPU   │  │ CPU   │
└───────┘  └───────┘           └───────┘  └───────┘
```

## Layer Responsibilities

### Assembler Core

The assembler core handles high-level orchestration:
- File inclusion and preprocessing
- Output generation (listing files, hex files)
- Error collection and reporting
- Two-pass assembly coordination

### Generic Parser

The generic parser handles all **CPU-independent** parsing:
- **Labels**: Definition and reference
- **Directives**: ORG, DB, DW, EQU, IF/ELSE/ENDIF, etc.
- **Macros**: Definition, expansion, parameter substitution
- **Scopes**: Nested scope management for local labels
- **Expressions**: Arithmetic, symbols, operators (shared infrastructure)
- **Comments**: Line and block comments

For **instructions**, the generic parser extracts the mnemonic and raw operand tokens, but does *not* interpret addressing mode syntax (that's family-specific).

### Family Handler

The family handler interprets **operand syntax** for its CPU family:
- Recognizes addressing mode patterns (`#expr`, `(expr,X)`, etc.)
- **Uses the generic expression parser** to evaluate operand values
- Encodes instructions from the family's common instruction set
- Falls through to the CPU handler for unrecognized mnemonics

### CPU Handler

The CPU handler adds **CPU-specific extensions**:
- Resolves ambiguous operands based on CPU capabilities
- Encodes CPU-specific instructions not in the family set
- Validates that addressing modes are supported by the target CPU

## Hierarchical Processing

The key architectural principle is **hierarchical processing** at both the operand parsing and instruction encoding levels.

### Processing Pipeline

1. **Generic Parser** handles labels, directives, macros, scopes; extracts mnemonic + operand tokens for instructions
2. **Family Handler** parses operand tokens into addressing modes (using generic expression parsing), attempts instruction encoding
3. **CPU Handler** resolves ambiguous operands, encodes CPU-specific instructions
4. **Error** is reported if neither layer recognizes the operand or instruction

### Shared Generic Services

Family and CPU handlers have access to generic parsing infrastructure:
- **Expression evaluation**: Parse and evaluate `BASE+1`, `SIZE*2`, `(ADDR >> 8)`, etc.
- **Symbol lookup**: Resolve label and constant references
- **Span tracking**: Maintain source location for error reporting

This allows the family handler to parse `#BASE+1` by recognizing the `#` prefix (immediate mode) and delegating `BASE+1` to the generic expression parser.

### Why Hierarchical?

Different CPUs in the same family share most syntax and instructions but may add extensions. The hierarchical approach provides:

- **Code Reuse**: Family-common syntax and instructions handled once, not duplicated per CPU
- **Clean Extensions**: Extended CPUs only implement their additions, not the full base set
- **Clear Errors**: "Instruction not supported on this CPU" rather than generic "syntax error"
- **Future-Proof**: Adding a new CPU means extending its family, not starting from scratch

## Family Extensions

### MOS 6502 Family

**Operand Syntax Extensions:**

| Syntax | 6502 (Base) | 65C02 (Extended) |
|--------|-------------|------------------|
| `#$20` | Immediate ✓ | Immediate ✓ |
| `$20` | Zero Page ✓ | Zero Page ✓ |
| `($20,X)` | Indexed Indirect ✓ | Indexed Indirect ✓ |
| `($20),Y` | Indirect Indexed ✓ | Indirect Indexed ✓ |
| `($20)` | ✗ Invalid | Zero Page Indirect ✓ |
| `($1234,X)` | ✗ Invalid | Absolute Indexed Indirect ✓ |

The family handler parses common modes (rows 1-4). The 65C02 CPU handler resolves ambiguous `(expr)` and `(expr,X)` patterns that could be extended modes (rows 5-6).

**Instruction Extensions:**

| Instruction | 6502 (Base) | 65C02 (Extended) |
|-------------|-------------|------------------|
| `LDA` | ✓ All modes | ✓ All modes + ($zp) |
| `BRA` | ✗ | ✓ Branch Always |
| `PHX`, `PLX` | ✗ | ✓ Push/Pull X |
| `PHY`, `PLY` | ✗ | ✓ Push/Pull Y |
| `STZ` | ✗ | ✓ Store Zero |
| `TRB`, `TSB` | ✗ | ✓ Test and Reset/Set Bits |
| `BBSn`, `BBRn` | ✗ | ✓ Branch on Bit Set/Reset |
| `RMBn`, `SMBn` | ✗ | ✓ Reset/Set Memory Bit |

The family encoder handles base instructions (LDA, JMP, etc.). The 65C02 CPU encoder adds extended mnemonics and new addressing mode variants.

### Intel 8080 Family

**Operand Syntax Extensions:**

| Syntax | 8080/8085 (Base) | Z80 (Extended) |
|--------|------------------|----------------|
| `A`, `B`, `HL` | Register ✓ | Register ✓ |
| `(HL)` | Indirect ✓ | Indirect ✓ |
| `(IX+d)`, `(IY+d)` | ✗ | Indexed ✓ |

**Instruction Extensions:**

The Z80 adds numerous instructions: `DJNZ`, `JR` (with conditions), `EX`, `EXX`, block operations (`LDI`, `LDIR`, etc.), bit operations (`BIT`, `SET`, `RES`), and rotates/shifts (`SLA`, `SRA`, etc.).

**Syntax Dialects:**

Unlike the MOS 6502 family where all CPUs share the same mnemonics, the Intel 8080 family has two distinct **syntax dialects** that map to the same underlying opcodes:

| Operation | 8080/8085 Dialect | Z80 Dialect | Opcode |
|-----------|-------------------|-------------|--------|
| Move register | `MOV A,B` | `LD A,B` | 78 |
| Move immediate | `MVI A,55h` | `LD A,55h` | 3E 55 |
| Load direct | `LDA 1234h` | `LD A,(1234h)` | 3A 34 12 |
| Store direct | `STA 1234h` | `LD (1234h),A` | 32 34 12 |
| Jump | `JMP 1000h` | `JP 1000h` | C3 00 10 |
| Jump if zero | `JZ 1000h` | `JP Z,1000h` | CA 00 10 |
| Call | `CALL 1000h` | `CALL 1000h` | CD 00 10 |
| Return | `RET` | `RET` | C9 |
| Add register | `ADD B` | `ADD A,B` | 80 |
| Add immediate | `ADI 10h` | `ADD A,10h` | C6 10 |

See the **Syntax Dialects** section below for how this is handled architecturally.

## Processing Flow Examples

### Operand Parsing: `LDA ($20)` on 65C02

```
Source: "LDA ($20)"
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Generic Parser                                                  │
│ → mnemonic = "LDA", operand_tokens = [LPAREN, $20, RPAREN]      │
│ → Does NOT interpret the operand — just tokenizes               │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ MOS6502 Family Handler                                          │
│ → Recognizes (expr) pattern                                     │
│ → Returns UnresolvedIndirect($20) — ambiguous, needs CPU input  │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 65C02 CPU Handler                                               │
│ → Sees UnresolvedIndirect on non-JMP instruction                │
│ → Resolves to IndirectZeroPage($20)                             │
│ → (Base 6502 would report error here)                           │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Encoding                                                        │
│ → Emits [0xB2, 0x20]                                            │
└─────────────────────────────────────────────────────────────────┘
```

### Instruction Encoding: `BRA LOOP` on 65C02

```
Source: "BRA LOOP"
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Generic Parser                                                  │
│ → mnemonic = "BRA", operand_tokens = [IDENT(LOOP)]              │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ MOS6502 Family Handler                                          │
│ → Parses operand as Relative(LOOP)                              │
│ → Looks up "BRA" in family table — NOT FOUND                    │
│ → Falls through to CPU handler                                  │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 65C02 CPU Handler                                               │
│ → Looks up "BRA" in CPU extension table — FOUND                 │
│ → Emits [0x80, offset]                                          │
│ → (Base 6502 would also fail → "unknown instruction" error)     │
└─────────────────────────────────────────────────────────────────┘
```

## Core Abstractions

### CPU Identification

- **CpuType**: Specific processor (I8085, Z80, M6502, M65C02, etc.)
- **CpuFamily**: Processor family (Intel8080, MOS6502, Motorola68k)

Each CPU type maps to exactly one family. The assembler selects the appropriate family handler based on the target CPU.

### Handler Traits

**FamilyHandler** provides:
- Operand parsing for family-common syntax patterns
- Instruction encoding for family-common mnemonics
- Register and condition code recognition

**CpuHandler** provides:
- Reference to its parent family handler
- Resolution of ambiguous operands to CPU-specific forms
- Instruction encoding for CPU-specific mnemonics
- Query methods for supported modes and mnemonics

### Operand Representation

Two levels of operand types support the hierarchical model:

**FamilyOperand** (intermediate):
- Represents operands as parsed by the family handler
- May contain ambiguous cases (e.g., `Indirect` that could be JMP indirect or 65C02 zero-page indirect)
- Carries unevaluated expressions

**Operand** (final):
- Represents CPU-specific operands with resolved semantics
- Contains evaluated values ready for encoding
- Includes CPU-specific variants (e.g., `IndirectZeroPage` for 65C02, `Indexed` for Z80)

### Addressing Modes

Each family defines its own addressing mode type. Extended CPUs add to the family set:

**MOS 6502 Family:**
- Base: Implied, Accumulator, Immediate, ZeroPage, ZeroPageX/Y, Absolute, AbsoluteX/Y, Indirect (JMP only), IndexedIndirectX, IndirectIndexedY, Relative
- 65C02 adds: IndirectZeroPage, AbsoluteIndexedIndirect

**Intel 8080 Family:**
- Base: Register, RegisterPair, Immediate, Direct, Indirect (via register pair)
- Z80 adds: Indexed (IX+d, IY+d), Bit addressing

### Type Isolation Between Families

**Critical invariant**: Data structures must not mix content from different CPU families.

Each family defines its own types for:
- **AddressMode** — the addressing modes available in that family
- **FamilyOperand** — intermediate operand representation for that family
- **Operand** — final operand representation for that family
- **Register** — the register set for that family

This means there is no assembler-wide `AddressMode` enum containing both `ZeroPage` (6502) and `RegisterPair` (8080). Instead:
- `mos6502::AddressMode` contains 6502-family modes
- `intel8080::AddressMode` contains 8080-family modes

**Within a family**, types may combine aspects of all CPUs in that family. For example, `mos6502::AddressMode` includes `IndirectZeroPage` even though only 65C02 supports it — the CPU handler validates whether the target CPU actually supports a given mode.

This isolation:
- Prevents invalid cross-family combinations at compile time
- Keeps each family's types cohesive and well-documented
- Allows families to evolve independently

## Syntax Dialects

Some CPU families have members that use **different mnemonics** for the same underlying opcodes. This is distinct from instruction extensions (new opcodes) — it's the same binary encoding with different source syntax.

### The Problem

The Intel 8080 family illustrates this:
- **8080/8085** use Intel-style mnemonics: `MOV`, `MVI`, `LDA`, `STA`, `JMP`, `JZ`, etc.
- **Z80** uses Zilog-style mnemonics: `LD`, `JP`, `JR`, etc.

Both produce identical machine code for shared instructions, but the assembly source looks completely different:

```asm
; 8085 dialect                    ; Z80 dialect
MOV A,B        ; 78               LD A,B         ; 78
MVI A,55h      ; 3E 55            LD A,55h       ; 3E 55
LDA 1234h      ; 3A 34 12         LD A,(1234h)   ; 3A 34 12
JMP 1000h      ; C3 00 10         JP 1000h       ; C3 00 10
JZ LOOP        ; CA xx xx         JP Z,LOOP      ; CA xx xx
```

This is different from the 6502/65C02 relationship, where both use identical mnemonics (`LDA`, `JMP`, etc.) and 65C02 simply adds new instructions.

### Architectural Solution

A **Syntax Dialect** is a mnemonic mapping layer that sits between the generic parser and instruction encoding:

```
┌─────────────────────────────────────────────────────────────┐
│                    Generic Parser                           │
│  → Extracts mnemonic + operand tokens                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Syntax Dialect                           │
│  → Maps dialect mnemonics to canonical forms                │
│  → Normalizes operand order if needed                       │
│  → Passes through mnemonics not in dialect mapping          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Family Handler / CPU Handler                   │
│  → Works with canonical instruction representation          │
│  → Encodes to machine code                                  │
└─────────────────────────────────────────────────────────────┘
```

### Dialect Types

**Transparent Dialect** (default): Mnemonics pass through unchanged. Used when all family members share the same mnemonic set (e.g., MOS 6502 family).

**Mapping Dialect**: Transforms mnemonics and potentially operand structure before encoding. Used when a CPU uses different assembly syntax for the same opcodes.

### Intel 8080 Family Dialects

The Intel 8080 family has two syntax dialects:

**Intel8080Dialect** (8080, 8085):
- Uses Intel mnemonics: `MOV`, `MVI`, `LDA`, `STA`, `JMP`, `JZ`, `ADI`, etc.
- Operand order: destination first (`MOV A,B` = A ← B)
- Single-operand arithmetic: `ADD B` (implicit accumulator)

**Z80Dialect** (Z80):
- Uses Zilog mnemonics: `LD`, `JP`, `JR`, `ADD`, etc.
- Operand order: destination first (`LD A,B` = A ← B)
- Explicit accumulator: `ADD A,B`
- Adds Z80-only mnemonics: `DJNZ`, `LDIR`, `BIT`, `SET`, `RES`, etc.

### Processing Flow with Dialects

```
Source: "LD A,B" (Z80 dialect)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Generic Parser                                                  │
│ → mnemonic = "LD", operands = [A, B]                            │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Z80 Syntax Dialect                                              │
│ → Maps "LD A,B" to canonical Intel mnemonic "MOV A,B"           │
│ → Rewrites operands where needed                                │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Intel8080 Family Handler                                        │
│ → Looks up "MOV A,B" → opcode 0x78                              │
│ → Emits [0x78]                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Approaches

**Approach A: Separate Instruction Tables**

Each dialect has its own instruction table with dialect-specific mnemonics:
- `Intel8080InstructionTable`: `MOV`, `MVI`, `JMP`, etc.
- `Z80InstructionTable`: `LD`, `JP`, `JR`, etc.

The CPU handler selects the appropriate table based on target CPU.

*Pros*: Simple, explicit, easy to understand
*Cons*: Duplicates encoding logic for shared opcodes

**Approach B: Canonical Form with Dialect Mapping**

Define a canonical instruction representation (could be either dialect or an abstract form). The dialect layer maps source mnemonics to canonical, and the encoder works with canonical forms.

*Pros*: Single encoding path, clear separation of concerns
*Cons*: More complex, adds indirection

**Approach C: Hybrid — Shared Opcodes, Dialect-Specific Extensions**

Use the family handler for opcodes common to all family members (with dialect mapping). Use CPU handlers for dialect-specific extensions (Z80's `DJNZ`, `BIT`, etc.).

*Pros*: Maximizes code reuse, clean extension model
*Cons*: Must carefully define the "common" vs "extended" boundary

### Recommended Approach

For the Intel 8080 family, **Approach C (Hybrid — Shared Opcodes, Dialect-Specific Extensions)** is currently implemented:

- `Intel8080FamilyHandler` encodes canonical Intel mnemonics via `FAMILY_INSTRUCTION_TABLE`
- Z80 dialect mapping normalizes Zilog mnemonics to canonical forms
- CPU handlers only encode extensions (e.g., Z80-only or 8085-only instructions)

This works because:
1. Shared opcodes are encoded once via the canonical table
2. Dialect mapping preserves Z80 syntax without duplicating encoding logic
3. Extensions remain isolated in CPU modules

### Dialect Selection

The assembler determines the active dialect from the target CPU:

| CpuType | Dialect | Instruction Table |
|---------|---------|-------------------|
| I8080 | Intel8080Dialect | Family table |
| I8085 | Intel8080Dialect | Family table + 8085 extensions |
| Z80 | Z80Dialect | Family table + Z80 extensions |
| M6502 | Transparent | Family table |
| M65C02 | Transparent | Family table + extensions |

The `.cpu` directive in source selects both the CPU type and its associated dialect.

## Module Structure

```
src/
├── core/
│   ├── parser.rs        # Generic parser
│   ├── operand.rs       # Operand types
│   ├── cpu.rs           # CpuType, CpuFamily
│   └── traits.rs        # FamilyHandler, CpuHandler traits
│
├── families/
│   ├── intel8080/       # 8080/8085 common parsing and encoding
│   └── mos6502/         # 6502 common parsing and encoding
│
├── i8085/               # 8085-specific extensions (RIM, SIM)
├── z80/                 # Z80 extensions and dialect mapping
├── m6502/               # Base 6502 (no extensions)
├── m65c02/              # 65C02 extensions
│
└── assembler/           # Main orchestration
```

## Design Decisions

### Why Unified Handler Traits?

Each handler trait combines parsing and encoding rather than separating them into `FamilyParser`/`FamilyEncoder`. This keeps related functionality together — the same handler that understands how to parse `($20)` also knows how to encode instructions that use that mode.

### Why FamilyOperand Intermediate Type?

Some syntax patterns are ambiguous at the family level:
- `($20)` could be JMP indirect (6502) or zero-page indirect (65C02)
- `(IX+5)` is only valid on Z80, not 8085

The family handler parses the *syntax* and marks ambiguous cases. The CPU handler resolves the *semantics* based on which CPU is targeted.

### Why Keep Expressions CPU-Neutral?

Arithmetic expressions (`BASE+1`, `SIZE*2`) work the same across all CPUs. The generic parser handles expression tokenization; family handlers wrap expressions in addressing mode context (e.g., `#BASE+1` → Immediate).

### Why Fallthrough Encoding?

The pipeline tries family encoding first, then CPU-specific:

```
Family Handler → "not found" → CPU Handler → "not found" → Error
```

This means:
- Common instructions are encoded by the family (shared code)
- Extended instructions fall through to the CPU (extension code)
- No need for explicit "is this a CPU-specific instruction?" checks

## Migration Path

To migrate from the current implementation to hierarchical parsing and encoding:

1. Create FamilyOperand type and FamilyHandler trait ✓
2. Implement MOS6502FamilyHandler with operand parsing and base instruction encoding ✓
3. Create CpuHandler trait; implement for M6502 and M65C02 ✓
4. Implement M65C02CpuHandler with extended instruction encoding ✓
5. Update assembler to use new pipeline for MOS6502 family ✓
6. Implement Intel8080FamilyHandler for 8080/8085 dialect ✓
7. Implement I8085CpuHandler for RIM/SIM extensions ✓
8. Implement Z80CpuHandler with Z80 extensions ✓
9. Wire Intel8080 family handlers into assembler ✓
10. Remove legacy CPU-specific processing code ✓

### Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| MOS6502FamilyHandler | ✅ Complete | Wired into assembler |
| M6502CpuHandler | ✅ Complete | Wired into assembler |
| M65C02CpuHandler | ✅ Complete | Wired into assembler |
| Intel8080FamilyHandler | ✅ Complete | Intel dialect table |
| I8085CpuHandler | ✅ Complete | RIM/SIM support |
| Z80CpuHandler | ✅ Complete | Zilog dialect table |
| Intel8080 assembler wiring | ✅ Complete | Uses dialect mapping + family table + extensions |

The Intel 8080 family handlers are wired into the assembler. Legacy `process_instruction_8085()` and `process_instruction_z80()` paths have been removed in favor of a unified `process_instruction_intel8080()` flow that uses dialect mapping, family encoding, and CPU extensions.
