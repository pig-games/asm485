# Instruction Table Architecture

This document describes the unified instruction table architecture for the Intel 8080 family CPUs.

## Implementation Status

**IMPLEMENTED** ✅

The following components have been created:

- `src/families/intel8080/dialect.rs` - Dialect mnemonic mapping (e.g., Zilog → canonical)
- `src/families/intel8080/extensions.rs` - Re-exports CPU-specific extension tables
- `src/families/intel8080/table.rs` - Updated with unified `InstructionEntry` and `Prefix` types

**Migration Status (2026-01-28)**
- Intel8080 now uses the family/CPU pipeline by default.
- The dialect mapping module is now wired into the Intel8080 pipeline for Zilog mnemonics.

## Problem Statement

Previously there were two separate, full instruction tables:
1. `I8085_INSTRUCTION_TABLE` - Intel 8080/8085 mnemonics (MOV, MVI, JMP, etc.)
2. `Z80_INSTRUCTION_TABLE` - Zilog Z80 mnemonics (LD, JP, JR, etc.)

Those legacy tables have been removed in favor of a canonical family table plus CPU extensions.

## Proposed Architecture

### Three-Layer Design

```
┌─────────────────────────────────────────────────────────────────┐
│                      Dialect Layer                               │
│  Maps dialect mnemonic → canonical mnemonic + operand transform │
│  Intel8080Dialect: identity mapping                              │
│  ZilogDialect: LD → MOV/MVI/LXI, JP → JMP, etc.                 │
│  (Generic naming: "from" → "canonical")                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Family Base Table                             │
│  Canonical encoding using Intel 8080 mnemonics                   │
│  (mnemonic, reg1, reg2) → (opcode, prefix, arg_type)            │
│  ~240 entries for base 8080 instruction set                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  CPU Extension Tables                            │
│  I8085: RIM, SIM (2 entries)                                    │
│  Z80: JR, DJNZ, IX/IY, CB prefix, ED prefix (~150 entries)      │
└─────────────────────────────────────────────────────────────────┘
```

### Dialect Mapping

The Zilog dialect maps to the canonical family mnemonics:

| Dialect (from) | Canonical | Notes |
|--------------|-----------------|-------|
| `LD r,r'` | `MOV r,r'` | Register-to-register |
| `LD r,n` | `MVI r,n` | Load immediate byte |
| `LD rp,nn` | `LXI rp,nn` | Load immediate word |
| `LD A,(BC)` | `LDAX B` | Load A indirect |
| `LD A,(DE)` | `LDAX D` | Load A indirect |
| `LD A,(nn)` | `LDA nn` | Load A from address |
| `LD (BC),A` | `STAX B` | Store A indirect |
| `LD (DE),A` | `STAX D` | Store A indirect |
| `LD (nn),A` | `STA nn` | Store A to address |
| `LD HL,(nn)` | `LHLD nn` | Load HL from address |
| `LD (nn),HL` | `SHLD nn` | Store HL to address |
| `LD SP,HL` | `SPHL` | SP ← HL |
| `JP nn` | `JMP nn` | Unconditional jump |
| `JP cc,nn` | `Jcc nn` | Conditional jump (JZ, JNZ, etc.) |
| `CALL cc,nn` | `Ccc nn` | Conditional call (CZ, CNZ, etc.) |
| `RET cc` | `Rcc` | Conditional return (RZ, RNZ, etc.) |
| `ADC A,n` | `ACI n` | Add immediate with carry |
| `SUB r` | `SUB r` | Same (but Z80 also accepts `SUB A,r`) |
| `AND r` | `ANA r` | Logical AND |
| `AND n` | `ANI n` | AND immediate |
| `OR r` | `ORA r` | Logical OR |
| `OR n` | `ORI n` | OR immediate |
| `XOR r` | `XRA r` | Exclusive OR |
| `XOR n` | `XRI n` | XOR immediate |
| `CP r` | `CMP r` | Compare |
| `CP n` | `CPI n` | Compare immediate |
| `INC r` | `INR r` | Increment 8-bit |
| `INC rp` | `INX rp` | Increment 16-bit |
| `DEC r` | `DCR r` | Decrement 8-bit |
| `DEC rp` | `DCX rp` | Decrement 16-bit |
| `ADD HL,rp` | `DAD rp` | 16-bit add |
| `EX DE,HL` | `XCHG` | Exchange DE/HL |
| `EX (SP),HL` | `XTHL` | Exchange stack/HL |
| `JP (HL)` | `PCHL` | Jump to HL |
| `RLCA` | `RLC` | Rotate left circular |
| `RRCA` | `RRC` | Rotate right circular |
| `RLA` | `RAL` | Rotate left through carry |
| `RRA` | `RAR` | Rotate right through carry |
| `CPL` | `CMA` | Complement A |
| `SCF` | `STC` | Set carry flag |
| `CCF` | `CMC` | Complement carry flag |
| `HALT` | `HLT` | Halt |
| `IN A,(n)` | `IN n` | Input port |
| `OUT (n),A` | `OUT n` | Output port |

### Register Name Mapping

Z80 uses different register pair names:

| Dialect (from) | Canonical | Notes |
|-------|-------|-------|
| BC | B | Register pair |
| DE | D | Register pair |
| HL | H | Register pair |
| AF | PSW | Flags + A |
| (HL) | M | Memory via HL |

### Z80-Only Instructions (Extension Table)

These have no Intel equivalent and go in the Z80 extension table:

- **Relative Jumps**: JR, DJNZ
- **Exchange**: EXX, EX AF,AF'
- **Block Transfers**: LDI, LDIR, LDD, LDDR
- **Block Compare**: CPI, CPIR, CPD, CPDR
- **Block I/O**: INI, INIR, IND, INDR, OUTI, OTIR, OUTD, OTDR
- **Bit Operations**: BIT, SET, RES, RL, RR, RLC, RRC, SLA, SRA, SRL, SLL
- **Index Registers**: All IX/IY operations
- **Interrupt**: IM, RETI, RETN
- **16-bit Arithmetic**: ADC HL,rp, SBC HL,rp
- **Special**: NEG, RLD, RRD
- **I/O Extended**: IN r,(C), OUT (C),r

## Implementation Plan

### Step 1: Create Dialect Mapping Module

```rust
// src/families/intel8080/dialect.rs

/// Maps a dialect mnemonic and operands to canonical family form.
/// Generic naming: "from" = dialect-specific, "canonical" = family standard
pub struct DialectEntry {
    pub from: &'static str,           // Dialect mnemonic (e.g., "LD")
    pub from_regs: &'static str,      // Operand pattern (e.g., "r,r")
    pub from_has_imm: bool,           // Has immediate value
    pub canonical: &'static str,      // Canonical mnemonic (e.g., "MOV")
    pub canonical_regs: &'static str, // Transformed pattern
    pub canonical_has_imm: bool,      // Transformed immediate
    pub transform: OperandTransform,  // How to transform operands
}

pub enum OperandTransform {
    Identity,                  // Keep operands as-is
    DropFirst,                 // Remove first operand (ADD A,B → ADD B)
    ConditionSuffix,           // Merge condition into mnemonic (JP Z → JZ)
    IndirectLoad,              // (rp) → LDAX/LDA transform
    IndirectStore,             // (rp) → STAX/STA transform
}
```

### Step 2: Consolidate Base Table

Keep `FAMILY_INSTRUCTION_TABLE` with Intel mnemonics as the single source of truth for base 8080 opcodes.

### Step 3: Create Extension Tables

```rust
// 8085-only instructions
pub static I8085_EXTENSION_TABLE: &[InstructionEntry] = &[
    InstructionEntry { mnemonic: "RIM", ... },
    InstructionEntry { mnemonic: "SIM", ... },
];

// Z80-only instructions (using Z80 mnemonics directly)
pub static Z80_EXTENSION_TABLE: &[InstructionEntry] = &[
    InstructionEntry { mnemonic: "JR", ... },
    InstructionEntry { mnemonic: "DJNZ", ... },
    // ... all Z80-specific instructions
];
```

### Step 4: Unified Instruction Resolution

```rust
fn resolve_instruction(
    cpu: CpuType,
        SyntaxDialect::Zilog => map_dialect_to_canonical(mnemonic, operands)?,
    };
    
    // 3. Look up in family base table
    FAMILY_INSTRUCTION_TABLE.lookup(canonical_mnemonic, transformed_operands)
        .map(|entry| encode(entry, transformed_operands))
}
```

## Benefits

1. **Single source of truth**: Base 8080 opcodes defined once
2. **Clear extension model**: CPU-specific instructions in separate tables
3. **Explicit dialect mapping**: Easy to verify and extend
4. **Reduced duplication**: ~240 fewer entries to maintain
5. **Better testing**: Can test dialect mapping independently

## Migration Path

1. Create dialect mapping module (new file)
2. Create extension tables (new entries)
3. Update instruction resolution to use new architecture
4. Remove duplicate entries from Z80 table
5. Validate all examples still work
