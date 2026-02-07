// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Zilog Z80 dialect mapping.
//!
//! This module maps Z80 (Zilog) mnemonics to their Intel 8080 equivalents
//! for instructions that exist on both processors but use different syntax.
//! Z80-only instructions (JR, DJNZ, etc.) are handled by the extension table.

/// Maps a Z80 register name to its Intel 8080 equivalent.
/// Returns None for Z80-only registers (IX, IY, I, R).
pub fn map_register(zilog_reg: &str) -> Option<&'static str> {
    match zilog_reg.to_ascii_uppercase().as_str() {
        // 8-bit registers - same names
        "A" => Some("A"),
        "B" => Some("B"),
        "C" => Some("C"),
        "D" => Some("D"),
        "E" => Some("E"),
        "H" => Some("H"),
        "L" => Some("L"),

        // Memory via HL
        "M" => Some("M"),
        "(HL)" => Some("M"),

        // 16-bit register pairs - Z80 uses full names
        "BC" => Some("B"),
        "DE" => Some("D"),
        "HL" => Some("H"),
        "SP" => Some("SP"),

        // Flags + A
        "AF" => Some("PSW"),
        "PSW" => Some("PSW"),

        // Z80-only registers - no mapping
        "IX" | "IY" | "IXH" | "IXL" | "IYH" | "IYL" | "I" | "R" => None,

        _ => None,
    }
}

/// Check if a mnemonic is Z80-specific (no Intel equivalent).
/// These instructions require the Z80 extension table.
pub fn is_z80_only_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        "JR" | "DJNZ" | "EXX" |
        "LDI" | "LDIR" | "LDD" | "LDDR" |
        "CPI" | "CPIR" | "CPD" | "CPDR" |
        "INI" | "INIR" | "IND" | "INDR" |
        "OUTI" | "OTIR" | "OUTD" | "OTDR" |
        "BIT" | "SET" | "RES" |
        "RL" | "RR" | "SLA" | "SRA" | "SRL" | "SLL" |
        "RLC" | "RRC" |  // CB-prefixed versions, not the simple ones
        "IM" | "RETI" | "RETN" |
        "NEG" | "RLD" | "RRD"
    )
}

use crate::families::intel8080::dialect::{DialectEntry, OperandTransform};

/// Table mapping Zilog dialect mnemonics to canonical Intel equivalents.
/// Only includes mappings where the syntax differs.
/// Entries are checked in order; more specific patterns should come first.
pub static ZILOG_DIALECT_MAP: &[DialectEntry] = &[
    // LD instructions with various patterns
    // LD r,r' - register to register → MOV r,r'
    DialectEntry {
        from: "LD",
        from_regs: 2,
        from_has_imm: false,
        canonical: "MOV",
        canonical_regs: 2,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // LD r,n - load immediate byte → MVI r,n
    DialectEntry {
        from: "LD",
        from_regs: 1,
        from_has_imm: true,
        canonical: "MVI",
        canonical_regs: 1,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // Note: LD rp,nn and other complex LD forms need special handling

    // JP instructions
    // JP nn → JMP nn
    DialectEntry {
        from: "JP",
        from_regs: 0,
        from_has_imm: true,
        canonical: "JMP",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // JP cc,nn → Jcc nn (e.g., JP Z,nn → JZ nn)
    DialectEntry {
        from: "JP",
        from_regs: 1,
        from_has_imm: true,
        canonical: "J",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::ConditionSuffix,
    },
    // JP (HL) → PCHL
    DialectEntry {
        from: "JP",
        from_regs: 1,
        from_has_imm: false,
        canonical: "PCHL",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // CALL instructions
    // CALL nn → CALL nn (same)
    DialectEntry {
        from: "CALL",
        from_regs: 0,
        from_has_imm: true,
        canonical: "CALL",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // CALL cc,nn → Ccc nn (e.g., CALL Z,nn → CZ nn)
    DialectEntry {
        from: "CALL",
        from_regs: 1,
        from_has_imm: true,
        canonical: "C",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::ConditionSuffix,
    },
    // RET instructions
    // RET → RET (same)
    DialectEntry {
        from: "RET",
        from_regs: 0,
        from_has_imm: false,
        canonical: "RET",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // RET cc → Rcc (e.g., RET Z → RZ)
    DialectEntry {
        from: "RET",
        from_regs: 1,
        from_has_imm: false,
        canonical: "R",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::ConditionSuffix,
    },
    // Arithmetic with A - Z80 uses explicit destination
    // ADD A,r → ADD r
    DialectEntry {
        from: "ADD",
        from_regs: 2,
        from_has_imm: false,
        canonical: "ADD",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::DropFirst,
    },
    // ADD A,n → ADI n
    DialectEntry {
        from: "ADD",
        from_regs: 1,
        from_has_imm: true,
        canonical: "ADI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::DropFirst,
    },
    // ADC A,r → ADC r
    DialectEntry {
        from: "ADC",
        from_regs: 2,
        from_has_imm: false,
        canonical: "ADC",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::DropFirst,
    },
    // ADC A,n → ACI n
    DialectEntry {
        from: "ADC",
        from_regs: 1,
        from_has_imm: true,
        canonical: "ACI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::DropFirst,
    },
    // SUB r (same) - Z80 also accepts SUB A,r
    DialectEntry {
        from: "SUB",
        from_regs: 2,
        from_has_imm: false,
        canonical: "SUB",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::DropFirst,
    },
    // SUB A,n → SUI n
    DialectEntry {
        from: "SUB",
        from_regs: 1,
        from_has_imm: true,
        canonical: "SUI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::DropFirst,
    },
    // SUB n → SUI n
    DialectEntry {
        from: "SUB",
        from_regs: 0,
        from_has_imm: true,
        canonical: "SUI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // SBC A,r → SBB r
    DialectEntry {
        from: "SBC",
        from_regs: 2,
        from_has_imm: false,
        canonical: "SBB",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::DropFirst,
    },
    // SBC A,n → SBI n
    DialectEntry {
        from: "SBC",
        from_regs: 1,
        from_has_imm: true,
        canonical: "SBI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::DropFirst,
    },
    // Logical operations - Z80 uses AND/OR/XOR, Intel uses ANA/ORA/XRA
    // AND r → ANA r
    DialectEntry {
        from: "AND",
        from_regs: 1,
        from_has_imm: false,
        canonical: "ANA",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // AND n → ANI n
    DialectEntry {
        from: "AND",
        from_regs: 0,
        from_has_imm: true,
        canonical: "ANI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // OR r → ORA r
    DialectEntry {
        from: "OR",
        from_regs: 1,
        from_has_imm: false,
        canonical: "ORA",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // OR n → ORI n
    DialectEntry {
        from: "OR",
        from_regs: 0,
        from_has_imm: true,
        canonical: "ORI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // XOR r → XRA r
    DialectEntry {
        from: "XOR",
        from_regs: 1,
        from_has_imm: false,
        canonical: "XRA",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // XOR n → XRI n
    DialectEntry {
        from: "XOR",
        from_regs: 0,
        from_has_imm: true,
        canonical: "XRI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // CP r → CMP r
    DialectEntry {
        from: "CP",
        from_regs: 1,
        from_has_imm: false,
        canonical: "CMP",
        canonical_regs: 1,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // CP n → CPI n
    DialectEntry {
        from: "CP",
        from_regs: 0,
        from_has_imm: true,
        canonical: "CPI",
        canonical_regs: 0,
        canonical_has_imm: true,
        transform: OperandTransform::Identity,
    },
    // Exchange
    // EX DE,HL → XCHG
    DialectEntry {
        from: "EX",
        from_regs: 2,
        from_has_imm: false,
        canonical: "XCHG",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // Rotate accumulator
    // RLCA → RLC
    DialectEntry {
        from: "RLCA",
        from_regs: 0,
        from_has_imm: false,
        canonical: "RLC",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // RRCA → RRC
    DialectEntry {
        from: "RRCA",
        from_regs: 0,
        from_has_imm: false,
        canonical: "RRC",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // RLA → RAL
    DialectEntry {
        from: "RLA",
        from_regs: 0,
        from_has_imm: false,
        canonical: "RAL",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // RRA → RAR
    DialectEntry {
        from: "RRA",
        from_regs: 0,
        from_has_imm: false,
        canonical: "RAR",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // Flags
    // CPL → CMA
    DialectEntry {
        from: "CPL",
        from_regs: 0,
        from_has_imm: false,
        canonical: "CMA",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // SCF → STC
    DialectEntry {
        from: "SCF",
        from_regs: 0,
        from_has_imm: false,
        canonical: "STC",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // CCF → CMC
    DialectEntry {
        from: "CCF",
        from_regs: 0,
        from_has_imm: false,
        canonical: "CMC",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
    // HALT → HLT
    DialectEntry {
        from: "HALT",
        from_regs: 0,
        from_has_imm: false,
        canonical: "HLT",
        canonical_regs: 0,
        canonical_has_imm: false,
        transform: OperandTransform::Identity,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_mapping() {
        assert_eq!(map_register("A"), Some("A"));
        assert_eq!(map_register("BC"), Some("B"));
        assert_eq!(map_register("DE"), Some("D"));
        assert_eq!(map_register("HL"), Some("H"));
        assert_eq!(map_register("AF"), Some("PSW"));
        assert_eq!(map_register("(HL)"), Some("M"));
        assert_eq!(map_register("M"), Some("M"));
        assert_eq!(map_register("IX"), None);
        assert_eq!(map_register("IY"), None);
    }

    #[test]
    fn test_z80_only_mnemonics() {
        assert!(is_z80_only_mnemonic("JR"));
        assert!(is_z80_only_mnemonic("DJNZ"));
        assert!(is_z80_only_mnemonic("LDIR"));
        assert!(is_z80_only_mnemonic("BIT"));
        assert!(!is_z80_only_mnemonic("LD"));
        assert!(!is_z80_only_mnemonic("ADD"));
        assert!(!is_z80_only_mnemonic("MOV"));
    }
}
