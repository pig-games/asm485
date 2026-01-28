// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Instruction table for MOS 6502 family common instructions.
//!
//! This table contains instructions that are common to all CPUs in the
//! 6502 family. CPU-specific instructions (like BRA on 65C02) are handled
//! by the CPU handler, not this family table.

use crate::families::mos6502::AddressMode;

/// A family-level instruction entry.
pub struct FamilyInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

/// Instruction table for base 6502 instructions.
///
/// This table is typically small enough that linear search is sufficient.
/// All entries here are valid on the base 6502.
pub static FAMILY_INSTRUCTION_TABLE: &[FamilyInstructionEntry] = &[
    // ADC - Add with Carry
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::Immediate, opcode: 0x69 },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::ZeroPage, opcode: 0x65 },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::ZeroPageX, opcode: 0x75 },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::Absolute, opcode: 0x6D },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::AbsoluteX, opcode: 0x7D },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::AbsoluteY, opcode: 0x79 },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::IndexedIndirectX, opcode: 0x61 },
    FamilyInstructionEntry { mnemonic: "ADC", mode: AddressMode::IndirectIndexedY, opcode: 0x71 },
    
    // AND - Logical AND
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::Immediate, opcode: 0x29 },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::ZeroPage, opcode: 0x25 },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::ZeroPageX, opcode: 0x35 },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::Absolute, opcode: 0x2D },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::AbsoluteX, opcode: 0x3D },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::AbsoluteY, opcode: 0x39 },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::IndexedIndirectX, opcode: 0x21 },
    FamilyInstructionEntry { mnemonic: "AND", mode: AddressMode::IndirectIndexedY, opcode: 0x31 },
    
    // ASL - Arithmetic Shift Left
    FamilyInstructionEntry { mnemonic: "ASL", mode: AddressMode::Accumulator, opcode: 0x0A },
    FamilyInstructionEntry { mnemonic: "ASL", mode: AddressMode::ZeroPage, opcode: 0x06 },
    FamilyInstructionEntry { mnemonic: "ASL", mode: AddressMode::ZeroPageX, opcode: 0x16 },
    FamilyInstructionEntry { mnemonic: "ASL", mode: AddressMode::Absolute, opcode: 0x0E },
    FamilyInstructionEntry { mnemonic: "ASL", mode: AddressMode::AbsoluteX, opcode: 0x1E },
    
    // BCC - Branch if Carry Clear
    FamilyInstructionEntry { mnemonic: "BCC", mode: AddressMode::Relative, opcode: 0x90 },
    
    // BCS - Branch if Carry Set
    FamilyInstructionEntry { mnemonic: "BCS", mode: AddressMode::Relative, opcode: 0xB0 },
    
    // BEQ - Branch if Equal (Zero set)
    FamilyInstructionEntry { mnemonic: "BEQ", mode: AddressMode::Relative, opcode: 0xF0 },
    
    // BIT - Bit Test
    FamilyInstructionEntry { mnemonic: "BIT", mode: AddressMode::ZeroPage, opcode: 0x24 },
    FamilyInstructionEntry { mnemonic: "BIT", mode: AddressMode::Absolute, opcode: 0x2C },
    
    // BMI - Branch if Minus
    FamilyInstructionEntry { mnemonic: "BMI", mode: AddressMode::Relative, opcode: 0x30 },
    
    // BNE - Branch if Not Equal
    FamilyInstructionEntry { mnemonic: "BNE", mode: AddressMode::Relative, opcode: 0xD0 },
    
    // BPL - Branch if Plus
    FamilyInstructionEntry { mnemonic: "BPL", mode: AddressMode::Relative, opcode: 0x10 },
    
    // BRK - Break
    FamilyInstructionEntry { mnemonic: "BRK", mode: AddressMode::Implied, opcode: 0x00 },
    
    // BVC - Branch if Overflow Clear
    FamilyInstructionEntry { mnemonic: "BVC", mode: AddressMode::Relative, opcode: 0x50 },
    
    // BVS - Branch if Overflow Set
    FamilyInstructionEntry { mnemonic: "BVS", mode: AddressMode::Relative, opcode: 0x70 },
    
    // CLC - Clear Carry
    FamilyInstructionEntry { mnemonic: "CLC", mode: AddressMode::Implied, opcode: 0x18 },
    
    // CLD - Clear Decimal
    FamilyInstructionEntry { mnemonic: "CLD", mode: AddressMode::Implied, opcode: 0xD8 },
    
    // CLI - Clear Interrupt Disable
    FamilyInstructionEntry { mnemonic: "CLI", mode: AddressMode::Implied, opcode: 0x58 },
    
    // CLV - Clear Overflow
    FamilyInstructionEntry { mnemonic: "CLV", mode: AddressMode::Implied, opcode: 0xB8 },
    
    // CMP - Compare Accumulator
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::Immediate, opcode: 0xC9 },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::ZeroPage, opcode: 0xC5 },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::ZeroPageX, opcode: 0xD5 },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::Absolute, opcode: 0xCD },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::AbsoluteX, opcode: 0xDD },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::AbsoluteY, opcode: 0xD9 },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::IndexedIndirectX, opcode: 0xC1 },
    FamilyInstructionEntry { mnemonic: "CMP", mode: AddressMode::IndirectIndexedY, opcode: 0xD1 },
    
    // CPX - Compare X
    FamilyInstructionEntry { mnemonic: "CPX", mode: AddressMode::Immediate, opcode: 0xE0 },
    FamilyInstructionEntry { mnemonic: "CPX", mode: AddressMode::ZeroPage, opcode: 0xE4 },
    FamilyInstructionEntry { mnemonic: "CPX", mode: AddressMode::Absolute, opcode: 0xEC },
    
    // CPY - Compare Y
    FamilyInstructionEntry { mnemonic: "CPY", mode: AddressMode::Immediate, opcode: 0xC0 },
    FamilyInstructionEntry { mnemonic: "CPY", mode: AddressMode::ZeroPage, opcode: 0xC4 },
    FamilyInstructionEntry { mnemonic: "CPY", mode: AddressMode::Absolute, opcode: 0xCC },
    
    // DEC - Decrement Memory
    FamilyInstructionEntry { mnemonic: "DEC", mode: AddressMode::ZeroPage, opcode: 0xC6 },
    FamilyInstructionEntry { mnemonic: "DEC", mode: AddressMode::ZeroPageX, opcode: 0xD6 },
    FamilyInstructionEntry { mnemonic: "DEC", mode: AddressMode::Absolute, opcode: 0xCE },
    FamilyInstructionEntry { mnemonic: "DEC", mode: AddressMode::AbsoluteX, opcode: 0xDE },
    
    // DEX - Decrement X
    FamilyInstructionEntry { mnemonic: "DEX", mode: AddressMode::Implied, opcode: 0xCA },
    
    // DEY - Decrement Y
    FamilyInstructionEntry { mnemonic: "DEY", mode: AddressMode::Implied, opcode: 0x88 },
    
    // EOR - Exclusive OR
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::Immediate, opcode: 0x49 },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::ZeroPage, opcode: 0x45 },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::ZeroPageX, opcode: 0x55 },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::Absolute, opcode: 0x4D },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::AbsoluteX, opcode: 0x5D },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::AbsoluteY, opcode: 0x59 },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::IndexedIndirectX, opcode: 0x41 },
    FamilyInstructionEntry { mnemonic: "EOR", mode: AddressMode::IndirectIndexedY, opcode: 0x51 },
    
    // INC - Increment Memory
    FamilyInstructionEntry { mnemonic: "INC", mode: AddressMode::ZeroPage, opcode: 0xE6 },
    FamilyInstructionEntry { mnemonic: "INC", mode: AddressMode::ZeroPageX, opcode: 0xF6 },
    FamilyInstructionEntry { mnemonic: "INC", mode: AddressMode::Absolute, opcode: 0xEE },
    FamilyInstructionEntry { mnemonic: "INC", mode: AddressMode::AbsoluteX, opcode: 0xFE },
    
    // INX - Increment X
    FamilyInstructionEntry { mnemonic: "INX", mode: AddressMode::Implied, opcode: 0xE8 },
    
    // INY - Increment Y
    FamilyInstructionEntry { mnemonic: "INY", mode: AddressMode::Implied, opcode: 0xC8 },
    
    // JMP - Jump
    FamilyInstructionEntry { mnemonic: "JMP", mode: AddressMode::Absolute, opcode: 0x4C },
    FamilyInstructionEntry { mnemonic: "JMP", mode: AddressMode::Indirect, opcode: 0x6C },
    
    // JSR - Jump to Subroutine
    FamilyInstructionEntry { mnemonic: "JSR", mode: AddressMode::Absolute, opcode: 0x20 },
    
    // LDA - Load Accumulator
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::Immediate, opcode: 0xA9 },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::ZeroPage, opcode: 0xA5 },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::ZeroPageX, opcode: 0xB5 },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::Absolute, opcode: 0xAD },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::AbsoluteX, opcode: 0xBD },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::AbsoluteY, opcode: 0xB9 },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::IndexedIndirectX, opcode: 0xA1 },
    FamilyInstructionEntry { mnemonic: "LDA", mode: AddressMode::IndirectIndexedY, opcode: 0xB1 },
    
    // LDX - Load X
    FamilyInstructionEntry { mnemonic: "LDX", mode: AddressMode::Immediate, opcode: 0xA2 },
    FamilyInstructionEntry { mnemonic: "LDX", mode: AddressMode::ZeroPage, opcode: 0xA6 },
    FamilyInstructionEntry { mnemonic: "LDX", mode: AddressMode::ZeroPageY, opcode: 0xB6 },
    FamilyInstructionEntry { mnemonic: "LDX", mode: AddressMode::Absolute, opcode: 0xAE },
    FamilyInstructionEntry { mnemonic: "LDX", mode: AddressMode::AbsoluteY, opcode: 0xBE },
    
    // LDY - Load Y
    FamilyInstructionEntry { mnemonic: "LDY", mode: AddressMode::Immediate, opcode: 0xA0 },
    FamilyInstructionEntry { mnemonic: "LDY", mode: AddressMode::ZeroPage, opcode: 0xA4 },
    FamilyInstructionEntry { mnemonic: "LDY", mode: AddressMode::ZeroPageX, opcode: 0xB4 },
    FamilyInstructionEntry { mnemonic: "LDY", mode: AddressMode::Absolute, opcode: 0xAC },
    FamilyInstructionEntry { mnemonic: "LDY", mode: AddressMode::AbsoluteX, opcode: 0xBC },
    
    // LSR - Logical Shift Right
    FamilyInstructionEntry { mnemonic: "LSR", mode: AddressMode::Accumulator, opcode: 0x4A },
    FamilyInstructionEntry { mnemonic: "LSR", mode: AddressMode::ZeroPage, opcode: 0x46 },
    FamilyInstructionEntry { mnemonic: "LSR", mode: AddressMode::ZeroPageX, opcode: 0x56 },
    FamilyInstructionEntry { mnemonic: "LSR", mode: AddressMode::Absolute, opcode: 0x4E },
    FamilyInstructionEntry { mnemonic: "LSR", mode: AddressMode::AbsoluteX, opcode: 0x5E },
    
    // NOP - No Operation
    FamilyInstructionEntry { mnemonic: "NOP", mode: AddressMode::Implied, opcode: 0xEA },
    
    // ORA - Logical OR
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::Immediate, opcode: 0x09 },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::ZeroPage, opcode: 0x05 },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::ZeroPageX, opcode: 0x15 },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::Absolute, opcode: 0x0D },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::AbsoluteX, opcode: 0x1D },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::AbsoluteY, opcode: 0x19 },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::IndexedIndirectX, opcode: 0x01 },
    FamilyInstructionEntry { mnemonic: "ORA", mode: AddressMode::IndirectIndexedY, opcode: 0x11 },
    
    // PHA - Push Accumulator
    FamilyInstructionEntry { mnemonic: "PHA", mode: AddressMode::Implied, opcode: 0x48 },
    
    // PHP - Push Processor Status
    FamilyInstructionEntry { mnemonic: "PHP", mode: AddressMode::Implied, opcode: 0x08 },
    
    // PLA - Pull Accumulator
    FamilyInstructionEntry { mnemonic: "PLA", mode: AddressMode::Implied, opcode: 0x68 },
    
    // PLP - Pull Processor Status
    FamilyInstructionEntry { mnemonic: "PLP", mode: AddressMode::Implied, opcode: 0x28 },
    
    // ROL - Rotate Left
    FamilyInstructionEntry { mnemonic: "ROL", mode: AddressMode::Accumulator, opcode: 0x2A },
    FamilyInstructionEntry { mnemonic: "ROL", mode: AddressMode::ZeroPage, opcode: 0x26 },
    FamilyInstructionEntry { mnemonic: "ROL", mode: AddressMode::ZeroPageX, opcode: 0x36 },
    FamilyInstructionEntry { mnemonic: "ROL", mode: AddressMode::Absolute, opcode: 0x2E },
    FamilyInstructionEntry { mnemonic: "ROL", mode: AddressMode::AbsoluteX, opcode: 0x3E },
    
    // ROR - Rotate Right
    FamilyInstructionEntry { mnemonic: "ROR", mode: AddressMode::Accumulator, opcode: 0x6A },
    FamilyInstructionEntry { mnemonic: "ROR", mode: AddressMode::ZeroPage, opcode: 0x66 },
    FamilyInstructionEntry { mnemonic: "ROR", mode: AddressMode::ZeroPageX, opcode: 0x76 },
    FamilyInstructionEntry { mnemonic: "ROR", mode: AddressMode::Absolute, opcode: 0x6E },
    FamilyInstructionEntry { mnemonic: "ROR", mode: AddressMode::AbsoluteX, opcode: 0x7E },
    
    // RTI - Return from Interrupt
    FamilyInstructionEntry { mnemonic: "RTI", mode: AddressMode::Implied, opcode: 0x40 },
    
    // RTS - Return from Subroutine
    FamilyInstructionEntry { mnemonic: "RTS", mode: AddressMode::Implied, opcode: 0x60 },
    
    // SBC - Subtract with Carry
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::Immediate, opcode: 0xE9 },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::ZeroPage, opcode: 0xE5 },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::ZeroPageX, opcode: 0xF5 },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::Absolute, opcode: 0xED },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::AbsoluteX, opcode: 0xFD },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::AbsoluteY, opcode: 0xF9 },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::IndexedIndirectX, opcode: 0xE1 },
    FamilyInstructionEntry { mnemonic: "SBC", mode: AddressMode::IndirectIndexedY, opcode: 0xF1 },
    
    // SEC - Set Carry
    FamilyInstructionEntry { mnemonic: "SEC", mode: AddressMode::Implied, opcode: 0x38 },
    
    // SED - Set Decimal
    FamilyInstructionEntry { mnemonic: "SED", mode: AddressMode::Implied, opcode: 0xF8 },
    
    // SEI - Set Interrupt Disable
    FamilyInstructionEntry { mnemonic: "SEI", mode: AddressMode::Implied, opcode: 0x78 },
    
    // STA - Store Accumulator
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::ZeroPage, opcode: 0x85 },
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::ZeroPageX, opcode: 0x95 },
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::Absolute, opcode: 0x8D },
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::AbsoluteX, opcode: 0x9D },
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::AbsoluteY, opcode: 0x99 },
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::IndexedIndirectX, opcode: 0x81 },
    FamilyInstructionEntry { mnemonic: "STA", mode: AddressMode::IndirectIndexedY, opcode: 0x91 },
    
    // STX - Store X
    FamilyInstructionEntry { mnemonic: "STX", mode: AddressMode::ZeroPage, opcode: 0x86 },
    FamilyInstructionEntry { mnemonic: "STX", mode: AddressMode::ZeroPageY, opcode: 0x96 },
    FamilyInstructionEntry { mnemonic: "STX", mode: AddressMode::Absolute, opcode: 0x8E },
    
    // STY - Store Y
    FamilyInstructionEntry { mnemonic: "STY", mode: AddressMode::ZeroPage, opcode: 0x84 },
    FamilyInstructionEntry { mnemonic: "STY", mode: AddressMode::ZeroPageX, opcode: 0x94 },
    FamilyInstructionEntry { mnemonic: "STY", mode: AddressMode::Absolute, opcode: 0x8C },
    
    // TAX - Transfer A to X
    FamilyInstructionEntry { mnemonic: "TAX", mode: AddressMode::Implied, opcode: 0xAA },
    
    // TAY - Transfer A to Y
    FamilyInstructionEntry { mnemonic: "TAY", mode: AddressMode::Implied, opcode: 0xA8 },
    
    // TSX - Transfer SP to X
    FamilyInstructionEntry { mnemonic: "TSX", mode: AddressMode::Implied, opcode: 0xBA },
    
    // TXA - Transfer X to A
    FamilyInstructionEntry { mnemonic: "TXA", mode: AddressMode::Implied, opcode: 0x8A },
    
    // TXS - Transfer X to SP
    FamilyInstructionEntry { mnemonic: "TXS", mode: AddressMode::Implied, opcode: 0x9A },
    
    // TYA - Transfer Y to A
    FamilyInstructionEntry { mnemonic: "TYA", mode: AddressMode::Implied, opcode: 0x98 },
];

/// Look up an instruction by mnemonic and addressing mode.
pub fn lookup_instruction(mnemonic: &str, mode: AddressMode) -> Option<&'static FamilyInstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    FAMILY_INSTRUCTION_TABLE
        .iter()
        .find(|e| e.mnemonic.eq_ignore_ascii_case(&upper) && e.mode == mode)
}

/// Check if a mnemonic exists in the family table (any mode).
pub fn has_mnemonic(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    FAMILY_INSTRUCTION_TABLE
        .iter()
        .any(|e| e.mnemonic.eq_ignore_ascii_case(&upper))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_lda_immediate() {
        let entry = lookup_instruction("LDA", AddressMode::Immediate);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0xA9);
    }

    #[test]
    fn lookup_jmp_indirect() {
        let entry = lookup_instruction("JMP", AddressMode::Indirect);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x6C);
    }

    #[test]
    fn has_mnemonic_test() {
        assert!(has_mnemonic("LDA"));
        assert!(has_mnemonic("lda"));
        assert!(has_mnemonic("JMP"));
        assert!(!has_mnemonic("BRA")); // 65C02 only
        assert!(!has_mnemonic("XXX"));
    }
}
