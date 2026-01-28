// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65C02-specific instruction table.
//!
//! This table contains only the instructions and addressing modes that are
//! specific to the 65C02 and not available on the base 6502. The family
//! handler covers all base 6502 instructions.

use crate::families::mos6502::AddressMode;

/// A CPU-level instruction entry for 65C02 extensions.
pub struct CpuInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

/// Instruction table for 65C02-only instructions.
///
/// This table is typically small enough that linear search is sufficient.
pub static CPU_INSTRUCTION_TABLE: &[CpuInstructionEntry] = &[
    // BRA - Branch Always (65C02 only)
    CpuInstructionEntry { mnemonic: "BRA", mode: AddressMode::Relative, opcode: 0x80 },
    
    // DEC A - Decrement Accumulator (65C02 only)
    CpuInstructionEntry { mnemonic: "DEC", mode: AddressMode::Accumulator, opcode: 0x3A },
    CpuInstructionEntry { mnemonic: "DEA", mode: AddressMode::Implied, opcode: 0x3A }, // alias
    
    // INC A - Increment Accumulator (65C02 only)
    CpuInstructionEntry { mnemonic: "INC", mode: AddressMode::Accumulator, opcode: 0x1A },
    CpuInstructionEntry { mnemonic: "INA", mode: AddressMode::Implied, opcode: 0x1A }, // alias
    
    // PHX - Push X Register (65C02 only)
    CpuInstructionEntry { mnemonic: "PHX", mode: AddressMode::Implied, opcode: 0xDA },
    
    // PHY - Push Y Register (65C02 only)
    CpuInstructionEntry { mnemonic: "PHY", mode: AddressMode::Implied, opcode: 0x5A },
    
    // PLX - Pull X Register (65C02 only)
    CpuInstructionEntry { mnemonic: "PLX", mode: AddressMode::Implied, opcode: 0xFA },
    
    // PLY - Pull Y Register (65C02 only)
    CpuInstructionEntry { mnemonic: "PLY", mode: AddressMode::Implied, opcode: 0x7A },
    
    // STP - Stop Processor (65C02 only)
    CpuInstructionEntry { mnemonic: "STP", mode: AddressMode::Implied, opcode: 0xDB },
    
    // STZ - Store Zero (65C02 only)
    CpuInstructionEntry { mnemonic: "STZ", mode: AddressMode::ZeroPage, opcode: 0x64 },
    CpuInstructionEntry { mnemonic: "STZ", mode: AddressMode::ZeroPageX, opcode: 0x74 },
    CpuInstructionEntry { mnemonic: "STZ", mode: AddressMode::Absolute, opcode: 0x9C },
    CpuInstructionEntry { mnemonic: "STZ", mode: AddressMode::AbsoluteX, opcode: 0x9E },
    
    // TRB - Test and Reset Bits (65C02 only)
    CpuInstructionEntry { mnemonic: "TRB", mode: AddressMode::ZeroPage, opcode: 0x14 },
    CpuInstructionEntry { mnemonic: "TRB", mode: AddressMode::Absolute, opcode: 0x1C },
    
    // TSB - Test and Set Bits (65C02 only)
    CpuInstructionEntry { mnemonic: "TSB", mode: AddressMode::ZeroPage, opcode: 0x04 },
    CpuInstructionEntry { mnemonic: "TSB", mode: AddressMode::Absolute, opcode: 0x0C },
    
    // WAI - Wait for Interrupt (65C02 only)
    CpuInstructionEntry { mnemonic: "WAI", mode: AddressMode::Implied, opcode: 0xCB },
    
    // BIT with extended addressing modes (65C02 only)
    CpuInstructionEntry { mnemonic: "BIT", mode: AddressMode::Immediate, opcode: 0x89 },
    CpuInstructionEntry { mnemonic: "BIT", mode: AddressMode::ZeroPageX, opcode: 0x34 },
    CpuInstructionEntry { mnemonic: "BIT", mode: AddressMode::AbsoluteX, opcode: 0x3C },
    
    // JMP with absolute indexed indirect (65C02 only)
    CpuInstructionEntry { mnemonic: "JMP", mode: AddressMode::AbsoluteIndexedIndirect, opcode: 0x7C },
    
    // Zero page indirect addressing modes (65C02 only)
    CpuInstructionEntry { mnemonic: "ADC", mode: AddressMode::ZeroPageIndirect, opcode: 0x72 },
    CpuInstructionEntry { mnemonic: "AND", mode: AddressMode::ZeroPageIndirect, opcode: 0x32 },
    CpuInstructionEntry { mnemonic: "CMP", mode: AddressMode::ZeroPageIndirect, opcode: 0xD2 },
    CpuInstructionEntry { mnemonic: "EOR", mode: AddressMode::ZeroPageIndirect, opcode: 0x52 },
    CpuInstructionEntry { mnemonic: "LDA", mode: AddressMode::ZeroPageIndirect, opcode: 0xB2 },
    CpuInstructionEntry { mnemonic: "ORA", mode: AddressMode::ZeroPageIndirect, opcode: 0x12 },
    CpuInstructionEntry { mnemonic: "SBC", mode: AddressMode::ZeroPageIndirect, opcode: 0xF2 },
    CpuInstructionEntry { mnemonic: "STA", mode: AddressMode::ZeroPageIndirect, opcode: 0x92 },
    
    // RMB - Reset Memory Bit (65C02 only)
    CpuInstructionEntry { mnemonic: "RMB0", mode: AddressMode::ZeroPage, opcode: 0x07 },
    CpuInstructionEntry { mnemonic: "RMB1", mode: AddressMode::ZeroPage, opcode: 0x17 },
    CpuInstructionEntry { mnemonic: "RMB2", mode: AddressMode::ZeroPage, opcode: 0x27 },
    CpuInstructionEntry { mnemonic: "RMB3", mode: AddressMode::ZeroPage, opcode: 0x37 },
    CpuInstructionEntry { mnemonic: "RMB4", mode: AddressMode::ZeroPage, opcode: 0x47 },
    CpuInstructionEntry { mnemonic: "RMB5", mode: AddressMode::ZeroPage, opcode: 0x57 },
    CpuInstructionEntry { mnemonic: "RMB6", mode: AddressMode::ZeroPage, opcode: 0x67 },
    CpuInstructionEntry { mnemonic: "RMB7", mode: AddressMode::ZeroPage, opcode: 0x77 },
    
    // SMB - Set Memory Bit (65C02 only)
    CpuInstructionEntry { mnemonic: "SMB0", mode: AddressMode::ZeroPage, opcode: 0x87 },
    CpuInstructionEntry { mnemonic: "SMB1", mode: AddressMode::ZeroPage, opcode: 0x97 },
    CpuInstructionEntry { mnemonic: "SMB2", mode: AddressMode::ZeroPage, opcode: 0xA7 },
    CpuInstructionEntry { mnemonic: "SMB3", mode: AddressMode::ZeroPage, opcode: 0xB7 },
    CpuInstructionEntry { mnemonic: "SMB4", mode: AddressMode::ZeroPage, opcode: 0xC7 },
    CpuInstructionEntry { mnemonic: "SMB5", mode: AddressMode::ZeroPage, opcode: 0xD7 },
    CpuInstructionEntry { mnemonic: "SMB6", mode: AddressMode::ZeroPage, opcode: 0xE7 },
    CpuInstructionEntry { mnemonic: "SMB7", mode: AddressMode::ZeroPage, opcode: 0xF7 },
    
    // BBR - Branch on Bit Reset (65C02 only)
    // These use ZeroPageRelative mode (2 bytes: zp addr, relative offset)
    // For now, we'll handle these specially in the handler
    
    // BBS - Branch on Bit Set (65C02 only)
    // These use ZeroPageRelative mode (2 bytes: zp addr, relative offset)
    // For now, we'll handle these specially in the handler
];

/// Look up an instruction in the CPU extension table.
pub fn lookup_instruction(mnemonic: &str, mode: AddressMode) -> Option<&'static CpuInstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    CPU_INSTRUCTION_TABLE
        .iter()
        .find(|e| e.mnemonic == upper && e.mode == mode)
}

/// Check if a mnemonic is in the CPU extension table.
pub fn has_mnemonic(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    CPU_INSTRUCTION_TABLE.iter().any(|e| e.mnemonic == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_bra() {
        let entry = lookup_instruction("BRA", AddressMode::Relative);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x80);
    }

    #[test]
    fn lookup_stz_zero_page() {
        let entry = lookup_instruction("STZ", AddressMode::ZeroPage);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x64);
    }

    #[test]
    fn has_65c02_only_mnemonics() {
        assert!(has_mnemonic("BRA"));
        assert!(has_mnemonic("PHX"));
        assert!(has_mnemonic("STZ"));
        assert!(has_mnemonic("TRB"));
        assert!(has_mnemonic("TSB"));
        // LDA has a 65C02-only mode (ZeroPageIndirect), so it IS in the extension table
        assert!(has_mnemonic("LDA"));
        // NOP has no 65C02 extensions
        assert!(!has_mnemonic("NOP"));
    }
}
