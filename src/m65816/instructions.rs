// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816-specific instruction table.

use crate::families::mos6502::AddressMode;

/// A CPU-level instruction entry for 65816 extensions.
pub struct CpuInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

/// Instruction table for prioritized 65816 MVP opcodes.
pub static CPU_INSTRUCTION_TABLE: &[CpuInstructionEntry] = &[
    CpuInstructionEntry {
        mnemonic: "BRL",
        mode: AddressMode::RelativeLong,
        opcode: 0x82,
    },
    CpuInstructionEntry {
        mnemonic: "JML",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x5C,
    },
    CpuInstructionEntry {
        mnemonic: "JML",
        mode: AddressMode::IndirectLong,
        opcode: 0xDC,
    },
    CpuInstructionEntry {
        mnemonic: "JSL",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x22,
    },
    CpuInstructionEntry {
        mnemonic: "RTL",
        mode: AddressMode::Implied,
        opcode: 0x6B,
    },
    CpuInstructionEntry {
        mnemonic: "REP",
        mode: AddressMode::Immediate,
        opcode: 0xC2,
    },
    CpuInstructionEntry {
        mnemonic: "SEP",
        mode: AddressMode::Immediate,
        opcode: 0xE2,
    },
    CpuInstructionEntry {
        mnemonic: "XCE",
        mode: AddressMode::Implied,
        opcode: 0xFB,
    },
    CpuInstructionEntry {
        mnemonic: "XBA",
        mode: AddressMode::Implied,
        opcode: 0xEB,
    },
    CpuInstructionEntry {
        mnemonic: "PHB",
        mode: AddressMode::Implied,
        opcode: 0x8B,
    },
    CpuInstructionEntry {
        mnemonic: "PLB",
        mode: AddressMode::Implied,
        opcode: 0xAB,
    },
    CpuInstructionEntry {
        mnemonic: "PHD",
        mode: AddressMode::Implied,
        opcode: 0x0B,
    },
    CpuInstructionEntry {
        mnemonic: "PLD",
        mode: AddressMode::Implied,
        opcode: 0x2B,
    },
    CpuInstructionEntry {
        mnemonic: "PHK",
        mode: AddressMode::Implied,
        opcode: 0x4B,
    },
    CpuInstructionEntry {
        mnemonic: "TCD",
        mode: AddressMode::Implied,
        opcode: 0x5B,
    },
    CpuInstructionEntry {
        mnemonic: "TDC",
        mode: AddressMode::Implied,
        opcode: 0x7B,
    },
    CpuInstructionEntry {
        mnemonic: "TCS",
        mode: AddressMode::Implied,
        opcode: 0x1B,
    },
    CpuInstructionEntry {
        mnemonic: "TSC",
        mode: AddressMode::Implied,
        opcode: 0x3B,
    },
    CpuInstructionEntry {
        mnemonic: "PEA",
        mode: AddressMode::Absolute,
        opcode: 0xF4,
    },
    CpuInstructionEntry {
        mnemonic: "PEI",
        mode: AddressMode::ZeroPageIndirect,
        opcode: 0xD4,
    },
    CpuInstructionEntry {
        mnemonic: "PER",
        mode: AddressMode::RelativeLong,
        opcode: 0x62,
    },
    CpuInstructionEntry {
        mnemonic: "COP",
        mode: AddressMode::Immediate,
        opcode: 0x02,
    },
    CpuInstructionEntry {
        mnemonic: "WDM",
        mode: AddressMode::Immediate,
        opcode: 0x42,
    },
    CpuInstructionEntry {
        mnemonic: "MVN",
        mode: AddressMode::BlockMove,
        opcode: 0x54,
    },
    CpuInstructionEntry {
        mnemonic: "MVP",
        mode: AddressMode::BlockMove,
        opcode: 0x44,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x0F,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0x1F,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x2F,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0x3F,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x4F,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0x5F,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x6F,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0x7F,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::AbsoluteLong,
        opcode: 0x8F,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0x9F,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::AbsoluteLong,
        opcode: 0xAF,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0xBF,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::AbsoluteLong,
        opcode: 0xCF,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0xDF,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::AbsoluteLong,
        opcode: 0xEF,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::AbsoluteLongX,
        opcode: 0xFF,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0x07,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0x17,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0x27,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0x37,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0x47,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0x57,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0x67,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0x77,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0x87,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0x97,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0xA7,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0xB7,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0xC7,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0xD7,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::DirectPageIndirectLong,
        opcode: 0xE7,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::DirectPageIndirectLongY,
        opcode: 0xF7,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::StackRelative,
        opcode: 0x03,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0x13,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::StackRelative,
        opcode: 0x23,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0x33,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::StackRelative,
        opcode: 0x43,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0x53,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::StackRelative,
        opcode: 0x63,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0x73,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::StackRelative,
        opcode: 0x83,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0x93,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::StackRelative,
        opcode: 0xA3,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0xB3,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::StackRelative,
        opcode: 0xC3,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0xD3,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::StackRelative,
        opcode: 0xE3,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0xF3,
    },
];

/// Look up an instruction in the CPU extension table.
pub fn lookup_instruction(
    mnemonic: &str,
    mode: AddressMode,
) -> Option<&'static CpuInstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    CPU_INSTRUCTION_TABLE
        .iter()
        .find(|entry| entry.mnemonic == upper && entry.mode == mode)
}

/// Check if a mnemonic is in the CPU extension table.
pub fn has_mnemonic(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    CPU_INSTRUCTION_TABLE
        .iter()
        .any(|entry| entry.mnemonic == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_contains_prioritized_entries() {
        assert!(has_mnemonic("BRL"));
        assert!(lookup_instruction("BRL", AddressMode::RelativeLong).is_some());
        assert!(lookup_instruction("JML", AddressMode::AbsoluteLong).is_some());
        assert!(lookup_instruction("LDA", AddressMode::AbsoluteLongX).is_some());
        assert!(lookup_instruction("LDA", AddressMode::DirectPageIndirectLongY).is_some());
        assert!(lookup_instruction("LDA", AddressMode::StackRelative).is_some());
        assert!(lookup_instruction("MVN", AddressMode::BlockMove).is_some());
    }
}
