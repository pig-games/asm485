// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 45GS02-specific instruction table.

use crate::families::mos6502::AddressMode;

pub struct CpuInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

pub static CPU_INSTRUCTION_TABLE: &[CpuInstructionEntry] = &[
    CpuInstructionEntry {
        mnemonic: "CLE",
        mode: AddressMode::Implied,
        opcode: 0x02,
    },
    CpuInstructionEntry {
        mnemonic: "SEE",
        mode: AddressMode::Implied,
        opcode: 0x03,
    },
    CpuInstructionEntry {
        mnemonic: "BPL",
        mode: AddressMode::RelativeLong,
        opcode: 0x13,
    },
    CpuInstructionEntry {
        mnemonic: "JSR",
        mode: AddressMode::Indirect,
        opcode: 0x22,
    },
    CpuInstructionEntry {
        mnemonic: "JSR",
        mode: AddressMode::AbsoluteIndexedIndirect,
        opcode: 0x23,
    },
    CpuInstructionEntry {
        mnemonic: "BMI",
        mode: AddressMode::RelativeLong,
        opcode: 0x33,
    },
    CpuInstructionEntry {
        mnemonic: "BVC",
        mode: AddressMode::RelativeLong,
        opcode: 0x53,
    },
    CpuInstructionEntry {
        mnemonic: "BSR",
        mode: AddressMode::RelativeLong,
        opcode: 0x63,
    },
    CpuInstructionEntry {
        mnemonic: "BVS",
        mode: AddressMode::RelativeLong,
        opcode: 0x73,
    },
    CpuInstructionEntry {
        mnemonic: "STZ",
        mode: AddressMode::Absolute,
        opcode: 0x8C,
    },
    CpuInstructionEntry {
        mnemonic: "STZ",
        mode: AddressMode::AbsoluteX,
        opcode: 0x8E,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0x82,
    },
    CpuInstructionEntry {
        mnemonic: "BRA",
        mode: AddressMode::RelativeLong,
        opcode: 0x83,
    },
    CpuInstructionEntry {
        mnemonic: "BCC",
        mode: AddressMode::RelativeLong,
        opcode: 0x93,
    },
    CpuInstructionEntry {
        mnemonic: "BCS",
        mode: AddressMode::RelativeLong,
        opcode: 0xB3,
    },
    CpuInstructionEntry {
        mnemonic: "BNE",
        mode: AddressMode::RelativeLong,
        opcode: 0xD3,
    },
    CpuInstructionEntry {
        mnemonic: "BEQ",
        mode: AddressMode::RelativeLong,
        opcode: 0xF3,
    },
    CpuInstructionEntry {
        mnemonic: "MAP",
        mode: AddressMode::Implied,
        opcode: 0x5C,
    },
    CpuInstructionEntry {
        mnemonic: "EOM",
        mode: AddressMode::Implied,
        opcode: 0xEA,
    },
    CpuInstructionEntry {
        mnemonic: "RTS",
        mode: AddressMode::Immediate,
        opcode: 0x62,
    },
    CpuInstructionEntry {
        mnemonic: "NEG",
        mode: AddressMode::Implied,
        opcode: 0x42,
    },
    CpuInstructionEntry {
        mnemonic: "INZ",
        mode: AddressMode::Implied,
        opcode: 0x0B,
    },
    CpuInstructionEntry {
        mnemonic: "TYS",
        mode: AddressMode::Implied,
        opcode: 0x1B,
    },
    CpuInstructionEntry {
        mnemonic: "DEZ",
        mode: AddressMode::Implied,
        opcode: 0x2B,
    },
    CpuInstructionEntry {
        mnemonic: "TAZ",
        mode: AddressMode::Implied,
        opcode: 0x3B,
    },
    CpuInstructionEntry {
        mnemonic: "TAB",
        mode: AddressMode::Implied,
        opcode: 0x4B,
    },
    CpuInstructionEntry {
        mnemonic: "TZA",
        mode: AddressMode::Implied,
        opcode: 0x5B,
    },
    CpuInstructionEntry {
        mnemonic: "TBA",
        mode: AddressMode::Implied,
        opcode: 0x6B,
    },
    CpuInstructionEntry {
        mnemonic: "TSY",
        mode: AddressMode::Implied,
        opcode: 0xFB,
    },
    CpuInstructionEntry {
        mnemonic: "PHZ",
        mode: AddressMode::Implied,
        opcode: 0xCB,
    },
    CpuInstructionEntry {
        mnemonic: "PLZ",
        mode: AddressMode::Implied,
        opcode: 0xEB,
    },
    CpuInstructionEntry {
        mnemonic: "LDZ",
        mode: AddressMode::Immediate,
        opcode: 0xA3,
    },
    CpuInstructionEntry {
        mnemonic: "LDZ",
        mode: AddressMode::Absolute,
        opcode: 0x9B,
    },
    CpuInstructionEntry {
        mnemonic: "LDZ",
        mode: AddressMode::AbsoluteX,
        opcode: 0xAB,
    },
    CpuInstructionEntry {
        mnemonic: "CPZ",
        mode: AddressMode::Immediate,
        opcode: 0xC2,
    },
    CpuInstructionEntry {
        mnemonic: "CPZ",
        mode: AddressMode::ZeroPage,
        opcode: 0xD4,
    },
    CpuInstructionEntry {
        mnemonic: "CPZ",
        mode: AddressMode::Absolute,
        opcode: 0xCC,
    },
    CpuInstructionEntry {
        mnemonic: "DEW",
        mode: AddressMode::ZeroPage,
        opcode: 0xC3,
    },
    CpuInstructionEntry {
        mnemonic: "INW",
        mode: AddressMode::ZeroPage,
        opcode: 0xE3,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::StackRelativeIndirectIndexedY,
        opcode: 0xE2,
    },
    CpuInstructionEntry {
        mnemonic: "ASW",
        mode: AddressMode::Absolute,
        opcode: 0xBB,
    },
    CpuInstructionEntry {
        mnemonic: "ROW",
        mode: AddressMode::Absolute,
        opcode: 0xDB,
    },
    CpuInstructionEntry {
        mnemonic: "PHW",
        mode: AddressMode::Immediate,
        opcode: 0xF4,
    },
    CpuInstructionEntry {
        mnemonic: "PHW",
        mode: AddressMode::Absolute,
        opcode: 0xEC,
    },
];

pub fn lookup_instruction(
    mnemonic: &str,
    mode: AddressMode,
) -> Option<&'static CpuInstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    CPU_INSTRUCTION_TABLE
        .iter()
        .find(|entry| entry.mnemonic == upper && entry.mode == mode)
}

pub fn has_mnemonic(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    CPU_INSTRUCTION_TABLE
        .iter()
        .any(|entry| entry.mnemonic == upper)
}
