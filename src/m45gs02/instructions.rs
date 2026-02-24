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
        mnemonic: "BPL",
        mode: AddressMode::RelativeLong,
        opcode: 0x13,
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
        mnemonic: "NEG",
        mode: AddressMode::Implied,
        opcode: 0x42,
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
