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
