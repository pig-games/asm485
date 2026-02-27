// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! HD6309 CPU extension instruction table.

use crate::families::m6800::AddressMode;

pub struct CpuInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

pub static CPU_INSTRUCTION_TABLE: &[CpuInstructionEntry] = &[CpuInstructionEntry {
    mnemonic: "SEXW",
    mode: AddressMode::Inherent,
    opcode: 0x14,
}];

pub fn lookup_instruction(
    mnemonic: &str,
    mode: AddressMode,
) -> Option<&'static CpuInstructionEntry> {
    CPU_INSTRUCTION_TABLE
        .iter()
        .find(|entry| entry.mode == mode && entry.mnemonic.eq_ignore_ascii_case(mnemonic))
}

pub fn has_mnemonic(mnemonic: &str) -> bool {
    CPU_INSTRUCTION_TABLE
        .iter()
        .any(|entry| entry.mnemonic.eq_ignore_ascii_case(mnemonic))
}
