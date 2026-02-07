// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816-specific instruction table.
//!
//! The M1 skeleton intentionally keeps this table empty. M3 will populate the
//! 65816-only instruction encodings.

use crate::families::mos6502::AddressMode;

/// A CPU-level instruction entry for 65816 extensions.
pub struct CpuInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

/// Instruction table for 65816-only opcodes (filled in later milestones).
pub static CPU_INSTRUCTION_TABLE: &[CpuInstructionEntry] = &[];

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
    fn table_starts_empty_for_m1() {
        assert!(!has_mnemonic("BRL"));
        assert!(lookup_instruction("BRL", AddressMode::Relative).is_none());
    }
}
