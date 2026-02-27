// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Baseline instruction table for Motorola 6800 family shared instructions.

use super::AddressMode;

pub struct FamilyInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

pub static FAMILY_INSTRUCTION_TABLE: &[FamilyInstructionEntry] = &[
    FamilyInstructionEntry {
        mnemonic: "NOP",
        mode: AddressMode::Inherent,
        opcode: 0x12,
    },
    FamilyInstructionEntry {
        mnemonic: "RTS",
        mode: AddressMode::Inherent,
        opcode: 0x39,
    },
    FamilyInstructionEntry {
        mnemonic: "ABX",
        mode: AddressMode::Inherent,
        opcode: 0x3A,
    },
    FamilyInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::Immediate8,
        opcode: 0x86,
    },
    FamilyInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::Direct,
        opcode: 0x96,
    },
    FamilyInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::Extended,
        opcode: 0xB6,
    },
    FamilyInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::Indexed,
        opcode: 0xA6,
    },
    FamilyInstructionEntry {
        mnemonic: "LDB",
        mode: AddressMode::Immediate8,
        opcode: 0xC6,
    },
    FamilyInstructionEntry {
        mnemonic: "LDB",
        mode: AddressMode::Direct,
        opcode: 0xD6,
    },
    FamilyInstructionEntry {
        mnemonic: "LDB",
        mode: AddressMode::Extended,
        opcode: 0xF6,
    },
    FamilyInstructionEntry {
        mnemonic: "LDB",
        mode: AddressMode::Indexed,
        opcode: 0xE6,
    },
    FamilyInstructionEntry {
        mnemonic: "LDD",
        mode: AddressMode::Immediate16,
        opcode: 0xCC,
    },
    FamilyInstructionEntry {
        mnemonic: "LDD",
        mode: AddressMode::Direct,
        opcode: 0xDC,
    },
    FamilyInstructionEntry {
        mnemonic: "LDD",
        mode: AddressMode::Extended,
        opcode: 0xFC,
    },
    FamilyInstructionEntry {
        mnemonic: "LDD",
        mode: AddressMode::Indexed,
        opcode: 0xEC,
    },
    FamilyInstructionEntry {
        mnemonic: "BRA",
        mode: AddressMode::Relative8,
        opcode: 0x20,
    },
    FamilyInstructionEntry {
        mnemonic: "BNE",
        mode: AddressMode::Relative8,
        opcode: 0x26,
    },
    FamilyInstructionEntry {
        mnemonic: "BEQ",
        mode: AddressMode::Relative8,
        opcode: 0x27,
    },
    FamilyInstructionEntry {
        mnemonic: "LBRA",
        mode: AddressMode::Relative16,
        opcode: 0x16,
    },
    FamilyInstructionEntry {
        mnemonic: "LBSR",
        mode: AddressMode::Relative16,
        opcode: 0x17,
    },
    FamilyInstructionEntry {
        mnemonic: "TFR",
        mode: AddressMode::RegisterPair,
        opcode: 0x1F,
    },
    FamilyInstructionEntry {
        mnemonic: "EXG",
        mode: AddressMode::RegisterPair,
        opcode: 0x1E,
    },
    FamilyInstructionEntry {
        mnemonic: "PSHS",
        mode: AddressMode::RegisterList,
        opcode: 0x34,
    },
    FamilyInstructionEntry {
        mnemonic: "PULS",
        mode: AddressMode::RegisterList,
        opcode: 0x35,
    },
    FamilyInstructionEntry {
        mnemonic: "PSHU",
        mode: AddressMode::RegisterList,
        opcode: 0x36,
    },
    FamilyInstructionEntry {
        mnemonic: "PULU",
        mode: AddressMode::RegisterList,
        opcode: 0x37,
    },
];

pub fn lookup_instruction(
    mnemonic: &str,
    mode: AddressMode,
) -> Option<&'static FamilyInstructionEntry> {
    FAMILY_INSTRUCTION_TABLE
        .iter()
        .find(|entry| entry.mode == mode && entry.mnemonic.eq_ignore_ascii_case(mnemonic))
}

pub fn has_mnemonic(mnemonic: &str) -> bool {
    FAMILY_INSTRUCTION_TABLE
        .iter()
        .any(|entry| entry.mnemonic.eq_ignore_ascii_case(mnemonic))
}
