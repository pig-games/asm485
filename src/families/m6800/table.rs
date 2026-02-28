// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Baseline instruction table for Motorola 6800 family shared instructions.

use super::AddressMode;

/// Page-2 prefix byte (0x10) for M6809/HD6309 extended instructions.
pub const PAGE2_PREFIX: u8 = 0x10;
/// Page-3 prefix byte (0x11) for M6809/HD6309 extended instructions.
pub const PAGE3_PREFIX: u8 = 0x11;

pub struct FamilyInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode: u8,
}

pub struct PrefixedFamilyInstructionEntry {
    pub mnemonic: &'static str,
    pub mode: AddressMode,
    pub opcode_bytes: &'static [u8],
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
        mnemonic: "LDX",
        mode: AddressMode::Immediate16,
        opcode: 0x8E,
    },
    FamilyInstructionEntry {
        mnemonic: "LDX",
        mode: AddressMode::Direct,
        opcode: 0x9E,
    },
    FamilyInstructionEntry {
        mnemonic: "LDX",
        mode: AddressMode::Indexed,
        opcode: 0xAE,
    },
    FamilyInstructionEntry {
        mnemonic: "LDX",
        mode: AddressMode::Extended,
        opcode: 0xBE,
    },
    FamilyInstructionEntry {
        mnemonic: "LDU",
        mode: AddressMode::Immediate16,
        opcode: 0xCE,
    },
    FamilyInstructionEntry {
        mnemonic: "LDU",
        mode: AddressMode::Direct,
        opcode: 0xDE,
    },
    FamilyInstructionEntry {
        mnemonic: "LDU",
        mode: AddressMode::Indexed,
        opcode: 0xEE,
    },
    FamilyInstructionEntry {
        mnemonic: "LDU",
        mode: AddressMode::Extended,
        opcode: 0xFE,
    },
    FamilyInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::Direct,
        opcode: 0x97,
    },
    FamilyInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::Indexed,
        opcode: 0xA7,
    },
    FamilyInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::Extended,
        opcode: 0xB7,
    },
    FamilyInstructionEntry {
        mnemonic: "STB",
        mode: AddressMode::Direct,
        opcode: 0xD7,
    },
    FamilyInstructionEntry {
        mnemonic: "STB",
        mode: AddressMode::Indexed,
        opcode: 0xE7,
    },
    FamilyInstructionEntry {
        mnemonic: "STB",
        mode: AddressMode::Extended,
        opcode: 0xF7,
    },
    FamilyInstructionEntry {
        mnemonic: "STD",
        mode: AddressMode::Direct,
        opcode: 0xDD,
    },
    FamilyInstructionEntry {
        mnemonic: "STD",
        mode: AddressMode::Indexed,
        opcode: 0xED,
    },
    FamilyInstructionEntry {
        mnemonic: "STD",
        mode: AddressMode::Extended,
        opcode: 0xFD,
    },
    FamilyInstructionEntry {
        mnemonic: "STX",
        mode: AddressMode::Direct,
        opcode: 0x9F,
    },
    FamilyInstructionEntry {
        mnemonic: "STX",
        mode: AddressMode::Indexed,
        opcode: 0xAF,
    },
    FamilyInstructionEntry {
        mnemonic: "STX",
        mode: AddressMode::Extended,
        opcode: 0xBF,
    },
    FamilyInstructionEntry {
        mnemonic: "STU",
        mode: AddressMode::Direct,
        opcode: 0xDF,
    },
    FamilyInstructionEntry {
        mnemonic: "STU",
        mode: AddressMode::Indexed,
        opcode: 0xEF,
    },
    FamilyInstructionEntry {
        mnemonic: "STU",
        mode: AddressMode::Extended,
        opcode: 0xFF,
    },
    FamilyInstructionEntry {
        mnemonic: "JMP",
        mode: AddressMode::Indexed,
        opcode: 0x6E,
    },
    FamilyInstructionEntry {
        mnemonic: "JMP",
        mode: AddressMode::Extended,
        opcode: 0x7E,
    },
    FamilyInstructionEntry {
        mnemonic: "JSR",
        mode: AddressMode::Indexed,
        opcode: 0xAD,
    },
    FamilyInstructionEntry {
        mnemonic: "JSR",
        mode: AddressMode::Extended,
        opcode: 0xBD,
    },
    FamilyInstructionEntry {
        mnemonic: "BSR",
        mode: AddressMode::Relative8,
        opcode: 0x8D,
    },
    FamilyInstructionEntry {
        mnemonic: "JMP",
        mode: AddressMode::Direct,
        opcode: 0x0E,
    },
    FamilyInstructionEntry {
        mnemonic: "JSR",
        mode: AddressMode::Direct,
        opcode: 0x9D,
    },
    FamilyInstructionEntry {
        mnemonic: "BRA",
        mode: AddressMode::Relative8,
        opcode: 0x20,
    },
    FamilyInstructionEntry {
        mnemonic: "BRN",
        mode: AddressMode::Relative8,
        opcode: 0x21,
    },
    FamilyInstructionEntry {
        mnemonic: "BHI",
        mode: AddressMode::Relative8,
        opcode: 0x22,
    },
    FamilyInstructionEntry {
        mnemonic: "BLS",
        mode: AddressMode::Relative8,
        opcode: 0x23,
    },
    FamilyInstructionEntry {
        mnemonic: "BCC",
        mode: AddressMode::Relative8,
        opcode: 0x24,
    },
    FamilyInstructionEntry {
        mnemonic: "BHS",
        mode: AddressMode::Relative8,
        opcode: 0x24,
    },
    FamilyInstructionEntry {
        mnemonic: "BCS",
        mode: AddressMode::Relative8,
        opcode: 0x25,
    },
    FamilyInstructionEntry {
        mnemonic: "BLO",
        mode: AddressMode::Relative8,
        opcode: 0x25,
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
        mnemonic: "BVC",
        mode: AddressMode::Relative8,
        opcode: 0x28,
    },
    FamilyInstructionEntry {
        mnemonic: "BVS",
        mode: AddressMode::Relative8,
        opcode: 0x29,
    },
    FamilyInstructionEntry {
        mnemonic: "BPL",
        mode: AddressMode::Relative8,
        opcode: 0x2A,
    },
    FamilyInstructionEntry {
        mnemonic: "BMI",
        mode: AddressMode::Relative8,
        opcode: 0x2B,
    },
    FamilyInstructionEntry {
        mnemonic: "BGE",
        mode: AddressMode::Relative8,
        opcode: 0x2C,
    },
    FamilyInstructionEntry {
        mnemonic: "BLT",
        mode: AddressMode::Relative8,
        opcode: 0x2D,
    },
    FamilyInstructionEntry {
        mnemonic: "BGT",
        mode: AddressMode::Relative8,
        opcode: 0x2E,
    },
    FamilyInstructionEntry {
        mnemonic: "BLE",
        mode: AddressMode::Relative8,
        opcode: 0x2F,
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

pub static PREFIXED_FAMILY_INSTRUCTION_TABLE: &[PrefixedFamilyInstructionEntry] = &[
    PrefixedFamilyInstructionEntry {
        mnemonic: "LDY",
        mode: AddressMode::Immediate16,
        opcode_bytes: &[PAGE2_PREFIX, 0x8E],
    },
    PrefixedFamilyInstructionEntry {
        mnemonic: "LDY",
        mode: AddressMode::Direct,
        opcode_bytes: &[PAGE2_PREFIX, 0x9E],
    },
    PrefixedFamilyInstructionEntry {
        mnemonic: "LDY",
        mode: AddressMode::Indexed,
        opcode_bytes: &[PAGE2_PREFIX, 0xAE],
    },
    PrefixedFamilyInstructionEntry {
        mnemonic: "LDY",
        mode: AddressMode::Extended,
        opcode_bytes: &[PAGE2_PREFIX, 0xBE],
    },
    PrefixedFamilyInstructionEntry {
        mnemonic: "STY",
        mode: AddressMode::Direct,
        opcode_bytes: &[PAGE2_PREFIX, 0x9F],
    },
    PrefixedFamilyInstructionEntry {
        mnemonic: "STY",
        mode: AddressMode::Indexed,
        opcode_bytes: &[PAGE2_PREFIX, 0xAF],
    },
    PrefixedFamilyInstructionEntry {
        mnemonic: "STY",
        mode: AddressMode::Extended,
        opcode_bytes: &[PAGE2_PREFIX, 0xBF],
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
        || PREFIXED_FAMILY_INSTRUCTION_TABLE
            .iter()
            .any(|entry| entry.mnemonic.eq_ignore_ascii_case(mnemonic))
}

pub fn lookup_prefixed_instruction(
    mnemonic: &str,
    mode: AddressMode,
) -> Option<&'static PrefixedFamilyInstructionEntry> {
    PREFIXED_FAMILY_INSTRUCTION_TABLE
        .iter()
        .find(|entry| entry.mode == mode && entry.mnemonic.eq_ignore_ascii_case(mnemonic))
}
