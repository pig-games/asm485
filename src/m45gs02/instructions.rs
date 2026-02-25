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
        mode: AddressMode::Relative,
        opcode: 0x10,
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
        mode: AddressMode::Relative,
        opcode: 0x30,
    },
    CpuInstructionEntry {
        mnemonic: "BMI",
        mode: AddressMode::RelativeLong,
        opcode: 0x33,
    },
    CpuInstructionEntry {
        mnemonic: "BVC",
        mode: AddressMode::Relative,
        opcode: 0x50,
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
        mode: AddressMode::Relative,
        opcode: 0x70,
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
        mode: AddressMode::Relative,
        opcode: 0x80,
    },
    CpuInstructionEntry {
        mnemonic: "BRA",
        mode: AddressMode::RelativeLong,
        opcode: 0x83,
    },
    CpuInstructionEntry {
        mnemonic: "BCC",
        mode: AddressMode::Relative,
        opcode: 0x90,
    },
    CpuInstructionEntry {
        mnemonic: "BCC",
        mode: AddressMode::RelativeLong,
        opcode: 0x93,
    },
    CpuInstructionEntry {
        mnemonic: "BCS",
        mode: AddressMode::Relative,
        opcode: 0xB0,
    },
    CpuInstructionEntry {
        mnemonic: "BCS",
        mode: AddressMode::RelativeLong,
        opcode: 0xB3,
    },
    CpuInstructionEntry {
        mnemonic: "BNE",
        mode: AddressMode::Relative,
        opcode: 0xD0,
    },
    CpuInstructionEntry {
        mnemonic: "BNE",
        mode: AddressMode::RelativeLong,
        opcode: 0xD3,
    },
    CpuInstructionEntry {
        mnemonic: "BEQ",
        mode: AddressMode::Relative,
        opcode: 0xF0,
    },
    CpuInstructionEntry {
        mnemonic: "BEQ",
        mode: AddressMode::RelativeLong,
        opcode: 0xF3,
    },
    CpuInstructionEntry {
        mnemonic: "BRK",
        mode: AddressMode::Implied,
        opcode: 0x00,
    },
    CpuInstructionEntry {
        mnemonic: "PHP",
        mode: AddressMode::Implied,
        opcode: 0xF8,
    },
    CpuInstructionEntry {
        mnemonic: "PHA",
        mode: AddressMode::Implied,
        opcode: 0x38,
    },
    CpuInstructionEntry {
        mnemonic: "PHY",
        mode: AddressMode::Implied,
        opcode: 0x4A,
    },
    CpuInstructionEntry {
        mnemonic: "PLP",
        mode: AddressMode::Implied,
        opcode: 0x18,
    },
    CpuInstructionEntry {
        mnemonic: "PLA",
        mode: AddressMode::Implied,
        opcode: 0x58,
    },
    CpuInstructionEntry {
        mnemonic: "PLY",
        mode: AddressMode::Implied,
        opcode: 0x6A,
    },
    CpuInstructionEntry {
        mnemonic: "PHX",
        mode: AddressMode::Implied,
        opcode: 0xCA,
    },
    CpuInstructionEntry {
        mnemonic: "PLX",
        mode: AddressMode::Implied,
        opcode: 0xEA,
    },
    CpuInstructionEntry {
        mnemonic: "RTI",
        mode: AddressMode::Implied,
        opcode: 0x40,
    },
    CpuInstructionEntry {
        mnemonic: "CLC",
        mode: AddressMode::Implied,
        opcode: 0x08,
    },
    CpuInstructionEntry {
        mnemonic: "SEC",
        mode: AddressMode::Implied,
        opcode: 0x28,
    },
    CpuInstructionEntry {
        mnemonic: "CLI",
        mode: AddressMode::Implied,
        opcode: 0x48,
    },
    CpuInstructionEntry {
        mnemonic: "SEI",
        mode: AddressMode::Implied,
        opcode: 0x68,
    },
    CpuInstructionEntry {
        mnemonic: "CLV",
        mode: AddressMode::Implied,
        opcode: 0xA8,
    },
    CpuInstructionEntry {
        mnemonic: "CLD",
        mode: AddressMode::Implied,
        opcode: 0xC8,
    },
    CpuInstructionEntry {
        mnemonic: "SED",
        mode: AddressMode::Implied,
        opcode: 0xE8,
    },
    CpuInstructionEntry {
        mnemonic: "DEY",
        mode: AddressMode::Implied,
        opcode: 0x78,
    },
    CpuInstructionEntry {
        mnemonic: "TXA",
        mode: AddressMode::Implied,
        opcode: 0x7A,
    },
    CpuInstructionEntry {
        mnemonic: "TXS",
        mode: AddressMode::Implied,
        opcode: 0x8A,
    },
    CpuInstructionEntry {
        mnemonic: "TYA",
        mode: AddressMode::Implied,
        opcode: 0x88,
    },
    CpuInstructionEntry {
        mnemonic: "TAY",
        mode: AddressMode::Implied,
        opcode: 0x98,
    },
    CpuInstructionEntry {
        mnemonic: "TAX",
        mode: AddressMode::Implied,
        opcode: 0x9A,
    },
    CpuInstructionEntry {
        mnemonic: "TSX",
        mode: AddressMode::Implied,
        opcode: 0xAA,
    },
    CpuInstructionEntry {
        mnemonic: "INY",
        mode: AddressMode::Implied,
        opcode: 0xB8,
    },
    CpuInstructionEntry {
        mnemonic: "DEX",
        mode: AddressMode::Implied,
        opcode: 0xBA,
    },
    CpuInstructionEntry {
        mnemonic: "INX",
        mode: AddressMode::Implied,
        opcode: 0xD8,
    },
    CpuInstructionEntry {
        mnemonic: "STY",
        mode: AddressMode::AbsoluteX,
        opcode: 0x7B,
    },
    CpuInstructionEntry {
        mnemonic: "STY",
        mode: AddressMode::Absolute,
        opcode: 0x7C,
    },
    CpuInstructionEntry {
        mnemonic: "STX",
        mode: AddressMode::Absolute,
        opcode: 0x7E,
    },
    CpuInstructionEntry {
        mnemonic: "STX",
        mode: AddressMode::AbsoluteY,
        opcode: 0x8B,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::AbsoluteX,
        opcode: 0x0D,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::AbsoluteX,
        opcode: 0x2D,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::AbsoluteX,
        opcode: 0x4D,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::AbsoluteX,
        opcode: 0x6D,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::AbsoluteX,
        opcode: 0x8D,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::AbsoluteX,
        opcode: 0xAD,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::AbsoluteX,
        opcode: 0xCD,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::AbsoluteX,
        opcode: 0xED,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::AbsoluteY,
        opcode: 0x09,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::AbsoluteY,
        opcode: 0x29,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::AbsoluteY,
        opcode: 0x49,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::AbsoluteY,
        opcode: 0x69,
    },
    CpuInstructionEntry {
        mnemonic: "STA",
        mode: AddressMode::AbsoluteY,
        opcode: 0x89,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::AbsoluteY,
        opcode: 0xA9,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::AbsoluteY,
        opcode: 0xC9,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::AbsoluteY,
        opcode: 0xE9,
    },
    CpuInstructionEntry {
        mnemonic: "AND",
        mode: AddressMode::Immediate,
        opcode: 0x19,
    },
    CpuInstructionEntry {
        mnemonic: "EOR",
        mode: AddressMode::Immediate,
        opcode: 0x39,
    },
    CpuInstructionEntry {
        mnemonic: "ADC",
        mode: AddressMode::Immediate,
        opcode: 0x59,
    },
    CpuInstructionEntry {
        mnemonic: "LDA",
        mode: AddressMode::Immediate,
        opcode: 0x99,
    },
    CpuInstructionEntry {
        mnemonic: "BIT",
        mode: AddressMode::Immediate,
        opcode: 0x79,
    },
    CpuInstructionEntry {
        mnemonic: "CMP",
        mode: AddressMode::Immediate,
        opcode: 0xB9,
    },
    CpuInstructionEntry {
        mnemonic: "ORA",
        mode: AddressMode::Immediate,
        opcode: 0xF9,
    },
    CpuInstructionEntry {
        mnemonic: "SBC",
        mode: AddressMode::Immediate,
        opcode: 0xD9,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn dataset_mode_key(mode: AddressMode) -> &'static str {
        match mode {
            AddressMode::Implied => "imp",
            AddressMode::Accumulator => "accumulator",
            AddressMode::Immediate => "immediate",
            AddressMode::ZeroPage => "zero_page",
            AddressMode::ZeroPageX => "zero_page_x",
            AddressMode::ZeroPageY => "zero_page_y",
            AddressMode::Absolute => "absolute",
            AddressMode::AbsoluteX => "absolute_x",
            AddressMode::AbsoluteY => "absolute_y",
            AddressMode::Indirect => "indirect",
            AddressMode::IndexedIndirectX => "indexed_indirect_x",
            AddressMode::IndirectIndexedY => "indirect_indexed_zp_y",
            AddressMode::Relative => "relative",
            AddressMode::RelativeLong => "relative_long",
            AddressMode::IndirectIndexedZ => "indirect_indexed_zp_z",
            AddressMode::ZeroPageIndirect => "zero_page_indirect",
            AddressMode::AbsoluteIndexedIndirect => "absolute_indexed_indirect",
            AddressMode::StackRelative => "stack_relative",
            AddressMode::StackRelativeIndirectIndexedY => "stack_relative_indirect_indexed_y",
            AddressMode::AbsoluteLong => "absolute_long",
            AddressMode::AbsoluteLongX => "absolute_long_x",
            AddressMode::IndirectLong => "indirect_long",
            AddressMode::DirectPageIndirectLongY => "direct_page_indirect_long_y",
            AddressMode::DirectPageIndirectLong => "direct_page_indirect_long",
            AddressMode::DirectPageIndirectLongZ => "bracket_indirect_long_z",
            AddressMode::BlockMove => "block_move",
        }
    }

    #[test]
    fn cpu_instruction_table_pairs_are_present_in_curated_dataset() {
        let dataset = include_str!("../../documentation/45gs02/opcode_dataset_v0_1.csv");

        let dataset_pairs: BTreeSet<String> = dataset
            .lines()
            .skip(1)
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let mut fields = trimmed.splitn(3, ',');
                let mnemonic = fields.next()?;
                let mode = fields.next()?;
                Some(format!("{},{}", mnemonic.to_ascii_uppercase(), mode))
            })
            .collect();

        let mut missing_pairs = Vec::new();
        for entry in CPU_INSTRUCTION_TABLE {
            let key = format!("{},{}", entry.mnemonic, dataset_mode_key(entry.mode));
            if !dataset_pairs.contains(&key) {
                missing_pairs.push(key);
            }
        }

        assert!(
            missing_pairs.is_empty(),
            "CPU instruction table entries missing from curated dataset: {}",
            missing_pairs.join(", ")
        );
    }
}
