// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8085-specific instruction extensions.
//!
//! This table contains instructions that exist only on the 8085 and not
//! on the base 8080: RIM (Read Interrupt Mask) and SIM (Set Interrupt Mask).

use crate::families::intel8080::table::{ArgType, InstructionEntry, Prefix};

/// I8085-specific instructions (RIM, SIM).
///
/// These instructions were added in the 8085 for interrupt mask control:
/// - RIM (0x20): Read Interrupt Mask - reads interrupt mask and serial input
/// - SIM (0x30): Set Interrupt Mask - sets interrupt mask and serial output
pub static I8085_EXTENSION_TABLE: &[InstructionEntry] = &[
    InstructionEntry {
        mnemonic: "RIM",
        reg1: "",
        reg2: "",
        num_regs: 0,
        prefix: Prefix::None,
        opcode: 0x20,
        arg_type: ArgType::None,
    },
    InstructionEntry {
        mnemonic: "SIM",
        reg1: "",
        reg2: "",
        num_regs: 0,
        prefix: Prefix::None,
        opcode: 0x30,
        arg_type: ArgType::None,
    },
];

/// Look up an instruction in the I8085 extension table.
pub fn lookup_extension(
    mnemonic: &str,
    reg1: Option<&str>,
    reg2: Option<&str>,
) -> Option<&'static InstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();

    for entry in I8085_EXTENSION_TABLE {
        if !entry.mnemonic.eq_ignore_ascii_case(&upper) {
            continue;
        }

        // Match register operands
        let reg1_matches = match (entry.num_regs, reg1) {
            (0, None) => true,
            (0, Some(_)) => false,
            (_, Some(r)) => entry.reg1.eq_ignore_ascii_case(r),
            (_, None) => false,
        };

        if !reg1_matches {
            continue;
        }

        let reg2_matches = match (entry.num_regs, reg2) {
            (0, _) | (1, None) => true,
            (1, Some(_)) => false,
            (2, Some(r)) => entry.reg2.eq_ignore_ascii_case(r),
            (2, None) => false,
            _ => false,
        };

        if reg2_matches {
            return Some(entry);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rim() {
        let entry = lookup_extension("RIM", None, None);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x20);
    }

    #[test]
    fn test_sim() {
        let entry = lookup_extension("SIM", None, None);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x30);
    }

    #[test]
    fn test_rim_with_operand_fails() {
        // RIM takes no operands
        let entry = lookup_extension("RIM", Some("A"), None);
        assert!(entry.is_none());
    }
}
