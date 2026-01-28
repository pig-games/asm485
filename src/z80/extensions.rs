// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Z80-specific instruction extensions.
//!
//! This table contains instructions that exist only on the Z80 and have
//! no Intel 8080/8085 equivalent. These use Z80 mnemonics directly.

use crate::families::intel8080::table::{ArgType, InstructionEntry, Prefix};

/// Z80-only instructions (no Intel equivalent).
///
/// These are instructions that were added by Zilog and have no 8080 equivalent:
/// - Relative jumps (JR, DJNZ)
/// - Exchange (EXX, EX AF,AF')
/// - Block operations (LDI/LDIR/LDD/LDDR, CPI/CPIR/CPD/CPDR, etc.)
/// - Bit operations (BIT/SET/RES, rotates/shifts on registers)
/// - Index register operations (IX, IY)
/// - 16-bit arithmetic with carry (ADC HL, SBC HL)
/// - Interrupt modes (IM)
/// - Special (NEG, RLD, RRD, RETI, RETN)
pub static Z80_EXTENSION_TABLE: &[InstructionEntry] = &[
    // ============================================================
    // Relative Jumps (Z80-only)
    // ============================================================
    InstructionEntry { mnemonic: "DJNZ", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x10, arg_type: ArgType::Relative },
    InstructionEntry { mnemonic: "JR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0x18, arg_type: ArgType::Relative },
    InstructionEntry { mnemonic: "JR", reg1: "C", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x38, arg_type: ArgType::Relative },
    InstructionEntry { mnemonic: "JR", reg1: "NC", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x30, arg_type: ArgType::Relative },
    InstructionEntry { mnemonic: "JR", reg1: "NZ", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x20, arg_type: ArgType::Relative },
    InstructionEntry { mnemonic: "JR", reg1: "Z", reg2: "", num_regs: 1, prefix: Prefix::None, opcode: 0x28, arg_type: ArgType::Relative },

    // ============================================================
    // Exchange (Z80-only)
    // ============================================================
    InstructionEntry { mnemonic: "EX", reg1: "AF", reg2: "AF", num_regs: 2, prefix: Prefix::None, opcode: 0x08, arg_type: ArgType::None }, // EX AF,AF'
    InstructionEntry { mnemonic: "EXX", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::None, opcode: 0xD9, arg_type: ArgType::None },

    // ============================================================
    // Block Transfer (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "LDD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xA8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LDDR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xB8, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LDI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xA0, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LDIR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xB0, arg_type: ArgType::None },

    // ============================================================
    // Block Compare (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "CPD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xA9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CPDR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xB9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CPI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xA1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "CPIR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xB1, arg_type: ArgType::None },

    // ============================================================
    // Block I/O (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "IND", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xAA, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INDR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xBA, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xA2, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INIR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xB2, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OTDR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xBB, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OTIR", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xB3, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUTD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xAB, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUTI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0xA3, arg_type: ArgType::None },

    // ============================================================
    // 16-bit Arithmetic with Carry (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "ADC", reg1: "HL", reg2: "BC", num_regs: 2, prefix: Prefix::Ed, opcode: 0x4A, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "HL", reg2: "DE", num_regs: 2, prefix: Prefix::Ed, opcode: 0x5A, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "HL", reg2: "HL", num_regs: 2, prefix: Prefix::Ed, opcode: 0x6A, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADC", reg1: "HL", reg2: "SP", num_regs: 2, prefix: Prefix::Ed, opcode: 0x7A, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBC", reg1: "HL", reg2: "BC", num_regs: 2, prefix: Prefix::Ed, opcode: 0x42, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBC", reg1: "HL", reg2: "DE", num_regs: 2, prefix: Prefix::Ed, opcode: 0x52, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBC", reg1: "HL", reg2: "HL", num_regs: 2, prefix: Prefix::Ed, opcode: 0x62, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "SBC", reg1: "HL", reg2: "SP", num_regs: 2, prefix: Prefix::Ed, opcode: 0x72, arg_type: ArgType::None },

    // ============================================================
    // Extended I/O (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "IN", reg1: "A", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x78, arg_type: ArgType::None }, // IN A,(C)
    InstructionEntry { mnemonic: "IN", reg1: "B", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x40, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "IN", reg1: "C", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x48, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "IN", reg1: "D", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x50, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "IN", reg1: "E", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x58, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "IN", reg1: "H", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x60, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "IN", reg1: "L", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x68, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "A", num_regs: 2, prefix: Prefix::Ed, opcode: 0x79, arg_type: ArgType::None }, // OUT (C),A
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "B", num_regs: 2, prefix: Prefix::Ed, opcode: 0x41, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "C", num_regs: 2, prefix: Prefix::Ed, opcode: 0x49, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "D", num_regs: 2, prefix: Prefix::Ed, opcode: 0x51, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "E", num_regs: 2, prefix: Prefix::Ed, opcode: 0x59, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "H", num_regs: 2, prefix: Prefix::Ed, opcode: 0x61, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "OUT", reg1: "C", reg2: "L", num_regs: 2, prefix: Prefix::Ed, opcode: 0x69, arg_type: ArgType::None },

    // ============================================================
    // Interrupt Control (Z80-only)
    // ============================================================
    InstructionEntry { mnemonic: "IM", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0x46, arg_type: ArgType::Im }, // IM 0/1/2
    InstructionEntry { mnemonic: "RETI", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0x4D, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RETN", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0x45, arg_type: ArgType::None },

    // ============================================================
    // Special (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "NEG", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0x44, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RLD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0x6F, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "RRD", reg1: "", reg2: "", num_regs: 0, prefix: Prefix::Ed, opcode: 0x67, arg_type: ArgType::None },

    // ============================================================
    // I/R Register Loads (Z80-only, ED prefix)
    // ============================================================
    InstructionEntry { mnemonic: "LD", reg1: "A", reg2: "I", num_regs: 2, prefix: Prefix::Ed, opcode: 0x57, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LD", reg1: "A", reg2: "R", num_regs: 2, prefix: Prefix::Ed, opcode: 0x5F, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LD", reg1: "I", reg2: "A", num_regs: 2, prefix: Prefix::Ed, opcode: 0x47, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LD", reg1: "R", reg2: "A", num_regs: 2, prefix: Prefix::Ed, opcode: 0x4F, arg_type: ArgType::None },

    // ============================================================
    // Index Register Operations (Z80-only, DD/FD prefix)
    // ============================================================
    // ADD IX/IY
    InstructionEntry { mnemonic: "ADD", reg1: "IX", reg2: "BC", num_regs: 2, prefix: Prefix::Dd, opcode: 0x09, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IX", reg2: "DE", num_regs: 2, prefix: Prefix::Dd, opcode: 0x19, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IX", reg2: "IX", num_regs: 2, prefix: Prefix::Dd, opcode: 0x29, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IX", reg2: "SP", num_regs: 2, prefix: Prefix::Dd, opcode: 0x39, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IY", reg2: "BC", num_regs: 2, prefix: Prefix::Fd, opcode: 0x09, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IY", reg2: "DE", num_regs: 2, prefix: Prefix::Fd, opcode: 0x19, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IY", reg2: "IY", num_regs: 2, prefix: Prefix::Fd, opcode: 0x29, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "ADD", reg1: "IY", reg2: "SP", num_regs: 2, prefix: Prefix::Fd, opcode: 0x39, arg_type: ArgType::None },

    // INC/DEC IX/IY
    InstructionEntry { mnemonic: "DEC", reg1: "IX", reg2: "", num_regs: 1, prefix: Prefix::Dd, opcode: 0x2B, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "DEC", reg1: "IY", reg2: "", num_regs: 1, prefix: Prefix::Fd, opcode: 0x2B, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INC", reg1: "IX", reg2: "", num_regs: 1, prefix: Prefix::Dd, opcode: 0x23, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "INC", reg1: "IY", reg2: "", num_regs: 1, prefix: Prefix::Fd, opcode: 0x23, arg_type: ArgType::None },

    // LD IX/IY,nn
    InstructionEntry { mnemonic: "LD", reg1: "IX", reg2: "", num_regs: 1, prefix: Prefix::Dd, opcode: 0x21, arg_type: ArgType::Word },
    InstructionEntry { mnemonic: "LD", reg1: "IY", reg2: "", num_regs: 1, prefix: Prefix::Fd, opcode: 0x21, arg_type: ArgType::Word },

    // LD SP,IX/IY
    InstructionEntry { mnemonic: "LD", reg1: "SP", reg2: "IX", num_regs: 2, prefix: Prefix::Dd, opcode: 0xF9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "LD", reg1: "SP", reg2: "IY", num_regs: 2, prefix: Prefix::Fd, opcode: 0xF9, arg_type: ArgType::None },

    // PUSH/POP IX/IY
    InstructionEntry { mnemonic: "POP", reg1: "IX", reg2: "", num_regs: 1, prefix: Prefix::Dd, opcode: 0xE1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "POP", reg1: "IY", reg2: "", num_regs: 1, prefix: Prefix::Fd, opcode: 0xE1, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "PUSH", reg1: "IX", reg2: "", num_regs: 1, prefix: Prefix::Dd, opcode: 0xE5, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "PUSH", reg1: "IY", reg2: "", num_regs: 1, prefix: Prefix::Fd, opcode: 0xE5, arg_type: ArgType::None },

    // EX (SP),IX/IY
    InstructionEntry { mnemonic: "EX", reg1: "SP", reg2: "IX", num_regs: 2, prefix: Prefix::Dd, opcode: 0xE3, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "EX", reg1: "SP", reg2: "IY", num_regs: 2, prefix: Prefix::Fd, opcode: 0xE3, arg_type: ArgType::None },

    // JP (IX)/(IY)
    InstructionEntry { mnemonic: "JP", reg1: "IX", reg2: "", num_regs: 1, prefix: Prefix::Dd, opcode: 0xE9, arg_type: ArgType::None },
    InstructionEntry { mnemonic: "JP", reg1: "IY", reg2: "", num_regs: 1, prefix: Prefix::Fd, opcode: 0xE9, arg_type: ArgType::None },

    // Note: Indexed addressing (IX+d), (IY+d) and CB-prefix bit operations
    // require special handling due to the displacement byte placement.
    // They are NOT simple table lookups and need encoder logic.
];

/// Look up an instruction in the Z80 extension table.
pub fn lookup_extension(
    mnemonic: &str,
    reg1: Option<&str>,
    reg2: Option<&str>,
) -> Option<&'static InstructionEntry> {
    lookup_in_table(Z80_EXTENSION_TABLE, mnemonic, reg1, reg2)
}

/// Check if a mnemonic exists in the Z80 extension table.
pub fn has_extension(mnemonic: &str) -> bool {
    let upper = mnemonic.to_ascii_uppercase();
    Z80_EXTENSION_TABLE
        .iter()
        .any(|entry| entry.mnemonic.eq_ignore_ascii_case(&upper))
}

/// Look up an instruction in an extension table.
pub fn lookup_in_table<'a>(
    table: &'a [InstructionEntry],
    mnemonic: &str,
    reg1: Option<&str>,
    reg2: Option<&str>,
) -> Option<&'a InstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();

    for entry in table {
        if !entry.mnemonic.eq_ignore_ascii_case(&upper) {
            continue;
        }

        // Match register operands - must match entry's expected operand count
        let reg1_matches = match (entry.num_regs, reg1) {
            // Entry expects 0 regs, caller provides none
            (0, None) => true,
            // Entry expects 0 regs, caller provides one - no match
            (0, Some(_)) => false,
            // Entry expects 1+ regs, caller provides one - check it
            (_, Some(r)) => entry.reg1.eq_ignore_ascii_case(r),
            // Entry expects 1+ regs, caller provides none - no match
            (_, None) => false,
        };

        if !reg1_matches {
            continue;
        }

        let reg2_matches = match (entry.num_regs, reg2) {
            // Entry expects 0 or 1 regs - reg2 doesn't matter
            (0, _) | (1, None) => true,
            // Entry expects 1 reg but caller provides 2 - no match
            (1, Some(_)) => false,
            // Entry expects 2 regs, caller provides 2 - check it
            (2, Some(r)) => entry.reg2.eq_ignore_ascii_case(r),
            // Entry expects 2 regs, caller provides less - no match
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
    fn test_jr() {
        let entry = lookup_extension("JR", None, None);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x18);

        let entry = lookup_extension("JR", Some("NZ"), None);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x20);
    }

    #[test]
    fn test_djnz() {
        let entry = lookup_extension("DJNZ", None, None);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().opcode, 0x10);
    }

    #[test]
    fn test_block_ops() {
        assert!(lookup_extension("LDIR", None, None).is_some());
        assert!(lookup_extension("LDDR", None, None).is_some());
        assert!(lookup_extension("CPIR", None, None).is_some());
    }
}
