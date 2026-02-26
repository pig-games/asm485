// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Zilog Z80 CPU support module.
//!
//! This module provides Z80-specific functionality:
//! - Register definitions
//! - CPU handler for instruction encoding
//! - Dialect mapping (Zilog to Intel)
//! - Extension table (Z80-only instructions)

pub mod dialect;
pub mod extensions;
pub mod formatter;
pub mod handler;
pub mod module;

pub use dialect::{is_z80_only_mnemonic, map_register};
pub use extensions::{lookup_extension, Z80_EXTENSION_TABLE};
pub use handler::Z80CpuHandler;

/// Check if an identifier is a Z80 register name.
///
/// Valid 8-bit registers: A, B, C, D, E, H, L, I, R, IXH, IXL, IYH, IYL
/// Valid 16-bit registers: AF, BC, DE, HL, SP, IX, IY
/// Memory operand: (HL) represented as M for compatibility
/// Shadow registers are not directly addressable as operands
pub fn is_register(ident: &str) -> bool {
    matches!(
        ident,
        // 8-bit registers
        "A" | "B" | "C" | "D" | "E" | "H" | "L" | "I" | "R" |
        // Undocumented 8-bit index register halves
        "IXH" | "IXL" | "IYH" | "IYL" |
        // 16-bit register pairs
        "AF" | "AF'" | "BC" | "DE" | "HL" | "SP" | "IX" | "IY" |
        // Memory operand (HL) and condition codes (used as pseudo-registers)
        // Note: M is used for both (HL) memory operand and "minus" condition
        "M" | "NZ" | "Z" | "NC" | "PO" | "PE" | "P"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::parser::{LineAst, Parser};
    use crate::core::tokenizer::register_checker_from_fn;

    #[test]
    fn recognizes_z80_registers() {
        // 8-bit
        assert!(is_register("A"));
        assert!(is_register("B"));
        assert!(is_register("H"));
        assert!(is_register("L"));
        assert!(is_register("I"));
        assert!(is_register("R"));

        // 16-bit
        assert!(is_register("BC"));
        assert!(is_register("DE"));
        assert!(is_register("HL"));
        assert!(is_register("SP"));
        assert!(is_register("IX"));
        assert!(is_register("IY"));
        assert!(is_register("AF"));
        assert!(is_register("AF'"));

        // Not registers
        assert!(!is_register("LD"));
        assert!(!is_register("JP"));
        assert!(!is_register("AX")); // x86 register
    }

    #[test]
    fn parses_z80_add_with_byte() {
        use crate::core::parser::Expr;

        // Note: mnemonic not at column 1 (spaces at start) to avoid being parsed as label
        let mut parser = Parser::from_line_with_registers(
            "        add a, 5",
            1,
            register_checker_from_fn(is_register),
        )
        .unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some("add"));
                assert_eq!(operands.len(), 2);
                assert!(matches!(&operands[0], Expr::Register(name, _) if name == "a"));
                assert!(matches!(&operands[1], Expr::Number(_, _)));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_z80_condition_codes() {
        use crate::core::parser::Expr;

        let mut parser = Parser::from_line_with_registers(
            "        jp nz, 1000h",
            1,
            register_checker_from_fn(is_register),
        )
        .unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some("jp"));
                // Should have NZ as register and 1000h as number
                assert_eq!(operands.len(), 2);
                assert!(
                    matches!(&operands[0], Expr::Register(name, _) if name.eq_ignore_ascii_case("NZ")),
                    "Expected NZ register, got {:?}",
                    operands[0]
                );
                assert!(matches!(&operands[1], Expr::Number(_, _)));
            }
            _ => panic!("Expected statement"),
        }
    }

    #[test]
    fn parses_z80_memory_operand() {
        let mut parser = Parser::from_line_with_registers(
            "        ld (hl), a",
            1,
            register_checker_from_fn(is_register),
        )
        .unwrap();
        let line = parser.parse_line().unwrap();
        match line {
            LineAst::Statement {
                mnemonic, operands, ..
            } => {
                assert_eq!(mnemonic.as_deref(), Some("ld"));
                // Note: (HL) syntax currently parses as HL (parentheses are stripped)
                // This is a limitation - proper Z80 (HL) syntax support would need parser changes
                assert_eq!(operands.len(), 2);
            }
            _ => panic!("Expected statement"),
        }
    }
}
