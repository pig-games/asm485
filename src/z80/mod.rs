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
pub mod handler;

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
        "AF" | "BC" | "DE" | "HL" | "SP" | "IX" | "IY" |
        // Memory operand (HL) and condition codes (used as pseudo-registers)
        // Note: M is used for both (HL) memory operand and "minus" condition
        "M" | "NZ" | "Z" | "NC" | "PO" | "PE" | "P"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        
        // Not registers
        assert!(!is_register("LD"));
        assert!(!is_register("JP"));
        assert!(!is_register("AX")); // x86 register
    }
}
