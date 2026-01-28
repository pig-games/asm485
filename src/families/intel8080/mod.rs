// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8080 CPU family handler.
//!
//! This module provides family-level parsing and encoding for all CPUs in
//! the Intel 8080 family (8080, 8085, Z80).
//!
//! # Family Characteristics
//!
//! - 8-bit data bus, 16-bit address bus
//! - Registers: A, B, C, D, E, H, L (8-bit), BC, DE, HL, SP (16-bit)
//! - M pseudo-register for (HL) indirect
//! - Condition codes: NZ, Z, NC, C, PO, PE, P, M
//!
//! # CPU Extensions
//!
//! - **8085**: RIM, SIM instructions (see `crate::i8085::extensions`)
//! - **Z80**: IX, IY index registers, (IX+d)/(IY+d) addressing, many new instructions (see `crate::z80::extensions`)
//!
//! # Table Architecture
//!
//! The instruction encoding uses a layered table architecture:
//!
//! 1. **Dialect Mapping** (`dialect.rs`): Maps Zilog mnemonics to Intel canonical form
//! 2. **Family Base Table** (`table.rs`): Intel 8080 opcodes using Intel mnemonics
//! 3. **Extension Tables**: CPU-specific instructions in their respective modules

pub mod dialect;
pub mod extensions;
pub mod handler;
mod operand;
pub mod table;

// Re-export I8085CpuHandler from i8085 module for backwards compatibility
pub use crate::i8085::I8085CpuHandler;
pub use dialect::{
    find_mapping, is_z80_only_mnemonic, map_register, map_zilog_to_canonical, DialectEntry,
    OperandTransform,
};
pub use extensions::{I8085_EXTENSION_TABLE, Z80_EXTENSION_TABLE};
pub use handler::Intel8080FamilyHandler;
pub use operand::{expr_span, FamilyOperand, Operand};
pub use table::{lookup_instruction, ArgType, InstructionEntry, Prefix, FAMILY_INSTRUCTION_TABLE};

/// Check if an identifier is a register name for the Intel 8080 family.
///
/// This includes all registers from the 8080/8085 and Z80 CPUs:
/// - 8-bit: A, B, C, D, E, H, L (all), I, R (Z80 only)
/// - 8-bit undocumented: IXH, IXL, IYH, IYL (Z80 only)
/// - 16-bit: BC, DE, HL, SP, AF/PSW (all), IX, IY (Z80 only)
/// - Memory: M (pseudo-register for (HL))
pub fn is_register(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        // 8-bit registers (all CPUs)
        "A" | "B" | "C" | "D" | "E" | "H" | "L" |
        // 8-bit registers (Z80 only)
        "I" | "R" | "IXH" | "IXL" | "IYH" | "IYL" |
        // 16-bit register pairs (all CPUs)
        "BC" | "DE" | "HL" | "SP" |
        // Accumulator + flags (Intel: PSW, Zilog: AF)
        "AF" | "PSW" |
        // Index registers (Z80 only)
        "IX" | "IY" |
        // Memory operand via (HL)
        "M"
    )
}

/// Check if an identifier is a condition code for the Intel 8080 family.
///
/// Condition codes for conditional jumps, calls, and returns:
/// - NZ (not zero), Z (zero)
/// - NC (no carry), C (carry)
/// - PO (parity odd), PE (parity even)
/// - P (positive/plus), M (minus/sign)
pub fn is_condition(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "NZ" | "Z" | "NC" | "C" | "PO" | "PE" | "P" | "M"
    )
}

/// Check if an identifier is a Z80 index register (IX or IY).
///
/// Index registers are used with indexed addressing modes:
/// - (IX+d) or (IX-d) - Index X with displacement
/// - (IY+d) or (IY-d) - Index Y with displacement
pub fn is_index_register(name: &str) -> bool {
    matches!(name.to_ascii_uppercase().as_str(), "IX" | "IY")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_register_8bit() {
        // Common 8-bit registers
        assert!(is_register("A"));
        assert!(is_register("B"));
        assert!(is_register("C"));
        assert!(is_register("D"));
        assert!(is_register("E"));
        assert!(is_register("H"));
        assert!(is_register("L"));
        assert!(is_register("M")); // Memory via (HL)
        
        // Case insensitive
        assert!(is_register("a"));
        assert!(is_register("b"));
    }

    #[test]
    fn test_is_register_z80_8bit() {
        // Z80-only 8-bit registers
        assert!(is_register("I"));
        assert!(is_register("R"));
        assert!(is_register("IXH"));
        assert!(is_register("IXL"));
        assert!(is_register("IYH"));
        assert!(is_register("IYL"));
    }

    #[test]
    fn test_is_register_16bit() {
        // Common 16-bit register pairs
        assert!(is_register("BC"));
        assert!(is_register("DE"));
        assert!(is_register("HL"));
        assert!(is_register("SP"));
        assert!(is_register("AF"));
        assert!(is_register("PSW"));
        
        // Z80-only index registers
        assert!(is_register("IX"));
        assert!(is_register("IY"));
    }

    #[test]
    fn test_is_register_negative() {
        assert!(!is_register("X"));
        assert!(!is_register("Y"));
        assert!(!is_register("AX"));
        assert!(!is_register("MOV"));
        assert!(!is_register("LD"));
        assert!(!is_register("NZ")); // This is a condition, not a register
    }

    #[test]
    fn test_is_condition() {
        // All 8 condition codes
        assert!(is_condition("NZ"));
        assert!(is_condition("Z"));
        assert!(is_condition("NC"));
        assert!(is_condition("C"));
        assert!(is_condition("PO"));
        assert!(is_condition("PE"));
        assert!(is_condition("P"));
        assert!(is_condition("M"));
        
        // Case insensitive
        assert!(is_condition("nz"));
        assert!(is_condition("Nz"));
    }

    #[test]
    fn test_is_condition_negative() {
        assert!(!is_condition("A"));
        assert!(!is_condition("HL"));
        assert!(!is_condition("JMP"));
        assert!(!is_condition("EQ")); // Not a valid 8080 condition
        assert!(!is_condition("NE")); // Not a valid 8080 condition
    }

    #[test]
    fn test_is_index_register() {
        // Z80 index registers
        assert!(is_index_register("IX"));
        assert!(is_index_register("IY"));
        
        // Case insensitive
        assert!(is_index_register("ix"));
        assert!(is_index_register("Ix"));
        assert!(is_index_register("iy"));
    }

    #[test]
    fn test_is_index_register_negative() {
        assert!(!is_index_register("HL")); // Not an index register
        assert!(!is_index_register("BC"));
        assert!(!is_index_register("DE"));
        assert!(!is_index_register("SP"));
        assert!(!is_index_register("A"));
        assert!(!is_index_register("IXH")); // Half of IX, not IX itself
        assert!(!is_index_register("IYL"));
    }
}