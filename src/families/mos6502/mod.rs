// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! MOS 6502 CPU family handler.
//!
//! This module provides family-level parsing and encoding for all CPUs in
//! the MOS 6502 family (6502, 65C02, 65816).
//!
//! # Family Characteristics
//!
//! - 8-bit data bus, 16-bit address bus
//! - Registers: A (accumulator), X, Y (index)
//! - Unique addressing modes with parentheses for indirect
//!
//! # Addressing Modes (Family Common)
//!
//! | Syntax | Mode |
//! |--------|------|
//! | `#$20` | Immediate |
//! | `$20` | Zero Page |
//! | `$20,X` | Zero Page,X |
//! | `$20,Y` | Zero Page,Y |
//! | `$1234` | Absolute |
//! | `$1234,X` | Absolute,X |
//! | `$1234,Y` | Absolute,Y |
//! | `($20,X)` | Indexed Indirect |
//! | `($20),Y` | Indirect Indexed |
//!
//! # CPU Extensions
//!
//! Some addressing modes are CPU-specific:
//! - `($20)` - Zero Page Indirect (65C02 only)
//! - `($1234,X)` - Absolute Indexed Indirect (65C02 only)

mod cpu_handler;
mod handler;
pub mod module;
mod operand;
mod table;

pub use cpu_handler::M6502CpuHandler;
pub use handler::MOS6502FamilyHandler;
pub use operand::{AddressMode, FamilyOperand, Operand, OperandForce};
pub use table::{has_mnemonic, lookup_instruction, FAMILY_INSTRUCTION_TABLE};

/// Check if an identifier is a register for the MOS 6502 family.
pub fn is_register(name: &str) -> bool {
    matches!(name, "A" | "X" | "Y")
}
