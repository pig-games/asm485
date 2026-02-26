// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8085 CPU support module.
//!
//! This module provides 8085-specific functionality:
//! - Register definitions
//! - CPU handler for instruction encoding
//! - Extension table (8085-only instructions: RIM, SIM)

pub mod extensions;
pub mod formatter;
pub mod handler;
pub mod module;

pub use extensions::{lookup_extension, I8085_EXTENSION_TABLE};
pub use handler::I8085CpuHandler;

/// Check if an identifier is an 8085 register name.
///
/// Valid registers: A, B, C, D, E, H, L, M, SP, PSW
pub fn is_register(ident: &str) -> bool {
    matches!(
        ident,
        "A" | "B" | "C" | "D" | "E" | "H" | "L" | "M" | "SP" | "PSW"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_8085_registers() {
        assert!(is_register("A"));
        assert!(is_register("B"));
        assert!(is_register("SP"));
        assert!(is_register("PSW"));
        assert!(!is_register("X"));
        assert!(!is_register("AX"));
        assert!(!is_register("MOV"));
    }
}
