// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! CPU abstraction for multi-processor support.
//!
//! This module provides traits and types for switching between different
//! target CPUs (8085, Z80, and potentially 6502, 68000) at assembly time.
//!
//! The [`CpuFamily`] enum groups related CPUs that share common characteristics,
//! enabling family-level instruction handling (e.g., RST for Intel 8080 family).

use crate::core::tokenizer::Span;

/// Syntax dialect for mnemonic variations within a CPU family.
///
/// Some CPU families have members that use different mnemonics for the same
/// underlying opcodes. For example, the Intel 8080 family has:
/// - **Intel dialect** (8080, 8085): `MOV`, `MVI`, `JMP`, `JZ`, etc.
/// - **Zilog dialect** (Z80): `LD`, `JP`, `JR`, etc.
///
/// Both dialects produce identical machine code for shared instructions,
/// but the assembly source syntax is different.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxDialect {
    /// Intel 8080/8085 mnemonics: MOV, MVI, LDA, STA, JMP, JZ, ADI, etc.
    Intel8080,
    /// Zilog Z80 mnemonics: LD, JP, JR, ADD A,r, etc.
    Zilog,
    /// No dialect mapping — mnemonics pass through unchanged.
    /// Used when all family members share the same mnemonic set (e.g., MOS 6502).
    Transparent,
}

impl SyntaxDialect {
    /// Returns true if this dialect requires mnemonic mapping.
    pub fn requires_mapping(&self) -> bool {
        !matches!(self, SyntaxDialect::Transparent)
    }

    /// Display name for the dialect.
    pub fn name(&self) -> &'static str {
        match self {
            SyntaxDialect::Intel8080 => "Intel 8080",
            SyntaxDialect::Zilog => "Zilog Z80",
            SyntaxDialect::Transparent => "Transparent",
        }
    }
}

/// CPU family groupings for shared behavior.
///
/// CPUs within the same family share certain characteristics like instruction
/// formats, register models, or special instructions that can be handled
/// generically by the assembler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuFamily {
    /// Intel 8080 family: 8080, 8085, Z80, Z180, etc.
    /// Shares RST 0-7 instructions, similar register model (A, B, C, D, E, H, L).
    Intel8080,
    /// MOS 6502 family: 6502, 65C02, 65816.
    /// 8-bit accumulator, X/Y index registers, unique addressing modes.
    MOS6502,
}

impl CpuFamily {
    /// Does this CPU family have RST 0-7 restart instructions?
    pub fn has_rst(&self) -> bool {
        matches!(self, CpuFamily::Intel8080)
    }

    /// Does this CPU family use condition code operands (NZ, Z, NC, C, etc.)?
    pub fn has_condition_operands(&self) -> bool {
        matches!(self, CpuFamily::Intel8080)
    }

    /// Primary register width in bits.
    pub fn register_width(&self) -> u8 {
        match self {
            CpuFamily::Intel8080 => 8,
            CpuFamily::MOS6502 => 8,
        }
    }

    /// Primary address width in bits.
    pub fn address_width(&self) -> u8 {
        match self {
            CpuFamily::Intel8080 => 16,
            CpuFamily::MOS6502 => 16,
        }
    }
}

/// Supported CPU types.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CpuType {
    /// Intel 8085 (default)
    #[default]
    I8085,
    /// Zilog Z80
    Z80,
    /// MOS 6502
    M6502,
    /// WDC 65C02
    M65C02,
}

impl CpuType {
    /// Parse a CPU type from a string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        let upper = s.to_ascii_uppercase();
        match upper.as_str() {
            "8085" | "I8085" | "8080" | "I8080" => Some(CpuType::I8085),
            "Z80" | "ZILOG" => Some(CpuType::Z80),
            "6502" | "M6502" | "MOS6502" => Some(CpuType::M6502),
            "65C02" | "M65C02" | "W65C02" | "WDC65C02" => Some(CpuType::M65C02),
            _ => None,
        }
    }

    /// Get the display name for this CPU.
    pub fn name(&self) -> &'static str {
        match self {
            CpuType::I8085 => "8085",
            CpuType::Z80 => "Z80",
            CpuType::M6502 => "6502",
            CpuType::M65C02 => "65C02",
        }
    }

    /// Get the CPU family for this CPU type.
    pub fn family(&self) -> CpuFamily {
        match self {
            CpuType::I8085 | CpuType::Z80 => CpuFamily::Intel8080,
            CpuType::M6502 | CpuType::M65C02 => CpuFamily::MOS6502,
        }
    }

    /// Get the syntax dialect for this CPU type.
    ///
    /// The dialect determines which mnemonic set is used for assembly.
    /// For example, Z80 uses Zilog mnemonics (LD, JP) while 8085 uses
    /// Intel mnemonics (MOV, JMP).
    pub fn dialect(&self) -> SyntaxDialect {
        match self {
            CpuType::I8085 => SyntaxDialect::Intel8080,
            CpuType::Z80 => SyntaxDialect::Zilog,
            CpuType::M6502 | CpuType::M65C02 => SyntaxDialect::Transparent,
        }
    }

    /// Get the `is_register` function for this CPU type.
    pub fn is_register_fn(&self) -> fn(&str) -> bool {
        match self {
            CpuType::I8085 => crate::i8085::is_register,
            CpuType::Z80 => crate::z80::is_register,
            CpuType::M6502 | CpuType::M65C02 => crate::families::mos6502::is_register,
        }
    }
}

/// Argument type for instruction encoding (shared between CPUs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgType {
    /// No immediate argument
    None,
    /// 8-bit immediate value
    Byte,
    /// 16-bit immediate value
    Word,
}

/// A generic instruction entry (for 8085-style single-byte opcodes).
pub struct InstructionEntry {
    pub mnemonic: &'static str,
    pub reg1: &'static str,
    pub reg2: &'static str,
    pub num_regs: u8,
    pub opcode: u8,
    pub arg_type: ArgType,
}

/// Error returned by operand parsing.
#[derive(Debug, Clone)]
pub struct OperandParseError {
    pub message: String,
    pub span: Span,
}

/// Error returned by instruction encoding.
#[derive(Debug, Clone)]
pub struct EncodeError {
    pub message: String,
    pub span: Option<Span>,
}

impl EncodeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
        }
    }

    pub fn with_span(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span: Some(span),
        }
    }

    pub fn with_span_opt(message: impl Into<String>, span: Option<Span>) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_type_parsing() {
        assert_eq!(CpuType::parse("8085"), Some(CpuType::I8085));
        assert_eq!(CpuType::parse("i8085"), Some(CpuType::I8085));
        assert_eq!(CpuType::parse("z80"), Some(CpuType::Z80));
        assert_eq!(CpuType::parse("Z80"), Some(CpuType::Z80));
        assert_eq!(CpuType::parse("6502"), Some(CpuType::M6502));
        assert_eq!(CpuType::parse("65c02"), Some(CpuType::M65C02));
        assert_eq!(CpuType::parse("unknown"), None);
    }

    #[test]
    fn cpu_family_assignment() {
        assert_eq!(CpuType::I8085.family(), CpuFamily::Intel8080);
        assert_eq!(CpuType::Z80.family(), CpuFamily::Intel8080);
        assert_eq!(CpuType::M6502.family(), CpuFamily::MOS6502);
        assert_eq!(CpuType::M65C02.family(), CpuFamily::MOS6502);
    }

    #[test]
    fn cpu_family_has_rst() {
        assert!(CpuFamily::Intel8080.has_rst());
        assert!(CpuType::I8085.family().has_rst());
        assert!(CpuType::Z80.family().has_rst());
        // 6502 does NOT have RST
        assert!(!CpuFamily::MOS6502.has_rst());
        assert!(!CpuType::M6502.family().has_rst());
    }

    #[test]
    fn cpu_family_properties() {
        // Intel 8080 family
        assert_eq!(CpuFamily::Intel8080.register_width(), 8);
        assert_eq!(CpuFamily::Intel8080.address_width(), 16);
        assert!(CpuFamily::Intel8080.has_condition_operands());

        // MOS 6502 family
        assert_eq!(CpuFamily::MOS6502.register_width(), 8);
        assert_eq!(CpuFamily::MOS6502.address_width(), 16);
        assert!(!CpuFamily::MOS6502.has_condition_operands());
    }

    #[test]
    fn cpu_dialect_selection() {
        // Intel 8080 family uses different dialects
        assert_eq!(CpuType::I8085.dialect(), SyntaxDialect::Intel8080);
        assert_eq!(CpuType::Z80.dialect(), SyntaxDialect::Zilog);

        // MOS 6502 family uses transparent dialect
        assert_eq!(CpuType::M6502.dialect(), SyntaxDialect::Transparent);
        assert_eq!(CpuType::M65C02.dialect(), SyntaxDialect::Transparent);
    }

    #[test]
    fn dialect_properties() {
        assert!(SyntaxDialect::Intel8080.requires_mapping());
        assert!(SyntaxDialect::Zilog.requires_mapping());
        assert!(!SyntaxDialect::Transparent.requires_mapping());

        assert_eq!(SyntaxDialect::Intel8080.name(), "Intel 8080");
        assert_eq!(SyntaxDialect::Zilog.name(), "Zilog Z80");
        assert_eq!(SyntaxDialect::Transparent.name(), "Transparent");
    }
}

