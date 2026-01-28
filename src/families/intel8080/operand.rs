// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Operand types for the Intel 8080 family.

use crate::core::parser::Expr;
use crate::core::tokenizer::Span;
pub use crate::core::assembler::expression::expr_span;

/// Intermediate operand representation from family-level parsing.
///
/// These operands carry unevaluated expressions and may include cases
/// that need CPU-level resolution (e.g., Z80 indexed addressing).
#[derive(Clone, Debug)]
pub enum FamilyOperand {
    /// Register: A, B, C, D, E, H, L, M, SP, PSW, BC, DE, HL, AF
    Register(String, Span),

    /// Indirect via register pair: (BC), (DE), (HL)
    Indirect(String, Span),

    /// Condition code: NZ, Z, NC, C, PO, PE, P, M
    Condition(String, Span),

    /// Immediate value or address (determined by instruction)
    Immediate(Expr),

    /// Indexed addressing (Z80): needs CPU resolution
    /// Base register and offset expression
    Indexed {
        base: String,
        offset: Expr,
        span: Span,
    },

    /// RST vector number (0-7)
    RstVector(Expr),

    /// Interrupt mode (Z80 IM instruction)
    InterruptMode(Expr),

    /// Bit number (Z80 BIT/SET/RES)
    BitNumber(Expr),

    /// Port number for I/O
    Port(Expr),
}

impl FamilyOperand {
    /// Get the span of this operand for error reporting.
    pub fn span(&self) -> Span {
        match self {
            FamilyOperand::Register(_, span) => *span,
            FamilyOperand::Indirect(_, span) => *span,
            FamilyOperand::Condition(_, span) => *span,
            FamilyOperand::Immediate(expr) => expr_span(expr),
            FamilyOperand::Indexed { span, .. } => *span,
            FamilyOperand::RstVector(expr) => expr_span(expr),
            FamilyOperand::InterruptMode(expr) => expr_span(expr),
            FamilyOperand::BitNumber(expr) => expr_span(expr),
            FamilyOperand::Port(expr) => expr_span(expr),
        }
    }
}

/// Final operand representation with resolved values.
#[derive(Clone, Debug)]
pub enum Operand {
    /// Register
    Register(String, Span),

    /// Indirect via register pair
    Indirect(String, Span),

    /// Condition code
    Condition(String, Span),

    /// 8-bit immediate value
    Immediate8(u8, Span),

    /// 16-bit immediate value or address
    Immediate16(u16, Span),

    /// Indexed addressing (Z80): (IX+d), (IY+d)
    Indexed {
        base: String,
        offset: i8,
        span: Span,
    },

    /// RST vector (0-7)
    RstVector(u8, Span),

    /// Interrupt mode (0, 1, 2)
    InterruptMode(u8, Span),

    /// Bit number (0-7)
    BitNumber(u8, Span),

    /// Port number
    Port(u8, Span),
}

impl Operand {
    /// Get the span of this operand for error reporting.
    pub fn span(&self) -> Span {
        match self {
            Operand::Register(_, span) => *span,
            Operand::Indirect(_, span) => *span,
            Operand::Condition(_, span) => *span,
            Operand::Immediate8(_, span) => *span,
            Operand::Immediate16(_, span) => *span,
            Operand::Indexed { span, .. } => *span,
            Operand::RstVector(_, span) => *span,
            Operand::InterruptMode(_, span) => *span,
            Operand::BitNumber(_, span) => *span,
            Operand::Port(_, span) => *span,
        }
    }

    /// Check if this is a register with the given name.
    pub fn is_register(&self, name: &str) -> bool {
        matches!(self, Operand::Register(n, _) if n.eq_ignore_ascii_case(name))
    }

    /// Check if this is an indirect with the given register.
    pub fn is_indirect(&self, name: &str) -> bool {
        matches!(self, Operand::Indirect(n, _) if n.eq_ignore_ascii_case(name))
    }

    /// Check if this is a condition with the given name.
    pub fn is_condition(&self, name: &str) -> bool {
        matches!(self, Operand::Condition(n, _) if n.eq_ignore_ascii_case(name))
    }

    /// Get the register name if this is a Register operand.
    pub fn as_register(&self) -> Option<&str> {
        match self {
            Operand::Register(name, _) => Some(name),
            _ => None,
        }
    }
}

