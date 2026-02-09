// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! CPU-agnostic operand representation.
//!
//! This module defines the `Operand` enum which represents instruction operands
//! in a CPU-neutral way. Different CPUs parse their source syntax into these
//! common operand types, which are then encoded by CPU-specific instruction tables.

use crate::core::parser::Expr;
use crate::core::tokenizer::Span;

/// Represents an instruction operand in a CPU-neutral form.
///
/// Different CPUs have different addressing modes and syntax, but most can be
/// mapped to these common operand types. The CPU-specific syntax parser is
/// responsible for converting source text into the appropriate `Operand` variant.
#[derive(Debug, Clone)]
pub enum Operand {
    /// Simple register reference: A, B, HL, IX, D0, X, etc.
    Register(String, Span),

    /// Memory access via register indirect: (HL), (BC), (A0), etc.
    /// The register name is stored without parentheses.
    Indirect(String, Span),

    /// Indexed addressing with offset: (IX+5), (IY-3), 5(A0), etc.
    /// Base register and offset expression.
    Indexed {
        base: String,
        offset: Expr,
        span: Span,
    },

    /// Condition code for conditional instructions: NZ, Z, NC, C, PO, PE, P, M
    Condition(String, Span),

    /// Immediate value (expression that evaluates to a constant).
    /// Used for `#$20` (6502), `5` after a register (Z80 `LD A, 5`), etc.
    Immediate(Expr),

    /// Absolute/direct address (expression that evaluates to an address).
    /// Used for `JMP $1234`, `LD A, (1234h)`, etc.
    Absolute(Expr),
}

impl Operand {
    /// Get the span of this operand for error reporting.
    pub fn span(&self) -> Span {
        match self {
            Operand::Register(_, span) => *span,
            Operand::Indirect(_, span) => *span,
            Operand::Indexed { span, .. } => *span,
            Operand::Condition(_, span) => *span,
            Operand::Immediate(expr) => expr_span(expr),
            Operand::Absolute(expr) => expr_span(expr),
        }
    }

    /// Check if this operand is a register with the given name (case-insensitive).
    pub fn is_register(&self, name: &str) -> bool {
        matches!(self, Operand::Register(n, _) if n.eq_ignore_ascii_case(name))
    }

    /// Check if this operand is an indirect reference to the given register.
    pub fn is_indirect(&self, name: &str) -> bool {
        matches!(self, Operand::Indirect(n, _) if n.eq_ignore_ascii_case(name))
    }

    /// Check if this operand is a condition code with the given name.
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

    /// Get the register name if this is an Indirect operand.
    pub fn as_indirect(&self) -> Option<&str> {
        match self {
            Operand::Indirect(name, _) => Some(name),
            _ => None,
        }
    }

    /// Get the condition code name if this is a Condition operand.
    pub fn as_condition(&self) -> Option<&str> {
        match self {
            Operand::Condition(name, _) => Some(name),
            _ => None,
        }
    }
}

/// Helper to extract span from an Expr.
fn expr_span(expr: &Expr) -> Span {
    match expr {
        Expr::Number(_, span) => *span,
        Expr::Identifier(_, span) => *span,
        Expr::Register(_, span) => *span,
        Expr::Indirect(_, span) => *span,
        Expr::IndirectLong(_, span) => *span,
        Expr::Immediate(_, span) => *span,
        Expr::Tuple(_, span) => *span,
        Expr::Dollar(span) => *span,
        Expr::String(_, span) => *span,
        Expr::Error(_, span) => *span,
        Expr::Ternary { span, .. } => *span,
        Expr::Unary { span, .. } => *span,
        Expr::Binary { span, .. } => *span,
    }
}

/// Size suffix for instructions (68000 family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SizeSuffix {
    Byte,
    Word,
    Long,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_span() -> Span {
        Span {
            line: 1,
            col_start: 1,
            col_end: 1,
        }
    }

    #[test]
    fn register_matching() {
        let op = Operand::Register("HL".to_string(), dummy_span());
        assert!(op.is_register("HL"));
        assert!(op.is_register("hl"));
        assert!(!op.is_register("BC"));
    }

    #[test]
    fn indirect_matching() {
        let op = Operand::Indirect("HL".to_string(), dummy_span());
        assert!(op.is_indirect("HL"));
        assert!(op.is_indirect("hl"));
        assert!(!op.is_register("HL")); // Not a register, it's indirect
    }

    #[test]
    fn condition_matching() {
        let op = Operand::Condition("NZ".to_string(), dummy_span());
        assert!(op.is_condition("NZ"));
        assert!(op.is_condition("nz"));
        assert!(!op.is_register("NZ"));
    }
}
