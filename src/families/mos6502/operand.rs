// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Operand types for the MOS 6502 family.
//!
//! This module defines family-specific operand types that are isolated from
//! other CPU families. There is no shared `AddressMode` enum that mixes
//! 6502 modes with 8080 modes.

use crate::core::parser::Expr;
use crate::core::assembler::expression::expr_span;
use crate::core::tokenizer::Span;

/// Addressing modes for the MOS 6502 family.
///
/// This enum includes all modes supported by any CPU in the family.
/// The CPU handler validates whether a specific mode is supported by
/// the target CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressMode {
    /// No operand (NOP, RTS, BRK, etc.)
    Implied,
    /// Accumulator (ASL A, ROL A, etc.)
    Accumulator,
    /// #$nn - 8-bit immediate value
    Immediate,
    /// $nn - Zero page (8-bit address)
    ZeroPage,
    /// $nn,X - Zero page indexed by X
    ZeroPageX,
    /// $nn,Y - Zero page indexed by Y
    ZeroPageY,
    /// $nnnn - Absolute (16-bit address)
    Absolute,
    /// $nnnn,X - Absolute indexed by X
    AbsoluteX,
    /// $nnnn,Y - Absolute indexed by Y
    AbsoluteY,
    /// ($nnnn) - Indirect (JMP only on base 6502)
    Indirect,
    /// ($nn,X) - Indexed indirect (zero page)
    IndexedIndirectX,
    /// ($nn),Y - Indirect indexed (zero page)
    IndirectIndexedY,
    /// Relative branch offset (8-bit signed)
    Relative,

    // 65C02 extensions
    /// ($nn) - Zero page indirect (65C02 only)
    ZeroPageIndirect,
    /// ($nnnn,X) - Absolute indexed indirect (65C02 only, JMP)
    AbsoluteIndexedIndirect,
}

impl AddressMode {
    /// Check if this mode is a 65C02 extension.
    pub fn is_65c02_only(&self) -> bool {
        matches!(
            self,
            AddressMode::ZeroPageIndirect | AddressMode::AbsoluteIndexedIndirect
        )
    }

    /// Get the number of operand bytes for this mode.
    pub fn operand_size(&self) -> u8 {
        match self {
            AddressMode::Implied | AddressMode::Accumulator => 0,
            AddressMode::Immediate
            | AddressMode::ZeroPage
            | AddressMode::ZeroPageX
            | AddressMode::ZeroPageY
            | AddressMode::IndexedIndirectX
            | AddressMode::IndirectIndexedY
            | AddressMode::Relative
            | AddressMode::ZeroPageIndirect => 1,
            AddressMode::Absolute
            | AddressMode::AbsoluteX
            | AddressMode::AbsoluteY
            | AddressMode::Indirect
            | AddressMode::AbsoluteIndexedIndirect => 2,
        }
    }
}

/// Intermediate operand representation from family-level parsing.
///
/// These operands carry unevaluated expressions and may include ambiguous
/// cases that need CPU-level resolution.
#[derive(Clone, Debug)]
pub enum FamilyOperand {
    /// Accumulator register
    Accumulator(Span),

    /// Immediate value: #expr
    Immediate(Expr),

    /// Direct address: expr (could be ZP or Absolute)
    Direct(Expr),

    /// X-indexed: expr,X (could be ZP,X or Absolute,X)
    DirectX(Expr),

    /// Y-indexed: expr,Y (could be ZP,Y or Absolute,Y)
    DirectY(Expr),

    /// Indexed indirect: (expr,X)
    IndexedIndirectX(Expr),

    /// Indirect indexed: (expr),Y
    IndirectIndexedY(Expr),

    /// Indirect: (expr) - AMBIGUOUS
    /// Could be:
    /// - JMP indirect ($nnnn) on base 6502
    /// - Zero page indirect ($nn) on 65C02
    /// - Absolute indexed indirect ($nnnn,X) needs special handling
    Indirect(Expr),

    /// Indirect with X index: (expr,X) where expr might be 16-bit
    /// On 65C02, JMP ($nnnn,X) is valid
    IndirectX(Expr),
}

impl FamilyOperand {
    /// Get the span of this operand for error reporting.
    pub fn span(&self) -> Span {
        match self {
            FamilyOperand::Accumulator(span) => *span,
            FamilyOperand::Immediate(expr) => expr_span(expr),
            FamilyOperand::Direct(expr) => expr_span(expr),
            FamilyOperand::DirectX(expr) => expr_span(expr),
            FamilyOperand::DirectY(expr) => expr_span(expr),
            FamilyOperand::IndexedIndirectX(expr) => expr_span(expr),
            FamilyOperand::IndirectIndexedY(expr) => expr_span(expr),
            FamilyOperand::Indirect(expr) => expr_span(expr),
            FamilyOperand::IndirectX(expr) => expr_span(expr),
        }
    }
}

/// Final operand representation with resolved addressing mode and value.
#[derive(Clone, Debug)]
pub enum Operand {
    /// No operand (implied mode)
    Implied,

    /// Accumulator
    Accumulator(Span),

    /// Immediate 8-bit value
    Immediate(u8, Span),

    /// Zero page address
    ZeroPage(u8, Span),

    /// Zero page,X
    ZeroPageX(u8, Span),

    /// Zero page,Y
    ZeroPageY(u8, Span),

    /// Absolute 16-bit address
    Absolute(u16, Span),

    /// Absolute,X
    AbsoluteX(u16, Span),

    /// Absolute,Y
    AbsoluteY(u16, Span),

    /// JMP indirect ($nnnn)
    Indirect(u16, Span),

    /// Indexed indirect ($nn,X)
    IndexedIndirectX(u8, Span),

    /// Indirect indexed ($nn),Y
    IndirectIndexedY(u8, Span),

    /// Relative branch (signed offset)
    Relative(i8, Span),

    // 65C02 extensions
    /// Zero page indirect ($nn) - 65C02
    ZeroPageIndirect(u8, Span),

    /// Absolute indexed indirect ($nnnn,X) - 65C02
    AbsoluteIndexedIndirect(u16, Span),
}

impl Operand {
    /// Get the addressing mode for this operand.
    pub fn mode(&self) -> AddressMode {
        match self {
            Operand::Implied => AddressMode::Implied,
            Operand::Accumulator(_) => AddressMode::Accumulator,
            Operand::Immediate(_, _) => AddressMode::Immediate,
            Operand::ZeroPage(_, _) => AddressMode::ZeroPage,
            Operand::ZeroPageX(_, _) => AddressMode::ZeroPageX,
            Operand::ZeroPageY(_, _) => AddressMode::ZeroPageY,
            Operand::Absolute(_, _) => AddressMode::Absolute,
            Operand::AbsoluteX(_, _) => AddressMode::AbsoluteX,
            Operand::AbsoluteY(_, _) => AddressMode::AbsoluteY,
            Operand::Indirect(_, _) => AddressMode::Indirect,
            Operand::IndexedIndirectX(_, _) => AddressMode::IndexedIndirectX,
            Operand::IndirectIndexedY(_, _) => AddressMode::IndirectIndexedY,
            Operand::Relative(_, _) => AddressMode::Relative,
            Operand::ZeroPageIndirect(_, _) => AddressMode::ZeroPageIndirect,
            Operand::AbsoluteIndexedIndirect(_, _) => AddressMode::AbsoluteIndexedIndirect,
        }
    }

    /// Get the span of this operand for error reporting.
    pub fn span(&self) -> Span {
        match self {
            Operand::Implied => Span::default(),
            Operand::Accumulator(span) => *span,
            Operand::Immediate(_, span) => *span,
            Operand::ZeroPage(_, span) => *span,
            Operand::ZeroPageX(_, span) => *span,
            Operand::ZeroPageY(_, span) => *span,
            Operand::Absolute(_, span) => *span,
            Operand::AbsoluteX(_, span) => *span,
            Operand::AbsoluteY(_, span) => *span,
            Operand::Indirect(_, span) => *span,
            Operand::IndexedIndirectX(_, span) => *span,
            Operand::IndirectIndexedY(_, span) => *span,
            Operand::Relative(_, span) => *span,
            Operand::ZeroPageIndirect(_, span) => *span,
            Operand::AbsoluteIndexedIndirect(_, span) => *span,
        }
    }

    /// Get the value bytes for this operand (for encoding).
    pub fn value_bytes(&self) -> Vec<u8> {
        match self {
            Operand::Implied | Operand::Accumulator(_) => vec![],
            Operand::Immediate(v, _)
            | Operand::ZeroPage(v, _)
            | Operand::ZeroPageX(v, _)
            | Operand::ZeroPageY(v, _)
            | Operand::IndexedIndirectX(v, _)
            | Operand::IndirectIndexedY(v, _)
            | Operand::ZeroPageIndirect(v, _) => vec![*v],
            Operand::Relative(v, _) => vec![*v as u8],
            Operand::Absolute(v, _)
            | Operand::AbsoluteX(v, _)
            | Operand::AbsoluteY(v, _)
            | Operand::Indirect(v, _)
            | Operand::AbsoluteIndexedIndirect(v, _) => {
                vec![(*v & 0xFF) as u8, (*v >> 8) as u8]
            }
        }
    }
}
