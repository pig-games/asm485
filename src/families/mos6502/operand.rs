// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Operand types for the MOS 6502 family.
//!
//! This module defines family-specific operand types that are isolated from
//! other CPU families. There is no shared `AddressMode` enum that mixes
//! 6502 modes with 8080 modes.

use crate::core::assembler::expression::expr_span;
use crate::core::parser::Expr;
use crate::core::tokenizer::Span;

/// Per-operand addressing override hint for 65816 ambiguous forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandForce {
    /// Force direct-page addressing selection (`...,d`).
    DirectPage,
    /// Force 16-bit absolute/data-bank addressing selection (`...,b`).
    DataBank,
    /// Force program-bank (code-bank) 16-bit addressing selection (`...,k`).
    ProgramBank,
    /// Force long (24-bit) addressing selection (`...,l`).
    Long,
}

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
    /// Relative long branch offset (16-bit signed, 65816)
    RelativeLong,

    // 45GS02 extensions
    /// (zp),Z - Base-page indirect indexed by Z (45GS02)
    IndirectIndexedZ,

    // 65C02 extensions
    /// ($nn) - Zero page indirect (65C02 only)
    ZeroPageIndirect,
    /// ($nnnn,X) - Absolute indexed indirect (65C02 only, JMP)
    AbsoluteIndexedIndirect,

    // 65816 extensions
    /// d,S - Stack-relative (8-bit offset)
    StackRelative,
    /// (d,S),Y - Stack-relative indirect indexed by Y
    StackRelativeIndirectIndexedY,
    /// $llhhhh - 24-bit absolute long
    AbsoluteLong,
    /// $llhhhh,X - 24-bit absolute long indexed by X
    AbsoluteLongX,
    /// [$nn] - absolute indirect long (JML)
    IndirectLong,
    /// [$nn],Y - direct-page indirect long indexed by Y
    DirectPageIndirectLongY,
    /// [$nn] - direct-page indirect long
    DirectPageIndirectLong,
    /// [$nn],Z - direct-page indirect long indexed by Z (45GS02 sugar)
    DirectPageIndirectLongZ,
    /// src,dst block move operands for MVN/MVP
    BlockMove,
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
            | AddressMode::ZeroPageIndirect
            | AddressMode::StackRelative
            | AddressMode::StackRelativeIndirectIndexedY
            | AddressMode::DirectPageIndirectLongY
            | AddressMode::DirectPageIndirectLong
            | AddressMode::IndirectIndexedZ
            | AddressMode::DirectPageIndirectLongZ => 1,
            AddressMode::Absolute
            | AddressMode::AbsoluteX
            | AddressMode::AbsoluteY
            | AddressMode::Indirect
            | AddressMode::AbsoluteIndexedIndirect
            | AddressMode::RelativeLong
            | AddressMode::IndirectLong
            | AddressMode::BlockMove => 2,
            AddressMode::AbsoluteLong | AddressMode::AbsoluteLongX => 3,
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

    /// Indirect indexed: (expr),Z (45GS02)
    IndirectIndexedZ(Expr),

    /// Indirect: (expr) - AMBIGUOUS
    /// Could be:
    /// - JMP indirect ($nnnn) on base 6502
    /// - Zero page indirect ($nn) on 65C02
    /// - Absolute indexed indirect ($nnnn,X) needs special handling
    Indirect(Expr),

    /// Indirect with X index: (expr,X) where expr might be 16-bit
    /// On 65C02, JMP ($nnnn,X) is valid
    IndirectX(Expr),

    /// Bracketed long-indirect: [expr]
    IndirectLong(Expr),

    /// Bracketed long-indirect indexed by Y: [expr],Y
    IndirectLongY(Expr),

    /// Bracketed long-indirect indexed by Z: [expr],Z (45GS02 sugar)
    IndirectLongZ(Expr),

    /// Stack-relative: expr,S
    StackRelative(Expr),

    /// Stack-relative indirect indexed: (expr,S),Y
    StackRelativeIndirectIndexedY(Expr),

    /// Block-move source/destination bank operands: src,dst
    BlockMove { src: Expr, dst: Expr, span: Span },

    /// Per-operand addressing override wrapper (65816 explicit control).
    Forced {
        inner: Box<FamilyOperand>,
        force: OperandForce,
        span: Span,
    },
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
            FamilyOperand::IndirectIndexedZ(expr) => expr_span(expr),
            FamilyOperand::Indirect(expr) => expr_span(expr),
            FamilyOperand::IndirectX(expr) => expr_span(expr),
            FamilyOperand::IndirectLong(expr) => expr_span(expr),
            FamilyOperand::IndirectLongY(expr) => expr_span(expr),
            FamilyOperand::IndirectLongZ(expr) => expr_span(expr),
            FamilyOperand::StackRelative(expr) => expr_span(expr),
            FamilyOperand::StackRelativeIndirectIndexedY(expr) => expr_span(expr),
            FamilyOperand::BlockMove { span, .. } => *span,
            FamilyOperand::Forced { span, .. } => *span,
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
    /// Immediate 16-bit value (65816 width-sensitive immediate)
    ImmediateWord(u16, Span),

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

    /// Indirect indexed ($nn),Z (45GS02)
    IndirectIndexedZ(u8, Span),

    /// Relative branch (signed offset)
    Relative(i8, Span),
    /// Relative long branch (signed 16-bit offset)
    RelativeLong(i16, Span),

    // 65C02 extensions
    /// Zero page indirect ($nn) - 65C02
    ZeroPageIndirect(u8, Span),

    /// Absolute indexed indirect ($nnnn,X) - 65C02
    AbsoluteIndexedIndirect(u16, Span),

    // 65816 extensions
    /// Stack-relative d,S
    StackRelative(u8, Span),
    /// Stack-relative indirect indexed (d,S),Y
    StackRelativeIndirectIndexedY(u8, Span),
    /// 24-bit absolute long
    AbsoluteLong(u32, Span),
    /// 24-bit absolute long indexed by X
    AbsoluteLongX(u32, Span),
    /// Bracketed absolute indirect long [$nnnn]
    IndirectLong(u16, Span),
    /// Direct page indirect long [$nn]
    DirectPageIndirectLong(u8, Span),
    /// Direct page indirect long indexed [$nn],Y
    DirectPageIndirectLongY(u8, Span),
    /// Direct page indirect long indexed [$nn],Z
    DirectPageIndirectLongZ(u8, Span),
    /// Block move operands for MVN/MVP
    BlockMove { src: u8, dst: u8, span: Span },
}

impl Operand {
    /// Get the addressing mode for this operand.
    pub fn mode(&self) -> AddressMode {
        match self {
            Operand::Implied => AddressMode::Implied,
            Operand::Accumulator(_) => AddressMode::Accumulator,
            Operand::Immediate(_, _) => AddressMode::Immediate,
            Operand::ImmediateWord(_, _) => AddressMode::Immediate,
            Operand::ZeroPage(_, _) => AddressMode::ZeroPage,
            Operand::ZeroPageX(_, _) => AddressMode::ZeroPageX,
            Operand::ZeroPageY(_, _) => AddressMode::ZeroPageY,
            Operand::Absolute(_, _) => AddressMode::Absolute,
            Operand::AbsoluteX(_, _) => AddressMode::AbsoluteX,
            Operand::AbsoluteY(_, _) => AddressMode::AbsoluteY,
            Operand::Indirect(_, _) => AddressMode::Indirect,
            Operand::IndexedIndirectX(_, _) => AddressMode::IndexedIndirectX,
            Operand::IndirectIndexedY(_, _) => AddressMode::IndirectIndexedY,
            Operand::IndirectIndexedZ(_, _) => AddressMode::IndirectIndexedZ,
            Operand::Relative(_, _) => AddressMode::Relative,
            Operand::RelativeLong(_, _) => AddressMode::RelativeLong,
            Operand::ZeroPageIndirect(_, _) => AddressMode::ZeroPageIndirect,
            Operand::AbsoluteIndexedIndirect(_, _) => AddressMode::AbsoluteIndexedIndirect,
            Operand::StackRelative(_, _) => AddressMode::StackRelative,
            Operand::StackRelativeIndirectIndexedY(_, _) => {
                AddressMode::StackRelativeIndirectIndexedY
            }
            Operand::AbsoluteLong(_, _) => AddressMode::AbsoluteLong,
            Operand::AbsoluteLongX(_, _) => AddressMode::AbsoluteLongX,
            Operand::IndirectLong(_, _) => AddressMode::IndirectLong,
            Operand::DirectPageIndirectLong(_, _) => AddressMode::DirectPageIndirectLong,
            Operand::DirectPageIndirectLongY(_, _) => AddressMode::DirectPageIndirectLongY,
            Operand::DirectPageIndirectLongZ(_, _) => AddressMode::DirectPageIndirectLongZ,
            Operand::BlockMove { .. } => AddressMode::BlockMove,
        }
    }

    /// Get the span of this operand for error reporting.
    pub fn span(&self) -> Span {
        match self {
            Operand::Implied => Span::default(),
            Operand::Accumulator(span) => *span,
            Operand::Immediate(_, span) => *span,
            Operand::ImmediateWord(_, span) => *span,
            Operand::ZeroPage(_, span) => *span,
            Operand::ZeroPageX(_, span) => *span,
            Operand::ZeroPageY(_, span) => *span,
            Operand::Absolute(_, span) => *span,
            Operand::AbsoluteX(_, span) => *span,
            Operand::AbsoluteY(_, span) => *span,
            Operand::Indirect(_, span) => *span,
            Operand::IndexedIndirectX(_, span) => *span,
            Operand::IndirectIndexedY(_, span) => *span,
            Operand::IndirectIndexedZ(_, span) => *span,
            Operand::Relative(_, span) => *span,
            Operand::RelativeLong(_, span) => *span,
            Operand::ZeroPageIndirect(_, span) => *span,
            Operand::AbsoluteIndexedIndirect(_, span) => *span,
            Operand::StackRelative(_, span) => *span,
            Operand::StackRelativeIndirectIndexedY(_, span) => *span,
            Operand::AbsoluteLong(_, span) => *span,
            Operand::AbsoluteLongX(_, span) => *span,
            Operand::IndirectLong(_, span) => *span,
            Operand::DirectPageIndirectLong(_, span) => *span,
            Operand::DirectPageIndirectLongY(_, span) => *span,
            Operand::DirectPageIndirectLongZ(_, span) => *span,
            Operand::BlockMove { span, .. } => *span,
        }
    }

    /// Get the value bytes for this operand (for encoding).
    pub fn value_bytes(&self) -> Vec<u8> {
        match self {
            Operand::Implied | Operand::Accumulator(_) => vec![],
            Operand::Immediate(v, _) => vec![*v],
            Operand::ImmediateWord(v, _) => vec![(*v & 0xFF) as u8, (*v >> 8) as u8],
            Operand::ZeroPage(v, _)
            | Operand::ZeroPageX(v, _)
            | Operand::ZeroPageY(v, _)
            | Operand::IndexedIndirectX(v, _)
            | Operand::IndirectIndexedY(v, _)
            | Operand::IndirectIndexedZ(v, _)
            | Operand::ZeroPageIndirect(v, _)
            | Operand::StackRelative(v, _)
            | Operand::StackRelativeIndirectIndexedY(v, _)
            | Operand::DirectPageIndirectLong(v, _)
            | Operand::DirectPageIndirectLongY(v, _)
            | Operand::DirectPageIndirectLongZ(v, _) => vec![*v],
            Operand::Relative(v, _) => vec![*v as u8],
            Operand::RelativeLong(v, _) => vec![(*v & 0xFF) as u8, ((*v >> 8) & 0xFF) as u8],
            Operand::Absolute(v, _)
            | Operand::AbsoluteX(v, _)
            | Operand::AbsoluteY(v, _)
            | Operand::Indirect(v, _)
            | Operand::AbsoluteIndexedIndirect(v, _) => {
                vec![(*v & 0xFF) as u8, (*v >> 8) as u8]
            }
            Operand::AbsoluteLong(v, _) | Operand::AbsoluteLongX(v, _) => {
                vec![
                    (*v & 0xFF) as u8,
                    ((*v >> 8) & 0xFF) as u8,
                    ((*v >> 16) & 0xFF) as u8,
                ]
            }
            Operand::IndirectLong(v, _) => vec![(*v & 0xFF) as u8, (*v >> 8) as u8],
            Operand::BlockMove { src, dst, .. } => vec![*src, *dst],
        }
    }
}
