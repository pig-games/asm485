// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Operand types for the Motorola 6800 family baseline (6809 + HD6309).

use crate::core::assembler::expression::expr_span;
use crate::core::parser::Expr;
use crate::core::tokenizer::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressMode {
    Inherent,
    Immediate8,
    Immediate16,
    Direct,
    Extended,
    Indexed,
    Relative8,
    Relative16,
    RegisterPair,
    RegisterList,
}

#[derive(Clone, Debug)]
pub enum FamilyOperand {
    Register(String, Span),
    RegisterList(Vec<(String, Span)>, Span),
    Indexed {
        offset: Expr,
        base: String,
        span: Span,
    },
    IndexedIndirect {
        offset: Expr,
        base: Option<String>,
        span: Span,
    },
    IndexedRegisterOffset {
        offset: String,
        base: String,
        span: Span,
    },
    IndexedIndirectRegisterOffset {
        offset: String,
        base: String,
        span: Span,
    },
    Immediate(Expr),
    Direct(Expr),
}

impl FamilyOperand {
    pub fn span(&self) -> Span {
        match self {
            Self::Register(_, span) => *span,
            Self::RegisterList(_, span)
            | Self::Indexed { span, .. }
            | Self::IndexedIndirect { span, .. }
            | Self::IndexedRegisterOffset { span, .. } => *span,
            Self::IndexedIndirectRegisterOffset { span, .. } => *span,
            Self::Immediate(expr) | Self::Direct(expr) => expr_span(expr),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Operand {
    Register(String, Span),
    Immediate8(u8, Span),
    Immediate16(u16, Span),
    Direct(u8, Span),
    Extended(u16, Span),
    Indexed {
        postbyte: u8,
        extra: Vec<u8>,
        span: Span,
    },
    Relative8(i8, Span),
    Relative16(i16, Span),
    RegisterList(u8, Span),
}

impl Operand {
    pub fn span(&self) -> Span {
        match self {
            Self::Register(_, span)
            | Self::Immediate8(_, span)
            | Self::Immediate16(_, span)
            | Self::Direct(_, span)
            | Self::Extended(_, span)
            | Self::Indexed { span, .. }
            | Self::Relative8(_, span)
            | Self::Relative16(_, span)
            | Self::RegisterList(_, span) => *span,
        }
    }

    pub fn mode(&self) -> AddressMode {
        match self {
            Self::Register(_, _) => AddressMode::RegisterPair,
            Self::Immediate8(_, _) => AddressMode::Immediate8,
            Self::Immediate16(_, _) => AddressMode::Immediate16,
            Self::Direct(_, _) => AddressMode::Direct,
            Self::Extended(_, _) => AddressMode::Extended,
            Self::Indexed { .. } => AddressMode::Indexed,
            Self::Relative8(_, _) => AddressMode::Relative8,
            Self::Relative16(_, _) => AddressMode::Relative16,
            Self::RegisterList(_, _) => AddressMode::RegisterList,
        }
    }
}
