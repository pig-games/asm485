// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Motorola 6800 family handler implementation.

use crate::core::assembler::expression::expr_span;
use crate::core::expr::parse_number;
use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::{Expr, UnaryOp};
use crate::core::tokenizer::Span;

use super::is_register;
use super::operand::{AddressMode, FamilyOperand, IndexedAutoMode, Operand};
use super::table::{has_mnemonic, lookup_instruction};

#[derive(Debug, Default)]
pub struct M6800FamilyHandler;

impl M6800FamilyHandler {
    pub fn new() -> Self {
        Self
    }

    fn register_code(name: &str) -> Option<u8> {
        match name.to_ascii_uppercase().as_str() {
            "D" => Some(0x0),
            "X" => Some(0x1),
            "Y" => Some(0x2),
            "U" => Some(0x3),
            "S" => Some(0x4),
            "PC" => Some(0x5),
            "A" => Some(0x8),
            "B" => Some(0x9),
            "CC" => Some(0xA),
            "DP" => Some(0xB),
            _ => None,
        }
    }

    fn register_pair_size(code: u8) -> u8 {
        if code < 0x8 {
            16
        } else {
            8
        }
    }

    fn is_register_pair_mnemonic(mnemonic: &str) -> bool {
        matches!(mnemonic.to_ascii_uppercase().as_str(), "TFR" | "EXG")
    }

    fn is_stack_register_list_mnemonic(mnemonic: &str) -> bool {
        matches!(
            mnemonic.to_ascii_uppercase().as_str(),
            "PSHS" | "PULS" | "PSHU" | "PULU"
        )
    }

    fn is_index_base_register(name: &str) -> bool {
        matches!(
            name.to_ascii_uppercase().as_str(),
            "X" | "Y" | "U" | "S" | "PC"
        )
    }

    fn span_for_exprs(exprs: &[Expr]) -> Span {
        let Some(first) = exprs.first() else {
            return Span::default();
        };
        let Some(last) = exprs.last() else {
            return expr_span(first);
        };
        let first_span = expr_span(first);
        let last_span = expr_span(last);
        Span {
            line: first_span.line,
            col_start: first_span.col_start,
            col_end: last_span.col_end,
        }
    }

    fn parse_register_expr(expr: &Expr) -> Option<(String, Span)> {
        match expr {
            Expr::Register(name, span) | Expr::Identifier(name, span) if is_register(name) => {
                Some((name.to_ascii_uppercase(), *span))
            }
            _ => None,
        }
    }

    fn parse_index_base_with_suffix(name: &str) -> Option<(String, Option<IndexedAutoMode>)> {
        let upper = name.to_ascii_uppercase();
        if let Some(base) = upper.strip_suffix("++") {
            return Some((base.to_string(), Some(IndexedAutoMode::PostInc2)));
        }
        if let Some(base) = upper.strip_suffix('+') {
            return Some((base.to_string(), Some(IndexedAutoMode::PostInc1)));
        }
        Some((upper, None))
    }

    fn parse_index_base_expr(expr: &Expr) -> Option<(String, Option<IndexedAutoMode>)> {
        match expr {
            Expr::Register(name, _) | Expr::Identifier(name, _) => {
                Self::parse_index_base_with_suffix(name)
            }
            Expr::Unary {
                op: UnaryOp::Minus,
                expr: inner,
                ..
            } => {
                if let Expr::Unary {
                    op: UnaryOp::Minus,
                    expr: double_inner,
                    ..
                } = &**inner
                {
                    let (base, mode) = Self::parse_index_base_expr(double_inner)?;
                    if mode.is_some() {
                        return None;
                    }
                    return Some((base, Some(IndexedAutoMode::PreDec2)));
                }
                let (base, mode) = Self::parse_index_base_expr(inner)?;
                if mode.is_some() {
                    return None;
                }
                Some((base, Some(IndexedAutoMode::PreDec1)))
            }
            _ => None,
        }
    }

    fn is_zero_expr(expr: &Expr) -> bool {
        match expr {
            Expr::Number(text, _) => parse_number(text) == Some(0),
            _ => false,
        }
    }

    fn parse_indexed_indirect(expr: &Expr, span: Span) -> Result<FamilyOperand, FamilyParseError> {
        let Expr::IndirectLong(inner, _) = expr else {
            return Err(FamilyParseError::new(
                "not an indirect-long expression",
                span,
            ));
        };
        match &**inner {
            Expr::Tuple(elements, _) if elements.len() == 2 => {
                let Some((base, _)) = Self::parse_register_expr(&elements[1]) else {
                    return Err(FamilyParseError::new(
                        "invalid indexed indirect base register",
                        expr_span(&elements[1]),
                    ));
                };
                if !Self::is_index_base_register(&base) {
                    return Err(FamilyParseError::new(
                        "invalid indexed indirect base register",
                        expr_span(&elements[1]),
                    ));
                }
                if let Some((register_offset, _)) = Self::parse_register_expr(&elements[0]) {
                    if matches!(register_offset.as_str(), "A" | "B" | "D") {
                        return Ok(FamilyOperand::IndexedIndirectRegisterOffset {
                            offset: register_offset,
                            base,
                            span,
                        });
                    }
                }
                Ok(FamilyOperand::IndexedIndirect {
                    offset: elements[0].clone(),
                    base: Some(base),
                    span,
                })
            }
            Expr::Tuple(_, tuple_span) => Err(FamilyParseError::new(
                "invalid indexed indirect tuple shape",
                *tuple_span,
            )),
            inner_expr => Ok(FamilyOperand::IndexedIndirect {
                offset: inner_expr.clone(),
                base: None,
                span,
            }),
        }
    }
}

impl FamilyHandler for M6800FamilyHandler {
    type FamilyOperand = FamilyOperand;
    type Operand = Operand;

    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Vec<Self::FamilyOperand>, FamilyParseError> {
        if exprs.is_empty() {
            return Ok(Vec::new());
        }

        if exprs.len() == 1 {
            if let Expr::IndirectLong(_, _) = &exprs[0] {
                let span = expr_span(&exprs[0]);
                return Self::parse_indexed_indirect(&exprs[0], span).map(|op| vec![op]);
            }
        }

        if Self::is_stack_register_list_mnemonic(mnemonic) {
            let mut list = Vec::with_capacity(exprs.len());
            for expr in exprs {
                let Some((register, span)) = Self::parse_register_expr(expr) else {
                    return Err(FamilyParseError::new(
                        format!(
                            "invalid register-list token in {}",
                            mnemonic.to_ascii_uppercase()
                        ),
                        expr_span(expr),
                    ));
                };
                list.push((register, span));
            }
            return Ok(vec![FamilyOperand::RegisterList(
                list,
                Self::span_for_exprs(exprs),
            )]);
        }

        if exprs.len() == 2 && Self::is_register_pair_mnemonic(mnemonic) {
            let mut result = Vec::with_capacity(2);
            for expr in exprs {
                let Some((register, span)) = Self::parse_register_expr(expr) else {
                    return Err(FamilyParseError::new(
                        format!(
                            "invalid register pair operand for {}",
                            mnemonic.to_ascii_uppercase()
                        ),
                        expr_span(expr),
                    ));
                };
                result.push(FamilyOperand::Register(register, span));
            }
            return Ok(result);
        }

        if exprs.len() == 2 {
            if let Some((base, auto_mode)) = Self::parse_index_base_expr(&exprs[1]) {
                if Self::is_index_base_register(&base) {
                    let span = Self::span_for_exprs(exprs);
                    if let Some(mode) = auto_mode {
                        if !Self::is_zero_expr(&exprs[0]) {
                            return Err(FamilyParseError::new(
                                "indexed auto inc/dec form does not allow displacement",
                                expr_span(&exprs[0]),
                            ));
                        }
                        return Ok(vec![FamilyOperand::IndexedAuto { base, mode, span }]);
                    }
                    if let Some((register_offset, _)) = Self::parse_register_expr(&exprs[0]) {
                        if matches!(register_offset.as_str(), "A" | "B" | "D") {
                            return Ok(vec![FamilyOperand::IndexedRegisterOffset {
                                offset: register_offset,
                                base,
                                span,
                            }]);
                        }
                    }
                    return Ok(vec![FamilyOperand::Indexed {
                        offset: exprs[0].clone(),
                        base,
                        span,
                    }]);
                }
            }
        }

        let mut result = Vec::with_capacity(exprs.len());
        for expr in exprs {
            match expr {
                Expr::Immediate(inner, _) => {
                    result.push(FamilyOperand::Immediate((**inner).clone()));
                }
                Expr::Register(name, span) | Expr::Identifier(name, span) if is_register(name) => {
                    result.push(FamilyOperand::Register(name.to_ascii_uppercase(), *span));
                }
                _ => result.push(FamilyOperand::Direct(expr.clone())),
            }
        }
        Ok(result)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Self::Operand],
        _ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        if !has_mnemonic(mnemonic) {
            return EncodeResult::NotFound;
        }

        let mode = match operands {
            [] => AddressMode::Inherent,
            [op] => op.mode(),
            [Operand::Register(_, _), Operand::Register(_, _)] => AddressMode::RegisterPair,
            _ => {
                return EncodeResult::error(format!(
                    "unsupported operand shape for {}",
                    mnemonic.to_ascii_uppercase()
                ))
            }
        };

        let Some(entry) = lookup_instruction(mnemonic, mode) else {
            return EncodeResult::NotFound;
        };

        let mut bytes = vec![entry.opcode];
        match operands {
            [] => {}
            [Operand::Immediate8(value, _)] | [Operand::Direct(value, _)] => bytes.push(*value),
            [Operand::Immediate16(value, _)] | [Operand::Extended(value, _)] => {
                bytes.push((value >> 8) as u8);
                bytes.push(*value as u8);
            }
            [Operand::Indexed {
                postbyte, extra, ..
            }] => {
                bytes.push(*postbyte);
                bytes.extend(extra);
            }
            [Operand::RegisterList(mask, _)] => bytes.push(*mask),
            [Operand::Relative8(offset, _)] => bytes.push(*offset as u8),
            [Operand::Relative16(offset, _)] => {
                let raw = *offset as u16;
                bytes.push((raw >> 8) as u8);
                bytes.push(raw as u8);
            }
            [Operand::Register(src, src_span), Operand::Register(dst, _)] => {
                let Some(src_code) = Self::register_code(src) else {
                    return EncodeResult::error_with_span(
                        format!("invalid register {}", src.to_ascii_uppercase()),
                        *src_span,
                    );
                };
                let Some(dst_code) = Self::register_code(dst) else {
                    return EncodeResult::error_with_span(
                        format!("invalid register {}", dst.to_ascii_uppercase()),
                        *src_span,
                    );
                };
                if Self::register_pair_size(src_code) != Self::register_pair_size(dst_code) {
                    return EncodeResult::error_with_span(
                        format!(
                            "invalid register pair {},{} for {}",
                            src.to_ascii_uppercase(),
                            dst.to_ascii_uppercase(),
                            mnemonic.to_ascii_uppercase()
                        ),
                        *src_span,
                    );
                }
                bytes.push((src_code << 4) | dst_code);
            }
            _ => {
                return EncodeResult::error(format!(
                    "unsupported operand shape for {}",
                    mnemonic.to_ascii_uppercase()
                ))
            }
        }

        EncodeResult::Ok(bytes)
    }

    fn is_register(&self, name: &str) -> bool {
        is_register(name)
    }
}
