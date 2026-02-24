// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! MOS 6502 family handler implementation.

use crate::core::assembler::expression::expr_span;
use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::Expr;
use crate::core::tokenizer::Span;
use crate::families::mos6502::is_register;
use crate::families::mos6502::operand::{AddressMode, FamilyOperand, Operand, OperandForce};
use crate::families::mos6502::table::{has_mnemonic, lookup_instruction};

/// Family handler for MOS 6502 family.
#[derive(Debug, Default)]
pub struct MOS6502FamilyHandler;

impl MOS6502FamilyHandler {
    pub fn new() -> Self {
        Self
    }

    /// Check if a mnemonic is a branch instruction (uses relative addressing).
    fn is_branch_instruction(mnemonic: &str) -> bool {
        matches!(
            mnemonic.to_ascii_uppercase().as_str(),
            "BCC" | "BCS" | "BEQ" | "BNE" | "BMI" | "BPL" | "BVC" | "BVS"
        )
    }

    /// Check if a mnemonic is a 65C02 bit branch instruction.
    fn is_bit_branch_instruction(mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        upper.starts_with("BBR") || upper.starts_with("BBS")
    }

    fn is_block_move_instruction(mnemonic: &str) -> bool {
        matches!(mnemonic.to_ascii_uppercase().as_str(), "MVN" | "MVP")
    }

    fn parse_force_suffix(expr: &Expr) -> Option<OperandForce> {
        let text = match expr {
            Expr::Identifier(name, _) | Expr::Register(name, _) => name,
            _ => return None,
        };
        match text.to_ascii_lowercase().as_str() {
            "d" => Some(OperandForce::DirectPage),
            "b" => Some(OperandForce::DataBank),
            "k" => Some(OperandForce::ProgramBank),
            "l" => Some(OperandForce::Long),
            _ => None,
        }
    }

    /// Parse a single expression into a FamilyOperand.
    fn parse_single_operand(&self, expr: &Expr) -> Result<FamilyOperand, FamilyParseError> {
        match expr {
            // Register A (accumulator mode)
            Expr::Register(name, span) if name.eq_ignore_ascii_case("A") => {
                Ok(FamilyOperand::Accumulator(*span))
            }

            // Immediate: #expr
            Expr::Immediate(inner, _) => Ok(FamilyOperand::Immediate((**inner).clone())),

            // Indirect: could be simple ($nn), or ($nn,X) tuple
            Expr::Indirect(inner, _) => {
                // Check for tuple inside indirect: ($nn,X)
                if let Expr::Tuple(elements, _) = &**inner {
                    if elements.len() == 2 {
                        // Check second element is X
                        let second = match &elements[1] {
                            Expr::Register(name, _) | Expr::Identifier(name, _) => {
                                name.to_ascii_uppercase()
                            }
                            _ => String::new(),
                        };
                        if second == "X" {
                            return Ok(FamilyOperand::IndexedIndirectX(elements[0].clone()));
                        }
                        if second == "S" {
                            return Err(FamilyParseError::new(
                                "Stack-relative indirect must use ,Y: (d,S),Y",
                                expr_span(expr),
                            ));
                        }
                    }
                    return Err(FamilyParseError::new(
                        "Invalid tuple in indirect address",
                        expr_span(expr),
                    ));
                }

                // Ordinary Indirect: ($nn) - could be JMP indirect or 65C02 ZP indirect
                Ok(FamilyOperand::Indirect((**inner).clone()))
            }

            // Bracketed long-indirect: [expr]
            Expr::IndirectLong(inner, _) => Ok(FamilyOperand::IndirectLong((**inner).clone())),

            // Binary with comma - check for indexed modes
            Expr::Binary {
                op: crate::core::parser::BinaryOp::Add,
                left: _,
                right: _,
                ..
            } => {
                // This doesn't capture expr,X syntax - that's handled differently
                // Just treat as direct address
                Ok(FamilyOperand::Direct(expr.clone()))
            }

            // Everything else is a direct address (could be ZP or Absolute)
            _ => Ok(FamilyOperand::Direct(expr.clone())),
        }
    }
}

impl FamilyHandler for MOS6502FamilyHandler {
    type FamilyOperand = FamilyOperand;
    type Operand = Operand;

    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Vec<FamilyOperand>, FamilyParseError> {
        // No operands = implied mode
        if exprs.is_empty() {
            return Ok(vec![]);
        }

        // 65C02 bit branches take two expression operands: zp,target
        if exprs.len() == 2 && Self::is_bit_branch_instruction(mnemonic) {
            return Ok(vec![
                FamilyOperand::Direct(exprs[0].clone()),
                FamilyOperand::Direct(exprs[1].clone()),
            ]);
        }

        // MVN/MVP block move source/destination bank operands
        if exprs.len() == 2 && Self::is_block_move_instruction(mnemonic) {
            let span = Span {
                line: expr_span(&exprs[0]).line,
                col_start: expr_span(&exprs[0]).col_start,
                col_end: expr_span(&exprs[1]).col_end,
            };
            return Ok(vec![FamilyOperand::BlockMove {
                src: exprs[0].clone(),
                dst: exprs[1].clone(),
                span,
            }]);
        }

        // Handle indexed modes that come as separate expressions
        // e.g., "LDA $20,X" might come as [expr($20), expr(X)]
        if exprs.len() == 2 {
            let index = match &exprs[1] {
                Expr::Register(name, _) | Expr::Identifier(name, _) => {
                    Some(name.to_ascii_uppercase())
                }
                _ => None,
            };
            if let Some(index) = index {
                if index == "X" {
                    return Ok(vec![FamilyOperand::DirectX(exprs[0].clone())]);
                }
                if index == "Y" {
                    if let Expr::Indirect(inner, _) = &exprs[0] {
                        // (d,S),Y stack-relative indirect indexed addressing (65816)
                        if let Expr::Tuple(elements, _) = &**inner {
                            if elements.len() == 2 {
                                let is_s = matches!(
                                    &elements[1],
                                    Expr::Register(name, _) | Expr::Identifier(name, _)
                                        if name.eq_ignore_ascii_case("S")
                                );
                                if is_s {
                                    return Ok(vec![FamilyOperand::StackRelativeIndirectIndexedY(
                                        elements[0].clone(),
                                    )]);
                                }
                            }
                        }
                        return Ok(vec![FamilyOperand::IndirectIndexedY((**inner).clone())]);
                    }
                    if let Expr::IndirectLong(inner, _) = &exprs[0] {
                        return Ok(vec![FamilyOperand::IndirectLongY((**inner).clone())]);
                    }
                    return Ok(vec![FamilyOperand::DirectY(exprs[0].clone())]);
                }
                if index == "Z" {
                    if let Expr::Indirect(inner, _) = &exprs[0] {
                        return Ok(vec![FamilyOperand::IndirectIndexedZ((**inner).clone())]);
                    }
                    if let Expr::IndirectLong(inner, _) = &exprs[0] {
                        return Ok(vec![FamilyOperand::IndirectLongZ((**inner).clone())]);
                    }
                    return Ok(vec![FamilyOperand::Direct(exprs[0].clone())]);
                }
                if index == "S" {
                    return Ok(vec![FamilyOperand::StackRelative(exprs[0].clone())]);
                }
            }

            if let Some(force) = Self::parse_force_suffix(&exprs[1]) {
                let base = self.parse_single_operand(&exprs[0])?;
                let span = Span {
                    line: expr_span(&exprs[0]).line,
                    col_start: expr_span(&exprs[0]).col_start,
                    col_end: expr_span(&exprs[1]).col_end,
                };
                return Ok(vec![FamilyOperand::Forced {
                    inner: Box::new(base),
                    force,
                    span,
                }]);
            }
        }

        // Single operand
        if exprs.len() == 1 {
            return Ok(vec![self.parse_single_operand(&exprs[0])?]);
        }

        // Too many operands
        let span = match exprs.first() {
            Some(e) => expr_span(e),
            None => Span::default(),
        };
        Err(FamilyParseError::new(
            format!("Too many operands for 6502 instruction: {}", exprs.len()),
            span,
        ))
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        // Check if mnemonic is in family table
        if !has_mnemonic(mnemonic) {
            return EncodeResult::NotFound;
        }

        // Determine addressing mode from operand
        let mode = if operands.is_empty() {
            AddressMode::Implied
        } else {
            operands[0].mode()
        };

        // Handle branch instructions specially (relative addressing)
        if Self::is_branch_instruction(mnemonic) {
            if let Some(Operand::Relative(offset, _span)) = operands.first() {
                if let Some(entry) = lookup_instruction(mnemonic, AddressMode::Relative) {
                    return EncodeResult::Ok(vec![entry.opcode, *offset as u8]);
                }
            }
            // If we have an absolute address, we need to calculate the offset
            if let Some(Operand::Absolute(addr, span)) = operands.first() {
                if let Some(entry) = lookup_instruction(mnemonic, AddressMode::Relative) {
                    let current = ctx.current_address() as i64 + 2; // +2 for instruction size
                    let target = *addr as i64;
                    let offset = target - current;
                    if !(-128..=127).contains(&offset) {
                        return EncodeResult::error_with_span(
                            format!("Branch target out of range: offset {}", offset),
                            *span,
                        );
                    }
                    return EncodeResult::Ok(vec![entry.opcode, offset as u8]);
                }
            }
        }

        // Look up instruction with mode promotion
        // If ZeroPage mode fails, try Absolute (same for ZeroPageX -> AbsoluteX, etc.)
        let modes_to_try = get_modes_to_try(mode, operands);

        for (try_mode, promoted_operand) in modes_to_try {
            if let Some(entry) = lookup_instruction(mnemonic, try_mode) {
                let mut bytes = vec![entry.opcode];
                if let Some(op) = promoted_operand {
                    bytes.extend(op.value_bytes());
                } else if !operands.is_empty() {
                    bytes.extend(operands[0].value_bytes());
                }
                return EncodeResult::Ok(bytes);
            }
        }

        // Not in family table - let CPU handler try
        EncodeResult::NotFound
    }

    fn is_register(&self, name: &str) -> bool {
        is_register(name)
    }
}

/// Get addressing modes to try in order of preference.
/// Returns pairs of (mode to try, optional promoted operand).
/// This implements mode promotion: ZeroPage -> Absolute, ZeroPageX -> AbsoluteX, etc.
fn get_modes_to_try(
    mode: AddressMode,
    operands: &[Operand],
) -> Vec<(AddressMode, Option<Operand>)> {
    match mode {
        AddressMode::ZeroPage => {
            // Try ZeroPage first, then promote to Absolute if needed
            if let Some(Operand::ZeroPage(val, span)) = operands.first() {
                vec![
                    (AddressMode::ZeroPage, None),
                    (
                        AddressMode::Absolute,
                        Some(Operand::Absolute(*val as u16, *span)),
                    ),
                ]
            } else {
                vec![(AddressMode::ZeroPage, None)]
            }
        }
        AddressMode::ZeroPageX => {
            // Try ZeroPageX first, then promote to AbsoluteX if needed
            if let Some(Operand::ZeroPageX(val, span)) = operands.first() {
                vec![
                    (AddressMode::ZeroPageX, None),
                    (
                        AddressMode::AbsoluteX,
                        Some(Operand::AbsoluteX(*val as u16, *span)),
                    ),
                ]
            } else {
                vec![(AddressMode::ZeroPageX, None)]
            }
        }
        AddressMode::ZeroPageY => {
            // Try ZeroPageY first, then promote to AbsoluteY if needed
            if let Some(Operand::ZeroPageY(val, span)) = operands.first() {
                vec![
                    (AddressMode::ZeroPageY, None),
                    (
                        AddressMode::AbsoluteY,
                        Some(Operand::AbsoluteY(*val as u16, *span)),
                    ),
                ]
            } else {
                vec![(AddressMode::ZeroPageY, None)]
            }
        }
        _ => vec![(mode, None)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_branch_test() {
        assert!(MOS6502FamilyHandler::is_branch_instruction("BEQ"));
        assert!(MOS6502FamilyHandler::is_branch_instruction("bne"));
        assert!(!MOS6502FamilyHandler::is_branch_instruction("JMP"));
        assert!(!MOS6502FamilyHandler::is_branch_instruction("LDA"));
    }
}
