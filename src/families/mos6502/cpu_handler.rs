// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Base 6502 CPU handler implementation.
//!
//! This handler implements the CpuHandler trait for the base 6502, using the
//! MOS6502 family handler. Unlike the 65C02, the base 6502 does not support
//! extended addressing modes like zero page indirect or 65C02-only instructions.

use crate::core::assembler::expression::expr_span;
use crate::core::family::{expr_has_unstable_symbols, AssemblerContext, CpuHandler, EncodeResult};
use crate::families::mos6502::{
    has_mnemonic, lookup_instruction, AddressMode, FamilyOperand, MOS6502FamilyHandler, Operand,
};

/// CPU handler for base MOS 6502.
#[derive(Debug)]
pub struct M6502CpuHandler {
    family: MOS6502FamilyHandler,
}

impl Default for M6502CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl M6502CpuHandler {
    pub fn new() -> Self {
        Self {
            family: MOS6502FamilyHandler::new(),
        }
    }

    /// Check if mnemonic is a branch instruction.
    fn is_branch_mnemonic(mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        matches!(
            upper.as_str(),
            "BCC" | "BCS" | "BEQ" | "BNE" | "BMI" | "BPL" | "BVC" | "BVS"
        )
    }

    fn has_mode(mnemonic: &str, mode: AddressMode) -> bool {
        lookup_instruction(mnemonic, mode).is_some()
    }
}

impl CpuHandler for M6502CpuHandler {
    type Family = MOS6502FamilyHandler;

    fn family(&self) -> &Self::Family {
        &self.family
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<Operand>, String> {
        // No operands = implied mode
        if family_operands.is_empty() {
            return Ok(vec![Operand::Implied]);
        }

        let mut result = Vec::with_capacity(family_operands.len());

        for fop in family_operands {
            let operand = match fop {
                FamilyOperand::Accumulator(span) => Operand::Accumulator(*span),

                FamilyOperand::Immediate(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&val) {
                        return Err(format!("Immediate value {} out of range (0-255)", val));
                    }
                    Operand::Immediate(val as u8, expr_span(expr))
                }

                FamilyOperand::Direct(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);

                    // Branch instructions use relative addressing
                    if Self::is_branch_mnemonic(mnemonic) {
                        let current = ctx.current_address() as i64 + 2;
                        let offset = val - current;
                        if !(-128..=127).contains(&offset) {
                            if ctx.pass() > 1 {
                                // Only report error on pass 2
                                return Err(format!(
                                    "Branch target out of range: offset {}",
                                    offset
                                ));
                            }
                            // On pass 1, use placeholder offset (0)
                            Operand::Relative(0, span)
                        } else {
                            Operand::Relative(offset as i8, span)
                        }
                    } else if (0..=255).contains(&val) {
                        if expr_has_unstable_symbols(expr, ctx)
                            && Self::has_mode(mnemonic, AddressMode::Absolute)
                        {
                            Operand::Absolute(val as u16, span)
                        } else {
                            // Prefer zero page when possible
                            Operand::ZeroPage(val as u8, span)
                        }
                    } else if (0..=65535).contains(&val) {
                        Operand::Absolute(val as u16, span)
                    } else {
                        return Err(format!("Address {} out of 16-bit range", val));
                    }
                }

                FamilyOperand::DirectX(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    if (0..=255).contains(&val) {
                        if expr_has_unstable_symbols(expr, ctx)
                            && Self::has_mode(mnemonic, AddressMode::AbsoluteX)
                        {
                            Operand::AbsoluteX(val as u16, span)
                        } else {
                            Operand::ZeroPageX(val as u8, span)
                        }
                    } else if (0..=65535).contains(&val) {
                        Operand::AbsoluteX(val as u16, span)
                    } else {
                        return Err(format!("Address {} out of 16-bit range", val));
                    }
                }

                FamilyOperand::DirectY(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    if (0..=255).contains(&val) {
                        if expr_has_unstable_symbols(expr, ctx)
                            && Self::has_mode(mnemonic, AddressMode::AbsoluteY)
                        {
                            Operand::AbsoluteY(val as u16, span)
                        } else {
                            Operand::ZeroPageY(val as u8, span)
                        }
                    } else if (0..=65535).contains(&val) {
                        Operand::AbsoluteY(val as u16, span)
                    } else {
                        return Err(format!("Address {} out of 16-bit range", val));
                    }
                }

                FamilyOperand::IndexedIndirectX(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&val) {
                        return Err(format!(
                            "Indexed indirect address {} out of zero page range",
                            val
                        ));
                    }
                    Operand::IndexedIndirectX(val as u8, expr_span(expr))
                }

                FamilyOperand::IndirectIndexedY(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&val) {
                        return Err(format!(
                            "Indirect indexed address {} out of zero page range",
                            val
                        ));
                    }
                    Operand::IndirectIndexedY(val as u8, expr_span(expr))
                }

                // Base 6502: (expr) is only valid for JMP indirect
                FamilyOperand::Indirect(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    let upper_mnemonic = mnemonic.to_ascii_uppercase();

                    if upper_mnemonic == "JMP" {
                        // JMP ($nnnn) - 16-bit indirect
                        if (0..=65535).contains(&val) {
                            Operand::Indirect(val as u16, span)
                        } else {
                            return Err(format!("Indirect address {} out of 16-bit range", val));
                        }
                    } else {
                        // Base 6502 does NOT support ($nn) zero page indirect
                        return Err(
                            "Indirect addressing ($nn) not supported on base 6502 (use 65C02)"
                                .to_string(),
                        );
                    }
                }

                // Base 6502 does NOT support (expr,X) for absolute indexed indirect
                FamilyOperand::IndirectX(_expr) => {
                    return Err(
                        "Absolute indexed indirect ($nnnn,X) not supported on base 6502 (use 65C02)".to_string()
                    );
                }
                FamilyOperand::IndirectLong(_)
                | FamilyOperand::IndirectLongY(_)
                | FamilyOperand::IndirectIndexedZ(_)
                | FamilyOperand::IndirectLongZ(_)
                | FamilyOperand::StackRelative(_)
                | FamilyOperand::StackRelativeIndirectIndexedY(_)
                | FamilyOperand::Forced { .. }
                | FamilyOperand::BlockMove { .. } => {
                    return Err("65816-only addressing mode not supported on base 6502".to_string());
                }
            };
            result.push(operand);
        }

        Ok(result)
    }

    fn encode_instruction(
        &self,
        _mnemonic: &str,
        _operands: &[Operand],
        _ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        // Base 6502 has no CPU-specific instructions beyond what the family provides
        // Everything is handled by the family handler
        EncodeResult::NotFound
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        has_mnemonic(mnemonic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_branch_detects_base_branches() {
        assert!(M6502CpuHandler::is_branch_mnemonic("BEQ"));
        assert!(M6502CpuHandler::is_branch_mnemonic("bne"));
        assert!(!M6502CpuHandler::is_branch_mnemonic("BRA")); // 65C02 only
        assert!(!M6502CpuHandler::is_branch_mnemonic("JMP"));
    }
}
