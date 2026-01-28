// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65C02 CPU handler implementation.
//!
//! This handler implements the CpuHandler trait for the 65C02, extending the
//! MOS6502 family handler with 65C02-specific operand resolution and
//! instruction encoding.

use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::core::assembler::expression::expr_span;
use crate::families::mos6502::{AddressMode, FamilyOperand, MOS6502FamilyHandler, Operand, has_mnemonic as has_family_mnemonic};
use crate::m65c02::instructions::{has_mnemonic, lookup_instruction};

/// CPU handler for WDC 65C02.
#[derive(Debug)]
pub struct M65C02CpuHandler {
    family: MOS6502FamilyHandler,
}

impl Default for M65C02CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl M65C02CpuHandler {
    pub fn new() -> Self {
        Self {
            family: MOS6502FamilyHandler::new(),
        }
    }

    /// Check if a mnemonic is a 65C02-only branch instruction.
    fn is_65c02_branch(mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        upper == "BRA"
            || upper.starts_with("BBR")
            || upper.starts_with("BBS")
    }
}

impl CpuHandler for M65C02CpuHandler {
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
                        return Err(format!(
                            "Immediate value {} out of range (0-255)",
                            val
                        ));
                    }
                    Operand::Immediate(val as u8, expr_span(expr))
                }

                FamilyOperand::Direct(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    
                    // Branch instructions use relative addressing
                    if Self::is_branch_mnemonic(mnemonic) {
                        let current = ctx.current_address() as i32 + 2;
                        let offset = val as i32 - current;
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
                        // Prefer zero page when possible
                        Operand::ZeroPage(val as u8, span)
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
                        Operand::ZeroPageX(val as u8, span)
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
                        Operand::ZeroPageY(val as u8, span)
                    } else if (0..=65535).contains(&val) {
                        Operand::AbsoluteY(val as u16, span)
                    } else {
                        return Err(format!("Address {} out of 16-bit range", val));
                    }
                }

                FamilyOperand::IndexedIndirectX(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    if (0..=255).contains(&val) {
                        // Standard 6502 indexed indirect: ($nn,X)
                        Operand::IndexedIndirectX(val as u8, expr_span(expr))
                    } else if (0..=65535).contains(&val) {
                        // 65C02 absolute indexed indirect: ($nnnn,X)
                        // This is only valid for JMP on 65C02
                        Operand::AbsoluteIndexedIndirect(val as u16, expr_span(expr))
                    } else {
                        return Err(format!(
                            "Indexed indirect address {} out of range",
                            val
                        ));
                    }
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

                // 65C02-specific: resolve ambiguous indirect
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
                        // 65C02: ($nn) is zero page indirect
                        if (0..=255).contains(&val) {
                            Operand::ZeroPageIndirect(val as u8, span)
                        } else {
                            return Err(format!(
                                "Zero page indirect address {} out of range (0-255)",
                                val
                            ));
                        }
                    }
                }

                // 65C02-specific: JMP ($nnnn,X)
                FamilyOperand::IndirectX(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    if (0..=65535).contains(&val) {
                        Operand::AbsoluteIndexedIndirect(val as u16, span)
                    } else {
                        return Err(format!(
                            "Absolute indexed indirect address {} out of 16-bit range",
                            val
                        ));
                    }
                }
            };
            result.push(operand);
        }

        Ok(result)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
        _ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        // Determine addressing mode from operand
        let mode = if operands.is_empty() {
            AddressMode::Implied
        } else {
            operands[0].mode()
        };

        // Handle 65C02-only branch (BRA)
        if Self::is_65c02_branch(mnemonic) {
            if let Some(Operand::Relative(offset, _)) = operands.first() {
                if let Some(entry) = lookup_instruction(mnemonic, AddressMode::Relative) {
                    return EncodeResult::Ok(vec![entry.opcode, *offset as u8]);
                }
            }
        }

        // Look up instruction in 65C02 extension table
        match lookup_instruction(mnemonic, mode) {
            Some(entry) => {
                let mut bytes = vec![entry.opcode];
                if !operands.is_empty() {
                    bytes.extend(operands[0].value_bytes());
                }
                EncodeResult::Ok(bytes)
            }
            None => {
                // Not in extension table - let family handler try
                EncodeResult::NotFound
            }
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        has_mnemonic(mnemonic) || has_family_mnemonic(mnemonic)
    }
}

impl M65C02CpuHandler {
    /// Check if mnemonic is a branch instruction.
    fn is_branch_mnemonic(mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        matches!(
            upper.as_str(),
            "BCC" | "BCS" | "BEQ" | "BNE" | "BMI" | "BPL" | "BVC" | "BVS" | "BRA"
        ) || upper.starts_with("BBR") || upper.starts_with("BBS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_65c02_branch_detects_bra() {
        assert!(M65C02CpuHandler::is_65c02_branch("BRA"));
        assert!(M65C02CpuHandler::is_65c02_branch("bra"));
        assert!(!M65C02CpuHandler::is_65c02_branch("BEQ")); // base 6502
    }
}
