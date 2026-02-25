// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Z80 CPU handler implementation.
//!
//! This handler implements the CpuHandler trait for the Z80. Unlike the 8085
//! which uses 8080 mnemonics, the Z80 uses its own mnemonic set (LD instead
//! of MOV, JP instead of JMP, etc.). This handler provides the Z80-specific
//! instruction table and encoding.

use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::core::parser::Expr;
use crate::families::intel8080::handler::Intel8080FamilyHandler;
use crate::families::intel8080::table::{ArgType, Prefix};
use crate::families::intel8080::{FamilyOperand, Operand};

use super::extensions::{has_extension, lookup_extension};

#[path = "handler_cb.rs"]
mod handler_cb;
#[path = "handler_half_index.rs"]
mod handler_half_index;
#[path = "handler_indexed.rs"]
mod handler_indexed;

/// CPU handler for Zilog Z80.
#[derive(Debug)]
pub struct Z80CpuHandler {
    family: Intel8080FamilyHandler,
}

impl Default for Z80CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Z80CpuHandler {
    pub fn new() -> Self {
        Self {
            family: Intel8080FamilyHandler,
        }
    }

    /// Check if a mnemonic is a relative branch instruction.
    fn is_relative_branch(mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        matches!(upper.as_str(), "JR" | "DJNZ")
    }

    /// Check if a mnemonic is an 8-bit IM instruction (interrupt mode).
    fn is_im_instruction(mnemonic: &str) -> bool {
        mnemonic.eq_ignore_ascii_case("IM")
    }

    /// Check if a mnemonic is an RST instruction.
    fn is_rst_instruction(mnemonic: &str) -> bool {
        mnemonic.eq_ignore_ascii_case("RST")
    }

    /// Check if a mnemonic uses CB-prefixed encoding forms.
    ///
    /// Includes SLL which is an undocumented Z80 opcode (CB 30+r).
    /// SLL shifts left and sets bit 0 to 1 (unlike SLA which clears it).
    fn is_cb_prefixed_instruction(mnemonic: &str) -> bool {
        matches!(
            mnemonic.to_ascii_uppercase().as_str(),
            "BIT" | "SET" | "RES" | "RL" | "RR" | "SLA" | "SRA" | "SRL" | "SLL" | "RLC" | "RRC"
        )
    }
}

/// Check if an identifier is a Z80-specific register (IX, IY, I, R, etc.)
pub fn is_z80_register(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "IX" | "IY" | "IXH" | "IXL" | "IYH" | "IYL" | "I" | "R" | "AF'"
    )
}

/// Check if an identifier is a Z80 condition code.
pub fn is_z80_condition(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "NZ" | "Z" | "NC" | "C" | "PO" | "PE" | "P" | "M"
    )
}

impl CpuHandler for Z80CpuHandler {
    type Family = Intel8080FamilyHandler;

    fn family(&self) -> &Self::Family {
        &self.family
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<Operand>, String> {
        let mut result = Vec::new();

        for (index, operand) in family_operands.iter().enumerate() {
            let resolved = match operand {
                FamilyOperand::Immediate(expr) => {
                    let value = ctx.eval_expr(expr)?;
                    let span = operand.span();
                    let upper = mnemonic.to_ascii_uppercase();

                    if upper == "LD" && matches!(expr, Expr::Indirect(_, _)) {
                        Operand::IndirectAddress16(value as u16, span)
                    } else {
                        let needs_word =
                            Self::needs_16bit_immediate(mnemonic, index, family_operands, expr);

                        if needs_word {
                            Operand::Immediate16(value as u16, span)
                        } else {
                            Operand::Immediate8(value as u8, span)
                        }
                    }
                }
                _ => self.resolve_z80_operand(mnemonic, operand, ctx)?,
            };
            result.push(resolved);
        }

        Ok(result)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        // Handle special instructions
        if Self::is_im_instruction(mnemonic) {
            return self.encode_im(operands);
        }

        if Self::is_rst_instruction(mnemonic) {
            return self.encode_rst(operands);
        }

        if let Some(cb_result) = self.encode_cb_instruction(mnemonic, operands) {
            return cb_result;
        }

        if let Some(ix_result) = self.encode_half_index_register_forms(mnemonic, operands) {
            return ix_result;
        }

        if let Some(ld_result) = self.encode_ld_indirect_forms(mnemonic, operands) {
            return ld_result;
        }

        if let Some(jp_result) = self.encode_jp_index_indirect(mnemonic, operands) {
            return jp_result;
        }

        if let Some(indexed_result) = self.encode_indexed_memory_forms(mnemonic, operands) {
            return indexed_result;
        }

        // Remaining indexed addressing forms fall through to this guard.
        for op in operands {
            if let Operand::Indexed { base, .. } = op {
                return EncodeResult::error(format!(
                    "Indexed addressing ({base}+d) is not yet supported for '{mnemonic}'"
                ));
            }
        }

        // Check if this is a Z80-only mnemonic
        if !has_extension(mnemonic) {
            return EncodeResult::NotFound;
        }

        // Extract register/condition names from operands
        let reg1 = operands.first().and_then(|op| op.as_register_or_indirect());
        let reg2 = operands.get(1).and_then(|op| op.as_register_or_indirect());

        // Look up the instruction
        let entry = match lookup_extension(mnemonic, reg1, reg2) {
            Some(e) => e,
            None => return EncodeResult::NotFound,
        };

        // Build output bytes with prefix
        let mut bytes = Vec::new();
        match entry.prefix {
            Prefix::None => {}
            Prefix::Cb => bytes.push(0xCB),
            Prefix::Dd => bytes.push(0xDD),
            Prefix::Ed => bytes.push(0xED),
            Prefix::Fd => bytes.push(0xFD),
            Prefix::DdCb => {
                bytes.push(0xDD);
                bytes.push(0xCB);
            }
            Prefix::FdCb => {
                bytes.push(0xFD);
                bytes.push(0xCB);
            }
        }

        bytes.push(entry.opcode);

        // Add immediate value if needed
        match entry.arg_type {
            ArgType::None => {}
            ArgType::Byte => {
                let imm_index = entry.num_regs as usize;
                if let Some(op) = operands.get(imm_index) {
                    match op {
                        Operand::Immediate8(val, _) | Operand::Port(val, _) => bytes.push(*val),
                        _ => {
                            return EncodeResult::error(format!(
                                "expected 8-bit immediate, got {:?}",
                                op
                            ));
                        }
                    }
                } else {
                    return EncodeResult::error("missing immediate operand");
                }
            }
            ArgType::Word => {
                let imm_index = entry.num_regs as usize;
                if let Some(op) = operands.get(imm_index) {
                    match op {
                        Operand::Immediate16(val, _) => {
                            bytes.push(*val as u8);
                            bytes.push((*val >> 8) as u8);
                        }
                        _ => {
                            return EncodeResult::error(format!(
                                "expected 16-bit immediate, got {:?}",
                                op
                            ));
                        }
                    }
                } else {
                    return EncodeResult::error("missing immediate operand");
                }
            }
            ArgType::Relative => {
                let imm_index = entry.num_regs as usize;
                if let Some(op) = operands.get(imm_index) {
                    match op {
                        Operand::Immediate8(offset, _) => {
                            bytes.push(*offset);
                        }
                        Operand::Immediate16(addr, span) => {
                            let current = ctx.current_address() as i64 + bytes.len() as i64 + 1;
                            let target = *addr as i64;
                            let offset = target - current;
                            if !(-128..=127).contains(&offset) {
                                return EncodeResult::error_with_span(
                                    format!("Branch target out of range: offset {}", offset),
                                    *span,
                                );
                            }
                            bytes.push(offset as u8);
                        }
                        _ => {
                            return EncodeResult::error(format!(
                                "expected relative address, got {:?}",
                                op
                            ));
                        }
                    }
                } else {
                    return EncodeResult::error("missing relative operand");
                }
            }
            ArgType::Im => {
                // Handled specially or encoded in opcode
            }
        }

        EncodeResult::Ok(bytes)
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        has_extension(mnemonic) || Self::is_cb_prefixed_instruction(mnemonic)
    }
}

impl Z80CpuHandler {
    /// Resolve a Z80-specific operand.
    fn resolve_z80_operand(
        &self,
        mnemonic: &str,
        operand: &FamilyOperand,
        ctx: &dyn AssemblerContext,
    ) -> Result<Operand, String> {
        match operand {
            FamilyOperand::Register(name, span) => {
                // Normalize AF' to AF for table lookup (`EX AF,AF'`).
                let normalized = if name.eq_ignore_ascii_case("AF'") {
                    "AF".to_string()
                } else {
                    name.clone()
                };
                Ok(Operand::Register(normalized, *span))
            }

            FamilyOperand::Indirect(name, span) => Ok(Operand::Indirect(name.clone(), *span)),

            FamilyOperand::Condition(name, span) => Ok(Operand::Condition(name.clone(), *span)),

            FamilyOperand::Immediate(expr) => {
                let value = ctx.eval_expr(expr)?;
                let span = operand.span();
                let upper = mnemonic.to_ascii_uppercase();
                let needs_word = matches!(upper.as_str(), "JP" | "CALL");

                if needs_word || Self::is_relative_branch(mnemonic) {
                    Ok(Operand::Immediate16(value as u16, span))
                } else {
                    Ok(Operand::Immediate8(value as u8, span))
                }
            }

            FamilyOperand::Indexed { base, offset, span } => {
                let offset_value = ctx.eval_expr(offset)? as i32;
                if !(-128..=127).contains(&offset_value) {
                    return Err(format!(
                        "Index offset {} out of range (-128..127)",
                        offset_value
                    ));
                }
                Ok(Operand::Indexed {
                    base: base.clone(),
                    offset: offset_value as i8,
                    span: *span,
                })
            }

            FamilyOperand::RstVector(expr) => {
                let value = ctx.eval_expr(expr)?;
                let vector = if value <= 7 {
                    value as u8
                } else if value % 8 == 0 && value <= 0x38 {
                    (value / 8) as u8
                } else {
                    return Err(format!(
                        "RST vector {} invalid (expected 0-7 or 0x00/0x08/.../0x38)",
                        value
                    ));
                };
                Ok(Operand::RstVector(vector, operand.span()))
            }

            FamilyOperand::InterruptMode(expr) => {
                let value = ctx.eval_expr(expr)?;
                if !(0..=2).contains(&value) {
                    return Err(format!("Interrupt mode {} out of range (0-2)", value));
                }
                Ok(Operand::InterruptMode(value as u8, operand.span()))
            }

            FamilyOperand::BitNumber(expr) => {
                let value = ctx.eval_expr(expr)?;
                if !(0..=7).contains(&value) {
                    return Err(format!("Bit number {} out of range (0-7)", value));
                }
                Ok(Operand::BitNumber(value as u8, operand.span()))
            }

            FamilyOperand::Port(expr) => {
                let value = ctx.eval_expr(expr)?;
                if !(0..=255).contains(&value) {
                    return Err(format!("Port number {} out of range (0-255)", value));
                }
                Ok(Operand::Port(value as u8, operand.span()))
            }
        }
    }

    /// Check if a Z80 mnemonic requires a 16-bit immediate operand.
    fn needs_16bit_immediate(
        mnemonic: &str,
        index: usize,
        operands: &[FamilyOperand],
        expr: &Expr,
    ) -> bool {
        if Self::is_relative_branch(mnemonic) {
            return true;
        }

        let upper = mnemonic.to_ascii_uppercase();
        if matches!(upper.as_str(), "JP" | "CALL") {
            return true;
        }

        if upper == "LD" {
            if matches!(expr, Expr::Indirect(_, _)) {
                return true;
            }

            let other = if index == 0 {
                operands.get(1)
            } else {
                operands.first()
            };

            if let Some(FamilyOperand::Register(name, _)) = other {
                return Self::is_16bit_register(name);
            }
        }

        false
    }

    fn is_16bit_register(name: &str) -> bool {
        matches!(
            name.to_ascii_uppercase().as_str(),
            "BC" | "DE" | "HL" | "SP" | "IX" | "IY" | "AF" | "AF'"
        )
    }

    /// Encode IM instruction (interrupt mode).
    fn encode_im(&self, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        if operands.is_empty() {
            return EncodeResult::error("IM requires a mode operand (0, 1, or 2)");
        }

        let mode = match &operands[0] {
            Operand::InterruptMode(m, _) => *m,
            Operand::Immediate8(m, _) => *m,
            _ => {
                return EncodeResult::error("IM requires a mode operand (0, 1, or 2)");
            }
        };

        let opcode = match mode {
            0 => 0x46,
            1 => 0x56,
            2 => 0x5E,
            _ => {
                return EncodeResult::error(format!(
                    "Invalid interrupt mode {}, expected 0, 1, or 2",
                    mode
                ));
            }
        };

        EncodeResult::Ok(vec![0xED, opcode])
    }

    /// Encode RST instruction.
    fn encode_rst(&self, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        if operands.is_empty() {
            return EncodeResult::error("RST requires a vector operand (0-7 or 0x00-0x38)");
        }

        let vector = match &operands[0] {
            Operand::RstVector(v, _) => *v,
            Operand::Immediate8(v, _) => {
                if *v <= 7 {
                    *v
                } else if *v % 8 == 0 && *v <= 0x38 {
                    *v / 8
                } else {
                    return EncodeResult::error(format!(
                        "RST vector {} invalid (expected 0-7 or 0x00/0x08/.../0x38)",
                        v
                    ));
                }
            }
            _ => {
                return EncodeResult::error("RST requires a vector operand");
            }
        };

        if vector > 7 {
            return EncodeResult::error(format!("RST vector {} out of range (0-7)", vector));
        }

        let opcode = 0xC7 | (vector << 3);
        EncodeResult::Ok(vec![opcode])
    }
}

impl Operand {
    /// Get the register or indirect register name for table lookup.
    fn as_register_or_indirect(&self) -> Option<&str> {
        match self {
            Operand::Register(name, _) => Some(name),
            Operand::Indirect(name, _) => {
                if name.eq_ignore_ascii_case("HL") {
                    Some("M")
                } else {
                    Some(name)
                }
            }
            Operand::Condition(name, _) => Some(name),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_z80_mnemonics() {
        let handler = Z80CpuHandler::new();
        assert!(handler.supports_mnemonic("LD"));
        assert!(handler.supports_mnemonic("JP"));
        assert!(handler.supports_mnemonic("JR"));
        assert!(handler.supports_mnemonic("DJNZ"));
        assert!(handler.supports_mnemonic("ld"));
        assert!(!handler.supports_mnemonic("MOV"));
        assert!(!handler.supports_mnemonic("MVI"));
    }

    #[test]
    fn recognizes_z80_registers() {
        assert!(is_z80_register("IX"));
        assert!(is_z80_register("IY"));
        assert!(is_z80_register("I"));
        assert!(is_z80_register("R"));
        assert!(!is_z80_register("A"));
        assert!(!is_z80_register("HL"));
    }

    #[test]
    fn recognizes_z80_conditions() {
        assert!(is_z80_condition("NZ"));
        assert!(is_z80_condition("Z"));
        assert!(is_z80_condition("NC"));
        assert!(is_z80_condition("C"));
        assert!(is_z80_condition("PO"));
        assert!(is_z80_condition("PE"));
        assert!(is_z80_condition("P"));
        assert!(is_z80_condition("M"));
    }
}
