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
    /// Encode undocumented Z80 half-index register forms (IXH/IXL/IYH/IYL).
    fn encode_half_index_register_forms(
        &self,
        mnemonic: &str,
        operands: &[Operand],
    ) -> Option<EncodeResult<Vec<u8>>> {
        let mut prefix: Option<u8> = None;

        for operand in operands {
            if let Operand::Register(name, _) = operand {
                if let Some((reg_prefix, _)) = Self::half_index_parts(name) {
                    match prefix {
                        None => prefix = Some(reg_prefix),
                        Some(existing) if existing == reg_prefix => {}
                        Some(_) => {
                            return Some(EncodeResult::error(
                                "Cannot mix IXH/IXL with IYH/IYL in one instruction",
                            ));
                        }
                    }
                }
            }
        }

        let prefix = prefix?;
        let upper = mnemonic.to_ascii_uppercase();

        match upper.as_str() {
            "LD" => Some(Self::encode_half_index_ld(prefix, operands)),
            "INC" | "DEC" => Some(Self::encode_half_index_inc_dec(prefix, &upper, operands)),
            "ADD" => Some(Self::encode_half_index_add(prefix, operands)),
            "ADC" => Some(Self::encode_half_index_adc(prefix, operands)),
            "SUB" => Some(Self::encode_half_index_sub(prefix, operands)),
            "SBC" => Some(Self::encode_half_index_sbc(prefix, operands)),
            "AND" => Some(Self::encode_half_index_logic(prefix, operands, 0xA0, "AND")),
            "XOR" => Some(Self::encode_half_index_logic(prefix, operands, 0xA8, "XOR")),
            "OR" => Some(Self::encode_half_index_logic(prefix, operands, 0xB0, "OR")),
            "CP" => Some(Self::encode_half_index_logic(prefix, operands, 0xB8, "CP")),
            _ => None,
        }
    }

    fn encode_half_index_ld(prefix: u8, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("LD with IXH/IXL/IYH/IYL requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(dst, _), Operand::Register(src, _)) => {
                let dst_code = match Self::half_index_reg_code(prefix, dst) {
                    Some(code) => code,
                    None => return EncodeResult::NotFound,
                };
                let src_code = match Self::half_index_reg_code(prefix, src) {
                    Some(code) => code,
                    None => return EncodeResult::NotFound,
                };
                let opcode = 0x40 | (dst_code << 3) | src_code;
                EncodeResult::Ok(vec![prefix, opcode])
            }
            (Operand::Register(dst, _), Operand::Immediate8(value, _)) => {
                let dst_code = match Self::half_index_parts(dst) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                let opcode = 0x06 | (dst_code << 3);
                EncodeResult::Ok(vec![prefix, opcode, *value])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_half_index_inc_dec(
        prefix: u8,
        mnemonic: &str,
        operands: &[Operand],
    ) -> EncodeResult<Vec<u8>> {
        if operands.len() != 1 {
            return EncodeResult::error(format!(
                "{mnemonic} with IXH/IXL/IYH/IYL requires one operand"
            ));
        }

        let code = match &operands[0] {
            Operand::Register(name, _) => match Self::half_index_parts(name) {
                Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                _ => return EncodeResult::NotFound,
            },
            _ => return EncodeResult::NotFound,
        };

        let opcode = if mnemonic == "INC" {
            0x04 | (code << 3)
        } else {
            0x05 | (code << 3)
        };
        EncodeResult::Ok(vec![prefix, opcode])
    }

    fn encode_half_index_add(prefix: u8, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("ADD A,IXH/IXL/IYH/IYL requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(acc, _), Operand::Register(src, _))
                if acc.eq_ignore_ascii_case("A") =>
            {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, 0x80 | code])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_half_index_adc(prefix: u8, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("ADC A,IXH/IXL/IYH/IYL requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(acc, _), Operand::Register(src, _))
                if acc.eq_ignore_ascii_case("A") =>
            {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, 0x88 | code])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_half_index_sub(prefix: u8, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        match operands {
            [Operand::Register(src, _)] => {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, 0x90 | code])
            }
            [Operand::Register(acc, _), Operand::Register(src, _)]
                if acc.eq_ignore_ascii_case("A") =>
            {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, 0x90 | code])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_half_index_sbc(prefix: u8, operands: &[Operand]) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("SBC A,IXH/IXL/IYH/IYL requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(acc, _), Operand::Register(src, _))
                if acc.eq_ignore_ascii_case("A") =>
            {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, 0x98 | code])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_half_index_logic(
        prefix: u8,
        operands: &[Operand],
        base_opcode: u8,
        mnemonic: &str,
    ) -> EncodeResult<Vec<u8>> {
        match operands {
            [Operand::Register(src, _)] => {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, base_opcode | code])
            }
            [Operand::Register(acc, _), Operand::Register(src, _)]
                if acc.eq_ignore_ascii_case("A") =>
            {
                let code = match Self::half_index_parts(src) {
                    Some((reg_prefix, reg_code)) if reg_prefix == prefix => reg_code,
                    _ => return EncodeResult::NotFound,
                };
                EncodeResult::Ok(vec![prefix, base_opcode | code])
            }
            _ => EncodeResult::error(format!(
                "{mnemonic} IXH/IXL/IYH/IYL form requires one operand (or A,<src>)"
            )),
        }
    }

    fn half_index_parts(name: &str) -> Option<(u8, u8)> {
        match name.to_ascii_uppercase().as_str() {
            "IXH" => Some((0xDD, 4)),
            "IXL" => Some((0xDD, 5)),
            "IYH" => Some((0xFD, 4)),
            "IYL" => Some((0xFD, 5)),
            _ => None,
        }
    }

    fn half_index_reg_code(prefix: u8, name: &str) -> Option<u8> {
        match name.to_ascii_uppercase().as_str() {
            "B" => Some(0),
            "C" => Some(1),
            "D" => Some(2),
            "E" => Some(3),
            "A" => Some(7),
            _ => match Self::half_index_parts(name) {
                Some((reg_prefix, reg_code)) if reg_prefix == prefix => Some(reg_code),
                _ => None,
            },
        }
    }

    /// Encode `LD` forms that use `(nn)` absolute memory indirection.
    ///
    /// These forms are distinct from plain immediate loads and therefore
    /// cannot be handled by the generic extension table lookup.
    fn encode_ld_indirect_forms(
        &self,
        mnemonic: &str,
        operands: &[Operand],
    ) -> Option<EncodeResult<Vec<u8>>> {
        if !mnemonic.eq_ignore_ascii_case("LD") || operands.len() != 2 {
            return None;
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(dst, _), Operand::IndirectAddress16(addr, _)) => {
                let (prefix, opcode) = match dst.to_ascii_uppercase().as_str() {
                    "A" => (None, 0x3A),
                    "HL" => (None, 0x2A),
                    "BC" => (Some(0xED), 0x4B),
                    "DE" => (Some(0xED), 0x5B),
                    "SP" => (Some(0xED), 0x7B),
                    "IX" => (Some(0xDD), 0x2A),
                    "IY" => (Some(0xFD), 0x2A),
                    _ => return None,
                };
                Some(EncodeResult::Ok(Self::emit_prefixed_word(
                    prefix, opcode, *addr,
                )))
            }
            (Operand::IndirectAddress16(addr, _), Operand::Register(src, _)) => {
                let (prefix, opcode) = match src.to_ascii_uppercase().as_str() {
                    "A" => (None, 0x32),
                    "HL" => (None, 0x22),
                    "BC" => (Some(0xED), 0x43),
                    "DE" => (Some(0xED), 0x53),
                    "SP" => (Some(0xED), 0x73),
                    "IX" => (Some(0xDD), 0x22),
                    "IY" => (Some(0xFD), 0x22),
                    _ => return None,
                };
                Some(EncodeResult::Ok(Self::emit_prefixed_word(
                    prefix, opcode, *addr,
                )))
            }
            _ => None,
        }
    }

    /// Encode `JP (IX)` and `JP (IY)` forms.
    fn encode_jp_index_indirect(
        &self,
        mnemonic: &str,
        operands: &[Operand],
    ) -> Option<EncodeResult<Vec<u8>>> {
        if !mnemonic.eq_ignore_ascii_case("JP") || operands.len() != 1 {
            return None;
        }

        match &operands[0] {
            Operand::Indexed { base, offset, .. } => {
                let prefix = if base.eq_ignore_ascii_case("IX") {
                    0xDD
                } else if base.eq_ignore_ascii_case("IY") {
                    0xFD
                } else {
                    return None;
                };

                if *offset != 0 {
                    return Some(EncodeResult::error(format!(
                        "JP ({base}+d) is invalid; use JP ({base})"
                    )));
                }

                Some(EncodeResult::Ok(vec![prefix, 0xE9]))
            }
            _ => None,
        }
    }

    /// Encode non-CB indexed memory forms that use `(IX+d)` / `(IY+d)`.
    fn encode_indexed_memory_forms(
        &self,
        mnemonic: &str,
        operands: &[Operand],
    ) -> Option<EncodeResult<Vec<u8>>> {
        let mut indexed_operands = Vec::new();
        for (idx, operand) in operands.iter().enumerate() {
            if let Operand::Indexed { base, offset, .. } = operand {
                let prefix = if base.eq_ignore_ascii_case("IX") {
                    0xDD
                } else if base.eq_ignore_ascii_case("IY") {
                    0xFD
                } else {
                    return Some(EncodeResult::error(format!(
                        "invalid indexed base '{base}'"
                    )));
                };
                indexed_operands.push((idx, base.as_str(), prefix, *offset));
            }
        }

        if indexed_operands.is_empty() {
            return None;
        }

        if indexed_operands.len() > 1 {
            return Some(EncodeResult::error(
                "Only one indexed memory operand is supported in this instruction form",
            ));
        }

        let (indexed_pos, base, prefix, displacement) = indexed_operands[0];
        let upper = mnemonic.to_ascii_uppercase();

        let result = match upper.as_str() {
            "LD" => Self::encode_indexed_ld(prefix, displacement, operands, indexed_pos),
            "INC" | "DEC" => {
                Self::encode_indexed_inc_dec(prefix, displacement, &upper, operands, indexed_pos)
            }
            "ADD" => Self::encode_indexed_add(prefix, displacement, operands, indexed_pos),
            "ADC" => Self::encode_indexed_adc(prefix, displacement, operands, indexed_pos),
            "SUB" => Self::encode_indexed_sub(prefix, displacement, operands, indexed_pos),
            "SBC" => Self::encode_indexed_sbc(prefix, displacement, operands, indexed_pos),
            "AND" => {
                Self::encode_indexed_logic(prefix, displacement, operands, indexed_pos, 0xA6, "AND")
            }
            "XOR" => {
                Self::encode_indexed_logic(prefix, displacement, operands, indexed_pos, 0xAE, "XOR")
            }
            "OR" => {
                Self::encode_indexed_logic(prefix, displacement, operands, indexed_pos, 0xB6, "OR")
            }
            "CP" => {
                Self::encode_indexed_logic(prefix, displacement, operands, indexed_pos, 0xBE, "CP")
            }
            _ => EncodeResult::NotFound,
        };

        if matches!(result, EncodeResult::NotFound) {
            return Some(EncodeResult::error(format!(
                "Indexed addressing ({base}+d) is not yet supported for '{mnemonic}'"
            )));
        }

        Some(result)
    }

    fn encode_indexed_ld(
        prefix: u8,
        displacement: i8,
        operands: &[Operand],
        indexed_pos: usize,
    ) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("LD indexed form requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(dst, _), Operand::Indexed { .. }) if indexed_pos == 1 => {
                let reg = match Self::indexed_reg_code(dst) {
                    Some(reg) => reg,
                    None => return EncodeResult::NotFound,
                };
                let opcode = 0x46 | (reg << 3);
                EncodeResult::Ok(vec![prefix, opcode, displacement as u8])
            }
            (Operand::Indexed { .. }, Operand::Register(src, _)) if indexed_pos == 0 => {
                let reg = match Self::indexed_reg_code(src) {
                    Some(reg) => reg,
                    None => return EncodeResult::NotFound,
                };
                let opcode = 0x70 | reg;
                EncodeResult::Ok(vec![prefix, opcode, displacement as u8])
            }
            (Operand::Indexed { .. }, Operand::Immediate8(value, _)) if indexed_pos == 0 => {
                EncodeResult::Ok(vec![prefix, 0x36, displacement as u8, *value])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_indexed_inc_dec(
        prefix: u8,
        displacement: i8,
        mnemonic: &str,
        operands: &[Operand],
        indexed_pos: usize,
    ) -> EncodeResult<Vec<u8>> {
        if operands.len() != 1 {
            return EncodeResult::error(format!("{mnemonic} indexed form requires one operand"));
        }
        if indexed_pos != 0 {
            return EncodeResult::NotFound;
        }

        let opcode = if mnemonic == "INC" { 0x34 } else { 0x35 };
        EncodeResult::Ok(vec![prefix, opcode, displacement as u8])
    }

    fn encode_indexed_add(
        prefix: u8,
        displacement: i8,
        operands: &[Operand],
        indexed_pos: usize,
    ) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("ADD indexed form requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(acc, _), Operand::Indexed { .. })
                if indexed_pos == 1 && acc.eq_ignore_ascii_case("A") =>
            {
                EncodeResult::Ok(vec![prefix, 0x86, displacement as u8])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_indexed_adc(
        prefix: u8,
        displacement: i8,
        operands: &[Operand],
        indexed_pos: usize,
    ) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("ADC indexed form requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(acc, _), Operand::Indexed { .. })
                if indexed_pos == 1 && acc.eq_ignore_ascii_case("A") =>
            {
                EncodeResult::Ok(vec![prefix, 0x8E, displacement as u8])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_indexed_sub(
        prefix: u8,
        displacement: i8,
        operands: &[Operand],
        indexed_pos: usize,
    ) -> EncodeResult<Vec<u8>> {
        match operands {
            [Operand::Indexed { .. }] if indexed_pos == 0 => {
                EncodeResult::Ok(vec![prefix, 0x96, displacement as u8])
            }
            [Operand::Register(acc, _), Operand::Indexed { .. }]
                if indexed_pos == 1 && acc.eq_ignore_ascii_case("A") =>
            {
                EncodeResult::Ok(vec![prefix, 0x96, displacement as u8])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_indexed_sbc(
        prefix: u8,
        displacement: i8,
        operands: &[Operand],
        indexed_pos: usize,
    ) -> EncodeResult<Vec<u8>> {
        if operands.len() != 2 {
            return EncodeResult::error("SBC indexed form requires two operands");
        }

        match (&operands[0], &operands[1]) {
            (Operand::Register(acc, _), Operand::Indexed { .. })
                if indexed_pos == 1 && acc.eq_ignore_ascii_case("A") =>
            {
                EncodeResult::Ok(vec![prefix, 0x9E, displacement as u8])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn encode_indexed_logic(
        prefix: u8,
        displacement: i8,
        operands: &[Operand],
        indexed_pos: usize,
        opcode: u8,
        mnemonic: &str,
    ) -> EncodeResult<Vec<u8>> {
        match operands {
            [Operand::Indexed { .. }] if indexed_pos == 0 => {
                EncodeResult::Ok(vec![prefix, opcode, displacement as u8])
            }
            [Operand::Register(acc, _), Operand::Indexed { .. }]
                if indexed_pos == 1 && acc.eq_ignore_ascii_case("A") =>
            {
                EncodeResult::Ok(vec![prefix, opcode, displacement as u8])
            }
            _ => EncodeResult::error(format!(
                "{mnemonic} indexed form requires one operand (or A,<src>)"
            )),
        }
    }

    fn indexed_reg_code(name: &str) -> Option<u8> {
        match name.to_ascii_uppercase().as_str() {
            "B" => Some(0),
            "C" => Some(1),
            "D" => Some(2),
            "E" => Some(3),
            "H" => Some(4),
            "L" => Some(5),
            "A" => Some(7),
            _ => None,
        }
    }

    /// Encode CB-prefixed bit/shift/rotate instructions.
    fn encode_cb_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
    ) -> Option<EncodeResult<Vec<u8>>> {
        if !Self::is_cb_prefixed_instruction(mnemonic) {
            return None;
        }

        let upper = mnemonic.to_ascii_uppercase();

        if matches!(upper.as_str(), "BIT" | "SET" | "RES") {
            if operands.len() != 2 {
                return Some(EncodeResult::error(format!(
                    "{upper} requires exactly two operands"
                )));
            }

            let bit = match Self::cb_bit_value(&operands[0]) {
                Ok(bit) => bit,
                Err(err) => return Some(EncodeResult::error(err)),
            };
            let (prefix, displacement, reg_code) = match Self::cb_target(&operands[1]) {
                Ok(target) => target,
                Err(err) => return Some(EncodeResult::error(err)),
            };

            let base = match upper.as_str() {
                "BIT" => 0x40,
                "RES" => 0x80,
                "SET" => 0xC0,
                _ => unreachable!(),
            };
            let opcode = base | (bit << 3) | reg_code;
            return Some(EncodeResult::Ok(Self::emit_cb_bytes(
                prefix,
                displacement,
                opcode,
            )));
        }

        if operands.len() != 1 {
            return Some(EncodeResult::error(format!(
                "{upper} requires exactly one operand"
            )));
        }

        let (prefix, displacement, reg_code) = match Self::cb_target(&operands[0]) {
            Ok(target) => target,
            Err(err) => return Some(EncodeResult::error(err)),
        };

        let base = match upper.as_str() {
            "RLC" => 0x00,
            "RRC" => 0x08,
            "RL" => 0x10,
            "RR" => 0x18,
            "SLA" => 0x20,
            "SRA" => 0x28,
            "SLL" => 0x30, // undocumented: shift left, set bit 0 to 1
            "SRL" => 0x38,
            _ => {
                return Some(EncodeResult::error(format!(
                    "Unsupported CB-prefix mnemonic '{mnemonic}'"
                )));
            }
        };

        let opcode = base | reg_code;
        Some(EncodeResult::Ok(Self::emit_cb_bytes(
            prefix,
            displacement,
            opcode,
        )))
    }

    fn cb_bit_value(operand: &Operand) -> Result<u8, String> {
        let value = match operand {
            Operand::BitNumber(bit, _) | Operand::Immediate8(bit, _) => *bit as i32,
            Operand::Immediate16(bit, _) => *bit as i32,
            _ => {
                return Err(format!("expected bit number (0-7), got {:?}", operand));
            }
        };

        if !(0..=7).contains(&value) {
            return Err(format!("bit number {} out of range (0-7)", value));
        }

        Ok(value as u8)
    }

    fn cb_target(operand: &Operand) -> Result<(Option<u8>, i8, u8), String> {
        match operand {
            Operand::Register(name, _) => {
                let reg = Self::cb_register_code(name)
                    .ok_or_else(|| format!("invalid CB target register '{name}'"))?;
                Ok((None, 0, reg))
            }
            Operand::Indirect(name, _) => {
                if name.eq_ignore_ascii_case("HL") {
                    Ok((None, 0, 6))
                } else {
                    Err(format!("invalid CB indirect target '({name})'"))
                }
            }
            Operand::Indexed { base, offset, .. } => {
                let prefix = if base.eq_ignore_ascii_case("IX") {
                    0xDD
                } else if base.eq_ignore_ascii_case("IY") {
                    0xFD
                } else {
                    return Err(format!("invalid indexed base '{base}' for CB instruction"));
                };
                Ok((Some(prefix), *offset, 6))
            }
            _ => Err(format!("invalid CB target operand {:?}", operand)),
        }
    }

    fn cb_register_code(name: &str) -> Option<u8> {
        match name.to_ascii_uppercase().as_str() {
            "B" => Some(0),
            "C" => Some(1),
            "D" => Some(2),
            "E" => Some(3),
            "H" => Some(4),
            "L" => Some(5),
            "M" => Some(6),
            "A" => Some(7),
            _ => None,
        }
    }

    fn emit_cb_bytes(prefix: Option<u8>, displacement: i8, opcode: u8) -> Vec<u8> {
        match prefix {
            Some(prefix) => vec![prefix, 0xCB, displacement as u8, opcode],
            None => vec![0xCB, opcode],
        }
    }

    fn emit_prefixed_word(prefix: Option<u8>, opcode: u8, value: u16) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4);
        if let Some(prefix) = prefix {
            bytes.push(prefix);
        }
        bytes.push(opcode);
        bytes.push(value as u8);
        bytes.push((value >> 8) as u8);
        bytes
    }

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
