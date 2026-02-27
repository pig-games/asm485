// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Motorola 6809 CPU handler implementation.

use crate::core::assembler::expression::expr_span;
use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::families::m6800::{FamilyOperand, M6800FamilyHandler, Operand};

#[derive(Debug)]
pub struct M6809CpuHandler {
    family: M6800FamilyHandler,
}

impl Default for M6809CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl M6809CpuHandler {
    pub fn new() -> Self {
        Self {
            family: M6800FamilyHandler::new(),
        }
    }

    fn is_rel8_branch(mnemonic: &str) -> bool {
        matches!(
            mnemonic.to_ascii_uppercase().as_str(),
            "BRA"
                | "BRN"
                | "BHI"
                | "BLS"
                | "BCC"
                | "BHS"
                | "BCS"
                | "BLO"
                | "BNE"
                | "BEQ"
                | "BVC"
                | "BVS"
                | "BPL"
                | "BMI"
                | "BGE"
                | "BLT"
                | "BGT"
                | "BLE"
        )
    }

    fn is_rel16_branch(mnemonic: &str) -> bool {
        matches!(mnemonic.to_ascii_uppercase().as_str(), "LBRA" | "LBSR")
    }

    fn is_immediate16_instruction(mnemonic: &str) -> bool {
        matches!(
            mnemonic.to_ascii_uppercase().as_str(),
            "LDD" | "LDX" | "LDU"
        )
    }

    fn index_register_code(name: &str) -> Option<u8> {
        match name.to_ascii_uppercase().as_str() {
            "X" => Some(0x0),
            "Y" => Some(0x1),
            "U" => Some(0x2),
            "S" => Some(0x3),
            _ => None,
        }
    }

    fn indexed_register_postbyte(offset_register: &str, base: &str) -> Option<u8> {
        let base_code = Self::index_register_code(base)?;
        let mode = match offset_register.to_ascii_uppercase().as_str() {
            "B" => 0x85,
            "A" => 0x86,
            "D" => 0x8B,
            _ => return None,
        };
        Some(mode | (base_code << 5))
    }

    fn indexed_register_postbyte_indirect(offset_register: &str, base: &str) -> Option<u8> {
        let base_code = Self::index_register_code(base)?;
        let mode = match offset_register.to_ascii_uppercase().as_str() {
            "B" => 0x95,
            "A" => 0x96,
            "D" => 0x9B,
            _ => return None,
        };
        Some(mode | (base_code << 5))
    }

    fn indexed_numeric_encoding(value: i64, base: &str) -> Result<(u8, Vec<u8>), String> {
        if base.eq_ignore_ascii_case("PC") {
            if (-128..=127).contains(&value) {
                return Ok((0x8C, vec![value as i8 as u8]));
            }
            if (-32768..=32767).contains(&value) {
                let word = value as i16 as u16;
                return Ok((0x8D, vec![(word >> 8) as u8, word as u8]));
            }
            return Err(format!(
                "indexed PC-relative displacement {} out of range",
                value
            ));
        }

        let Some(base_code) = Self::index_register_code(base) else {
            return Err(format!(
                "invalid indexed base register {}",
                base.to_ascii_uppercase()
            ));
        };

        if (-16..=15).contains(&value) {
            return Ok((
                ((base_code << 5) | ((value as i8 as u8) & 0x1F)),
                Vec::new(),
            ));
        }
        if (-128..=127).contains(&value) {
            return Ok((0x88 | (base_code << 5), vec![value as i8 as u8]));
        }
        if (-32768..=32767).contains(&value) {
            let word = value as i16 as u16;
            return Ok((0x89 | (base_code << 5), vec![(word >> 8) as u8, word as u8]));
        }
        Err(format!("indexed displacement {} out of range", value))
    }

    fn indexed_numeric_encoding_indirect(value: i64, base: &str) -> Result<(u8, Vec<u8>), String> {
        if base.eq_ignore_ascii_case("PC") {
            if (-128..=127).contains(&value) {
                return Ok((0x9C, vec![value as i8 as u8]));
            }
            if (-32768..=32767).contains(&value) {
                let word = value as i16 as u16;
                return Ok((0x9D, vec![(word >> 8) as u8, word as u8]));
            }
            return Err(format!(
                "indirect indexed PC-relative displacement {} out of range",
                value
            ));
        }

        let Some(base_code) = Self::index_register_code(base) else {
            return Err(format!(
                "invalid indexed indirect base register {}",
                base.to_ascii_uppercase()
            ));
        };

        if value == 0 {
            return Ok((0x94 | (base_code << 5), Vec::new()));
        }
        if (-128..=127).contains(&value) {
            return Ok((0x98 | (base_code << 5), vec![value as i8 as u8]));
        }
        if (-32768..=32767).contains(&value) {
            let word = value as i16 as u16;
            return Ok((0x99 | (base_code << 5), vec![(word >> 8) as u8, word as u8]));
        }
        Err(format!(
            "indirect indexed displacement {} out of range",
            value
        ))
    }

    fn register_list_bit(mnemonic: &str, register: &str) -> Option<u8> {
        let upper_mnemonic = mnemonic.to_ascii_uppercase();
        let upper_register = register.to_ascii_uppercase();
        match upper_register.as_str() {
            "CC" => Some(0x01),
            "A" => Some(0x02),
            "B" => Some(0x04),
            "DP" => Some(0x08),
            "X" => Some(0x10),
            "Y" => Some(0x20),
            "PC" => Some(0x80),
            "U" if matches!(upper_mnemonic.as_str(), "PSHS" | "PULS") => Some(0x40),
            "S" if matches!(upper_mnemonic.as_str(), "PSHU" | "PULU") => Some(0x40),
            _ => None,
        }
    }
}

impl CpuHandler for M6809CpuHandler {
    type Family = M6800FamilyHandler;

    fn family(&self) -> &Self::Family {
        &self.family
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<Operand>, String> {
        let mut result = Vec::with_capacity(family_operands.len());
        for operand in family_operands {
            match operand {
                FamilyOperand::Register(name, span) => {
                    result.push(Operand::Register(name.clone(), *span));
                }
                FamilyOperand::RegisterList(registers, span) => {
                    let mut mask = 0u8;
                    for (name, _) in registers {
                        let Some(bit) = Self::register_list_bit(mnemonic, name) else {
                            return Err(format!(
                                "invalid register {} in {} register list",
                                name.to_ascii_uppercase(),
                                mnemonic.to_ascii_uppercase()
                            ));
                        };
                        mask |= bit;
                    }
                    result.push(Operand::RegisterList(mask, *span));
                }
                FamilyOperand::Indexed { offset, base, span } => {
                    let value = ctx.eval_expr(offset)?;
                    let (postbyte, extra) = Self::indexed_numeric_encoding(value, base)?;
                    result.push(Operand::Indexed {
                        postbyte,
                        extra,
                        span: *span,
                    });
                }
                FamilyOperand::IndexedRegisterOffset { offset, base, span } => {
                    let Some(postbyte) = Self::indexed_register_postbyte(offset, base) else {
                        return Err(format!(
                            "invalid indexed register offset form {},{}",
                            offset.to_ascii_uppercase(),
                            base.to_ascii_uppercase()
                        ));
                    };
                    result.push(Operand::Indexed {
                        postbyte,
                        extra: Vec::new(),
                        span: *span,
                    });
                }
                FamilyOperand::IndexedIndirect { offset, base, span } => {
                    if let Some(base) = base {
                        let value = ctx.eval_expr(offset)?;
                        let (postbyte, extra) =
                            Self::indexed_numeric_encoding_indirect(value, base)?;
                        result.push(Operand::Indexed {
                            postbyte,
                            extra,
                            span: *span,
                        });
                    } else {
                        let value = ctx.eval_expr(offset)?;
                        if !(0..=0xFFFF).contains(&value) {
                            return Err(format!(
                                "indirect extended address {} out of 16-bit range",
                                value
                            ));
                        }
                        let word = value as u16;
                        result.push(Operand::Indexed {
                            postbyte: 0x9F,
                            extra: vec![(word >> 8) as u8, word as u8],
                            span: *span,
                        });
                    }
                }
                FamilyOperand::IndexedIndirectRegisterOffset { offset, base, span } => {
                    let Some(postbyte) = Self::indexed_register_postbyte_indirect(offset, base)
                    else {
                        return Err(format!(
                            "invalid indexed indirect register offset form {},{}",
                            offset.to_ascii_uppercase(),
                            base.to_ascii_uppercase()
                        ));
                    };
                    result.push(Operand::Indexed {
                        postbyte,
                        extra: Vec::new(),
                        span: *span,
                    });
                }
                FamilyOperand::Immediate(expr) => {
                    let value = ctx.eval_expr(expr)?;
                    if Self::is_immediate16_instruction(mnemonic) {
                        if !(0..=0xFFFF).contains(&value) {
                            return Err(format!(
                                "Immediate value {} out of range (0-65535)",
                                value
                            ));
                        }
                        result.push(Operand::Immediate16(value as u16, expr_span(expr)));
                    } else {
                        if !(0..=0xFF).contains(&value) {
                            return Err(format!("Immediate value {} out of range (0-255)", value));
                        }
                        result.push(Operand::Immediate8(value as u8, expr_span(expr)));
                    }
                }
                FamilyOperand::Direct(expr) => {
                    let span = expr_span(expr);
                    let value = ctx.eval_expr(expr)?;
                    if Self::is_rel8_branch(mnemonic) {
                        let target = value;
                        let current = ctx.current_address() as i64 + 2;
                        let offset = target - current;
                        if !(-128..=127).contains(&offset) {
                            if ctx.pass() > 1 {
                                return Err(format!(
                                    "Branch target out of range: offset {}",
                                    offset
                                ));
                            }
                            result.push(Operand::Relative8(0, span));
                        } else {
                            result.push(Operand::Relative8(offset as i8, span));
                        }
                        continue;
                    }
                    if Self::is_rel16_branch(mnemonic) {
                        let target = value;
                        let current = ctx.current_address() as i64 + 3;
                        let offset = target - current;
                        if !(-32768..=32767).contains(&offset) {
                            if ctx.pass() > 1 {
                                return Err(format!(
                                    "Long branch target out of range: offset {}",
                                    offset
                                ));
                            }
                            result.push(Operand::Relative16(0, span));
                        } else {
                            result.push(Operand::Relative16(offset as i16, span));
                        }
                        continue;
                    }
                    if (0..=0xFF).contains(&value) {
                        result.push(Operand::Direct(value as u8, span));
                    } else if (0..=0xFFFF).contains(&value) {
                        result.push(Operand::Extended(value as u16, span));
                    } else {
                        return Err(format!("Address {} out of 16-bit range", value));
                    }
                }
            }
        }
        Ok(result)
    }

    fn encode_instruction(
        &self,
        _mnemonic: &str,
        _operands: &[Operand],
        _ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        EncodeResult::NotFound
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        crate::families::m6800::has_mnemonic(mnemonic)
    }
}
