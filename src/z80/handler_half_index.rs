// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::family::EncodeResult;
use crate::families::intel8080::Operand;

use super::Z80CpuHandler;

impl Z80CpuHandler {
    /// Encode undocumented Z80 half-index register forms (IXH/IXL/IYH/IYL).
    pub(super) fn encode_half_index_register_forms(
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
}
