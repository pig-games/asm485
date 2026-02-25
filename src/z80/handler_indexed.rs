// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::family::EncodeResult;
use crate::families::intel8080::Operand;

use super::Z80CpuHandler;

impl Z80CpuHandler {
    /// Encode `LD` forms that use `(nn)` absolute memory indirection.
    ///
    /// These forms are distinct from plain immediate loads and therefore
    /// cannot be handled by the generic extension table lookup.
    pub(super) fn encode_ld_indirect_forms(
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
    pub(super) fn encode_jp_index_indirect(
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
    pub(super) fn encode_indexed_memory_forms(
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
}
