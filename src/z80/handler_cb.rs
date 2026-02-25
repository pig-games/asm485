// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::family::EncodeResult;
use crate::families::intel8080::Operand;

use super::Z80CpuHandler;

impl Z80CpuHandler {
    /// Encode CB-prefixed bit/shift/rotate instructions.
    pub(super) fn encode_cb_instruction(
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
                _ => {
                    return Some(EncodeResult::error(format!(
                        "Unsupported CB-prefix mnemonic '{mnemonic}'"
                    )));
                }
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
            "SLL" => 0x30,
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
}
