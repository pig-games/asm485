// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Motorola 6800 family module.

use std::any::Any;

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::Expr;
use crate::core::registry::{
    DialectModule, FamilyHandlerDyn, FamilyModule, FamilyOperandSet, OperandSet, VmEncodeCandidate,
};

use super::{AddressMode, FamilyOperand, M6800FamilyHandler, Operand};

pub const DIALECT_MOTOROLA680X: &str = "motorola680x";
pub const FAMILY_ID: CpuFamily = CpuFamily::new("motorola6800");
const FAMILY_CPU_NAME: &str = "6809";
const FAMILY_REGISTER_IDS: &[&str] = &[
    "A", "B", "CC", "DP", "D", "X", "Y", "U", "S", "PC", "E", "F", "W", "V", "MD",
];

fn family_form_mnemonics() -> Vec<String> {
    let mut mnemonics: Vec<String> = super::table::FAMILY_INSTRUCTION_TABLE
        .iter()
        .map(|entry| entry.mnemonic.to_ascii_lowercase())
        .collect();
    mnemonics.sort();
    mnemonics.dedup();
    mnemonics
}

pub struct Motorola6800FamilyModule;

impl FamilyModule for Motorola6800FamilyModule {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn family_cpu_id(&self) -> Option<CpuType> {
        Some(crate::m6809::module::CPU_ID)
    }

    fn family_cpu_name(&self) -> Option<&'static str> {
        Some(FAMILY_CPU_NAME)
    }

    fn canonical_dialect(&self) -> &'static str {
        DIALECT_MOTOROLA680X
    }

    fn register_ids(&self) -> &'static [&'static str] {
        FAMILY_REGISTER_IDS
    }

    fn form_mnemonics(&self) -> Vec<String> {
        family_form_mnemonics()
    }

    fn dialects(&self) -> Vec<Box<dyn DialectModule>> {
        vec![Box::new(CanonicalDialect)]
    }

    fn handler(&self) -> Box<dyn FamilyHandlerDyn> {
        Box::new(M6800FamilyHandler::new())
    }
}

#[derive(Clone)]
pub struct M6800FamilyOperands(pub Vec<FamilyOperand>);

impl FamilyOperandSet for M6800FamilyOperands {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn FamilyOperandSet> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct M6800Operands(pub Vec<Operand>);

impl OperandSet for M6800Operands {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn OperandSet> {
        Box::new(self.clone())
    }

    fn vm_encode_candidates(&self) -> Vec<VmEncodeCandidate> {
        vm_encode_candidates_for_operands(&self.0)
    }
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

fn mode_key(mode: AddressMode) -> String {
    format!("{mode:?}").to_ascii_lowercase()
}

pub(crate) fn vm_encode_candidates_for_operands(operands: &[Operand]) -> Vec<VmEncodeCandidate> {
    let Some(candidate) = vm_encode_candidate_for_operands(operands) else {
        return Vec::new();
    };
    vec![candidate]
}

fn vm_encode_candidate_for_operands(operands: &[Operand]) -> Option<VmEncodeCandidate> {
    match operands {
        [] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::Inherent),
            operand_bytes: Vec::new(),
        }),
        [Operand::Immediate8(value, _)] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::Immediate8),
            operand_bytes: vec![vec![*value]],
        }),
        [Operand::Immediate16(value, _)] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::Immediate16),
            operand_bytes: vec![vec![(*value >> 8) as u8, *value as u8]],
        }),
        [Operand::Direct(value, _)] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::Direct),
            operand_bytes: vec![vec![*value]],
        }),
        [Operand::Extended(value, _)] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::Extended),
            operand_bytes: vec![vec![(*value >> 8) as u8, *value as u8]],
        }),
        [Operand::Indexed {
            postbyte, extra, ..
        }] => {
            let mut encoded = Vec::with_capacity(1 + extra.len());
            encoded.push(*postbyte);
            encoded.extend(extra.iter().copied());
            Some(VmEncodeCandidate {
                mode_key: mode_key(AddressMode::Indexed),
                operand_bytes: vec![encoded],
            })
        }
        [Operand::Relative8(offset, _)] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::Relative8),
            operand_bytes: vec![vec![*offset as u8]],
        }),
        [Operand::Relative16(offset, _)] => {
            let raw = *offset as u16;
            Some(VmEncodeCandidate {
                mode_key: mode_key(AddressMode::Relative16),
                operand_bytes: vec![vec![(raw >> 8) as u8, raw as u8]],
            })
        }
        [Operand::RegisterList(mask, _)] => Some(VmEncodeCandidate {
            mode_key: mode_key(AddressMode::RegisterList),
            operand_bytes: vec![vec![*mask]],
        }),
        [Operand::Register(src, _), Operand::Register(dst, _)] => {
            let src_code = register_code(src)?;
            let dst_code = register_code(dst)?;
            if register_pair_size(src_code) != register_pair_size(dst_code) {
                return None;
            }
            Some(VmEncodeCandidate {
                mode_key: mode_key(AddressMode::RegisterPair),
                operand_bytes: vec![vec![(src_code << 4) | dst_code]],
            })
        }
        _ => None,
    }
}

struct CanonicalDialect;

impl DialectModule for CanonicalDialect {
    fn dialect_id(&self) -> &'static str {
        DIALECT_MOTOROLA680X
    }

    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn map_mnemonic(
        &self,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Box<dyn FamilyOperandSet>)> {
        let m6800_operands = operands.as_any().downcast_ref::<M6800FamilyOperands>()?;
        Some((
            mnemonic.to_string(),
            Box::new(M6800FamilyOperands(m6800_operands.0.clone())),
        ))
    }
}

impl FamilyHandlerDyn for M6800FamilyHandler {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Box<dyn FamilyOperandSet>, FamilyParseError> {
        <Self as FamilyHandler>::parse_operands(self, mnemonic, exprs)
            .map(|ops| Box::new(M6800FamilyOperands(ops)) as Box<dyn FamilyOperandSet>)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        let m6800_operands = match operands.as_any().downcast_ref::<M6800Operands>() {
            Some(ops) => ops,
            None => return EncodeResult::error("expected Motorola 6800 operands"),
        };
        <Self as FamilyHandler>::encode_instruction(self, mnemonic, &m6800_operands.0, ctx)
    }

    fn is_register(&self, name: &str) -> bool {
        <Self as FamilyHandler>::is_register(self, name)
    }

    fn is_condition(&self, name: &str) -> bool {
        <Self as FamilyHandler>::is_condition(self, name)
    }
}
