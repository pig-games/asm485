// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Motorola 6800 family module.

use std::any::Any;

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::Expr;
use crate::core::registry::{
    DialectModule, FamilyHandlerDyn, FamilyModule, FamilyOperandSet, OperandSet,
};

use super::{FamilyOperand, M6800FamilyHandler, Operand};

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
