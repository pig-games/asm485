// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! MOS 6502 family module.

use std::any::Any;

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::Expr;
use crate::core::registry::{
    CpuHandlerDyn, CpuModule, DialectModule, FamilyHandlerDyn, FamilyModule, FamilyOperandSet,
    OperandSet,
};

use super::{FamilyOperand, M6502CpuHandler, MOS6502FamilyHandler, Operand};

pub const DIALECT_TRANSPARENT: &str = "transparent";
pub const FAMILY_ID: CpuFamily = CpuFamily::new("mos6502");
pub const CPU_ID: CpuType = CpuType::new("m6502");
const FAMILY_CPU_NAME: &str = "6502";
const FAMILY_REGISTER_IDS: &[&str] = &["A", "X", "Y"];

fn family_form_mnemonics() -> Vec<String> {
    let mut mnemonics: Vec<String> = super::table::FAMILY_INSTRUCTION_TABLE
        .iter()
        .map(|entry| entry.mnemonic.to_ascii_lowercase())
        .collect();
    mnemonics.sort();
    mnemonics.dedup();
    mnemonics
}

pub struct MOS6502FamilyModule;

impl FamilyModule for MOS6502FamilyModule {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn family_cpu_id(&self) -> Option<CpuType> {
        Some(CPU_ID)
    }

    fn family_cpu_name(&self) -> Option<&'static str> {
        Some(FAMILY_CPU_NAME)
    }

    fn canonical_dialect(&self) -> &'static str {
        DIALECT_TRANSPARENT
    }

    fn register_ids(&self) -> &'static [&'static str] {
        FAMILY_REGISTER_IDS
    }

    fn form_mnemonics(&self) -> Vec<String> {
        family_form_mnemonics()
    }

    fn dialects(&self) -> Vec<Box<dyn DialectModule>> {
        vec![Box::new(TransparentDialect)]
    }

    fn handler(&self) -> Box<dyn FamilyHandlerDyn> {
        Box::new(MOS6502FamilyHandler::new())
    }
}

#[derive(Clone)]
pub struct MOS6502FamilyOperands(pub Vec<FamilyOperand>);

impl FamilyOperandSet for MOS6502FamilyOperands {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn FamilyOperandSet> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct MOS6502Operands(pub Vec<Operand>);

impl OperandSet for MOS6502Operands {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn OperandSet> {
        Box::new(self.clone())
    }
}

pub struct M6502CpuModule;

impl CpuModule for M6502CpuModule {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn cpu_name(&self) -> &'static str {
        CPU_ID.as_str()
    }

    fn default_dialect(&self) -> &'static str {
        DIALECT_TRANSPARENT
    }

    fn handler(&self) -> Box<dyn CpuHandlerDyn> {
        Box::new(M6502CpuHandler::new())
    }
}

struct TransparentDialect;

impl DialectModule for TransparentDialect {
    fn dialect_id(&self) -> &'static str {
        DIALECT_TRANSPARENT
    }

    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn map_mnemonic(
        &self,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Box<dyn FamilyOperandSet>)> {
        let mos_operands = operands.as_any().downcast_ref::<MOS6502FamilyOperands>()?;
        Some((
            mnemonic.to_string(),
            Box::new(MOS6502FamilyOperands(mos_operands.0.clone())),
        ))
    }
}

impl FamilyHandlerDyn for MOS6502FamilyHandler {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Box<dyn FamilyOperandSet>, FamilyParseError> {
        <Self as FamilyHandler>::parse_operands(self, mnemonic, exprs)
            .map(|ops| Box::new(MOS6502FamilyOperands(ops)) as Box<dyn FamilyOperandSet>)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        let mos_operands = match operands.as_any().downcast_ref::<MOS6502Operands>() {
            Some(ops) => ops,
            None => return EncodeResult::error("expected MOS 6502 operands"),
        };
        <Self as FamilyHandler>::encode_instruction(self, mnemonic, &mos_operands.0, ctx)
    }

    fn is_register(&self, name: &str) -> bool {
        <Self as FamilyHandler>::is_register(self, name)
    }

    fn is_condition(&self, name: &str) -> bool {
        <Self as FamilyHandler>::is_condition(self, name)
    }
}

impl CpuHandlerDyn for M6502CpuHandler {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &dyn FamilyOperandSet,
        ctx: &dyn AssemblerContext,
    ) -> Result<Box<dyn OperandSet>, String> {
        let mos_operands = family_operands
            .as_any()
            .downcast_ref::<MOS6502FamilyOperands>()
            .ok_or_else(|| "expected MOS 6502 family operands".to_string())?;
        <Self as crate::core::family::CpuHandler>::resolve_operands(
            self,
            mnemonic,
            &mos_operands.0,
            ctx,
        )
        .map(|ops| Box::new(MOS6502Operands(ops)) as Box<dyn OperandSet>)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        let mos_operands = match operands.as_any().downcast_ref::<MOS6502Operands>() {
            Some(ops) => ops,
            None => return EncodeResult::error("expected MOS 6502 operands"),
        };
        <Self as crate::core::family::CpuHandler>::encode_instruction(
            self,
            mnemonic,
            &mos_operands.0,
            ctx,
        )
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        <Self as crate::core::family::CpuHandler>::supports_mnemonic(self, mnemonic)
    }
}
