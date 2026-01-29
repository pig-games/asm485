// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8080 family module.

use std::any::Any;

use crate::core::cpu::CpuFamily;
use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::Expr;
use crate::core::registry::{
    DialectModule, FamilyHandlerDyn, FamilyModule, FamilyOperandSet, OperandSet,
};

use super::dialect::map_zilog_to_canonical;
use super::{FamilyOperand, Intel8080FamilyHandler, Operand};

pub const DIALECT_INTEL8080: &str = "intel8080";
pub const DIALECT_ZILOG: &str = "zilog";
pub const FAMILY_ID: CpuFamily = CpuFamily::new("intel8080");

pub struct Intel8080FamilyModule;

impl FamilyModule for Intel8080FamilyModule {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn canonical_dialect(&self) -> &'static str {
        DIALECT_INTEL8080
    }

    fn dialects(&self) -> Vec<Box<dyn DialectModule>> {
        vec![Box::new(Intel8080Dialect), Box::new(ZilogDialect)]
    }

    fn handler(&self) -> Box<dyn FamilyHandlerDyn> {
        Box::new(Intel8080FamilyHandler)
    }
}

#[derive(Clone)]
pub struct Intel8080FamilyOperands(pub Vec<FamilyOperand>);

impl FamilyOperandSet for Intel8080FamilyOperands {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn FamilyOperandSet> {
        Box::new(self.clone())
    }
}

#[derive(Clone)]
pub struct Intel8080Operands(pub Vec<Operand>);

impl OperandSet for Intel8080Operands {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn OperandSet> {
        Box::new(self.clone())
    }
}

struct Intel8080Dialect;

impl DialectModule for Intel8080Dialect {
    fn dialect_id(&self) -> &'static str {
        DIALECT_INTEL8080
    }

    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn map_mnemonic(
        &self,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Box<dyn FamilyOperandSet>)> {
        let intel_operands = operands
            .as_any()
            .downcast_ref::<Intel8080FamilyOperands>()?;
        Some((
            mnemonic.to_string(),
            Box::new(Intel8080FamilyOperands(intel_operands.0.clone())),
        ))
    }
}

struct ZilogDialect;

impl DialectModule for ZilogDialect {
    fn dialect_id(&self) -> &'static str {
        DIALECT_ZILOG
    }

    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn map_mnemonic(
        &self,
        mnemonic: &str,
        operands: &dyn FamilyOperandSet,
    ) -> Option<(String, Box<dyn FamilyOperandSet>)> {
        let intel_operands = operands
            .as_any()
            .downcast_ref::<Intel8080FamilyOperands>()?;

        let (mapped_mnemonic, mapped_operands) =
            map_zilog_to_canonical(mnemonic, &intel_operands.0)?;
        Some((
            mapped_mnemonic,
            Box::new(Intel8080FamilyOperands(mapped_operands)),
        ))
    }
}

impl FamilyHandlerDyn for Intel8080FamilyHandler {
    fn family_id(&self) -> CpuFamily {
        FAMILY_ID
    }

    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Box<dyn FamilyOperandSet>, FamilyParseError> {
        <Self as FamilyHandler>::parse_operands(self, mnemonic, exprs)
            .map(|ops| Box::new(Intel8080FamilyOperands(ops)) as Box<dyn FamilyOperandSet>)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        let intel_operands = match operands.as_any().downcast_ref::<Intel8080Operands>() {
            Some(ops) => ops,
            None => return EncodeResult::error("expected Intel 8080 operands"),
        };
        <Self as FamilyHandler>::encode_instruction(self, mnemonic, &intel_operands.0, ctx)
    }

    fn is_register(&self, name: &str) -> bool {
        <Self as FamilyHandler>::is_register(self, name)
    }

    fn is_condition(&self, name: &str) -> bool {
        <Self as FamilyHandler>::is_condition(self, name)
    }

    fn supports_rst(&self) -> bool {
        true
    }
}