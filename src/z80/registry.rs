// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Z80 CPU registry module.

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::AssemblerContext;
use crate::core::registry::{CpuHandlerDyn, CpuModule, OperandSet, FamilyOperandSet};
use crate::families::intel8080::registry::DIALECT_ZILOG;
use crate::families::intel8080::registry::{Intel8080FamilyOperands, Intel8080Operands};

use super::Z80CpuHandler;

pub struct Z80CpuModule;

impl CpuModule for Z80CpuModule {
    fn cpu_id(&self) -> CpuType {
        CpuType::Z80
    }

    fn family_id(&self) -> CpuFamily {
        CpuFamily::Intel8080
    }

    fn default_dialect(&self) -> &'static str {
        DIALECT_ZILOG
    }

    fn handler(&self) -> Box<dyn CpuHandlerDyn> {
        Box::new(Z80CpuHandler::new())
    }
}

impl CpuHandlerDyn for Z80CpuHandler {
    fn cpu_id(&self) -> CpuType {
        CpuType::Z80
    }

    fn family_id(&self) -> CpuFamily {
        CpuFamily::Intel8080
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &dyn FamilyOperandSet,
        ctx: &dyn AssemblerContext,
    ) -> Result<Box<dyn OperandSet>, String> {
        let intel_operands = family_operands
            .as_any()
            .downcast_ref::<Intel8080FamilyOperands>()
            .ok_or_else(|| "expected Intel 8080 family operands".to_string())?;
        <Self as crate::core::family::CpuHandler>::resolve_operands(
            self,
            mnemonic,
            &intel_operands.0,
            ctx,
        )
        .map(|ops| Box::new(Intel8080Operands(ops)) as Box<dyn OperandSet>)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        ctx: &dyn AssemblerContext,
    ) -> crate::core::family::EncodeResult<Vec<u8>> {
        let intel_operands = match operands.as_any().downcast_ref::<Intel8080Operands>() {
            Some(ops) => ops,
            None => return crate::core::family::EncodeResult::error("expected Intel 8080 operands"),
        };
        <Self as crate::core::family::CpuHandler>::encode_instruction(self, mnemonic, &intel_operands.0, ctx)
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        <Self as crate::core::family::CpuHandler>::supports_mnemonic(self, mnemonic)
    }
}
