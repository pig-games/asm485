// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65C02 CPU registry module.

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::AssemblerContext;
use crate::core::registry::{CpuHandlerDyn, CpuModule, OperandSet, FamilyOperandSet};
use crate::families::mos6502::registry::DIALECT_TRANSPARENT;
use crate::families::mos6502::registry::{MOS6502FamilyOperands, MOS6502Operands};

use super::M65C02CpuHandler;

pub struct M65C02CpuModule;

impl CpuModule for M65C02CpuModule {
    fn cpu_id(&self) -> CpuType {
        CpuType::M65C02
    }

    fn family_id(&self) -> CpuFamily {
        CpuFamily::MOS6502
    }

    fn default_dialect(&self) -> &'static str {
        DIALECT_TRANSPARENT
    }

    fn handler(&self) -> Box<dyn CpuHandlerDyn> {
        Box::new(M65C02CpuHandler::new())
    }
}

impl CpuHandlerDyn for M65C02CpuHandler {
    fn cpu_id(&self) -> CpuType {
        CpuType::M65C02
    }

    fn family_id(&self) -> CpuFamily {
        CpuFamily::MOS6502
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
    ) -> crate::core::family::EncodeResult<Vec<u8>> {
        let mos_operands = match operands.as_any().downcast_ref::<MOS6502Operands>() {
            Some(ops) => ops,
            None => return crate::core::family::EncodeResult::error("expected MOS 6502 operands"),
        };
        <Self as crate::core::family::CpuHandler>::encode_instruction(self, mnemonic, &mos_operands.0, ctx)
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        <Self as crate::core::family::CpuHandler>::supports_mnemonic(self, mnemonic)
    }
}
