// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65C02 CPU module.

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::AssemblerContext;
use crate::core::registry::{CpuHandlerDyn, CpuModule, FamilyOperandSet, OperandSet};
use crate::families::mos6502::module::{
    DIALECT_TRANSPARENT, FAMILY_ID as MOS6502_FAMILY_ID, MOS6502FamilyOperands,
    MOS6502Operands,
};

use super::M65C02CpuHandler;

pub struct M65C02CpuModule;

pub const CPU_ID: CpuType = CpuType::new("m65c02");
pub const CPU_NAMES: &[&str] = &["65c02", "m65c02", "w65c02", "wdc65c02"];

impl CpuModule for M65C02CpuModule {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        MOS6502_FAMILY_ID
    }

    fn cpu_names(&self) -> &'static [&'static str] {
        CPU_NAMES
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
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        MOS6502_FAMILY_ID
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
            None => {
                return crate::core::family::EncodeResult::error(
                    "expected MOS 6502 operands",
                )
            }
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