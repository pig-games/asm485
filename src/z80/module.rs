// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Z80 CPU module.

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::AssemblerContext;
use crate::core::registry::{CpuHandlerDyn, CpuModule, FamilyOperandSet, OperandSet};
use crate::families::intel8080::module::{
    Intel8080FamilyOperands, Intel8080Operands, DIALECT_ZILOG, FAMILY_ID as INTEL8080_FAMILY_ID,
};

use super::Z80CpuHandler;

pub struct Z80CpuModule;

pub const CPU_ID: CpuType = CpuType::new("z80");
const CPU_REGISTER_IDS: &[&str] = &[
    "AF", "AF'", "I", "R", "IX", "IY", "IXH", "IXL", "IYH", "IYL",
];

fn cpu_form_mnemonics() -> Vec<String> {
    let mut mnemonics: Vec<String> = super::Z80_EXTENSION_TABLE
        .iter()
        .map(|entry| entry.mnemonic.to_ascii_lowercase())
        .collect();
    mnemonics.sort();
    mnemonics.dedup();
    mnemonics
}

impl CpuModule for Z80CpuModule {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        INTEL8080_FAMILY_ID
    }

    fn cpu_name(&self) -> &'static str {
        CPU_ID.as_str()
    }

    fn default_dialect(&self) -> &'static str {
        DIALECT_ZILOG
    }

    fn register_ids(&self) -> &'static [&'static str] {
        CPU_REGISTER_IDS
    }

    fn form_mnemonics(&self) -> Vec<String> {
        cpu_form_mnemonics()
    }

    fn handler(&self) -> Box<dyn CpuHandlerDyn> {
        Box::new(Z80CpuHandler::new())
    }
}

impl CpuHandlerDyn for Z80CpuHandler {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        INTEL8080_FAMILY_ID
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
            None => {
                return crate::core::family::EncodeResult::error("expected Intel 8080 operands")
            }
        };
        <Self as crate::core::family::CpuHandler>::encode_instruction(
            self,
            mnemonic,
            &intel_operands.0,
            ctx,
        )
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        <Self as crate::core::family::CpuHandler>::supports_mnemonic(self, mnemonic)
    }
}
