// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 45GS02 CPU module.

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::{AssemblerContext, CpuHandler};
use crate::core::registry::{CpuHandlerDyn, CpuModule, FamilyOperandSet, OperandSet};
use crate::families::mos6502::module::{
    MOS6502FamilyOperands, MOS6502Operands, DIALECT_TRANSPARENT, FAMILY_ID as MOS6502_FAMILY_ID,
};

use super::M45GS02CpuHandler;

pub struct M45GS02CpuModule;

pub const CPU_ID: CpuType = CpuType::new("45gs02");
const CPU_ALIASES: &[&str] = &["m45gs02", "mega65", "4510", "csg4510"];
const REGISTER_IDS: &[&str] = &["A", "X", "Y", "Z"];

fn cpu_form_mnemonics() -> Vec<String> {
    let mut mnemonics: Vec<String> = crate::families::mos6502::FAMILY_INSTRUCTION_TABLE
        .iter()
        .map(|entry| entry.mnemonic.to_ascii_lowercase())
        .collect();

    mnemonics.extend(
        crate::m65c02::instructions::CPU_INSTRUCTION_TABLE
            .iter()
            .map(|entry| entry.mnemonic.to_ascii_lowercase()),
    );
    mnemonics.extend(
        super::instructions::CPU_INSTRUCTION_TABLE
            .iter()
            .map(|entry| entry.mnemonic.to_ascii_lowercase()),
    );
    mnemonics.extend(
        [
            "ldq", "stq", "adcq", "andq", "cmpq", "eorq", "ldaq", "oraq", "sbcq",
        ]
        .into_iter()
        .map(str::to_string),
    );

    mnemonics.sort();
    mnemonics.dedup();
    mnemonics
}

impl CpuModule for M45GS02CpuModule {
    fn cpu_id(&self) -> CpuType {
        CPU_ID
    }

    fn family_id(&self) -> CpuFamily {
        MOS6502_FAMILY_ID
    }

    fn cpu_name(&self) -> &'static str {
        CPU_ID.as_str()
    }

    fn cpu_aliases(&self) -> &'static [&'static str] {
        CPU_ALIASES
    }

    fn default_dialect(&self) -> &'static str {
        DIALECT_TRANSPARENT
    }

    fn register_ids(&self) -> &'static [&'static str] {
        REGISTER_IDS
    }

    fn form_mnemonics(&self) -> Vec<String> {
        cpu_form_mnemonics()
    }

    fn handler(&self) -> Box<dyn CpuHandlerDyn> {
        Box::new(M45GS02CpuHandler::new())
    }
}

impl CpuHandlerDyn for M45GS02CpuHandler {
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
        <Self as CpuHandler>::resolve_operands(self, mnemonic, &mos_operands.0, ctx)
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
        <Self as CpuHandler>::encode_instruction(self, mnemonic, &mos_operands.0, ctx)
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        <Self as CpuHandler>::supports_mnemonic(self, mnemonic)
    }
}
