// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816 CPU module.

use std::collections::HashMap;

use crate::core::cpu::{CpuFamily, CpuType};
use crate::core::family::AssemblerContext;
use crate::core::registry::{CpuHandlerDyn, CpuModule, FamilyOperandSet, OperandSet};
use crate::families::mos6502::module::{
    MOS6502FamilyOperands, MOS6502Operands, DIALECT_TRANSPARENT, FAMILY_ID as MOS6502_FAMILY_ID,
};

use super::{state, M65816CpuHandler};

pub struct M65816CpuModule;

pub const CPU_ID: CpuType = CpuType::new("65816");
const CPU_ALIASES: &[&str] = &["65c816", "w65c816"];

impl CpuModule for M65816CpuModule {
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

    fn handler(&self) -> Box<dyn CpuHandlerDyn> {
        Box::new(M65816CpuHandler::new())
    }
}

impl CpuHandlerDyn for M65816CpuHandler {
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
            None => return crate::core::family::EncodeResult::error("expected MOS 6502 operands"),
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

    fn max_program_address(&self) -> u32 {
        u32::MAX
    }

    fn runtime_state_defaults(&self) -> HashMap<String, u32> {
        state::initial_state()
    }

    fn update_runtime_state_after_encode(
        &self,
        mnemonic: &str,
        operands: &dyn OperandSet,
        state_flags: &mut HashMap<String, u32>,
    ) {
        let Some(mos_operands) = operands.as_any().downcast_ref::<MOS6502Operands>() else {
            return;
        };
        state::apply_after_encode(mnemonic, &mos_operands.0, state_flags);
    }
}
