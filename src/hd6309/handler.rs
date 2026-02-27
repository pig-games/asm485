// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Hitachi HD6309 CPU handler implementation.

use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::families::m6800::{AddressMode, FamilyOperand, M6800FamilyHandler, Operand};
use crate::m6809::M6809CpuHandler;

#[derive(Debug)]
pub struct HD6309CpuHandler {
    baseline: M6809CpuHandler,
}

impl Default for HD6309CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl HD6309CpuHandler {
    pub fn new() -> Self {
        Self {
            baseline: M6809CpuHandler::new(),
        }
    }
}

impl CpuHandler for HD6309CpuHandler {
    type Family = M6800FamilyHandler;

    fn family(&self) -> &Self::Family {
        <M6809CpuHandler as CpuHandler>::family(&self.baseline)
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<Operand>, String> {
        <M6809CpuHandler as CpuHandler>::resolve_operands(
            &self.baseline,
            mnemonic,
            family_operands,
            ctx,
        )
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        if let Some(entry) =
            super::instructions::lookup_instruction(mnemonic, AddressMode::Inherent)
        {
            if operands.is_empty() {
                return EncodeResult::Ok(entry.opcode_bytes.to_vec());
            }
        }
        <M6809CpuHandler as CpuHandler>::encode_instruction(&self.baseline, mnemonic, operands, ctx)
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        super::instructions::has_mnemonic(mnemonic)
            || <M6809CpuHandler as CpuHandler>::supports_mnemonic(&self.baseline, mnemonic)
    }
}
