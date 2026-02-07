// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816 CPU handler implementation.
//!
//! The M1 skeleton delegates operand resolution and currently-supported
//! extension encodings to the existing 65C02 handler to provide a safe baseline
//! while the 65816-specific parser/encoding work lands in later milestones.

use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::families::mos6502::{
    has_mnemonic as has_family_mnemonic, AddressMode, FamilyOperand, Operand,
};
use crate::m65816::instructions::{has_mnemonic, lookup_instruction};

/// CPU handler for WDC 65816.
#[derive(Debug)]
pub struct M65816CpuHandler {
    baseline: crate::m65c02::M65C02CpuHandler,
}

impl Default for M65816CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl M65816CpuHandler {
    pub fn new() -> Self {
        Self {
            baseline: crate::m65c02::M65C02CpuHandler::new(),
        }
    }
}

impl CpuHandler for M65816CpuHandler {
    type Family = crate::families::mos6502::MOS6502FamilyHandler;

    fn family(&self) -> &Self::Family {
        <crate::m65c02::M65C02CpuHandler as CpuHandler>::family(&self.baseline)
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<Operand>, String> {
        <crate::m65c02::M65C02CpuHandler as CpuHandler>::resolve_operands(
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
        let mode = if operands.is_empty() {
            AddressMode::Implied
        } else {
            operands[0].mode()
        };

        if let Some(entry) = lookup_instruction(mnemonic, mode) {
            let mut bytes = vec![entry.opcode];
            for operand in operands {
                bytes.extend(operand.value_bytes());
            }
            return EncodeResult::Ok(bytes);
        }

        <crate::m65c02::M65C02CpuHandler as CpuHandler>::encode_instruction(
            &self.baseline,
            mnemonic,
            operands,
            ctx,
        )
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        has_mnemonic(mnemonic)
            || <crate::m65c02::M65C02CpuHandler as CpuHandler>::supports_mnemonic(
                &self.baseline,
                mnemonic,
            )
            || has_family_mnemonic(mnemonic)
    }
}
