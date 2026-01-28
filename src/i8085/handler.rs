// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8085 CPU handler implementation.
//!
//! This handler implements the CpuHandler trait for the 8085, using the
//! Intel8080 family handler. The 8085 adds RIM and SIM instructions
//! over the base 8080.

use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::families::intel8080::handler::{resolve_operands, Intel8080FamilyHandler};
use crate::families::intel8080::{FamilyOperand, Operand};

/// CPU handler for Intel 8085.
#[derive(Debug)]
pub struct I8085CpuHandler {
    family: Intel8080FamilyHandler,
}

impl Default for I8085CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl I8085CpuHandler {
    pub fn new() -> Self {
        Self {
            family: Intel8080FamilyHandler,
        }
    }
}

impl CpuHandler for I8085CpuHandler {
    type Family = Intel8080FamilyHandler;

    fn family(&self) -> &Self::Family {
        &self.family
    }

    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<Operand>, String> {
        resolve_operands(mnemonic, family_operands, ctx).map_err(|e| e.message)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Operand],
        _ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        let upper = mnemonic.to_ascii_uppercase();

        // 8085-specific instructions
        match upper.as_str() {
            "RIM" => {
                if !operands.is_empty() {
                    return EncodeResult::error("RIM takes no operands");
                }
                EncodeResult::Ok(vec![0x20])
            }
            "SIM" => {
                if !operands.is_empty() {
                    return EncodeResult::error("SIM takes no operands");
                }
                EncodeResult::Ok(vec![0x30])
            }
            _ => EncodeResult::NotFound,
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        let upper = mnemonic.to_ascii_uppercase();
        matches!(upper.as_str(), "RIM" | "SIM")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_rim_sim() {
        let handler = I8085CpuHandler::new();
        assert!(handler.supports_mnemonic("RIM"));
        assert!(handler.supports_mnemonic("SIM"));
        assert!(handler.supports_mnemonic("rim"));
        assert!(!handler.supports_mnemonic("LD")); // Z80
    }
}
