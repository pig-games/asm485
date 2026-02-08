// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816 runtime width-state helpers.
//!
//! This module owns the M/X immediate-width policy and state transitions
//! driven by `REP`/`SEP` so assembler-core files remain CPU-agnostic.

use std::collections::HashMap;

use crate::core::cpu::CpuType;
use crate::core::family::AssemblerContext;
use crate::core::registry::OperandSet;
use crate::families::mos6502::module::MOS6502Operands;
use crate::families::mos6502::Operand;
use crate::m65816::module::CPU_ID;

pub const ACCUMULATOR_8BIT_KEY: &str = "m65816.accumulator_8bit";
pub const INDEX_8BIT_KEY: &str = "m65816.index_8bit";

pub fn initial_state_for_cpu(cpu: CpuType) -> HashMap<String, u32> {
    let mut state = HashMap::new();
    if cpu == CPU_ID {
        state.insert(ACCUMULATOR_8BIT_KEY.to_string(), 1);
        state.insert(INDEX_8BIT_KEY.to_string(), 1);
    }
    state
}

pub fn accumulator_is_8bit(ctx: &dyn AssemblerContext) -> bool {
    ctx.cpu_state_flag(ACCUMULATOR_8BIT_KEY).unwrap_or(1) != 0
}

pub fn index_is_8bit(ctx: &dyn AssemblerContext) -> bool {
    ctx.cpu_state_flag(INDEX_8BIT_KEY).unwrap_or(1) != 0
}

pub fn apply_after_encode(
    cpu: CpuType,
    mnemonic: &str,
    operands: &dyn OperandSet,
    state: &mut HashMap<String, u32>,
) {
    if cpu != CPU_ID {
        return;
    }

    let upper = mnemonic.to_ascii_uppercase();
    if !matches!(upper.as_str(), "REP" | "SEP") {
        return;
    }

    let Some(mos_operands) = operands.as_any().downcast_ref::<MOS6502Operands>() else {
        return;
    };

    let mask = match mos_operands.0.first() {
        Some(Operand::Immediate(val, _)) => *val,
        Some(Operand::ImmediateWord(val, _)) => (*val & 0xFF) as u8,
        _ => return,
    };

    if upper == "REP" {
        if mask & 0x20 != 0 {
            state.insert(ACCUMULATOR_8BIT_KEY.to_string(), 0);
        }
        if mask & 0x10 != 0 {
            state.insert(INDEX_8BIT_KEY.to_string(), 0);
        }
    } else {
        if mask & 0x20 != 0 {
            state.insert(ACCUMULATOR_8BIT_KEY.to_string(), 1);
        }
        if mask & 0x10 != 0 {
            state.insert(INDEX_8BIT_KEY.to_string(), 1);
        }
    }
}
