// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816 runtime width-state helpers.
//!
//! This module owns the M/X immediate-width policy and state transitions
//! driven by `REP`/`SEP` so assembler-core files remain CPU-agnostic.

use std::collections::HashMap;

use crate::core::family::AssemblerContext;
use crate::core::parser::{BinaryOp, Expr};
use crate::families::mos6502::Operand;

pub const ACCUMULATOR_8BIT_KEY: &str = "m65816.accumulator_8bit";
pub const INDEX_8BIT_KEY: &str = "m65816.index_8bit";
pub const EMULATION_MODE_KEY: &str = "m65816.emulation_mode";
pub const DATA_BANK_KEY: &str = "m65816.data_bank";
pub const PROGRAM_BANK_KEY: &str = "m65816.program_bank";
pub const PROGRAM_BANK_EXPLICIT_KEY: &str = "m65816.program_bank_explicit";
pub const DIRECT_PAGE_KEY: &str = "m65816.direct_page";

pub fn initial_state() -> HashMap<String, u32> {
    let mut state = HashMap::new();
    state.insert(EMULATION_MODE_KEY.to_string(), 0);
    state.insert(ACCUMULATOR_8BIT_KEY.to_string(), 1);
    state.insert(INDEX_8BIT_KEY.to_string(), 1);
    state.insert(DATA_BANK_KEY.to_string(), 0);
    state.insert(PROGRAM_BANK_KEY.to_string(), 0);
    state.insert(PROGRAM_BANK_EXPLICIT_KEY.to_string(), 0);
    state.insert(DIRECT_PAGE_KEY.to_string(), 0);
    state
}

pub fn emulation_mode(ctx: &dyn AssemblerContext) -> bool {
    ctx.cpu_state_flag(EMULATION_MODE_KEY).unwrap_or(0) != 0
}

pub fn accumulator_is_8bit(ctx: &dyn AssemblerContext) -> bool {
    if emulation_mode(ctx) {
        return true;
    }
    ctx.cpu_state_flag(ACCUMULATOR_8BIT_KEY).unwrap_or(1) != 0
}

pub fn index_is_8bit(ctx: &dyn AssemblerContext) -> bool {
    if emulation_mode(ctx) {
        return true;
    }
    ctx.cpu_state_flag(INDEX_8BIT_KEY).unwrap_or(1) != 0
}

pub fn data_bank(ctx: &dyn AssemblerContext) -> u8 {
    ctx.cpu_state_flag(DATA_BANK_KEY).unwrap_or(0) as u8
}

pub fn program_bank(ctx: &dyn AssemblerContext) -> u8 {
    if ctx.cpu_state_flag(PROGRAM_BANK_EXPLICIT_KEY).unwrap_or(0) != 0 {
        return ctx.cpu_state_flag(PROGRAM_BANK_KEY).unwrap_or(0) as u8;
    }
    ((ctx.current_address() >> 16) & 0xFF) as u8
}

pub fn direct_page(ctx: &dyn AssemblerContext) -> u16 {
    ctx.cpu_state_flag(DIRECT_PAGE_KEY).unwrap_or(0) as u16
}

pub fn apply_runtime_directive(
    directive: &str,
    operands: &[Expr],
    ctx: &dyn AssemblerContext,
    state: &mut HashMap<String, u32>,
) -> Result<bool, String> {
    if !directive.eq_ignore_ascii_case("ASSUME") {
        return Ok(false);
    }
    apply_assume_directive(operands, ctx, state)?;
    Ok(true)
}

pub fn apply_after_encode(mnemonic: &str, operands: &[Operand], state: &mut HashMap<String, u32>) {
    let upper = mnemonic.to_ascii_uppercase();
    if !matches!(upper.as_str(), "REP" | "SEP") {
        return;
    }

    // Emulation mode forces M/X to 8-bit regardless of REP/SEP effects.
    if emulation_mode_from_state(state) {
        force_mx_8bit(state);
        return;
    }

    let mask = match operands.first() {
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

fn emulation_mode_from_state(state: &HashMap<String, u32>) -> bool {
    state.get(EMULATION_MODE_KEY).copied().unwrap_or(0) != 0
}

fn force_mx_8bit(state: &mut HashMap<String, u32>) {
    state.insert(ACCUMULATOR_8BIT_KEY.to_string(), 1);
    state.insert(INDEX_8BIT_KEY.to_string(), 1);
}

#[derive(Default)]
struct AssumeUpdate {
    emulation: Option<bool>,
    m_8bit: Option<bool>,
    x_8bit: Option<bool>,
    dbr: Option<u8>,
    pbr: Option<u8>,
    dp: Option<u16>,
}

fn apply_assume_directive(
    operands: &[Expr],
    ctx: &dyn AssemblerContext,
    state: &mut HashMap<String, u32>,
) -> Result<(), String> {
    if operands.is_empty() {
        return Err("Expected .assume key=value options".to_string());
    }

    let mut update = AssumeUpdate::default();
    for option in operands {
        let Expr::Binary {
            op, left, right, ..
        } = option
        else {
            return Err("Invalid .assume option; expected key=value".to_string());
        };
        if *op != BinaryOp::Eq {
            return Err("Invalid .assume option; expected key=value".to_string());
        }
        let key = option_key(left).ok_or_else(|| {
            "Invalid .assume option key; expected identifier on the left of '='".to_string()
        })?;
        match key.as_str() {
            "e" => {
                if update.emulation.is_some() {
                    return Err("Duplicate .assume option: e".to_string());
                }
                update.emulation = Some(parse_emulation_value(right, ctx)?);
            }
            "m" => {
                if update.m_8bit.is_some() {
                    return Err("Duplicate .assume option: m".to_string());
                }
                update.m_8bit = Some(parse_width_value(right, ctx, "m")?);
            }
            "x" => {
                if update.x_8bit.is_some() {
                    return Err("Duplicate .assume option: x".to_string());
                }
                update.x_8bit = Some(parse_width_value(right, ctx, "x")?);
            }
            "dbr" | "db" => {
                if update.dbr.is_some() {
                    return Err("Duplicate .assume option: dbr".to_string());
                }
                update.dbr = Some(parse_u8_value(right, ctx, "dbr")?);
            }
            "pbr" | "pb" => {
                if update.pbr.is_some() {
                    return Err("Duplicate .assume option: pbr".to_string());
                }
                update.pbr = Some(parse_u8_value(right, ctx, "pbr")?);
            }
            "dp" => {
                if update.dp.is_some() {
                    return Err("Duplicate .assume option: dp".to_string());
                }
                update.dp = Some(parse_u16_value(right, ctx, "dp")?);
            }
            _ => {
                return Err(format!(
                    "Unknown .assume option '{key}' (expected e,m,x,dbr,pbr,dp)"
                ))
            }
        }
    }

    if let Some(emulation) = update.emulation {
        state.insert(EMULATION_MODE_KEY.to_string(), u32::from(emulation));
        if emulation {
            force_mx_8bit(state);
        }
    }

    let emulation_now = emulation_mode_from_state(state);
    if let Some(m_8bit) = update.m_8bit {
        if emulation_now && !m_8bit {
            return Err(".assume m=16 requires native mode (e=0)".to_string());
        }
        state.insert(ACCUMULATOR_8BIT_KEY.to_string(), u32::from(m_8bit));
    }
    if let Some(x_8bit) = update.x_8bit {
        if emulation_now && !x_8bit {
            return Err(".assume x=16 requires native mode (e=0)".to_string());
        }
        state.insert(INDEX_8BIT_KEY.to_string(), u32::from(x_8bit));
    }
    if let Some(dbr) = update.dbr {
        state.insert(DATA_BANK_KEY.to_string(), dbr as u32);
    }
    if let Some(pbr) = update.pbr {
        state.insert(PROGRAM_BANK_KEY.to_string(), pbr as u32);
        state.insert(PROGRAM_BANK_EXPLICIT_KEY.to_string(), 1);
    }
    if let Some(dp) = update.dp {
        state.insert(DIRECT_PAGE_KEY.to_string(), dp as u32);
    }

    Ok(())
}

fn option_key(expr: &Expr) -> Option<String> {
    let raw = match expr {
        Expr::Identifier(name, _) | Expr::Register(name, _) => name,
        _ => return None,
    };
    Some(raw.to_ascii_lowercase())
}

fn parse_width_value(expr: &Expr, ctx: &dyn AssemblerContext, name: &str) -> Result<bool, String> {
    if let Some(text) = expr_text(expr) {
        return match text.to_ascii_lowercase().as_str() {
            "8" | "byte" => Ok(true),
            "16" | "word" => Ok(false),
            _ => Err(format!(".assume {name}=... must be 8 or 16")),
        };
    }
    match ctx.eval_expr(expr) {
        Ok(8) => Ok(true),
        Ok(16) => Ok(false),
        Ok(_) => Err(format!(".assume {name}=... must be 8 or 16")),
        Err(err) => Err(err),
    }
}

fn parse_emulation_value(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<bool, String> {
    if let Some(text) = expr_text(expr) {
        return match text.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "emulation" | "emul" => Ok(true),
            "0" | "false" | "no" | "off" | "native" => Ok(false),
            _ => Err(".assume e=... must be emulation/native or 1/0".to_string()),
        };
    }
    match ctx.eval_expr(expr) {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        Ok(_) => Err(".assume e=... must be emulation/native or 1/0".to_string()),
        Err(err) => Err(err),
    }
}

fn parse_u8_value(expr: &Expr, ctx: &dyn AssemblerContext, name: &str) -> Result<u8, String> {
    let value = ctx.eval_expr(expr)?;
    if !(0..=255).contains(&value) {
        return Err(format!(
            ".assume {name}=... value {value} out of range (0-255)"
        ));
    }
    Ok(value as u8)
}

fn parse_u16_value(expr: &Expr, ctx: &dyn AssemblerContext, name: &str) -> Result<u16, String> {
    let value = ctx.eval_expr(expr)?;
    if !(0..=65535).contains(&value) {
        return Err(format!(
            ".assume {name}=... value {value} out of range (0-65535)"
        ));
    }
    Ok(value as u16)
}

fn expr_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(text, _) | Expr::Register(text, _) | Expr::Number(text, _) => {
            Some(text.clone())
        }
        Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
        _ => None,
    }
}
