// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816 CPU handler implementation.

use crate::core::family::{expr_has_unstable_symbols, AssemblerContext, CpuHandler, EncodeResult};
use crate::families::mos6502::{
    has_mnemonic as has_family_mnemonic, lookup_instruction as lookup_family_instruction,
    AddressMode, FamilyOperand, Operand, OperandForce,
};
use crate::m65816::instructions::{has_mnemonic, lookup_instruction};
use crate::m65816::state;
use crate::m65c02::instructions::lookup_instruction as lookup_m65c02_instruction;

/// CPU handler for WDC 65816.
#[derive(Debug)]
pub struct M65816CpuHandler {
    baseline: crate::m65c02::M65C02CpuHandler,
}

struct DirectPageResolutionSpec {
    zero_page_mode: AddressMode,
    absolute_mode: AddressMode,
    zero_page_ctor: fn(u8, crate::core::tokenizer::Span) -> Operand,
    absolute_ctor: fn(u16, crate::core::tokenizer::Span) -> Operand,
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

    fn upper_mnemonic(mnemonic: &str) -> String {
        mnemonic.to_ascii_uppercase()
    }

    fn is_m65c02_only_mnemonic_for_65816(upper_mnemonic: &str) -> bool {
        matches!(
            upper_mnemonic,
            "RMB0"
                | "RMB1"
                | "RMB2"
                | "RMB3"
                | "RMB4"
                | "RMB5"
                | "RMB6"
                | "RMB7"
                | "SMB0"
                | "SMB1"
                | "SMB2"
                | "SMB3"
                | "SMB4"
                | "SMB5"
                | "SMB6"
                | "SMB7"
        )
    }

    fn resolve_direct(
        &self,
        mnemonic: &str,
        expr: &crate::core::parser::Expr,
        ctx: &dyn AssemblerContext,
    ) -> Result<Operand, String> {
        let upper = Self::upper_mnemonic(mnemonic);
        let val = ctx.eval_expr(expr)?;
        let span = crate::core::assembler::expression::expr_span(expr);

        if matches!(upper.as_str(), "BRL" | "PER") {
            let current = ctx.current_address() as i64 + 3;
            let offset = val - current;
            if !(-32768..=32767).contains(&offset) {
                if ctx.pass() > 1 {
                    return Err(format!(
                        "Long branch target out of range: offset {}",
                        offset
                    ));
                }
                return Ok(Operand::RelativeLong(0, span));
            }
            return Ok(Operand::RelativeLong(offset as i16, span));
        }

        if upper == "PEA" {
            if (0..=65535).contains(&val) {
                return Ok(Operand::Absolute(val as u16, span));
            }
            return Err(format!("PEA operand {} out of 16-bit range", val));
        }

        if matches!(upper.as_str(), "JSL" | "JML") {
            if (0..=0xFF_FFFF).contains(&val) {
                return Ok(Operand::AbsoluteLong(val as u32, span));
            }
            return Err(format!("Long address {} out of 24-bit range", val));
        }

        if (0..=255).contains(&val) {
            return Ok(Operand::ZeroPage(val as u8, span));
        }
        if (0..=65535).contains(&val) {
            return Ok(Operand::Absolute(val as u16, span));
        }
        if (0..=0xFF_FFFF).contains(&val) {
            return Ok(Operand::AbsoluteLong(val as u32, span));
        }
        Err(format!("Address {} out of 24-bit range", val))
    }

    fn is_accumulator_width_immediate_mnemonic(mnemonic: &str) -> bool {
        matches!(
            mnemonic,
            "ADC" | "AND" | "BIT" | "CMP" | "EOR" | "LDA" | "ORA" | "SBC"
        )
    }

    fn is_index_width_immediate_mnemonic(mnemonic: &str) -> bool {
        matches!(mnemonic, "CPX" | "CPY" | "LDX" | "LDY")
    }

    fn resolve_immediate(
        &self,
        mnemonic: &str,
        expr: &crate::core::parser::Expr,
        ctx: &dyn AssemblerContext,
    ) -> Result<Operand, String> {
        let val = ctx.eval_expr(expr)?;
        let span = crate::core::assembler::expression::expr_span(expr);
        let upper = Self::upper_mnemonic(mnemonic);

        if Self::is_accumulator_width_immediate_mnemonic(&upper) {
            let is_8bit = state::accumulator_is_8bit(ctx);
            if is_8bit {
                if !(0..=255).contains(&val) {
                    return Err(format!(
                        "Accumulator immediate value {} out of range (0-255) in 8-bit mode",
                        val
                    ));
                }
                return Ok(Operand::Immediate(val as u8, span));
            }
            if !(0..=65535).contains(&val) {
                return Err(format!(
                    "Accumulator immediate value {} out of range (0-65535) in 16-bit mode",
                    val
                ));
            }
            return Ok(Operand::ImmediateWord(val as u16, span));
        }

        if Self::is_index_width_immediate_mnemonic(&upper) {
            let is_8bit = state::index_is_8bit(ctx);
            if is_8bit {
                if !(0..=255).contains(&val) {
                    return Err(format!(
                        "Index immediate value {} out of range (0-255) in 8-bit mode",
                        val
                    ));
                }
                return Ok(Operand::Immediate(val as u8, span));
            }
            if !(0..=65535).contains(&val) {
                return Err(format!(
                    "Index immediate value {} out of range (0-65535) in 16-bit mode",
                    val
                ));
            }
            return Ok(Operand::ImmediateWord(val as u16, span));
        }

        if !(0..=255).contains(&val) {
            return Err(format!("Immediate value {} out of range (0-255)", val));
        }
        Ok(Operand::Immediate(val as u8, span))
    }

    fn has_mode(mnemonic: &str, mode: AddressMode) -> bool {
        lookup_instruction(mnemonic, mode).is_some()
            || lookup_m65c02_instruction(mnemonic, mode).is_some()
            || lookup_family_instruction(mnemonic, mode).is_some()
    }

    fn expr_has_unresolved_symbols(
        expr: &crate::core::parser::Expr,
        ctx: &dyn AssemblerContext,
    ) -> bool {
        use crate::core::parser::Expr;

        match expr {
            Expr::Identifier(name, _) | Expr::Register(name, _) => !ctx.has_symbol(name),
            Expr::Indirect(inner, _) | Expr::Immediate(inner, _) | Expr::IndirectLong(inner, _) => {
                Self::expr_has_unresolved_symbols(inner, ctx)
            }
            Expr::Tuple(items, _) => items
                .iter()
                .any(|item| Self::expr_has_unresolved_symbols(item, ctx)),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                Self::expr_has_unresolved_symbols(cond, ctx)
                    || Self::expr_has_unresolved_symbols(then_expr, ctx)
                    || Self::expr_has_unresolved_symbols(else_expr, ctx)
            }
            Expr::Unary { expr, .. } => Self::expr_has_unresolved_symbols(expr, ctx),
            Expr::Binary { left, right, .. } => {
                Self::expr_has_unresolved_symbols(left, ctx)
                    || Self::expr_has_unresolved_symbols(right, ctx)
            }
            Expr::Number(_, _) | Expr::Dollar(_) | Expr::String(_, _) | Expr::Error(_, _) => false,
        }
    }

    fn expr_has_symbol_references(expr: &crate::core::parser::Expr) -> bool {
        use crate::core::parser::Expr;

        match expr {
            Expr::Identifier(_, _) | Expr::Register(_, _) => true,
            Expr::Indirect(inner, _) | Expr::Immediate(inner, _) | Expr::IndirectLong(inner, _) => {
                Self::expr_has_symbol_references(inner)
            }
            Expr::Tuple(items, _) => items.iter().any(Self::expr_has_symbol_references),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                Self::expr_has_symbol_references(cond)
                    || Self::expr_has_symbol_references(then_expr)
                    || Self::expr_has_symbol_references(else_expr)
            }
            Expr::Unary { expr, .. } => Self::expr_has_symbol_references(expr),
            Expr::Binary { left, right, .. } => {
                Self::expr_has_symbol_references(left) || Self::expr_has_symbol_references(right)
            }
            Expr::Number(_, _) | Expr::Dollar(_) | Expr::String(_, _) | Expr::Error(_, _) => false,
        }
    }

    fn assumed_absolute_bank(mnemonic: &str, ctx: &dyn AssemblerContext) -> u8 {
        if matches!(mnemonic, "JMP" | "JSR") {
            state::program_bank(ctx)
        } else {
            state::data_bank(ctx)
        }
    }

    fn assumed_absolute_bank_known(mnemonic: &str, ctx: &dyn AssemblerContext) -> bool {
        if matches!(mnemonic, "JMP" | "JSR") {
            state::program_bank_known(ctx)
        } else {
            state::data_bank_known(ctx)
        }
    }

    fn assumed_absolute_bank_key(mnemonic: &str) -> &'static str {
        if matches!(mnemonic, "JMP" | "JSR") {
            "pbr"
        } else {
            "dbr"
        }
    }

    fn direct_page_offset_for_absolute_address(
        address: u16,
        ctx: &dyn AssemblerContext,
    ) -> Option<u8> {
        if !state::direct_page_known(ctx) {
            return None;
        }
        if address <= 0x00FF {
            return None;
        }
        let dp = state::direct_page(ctx);
        let offset = address.wrapping_sub(dp);
        if offset <= 0x00FF {
            Some(offset as u8)
        } else {
            None
        }
    }

    fn bank_mismatch_error(
        address: u32,
        actual_bank: u8,
        assumed_bank: u8,
        assumed_bank_key: &str,
    ) -> String {
        format!(
            "Address ${address:06X} is in bank ${actual_bank:02X}, but .assume {assumed_bank_key}=${assumed_bank:02X}"
        )
    }

    fn bank_unknown_error(assumed_bank_key: &str, mnemonic: &str) -> String {
        let mut message = format!(
            "Unable to resolve 24-bit bank because .assume {assumed_bank_key}=... is unknown; set .assume {assumed_bank_key}=$00..$FF or {assumed_bank_key}=auto"
        );
        message.push_str(
            ". If this source relied on removed stack-sequence inference, update .assume near this site",
        );
        if Self::has_mode(mnemonic, AddressMode::AbsoluteLong)
            || Self::has_mode(mnemonic, AddressMode::AbsoluteLongX)
        {
            message.push_str("; long-capable operands can be forced with ',l'");
        }
        message.push('.');
        message
    }

    fn force_suffix(force: OperandForce) -> &'static str {
        match force {
            OperandForce::DirectPage => "d",
            OperandForce::DataBank => "b",
            OperandForce::ProgramBank => "k",
            OperandForce::Long => "l",
        }
    }

    fn invalid_force_error(force: OperandForce, context: &str) -> String {
        format!(
            "Explicit addressing override ',{}' is not valid for {}",
            Self::force_suffix(force),
            context
        )
    }

    fn resolve_forced_direct_page_operand(
        upper_mnemonic: &str,
        val: i64,
        span: crate::core::tokenizer::Span,
        ctx: &dyn AssemblerContext,
        zero_page_mode: AddressMode,
        zero_page_ctor: fn(u8, crate::core::tokenizer::Span) -> Operand,
    ) -> Result<Operand, String> {
        if !Self::has_mode(upper_mnemonic, zero_page_mode) {
            return Err(Self::invalid_force_error(
                OperandForce::DirectPage,
                upper_mnemonic,
            ));
        }
        if (0..=255).contains(&val) {
            return Ok(zero_page_ctor(val as u8, span));
        }
        if (0..=0xFFFF).contains(&val) {
            let absolute_value = val as u16;
            if let Some(dp_offset) =
                Self::direct_page_offset_for_absolute_address(absolute_value, ctx)
            {
                return Ok(zero_page_ctor(dp_offset, span));
            }
            return Err(format!(
                "Address ${absolute_value:04X} is outside the direct-page window for explicit ',d'"
            ));
        }
        Err(format!(
            "Address {} out of 16-bit range for explicit ',d'",
            val
        ))
    }

    fn resolve_direct_page_window_operand(
        upper_mnemonic: &str,
        expr: &crate::core::parser::Expr,
        val: i64,
        span: crate::core::tokenizer::Span,
        ctx: &dyn AssemblerContext,
        spec: DirectPageResolutionSpec,
    ) -> Option<Operand> {
        if (0..=0xFFFF).contains(&val) && Self::has_mode(upper_mnemonic, spec.zero_page_mode) {
            let absolute_value = val as u16;
            if let Some(dp_offset) =
                Self::direct_page_offset_for_absolute_address(absolute_value, ctx)
            {
                if expr_has_unstable_symbols(expr, ctx)
                    && Self::has_mode(upper_mnemonic, spec.absolute_mode)
                {
                    return Some((spec.absolute_ctor)(absolute_value, span));
                }
                return Some((spec.zero_page_ctor)(dp_offset, span));
            }
        }
        None
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
        let upper_mnemonic = Self::upper_mnemonic(mnemonic);
        if Self::is_m65c02_only_mnemonic_for_65816(&upper_mnemonic) {
            return Err(format!(
                "Mnemonic {upper_mnemonic} is not supported on CPU 65816"
            ));
        }

        if family_operands.len() == 1 {
            let (single_operand, force_override) = match &family_operands[0] {
                FamilyOperand::Forced { inner, force, .. } => (inner.as_ref(), Some(*force)),
                other => (other, None),
            };

            match single_operand {
                FamilyOperand::Immediate(expr) => {
                    if let Some(force) = force_override {
                        return Err(Self::invalid_force_error(force, "immediate operands"));
                    }
                    return Ok(vec![self.resolve_immediate(mnemonic, expr, ctx)?]);
                }
                FamilyOperand::Direct(expr) => {
                    if matches!(
                        upper_mnemonic.as_str(),
                        "BRL" | "PER" | "PEA" | "JSL" | "JML"
                    ) {
                        if let Some(force) = force_override {
                            return Err(Self::invalid_force_error(force, &upper_mnemonic));
                        }
                        return Ok(vec![self.resolve_direct(mnemonic, expr, ctx)?]);
                    }

                    let unresolved =
                        ctx.pass() == 1 && Self::expr_has_unresolved_symbols(expr, ctx);
                    let assumed_known = Self::assumed_absolute_bank_known(&upper_mnemonic, ctx);
                    if unresolved {
                        if let Some(force) = force_override {
                            let span = crate::core::assembler::expression::expr_span(expr);
                            match force {
                                OperandForce::DirectPage => {
                                    if Self::has_mode(&upper_mnemonic, AddressMode::ZeroPage) {
                                        return Ok(vec![Operand::ZeroPage(0, span)]);
                                    }
                                }
                                OperandForce::DataBank | OperandForce::ProgramBank => {
                                    if Self::has_mode(&upper_mnemonic, AddressMode::Absolute) {
                                        return Ok(vec![Operand::Absolute(0, span)]);
                                    }
                                }
                                OperandForce::Long => {
                                    if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLong) {
                                        return Ok(vec![Operand::AbsoluteLong(0, span)]);
                                    }
                                }
                            }
                            return Err(Self::invalid_force_error(force, &upper_mnemonic));
                        }
                    }
                    if force_override.is_none()
                        && unresolved
                        && (ctx.current_address() > 0xFFFF
                            || !assumed_known
                            || Self::assumed_absolute_bank(&upper_mnemonic, ctx) != 0)
                        && lookup_instruction(&upper_mnemonic, AddressMode::AbsoluteLong).is_some()
                    {
                        return Ok(vec![Operand::AbsoluteLong(
                            0,
                            crate::core::assembler::expression::expr_span(expr),
                        )]);
                    }

                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    let assumed_bank = Self::assumed_absolute_bank(&upper_mnemonic, ctx);
                    let assumed_known = Self::assumed_absolute_bank_known(&upper_mnemonic, ctx);
                    let assumed_key = Self::assumed_absolute_bank_key(&upper_mnemonic);
                    let symbol_based = Self::expr_has_symbol_references(expr);
                    let symbol_unstable = expr_has_unstable_symbols(expr, ctx);

                    if let Some(force) = force_override {
                        match force {
                            OperandForce::DirectPage => {
                                return Ok(vec![Self::resolve_forced_direct_page_operand(
                                    &upper_mnemonic,
                                    val,
                                    span,
                                    ctx,
                                    AddressMode::ZeroPage,
                                    Operand::ZeroPage,
                                )?]);
                            }
                            OperandForce::Long => {
                                if !Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLong) {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if (0..=0xFF_FFFF).contains(&val) {
                                    return Ok(vec![Operand::AbsoluteLong(val as u32, span)]);
                                }
                                return Err(format!(
                                    "Address {} out of 24-bit range for explicit ',l'",
                                    val
                                ));
                            }
                            OperandForce::DataBank => {
                                if matches!(upper_mnemonic.as_str(), "JMP" | "JSR") {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if !Self::has_mode(&upper_mnemonic, AddressMode::Absolute) {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if (0..=0xFFFF).contains(&val) {
                                    return Ok(vec![Operand::Absolute(val as u16, span)]);
                                }
                                if (0..=0xFF_FFFF).contains(&val) {
                                    let absolute_bank = ((val as u32) >> 16) as u8;
                                    if !assumed_known {
                                        return Err(Self::bank_unknown_error(
                                            assumed_key,
                                            &upper_mnemonic,
                                        ));
                                    }
                                    if absolute_bank != assumed_bank {
                                        return Err(Self::bank_mismatch_error(
                                            val as u32,
                                            absolute_bank,
                                            assumed_bank,
                                            assumed_key,
                                        ));
                                    }
                                    return Ok(vec![Operand::Absolute(
                                        (val as u32 & 0xFFFF) as u16,
                                        span,
                                    )]);
                                }
                                return Err(format!(
                                    "Address {} out of 24-bit range for explicit ',b'",
                                    val
                                ));
                            }
                            OperandForce::ProgramBank => {
                                if !matches!(upper_mnemonic.as_str(), "JMP" | "JSR") {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if !Self::has_mode(&upper_mnemonic, AddressMode::Absolute) {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if (0..=0xFFFF).contains(&val) {
                                    return Ok(vec![Operand::Absolute(val as u16, span)]);
                                }
                                if (0..=0xFF_FFFF).contains(&val) {
                                    let absolute_bank = ((val as u32) >> 16) as u8;
                                    if !assumed_known {
                                        return Err(Self::bank_unknown_error(
                                            assumed_key,
                                            &upper_mnemonic,
                                        ));
                                    }
                                    if absolute_bank != assumed_bank {
                                        return Err(Self::bank_mismatch_error(
                                            val as u32,
                                            absolute_bank,
                                            assumed_bank,
                                            assumed_key,
                                        ));
                                    }
                                    return Ok(vec![Operand::Absolute(
                                        (val as u32 & 0xFFFF) as u16,
                                        span,
                                    )]);
                                }
                                return Err(format!(
                                    "Address {} out of 24-bit range for explicit ',k'",
                                    val
                                ));
                            }
                        }
                    }

                    if symbol_based && (0..=0xFFFF).contains(&val) && !assumed_known {
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLong) {
                            return Ok(vec![Operand::AbsoluteLong(val as u32, span)]);
                        }
                        if !symbol_unstable
                            && Self::has_mode(&upper_mnemonic, AddressMode::Absolute)
                        {
                            return Err(Self::bank_unknown_error(assumed_key, &upper_mnemonic));
                        }
                    }

                    if symbol_based
                        && (0..=0xFFFF).contains(&val)
                        && assumed_known
                        && assumed_bank != 0
                    {
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLong) {
                            return Ok(vec![Operand::AbsoluteLong(val as u32, span)]);
                        }
                        if !symbol_unstable
                            && Self::has_mode(&upper_mnemonic, AddressMode::Absolute)
                        {
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                0,
                                assumed_bank,
                                assumed_key,
                            ));
                        }
                    }

                    if (0..=0xFF_FFFF).contains(&val) && val > 0xFFFF {
                        let absolute_bank = ((val as u32) >> 16) as u8;
                        let absolute_value = (val as u32 & 0xFFFF) as u16;
                        if assumed_known
                            && absolute_bank == assumed_bank
                            && Self::has_mode(&upper_mnemonic, AddressMode::Absolute)
                        {
                            return Ok(vec![Operand::Absolute(absolute_value, span)]);
                        }
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLong) {
                            return Ok(vec![Operand::AbsoluteLong(val as u32, span)]);
                        }
                        if Self::has_mode(&upper_mnemonic, AddressMode::Absolute) {
                            if !assumed_known {
                                return Err(Self::bank_unknown_error(assumed_key, &upper_mnemonic));
                            }
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                absolute_bank,
                                assumed_bank,
                                assumed_key,
                            ));
                        }
                    }

                    if let Some(resolved) = Self::resolve_direct_page_window_operand(
                        &upper_mnemonic,
                        expr,
                        val,
                        span,
                        ctx,
                        DirectPageResolutionSpec {
                            zero_page_mode: AddressMode::ZeroPage,
                            absolute_mode: AddressMode::Absolute,
                            zero_page_ctor: Operand::ZeroPage,
                            absolute_ctor: Operand::Absolute,
                        },
                    ) {
                        return Ok(vec![resolved]);
                    }
                }
                FamilyOperand::DirectX(expr) => {
                    let unresolved =
                        ctx.pass() == 1 && Self::expr_has_unresolved_symbols(expr, ctx);
                    let assumed_known = Self::assumed_absolute_bank_known(&upper_mnemonic, ctx);
                    if unresolved {
                        if let Some(force) = force_override {
                            let span = crate::core::assembler::expression::expr_span(expr);
                            match force {
                                OperandForce::DirectPage => {
                                    if Self::has_mode(&upper_mnemonic, AddressMode::ZeroPageX) {
                                        return Ok(vec![Operand::ZeroPageX(0, span)]);
                                    }
                                }
                                OperandForce::DataBank => {
                                    if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteX) {
                                        return Ok(vec![Operand::AbsoluteX(0, span)]);
                                    }
                                }
                                OperandForce::Long => {
                                    if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLongX) {
                                        return Ok(vec![Operand::AbsoluteLongX(0, span)]);
                                    }
                                }
                                OperandForce::ProgramBank => {}
                            }
                            return Err(Self::invalid_force_error(force, &upper_mnemonic));
                        }
                    }
                    if force_override.is_none()
                        && unresolved
                        && (ctx.current_address() > 0xFFFF
                            || !assumed_known
                            || Self::assumed_absolute_bank(&upper_mnemonic, ctx) != 0)
                        && lookup_instruction(&upper_mnemonic, AddressMode::AbsoluteLongX).is_some()
                    {
                        return Ok(vec![Operand::AbsoluteLongX(
                            0,
                            crate::core::assembler::expression::expr_span(expr),
                        )]);
                    }

                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    let assumed_bank = Self::assumed_absolute_bank(&upper_mnemonic, ctx);
                    let assumed_known = Self::assumed_absolute_bank_known(&upper_mnemonic, ctx);
                    let assumed_key = Self::assumed_absolute_bank_key(&upper_mnemonic);
                    let symbol_based = Self::expr_has_symbol_references(expr);
                    let symbol_unstable = expr_has_unstable_symbols(expr, ctx);

                    if let Some(force) = force_override {
                        match force {
                            OperandForce::DirectPage => {
                                return Ok(vec![Self::resolve_forced_direct_page_operand(
                                    &upper_mnemonic,
                                    val,
                                    span,
                                    ctx,
                                    AddressMode::ZeroPageX,
                                    Operand::ZeroPageX,
                                )?]);
                            }
                            OperandForce::Long => {
                                if !Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLongX) {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if (0..=0xFF_FFFF).contains(&val) {
                                    return Ok(vec![Operand::AbsoluteLongX(val as u32, span)]);
                                }
                                return Err(format!(
                                    "Address {} out of 24-bit range for explicit ',l'",
                                    val
                                ));
                            }
                            OperandForce::DataBank => {
                                if !Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteX) {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if (0..=0xFFFF).contains(&val) {
                                    return Ok(vec![Operand::AbsoluteX(val as u16, span)]);
                                }
                                if (0..=0xFF_FFFF).contains(&val) {
                                    let absolute_bank = ((val as u32) >> 16) as u8;
                                    if !assumed_known {
                                        return Err(Self::bank_unknown_error(
                                            assumed_key,
                                            &upper_mnemonic,
                                        ));
                                    }
                                    if absolute_bank != assumed_bank {
                                        return Err(Self::bank_mismatch_error(
                                            val as u32,
                                            absolute_bank,
                                            assumed_bank,
                                            assumed_key,
                                        ));
                                    }
                                    return Ok(vec![Operand::AbsoluteX(
                                        (val as u32 & 0xFFFF) as u16,
                                        span,
                                    )]);
                                }
                                return Err(format!(
                                    "Address {} out of 24-bit range for explicit ',b'",
                                    val
                                ));
                            }
                            OperandForce::ProgramBank => {
                                return Err(Self::invalid_force_error(force, &upper_mnemonic));
                            }
                        }
                    }

                    if symbol_based && (0..=0xFFFF).contains(&val) && !assumed_known {
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLongX) {
                            return Ok(vec![Operand::AbsoluteLongX(val as u32, span)]);
                        }
                        if !symbol_unstable
                            && Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteX)
                        {
                            return Err(Self::bank_unknown_error(assumed_key, &upper_mnemonic));
                        }
                    }

                    if symbol_based
                        && (0..=0xFFFF).contains(&val)
                        && assumed_known
                        && assumed_bank != 0
                    {
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLongX) {
                            return Ok(vec![Operand::AbsoluteLongX(val as u32, span)]);
                        }
                        if !symbol_unstable
                            && Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteX)
                        {
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                0,
                                assumed_bank,
                                assumed_key,
                            ));
                        }
                    }

                    if (0..=0xFF_FFFF).contains(&val) && val > 0xFFFF {
                        let absolute_bank = ((val as u32) >> 16) as u8;
                        let absolute_value = (val as u32 & 0xFFFF) as u16;
                        if assumed_known
                            && absolute_bank == assumed_bank
                            && Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteX)
                        {
                            return Ok(vec![Operand::AbsoluteX(absolute_value, span)]);
                        }
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteLongX) {
                            return Ok(vec![Operand::AbsoluteLongX(val as u32, span)]);
                        }
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteX) {
                            if !assumed_known {
                                return Err(Self::bank_unknown_error(assumed_key, &upper_mnemonic));
                            }
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                absolute_bank,
                                assumed_bank,
                                assumed_key,
                            ));
                        }
                    }

                    if let Some(resolved) = Self::resolve_direct_page_window_operand(
                        &upper_mnemonic,
                        expr,
                        val,
                        span,
                        ctx,
                        DirectPageResolutionSpec {
                            zero_page_mode: AddressMode::ZeroPageX,
                            absolute_mode: AddressMode::AbsoluteX,
                            zero_page_ctor: Operand::ZeroPageX,
                            absolute_ctor: Operand::AbsoluteX,
                        },
                    ) {
                        return Ok(vec![resolved]);
                    }
                }
                FamilyOperand::DirectY(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    let symbol_based = Self::expr_has_symbol_references(expr);
                    let symbol_unstable = expr_has_unstable_symbols(expr, ctx);
                    let assumed_bank = state::data_bank(ctx);
                    let assumed_known = state::data_bank_known(ctx);

                    if let Some(force) = force_override {
                        match force {
                            OperandForce::DirectPage => {
                                return Ok(vec![Self::resolve_forced_direct_page_operand(
                                    &upper_mnemonic,
                                    val,
                                    span,
                                    ctx,
                                    AddressMode::ZeroPageY,
                                    Operand::ZeroPageY,
                                )?]);
                            }
                            OperandForce::DataBank => {
                                if !Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteY) {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                                if (0..=0xFFFF).contains(&val) {
                                    return Ok(vec![Operand::AbsoluteY(val as u16, span)]);
                                }
                                if (0..=0xFF_FFFF).contains(&val) {
                                    let absolute_bank = ((val as u32) >> 16) as u8;
                                    if !assumed_known {
                                        return Err(Self::bank_unknown_error(
                                            "dbr",
                                            &upper_mnemonic,
                                        ));
                                    }
                                    if absolute_bank != assumed_bank {
                                        return Err(Self::bank_mismatch_error(
                                            val as u32,
                                            absolute_bank,
                                            assumed_bank,
                                            "dbr",
                                        ));
                                    }
                                    return Ok(vec![Operand::AbsoluteY(
                                        (val as u32 & 0xFFFF) as u16,
                                        span,
                                    )]);
                                }
                                return Err(format!(
                                    "Address {} out of 24-bit range for explicit ',b'",
                                    val
                                ));
                            }
                            OperandForce::Long | OperandForce::ProgramBank => {
                                return Err(Self::invalid_force_error(force, &upper_mnemonic));
                            }
                        }
                    }

                    if symbol_based
                        && (0..=0xFFFF).contains(&val)
                        && !symbol_unstable
                        && Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteY)
                    {
                        if !assumed_known {
                            return Err(Self::bank_unknown_error("dbr", &upper_mnemonic));
                        }
                        if assumed_bank == 0 {
                            // In matching low bank we can keep absolute Y as-is.
                        } else {
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                0,
                                assumed_bank,
                                "dbr",
                            ));
                        }
                    }

                    if (0..=0xFF_FFFF).contains(&val) && val > 0xFFFF {
                        let absolute_bank = ((val as u32) >> 16) as u8;
                        let absolute_value = (val as u32 & 0xFFFF) as u16;
                        if assumed_known
                            && absolute_bank == assumed_bank
                            && Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteY)
                        {
                            return Ok(vec![Operand::AbsoluteY(absolute_value, span)]);
                        }
                        if Self::has_mode(&upper_mnemonic, AddressMode::AbsoluteY) {
                            if !assumed_known {
                                return Err(Self::bank_unknown_error("dbr", &upper_mnemonic));
                            }
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                absolute_bank,
                                assumed_bank,
                                "dbr",
                            ));
                        }
                    }

                    if let Some(resolved) = Self::resolve_direct_page_window_operand(
                        &upper_mnemonic,
                        expr,
                        val,
                        span,
                        ctx,
                        DirectPageResolutionSpec {
                            zero_page_mode: AddressMode::ZeroPageY,
                            absolute_mode: AddressMode::AbsoluteY,
                            zero_page_ctor: Operand::ZeroPageY,
                            absolute_ctor: Operand::AbsoluteY,
                        },
                    ) {
                        return Ok(vec![resolved]);
                    }
                }
                FamilyOperand::IndexedIndirectX(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    let symbol_based = Self::expr_has_symbol_references(expr);
                    let symbol_unstable = expr_has_unstable_symbols(expr, ctx);

                    if matches!(upper_mnemonic.as_str(), "JMP" | "JSR") {
                        if let Some(force) = force_override {
                            match force {
                                OperandForce::ProgramBank => {
                                    if (0..=0xFFFF).contains(&val) {
                                        return Ok(vec![Operand::AbsoluteIndexedIndirect(
                                            val as u16, span,
                                        )]);
                                    }
                                    if (0..=0xFF_FFFF).contains(&val) {
                                        let assumed_bank = state::program_bank(ctx);
                                        let assumed_known = state::program_bank_known(ctx);
                                        let absolute_bank = ((val as u32) >> 16) as u8;
                                        if !assumed_known {
                                            return Err(Self::bank_unknown_error(
                                                "pbr",
                                                &upper_mnemonic,
                                            ));
                                        }
                                        if absolute_bank != assumed_bank {
                                            return Err(Self::bank_mismatch_error(
                                                val as u32,
                                                absolute_bank,
                                                assumed_bank,
                                                "pbr",
                                            ));
                                        }
                                        return Ok(vec![Operand::AbsoluteIndexedIndirect(
                                            (val as u32 & 0xFFFF) as u16,
                                            span,
                                        )]);
                                    }
                                    return Err(format!(
                                        "Absolute indexed indirect address {} out of 24-bit range",
                                        val
                                    ));
                                }
                                _ => {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                            }
                        }

                        let assumed_bank = state::program_bank(ctx);
                        let assumed_known = state::program_bank_known(ctx);
                        if symbol_based && (0..=0xFFFF).contains(&val) && !symbol_unstable {
                            if !assumed_known {
                                return Err(Self::bank_unknown_error("pbr", &upper_mnemonic));
                            }
                            if assumed_bank != 0 {
                                return Err(Self::bank_mismatch_error(
                                    val as u32,
                                    0,
                                    assumed_bank,
                                    "pbr",
                                ));
                            }
                        }
                        if (0..=0xFFFF).contains(&val) {
                            return Ok(vec![Operand::AbsoluteIndexedIndirect(val as u16, span)]);
                        }
                        if (0..=0xFF_FFFF).contains(&val) {
                            let absolute_bank = ((val as u32) >> 16) as u8;
                            if assumed_known && absolute_bank == assumed_bank {
                                return Ok(vec![Operand::AbsoluteIndexedIndirect(
                                    (val as u32 & 0xFFFF) as u16,
                                    span,
                                )]);
                            }
                            if !assumed_known {
                                return Err(Self::bank_unknown_error("pbr", &upper_mnemonic));
                            }
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                absolute_bank,
                                assumed_bank,
                                "pbr",
                            ));
                        }
                        return Err(format!(
                            "Absolute indexed indirect address {} out of 24-bit range",
                            val
                        ));
                    }

                    if let Some(force) = force_override {
                        match force {
                            OperandForce::DirectPage => {
                                if (0..=255).contains(&val) {
                                    return Ok(vec![Operand::IndexedIndirectX(val as u8, span)]);
                                }
                                if (0..=0xFFFF).contains(&val) {
                                    if let Some(dp_offset) =
                                        Self::direct_page_offset_for_absolute_address(
                                            val as u16, ctx,
                                        )
                                    {
                                        return Ok(vec![Operand::IndexedIndirectX(
                                            dp_offset, span,
                                        )]);
                                    }
                                    return Err(format!(
                                        "Address ${:04X} is outside the direct-page window for explicit ',d'",
                                        val as u16
                                    ));
                                }
                                return Err(format!(
                                    "Indexed indirect address {} out of 16-bit range for explicit ',d'",
                                    val
                                ));
                            }
                            _ => return Err(Self::invalid_force_error(force, &upper_mnemonic)),
                        }
                    }

                    if (0..=255).contains(&val) {
                        return Ok(vec![Operand::IndexedIndirectX(val as u8, span)]);
                    }
                    if (0..=0xFFFF).contains(&val) {
                        if let Some(dp_offset) =
                            Self::direct_page_offset_for_absolute_address(val as u16, ctx)
                        {
                            return Ok(vec![Operand::IndexedIndirectX(dp_offset, span)]);
                        }
                    }
                    return Err(format!(
                        "Indexed indirect address {} out of direct-page range (0-255)",
                        val
                    ));
                }
                FamilyOperand::IndirectIndexedY(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    if let Some(force) = force_override {
                        match force {
                            OperandForce::DirectPage => {}
                            _ => return Err(Self::invalid_force_error(force, &upper_mnemonic)),
                        }
                    }
                    if (0..=255).contains(&val) {
                        return Ok(vec![Operand::IndirectIndexedY(val as u8, span)]);
                    }
                    if (0..=0xFFFF).contains(&val) {
                        if let Some(dp_offset) =
                            Self::direct_page_offset_for_absolute_address(val as u16, ctx)
                        {
                            return Ok(vec![Operand::IndirectIndexedY(dp_offset, span)]);
                        }
                    }
                    return Err(format!(
                        "Indirect indexed address {} out of direct-page range (0-255)",
                        val
                    ));
                }
                FamilyOperand::Indirect(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    let symbol_based = Self::expr_has_symbol_references(expr);
                    let symbol_unstable = expr_has_unstable_symbols(expr, ctx);
                    if upper_mnemonic == "JMP" {
                        if let Some(force) = force_override {
                            match force {
                                OperandForce::ProgramBank => {
                                    if (0..=0xFFFF).contains(&val) {
                                        return Ok(vec![Operand::Indirect(val as u16, span)]);
                                    }
                                    if (0..=0xFF_FFFF).contains(&val) {
                                        let assumed_bank = state::program_bank(ctx);
                                        let assumed_known = state::program_bank_known(ctx);
                                        let absolute_bank = ((val as u32) >> 16) as u8;
                                        if !assumed_known {
                                            return Err(Self::bank_unknown_error(
                                                "pbr",
                                                &upper_mnemonic,
                                            ));
                                        }
                                        if absolute_bank != assumed_bank {
                                            return Err(Self::bank_mismatch_error(
                                                val as u32,
                                                absolute_bank,
                                                assumed_bank,
                                                "pbr",
                                            ));
                                        }
                                        return Ok(vec![Operand::Indirect(
                                            (val as u32 & 0xFFFF) as u16,
                                            span,
                                        )]);
                                    }
                                    return Err(format!(
                                        "Indirect address {} out of 24-bit range",
                                        val
                                    ));
                                }
                                _ => {
                                    return Err(Self::invalid_force_error(force, &upper_mnemonic));
                                }
                            }
                        }

                        let assumed_bank = state::program_bank(ctx);
                        let assumed_known = state::program_bank_known(ctx);
                        if symbol_based && (0..=0xFFFF).contains(&val) && !symbol_unstable {
                            if !assumed_known {
                                return Err(Self::bank_unknown_error("pbr", &upper_mnemonic));
                            }
                            if assumed_bank != 0 {
                                return Err(Self::bank_mismatch_error(
                                    val as u32,
                                    0,
                                    assumed_bank,
                                    "pbr",
                                ));
                            }
                        }
                        if (0..=0xFFFF).contains(&val) {
                            return Ok(vec![Operand::Indirect(val as u16, span)]);
                        }
                        if (0..=0xFF_FFFF).contains(&val) {
                            let absolute_bank = ((val as u32) >> 16) as u8;
                            if assumed_known && absolute_bank == assumed_bank {
                                return Ok(vec![Operand::Indirect(
                                    (val as u32 & 0xFFFF) as u16,
                                    span,
                                )]);
                            }
                            if !assumed_known {
                                return Err(Self::bank_unknown_error("pbr", &upper_mnemonic));
                            }
                            return Err(Self::bank_mismatch_error(
                                val as u32,
                                absolute_bank,
                                assumed_bank,
                                "pbr",
                            ));
                        }
                        return Err(format!("Indirect address {} out of 24-bit range", val));
                    }

                    if let Some(force) = force_override {
                        match force {
                            OperandForce::DirectPage => {}
                            _ => return Err(Self::invalid_force_error(force, &upper_mnemonic)),
                        }
                    }

                    if (0..=255).contains(&val) {
                        return Ok(vec![Operand::ZeroPageIndirect(val as u8, span)]);
                    }
                    if (0..=0xFFFF).contains(&val) {
                        if let Some(dp_offset) =
                            Self::direct_page_offset_for_absolute_address(val as u16, ctx)
                        {
                            return Ok(vec![Operand::ZeroPageIndirect(dp_offset, span)]);
                        }
                    }
                    return Err(format!(
                        "Direct-page indirect address {} out of range (0-255)",
                        val
                    ));
                }
                FamilyOperand::StackRelative(expr) => {
                    if let Some(force) = force_override {
                        return Err(Self::invalid_force_error(force, &upper_mnemonic));
                    }
                    let val = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&val) {
                        return Err(format!(
                            "Stack-relative offset {} out of range (0-255)",
                            val
                        ));
                    }
                    return Ok(vec![Operand::StackRelative(
                        val as u8,
                        crate::core::assembler::expression::expr_span(expr),
                    )]);
                }
                FamilyOperand::StackRelativeIndirectIndexedY(expr) => {
                    if let Some(force) = force_override {
                        return Err(Self::invalid_force_error(force, &upper_mnemonic));
                    }
                    let val = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&val) {
                        return Err(format!(
                            "Stack-relative offset {} out of range (0-255)",
                            val
                        ));
                    }
                    return Ok(vec![Operand::StackRelativeIndirectIndexedY(
                        val as u8,
                        crate::core::assembler::expression::expr_span(expr),
                    )]);
                }
                FamilyOperand::IndirectLong(expr) => {
                    if let Some(force) = force_override {
                        return Err(Self::invalid_force_error(force, &upper_mnemonic));
                    }
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    if matches!(Self::upper_mnemonic(mnemonic).as_str(), "JML" | "JMP") {
                        if (0..=65535).contains(&val) {
                            return Ok(vec![Operand::IndirectLong(val as u16, span)]);
                        }
                        return Err(format!(
                            "{} indirect operand {} out of 16-bit range",
                            Self::upper_mnemonic(mnemonic),
                            val
                        ));
                    }
                    if (0..=255).contains(&val) {
                        return Ok(vec![Operand::DirectPageIndirectLong(val as u8, span)]);
                    }
                    if (0..=0xFFFF).contains(&val) {
                        if let Some(dp_offset) =
                            Self::direct_page_offset_for_absolute_address(val as u16, ctx)
                        {
                            return Ok(vec![Operand::DirectPageIndirectLong(dp_offset, span)]);
                        }
                    }
                    return Err(format!(
                        "Bracketed direct-page indirect operand {} out of range (0-255)",
                        val
                    ));
                }
                FamilyOperand::IndirectLongY(expr) => {
                    if let Some(force) = force_override {
                        return Err(Self::invalid_force_error(force, &upper_mnemonic));
                    }
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    if (0..=255).contains(&val) {
                        return Ok(vec![Operand::DirectPageIndirectLongY(val as u8, span)]);
                    }
                    if (0..=0xFFFF).contains(&val) {
                        if let Some(dp_offset) =
                            Self::direct_page_offset_for_absolute_address(val as u16, ctx)
                        {
                            return Ok(vec![Operand::DirectPageIndirectLongY(dp_offset, span)]);
                        }
                    }
                    return Err(format!(
                        "Bracketed direct-page indirect indexed operand {} out of range (0-255)",
                        val
                    ));
                }
                FamilyOperand::BlockMove { src, dst, span } => {
                    if let Some(force) = force_override {
                        return Err(Self::invalid_force_error(force, &upper_mnemonic));
                    }
                    let src_val = ctx.eval_expr(src)?;
                    let dst_val = ctx.eval_expr(dst)?;
                    if !(0..=255).contains(&src_val) {
                        return Err(format!(
                            "Block-move source bank {} out of range (0-255)",
                            src_val
                        ));
                    }
                    if !(0..=255).contains(&dst_val) {
                        return Err(format!(
                            "Block-move destination bank {} out of range (0-255)",
                            dst_val
                        ));
                    }
                    return Ok(vec![Operand::BlockMove {
                        src: src_val as u8,
                        dst: dst_val as u8,
                        span: *span,
                    }]);
                }
                _ => {}
            }
        }

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
        let upper_mnemonic = Self::upper_mnemonic(mnemonic);
        if Self::is_m65c02_only_mnemonic_for_65816(&upper_mnemonic) {
            return EncodeResult::error(format!(
                "Mnemonic {upper_mnemonic} is not supported on CPU 65816"
            ));
        }

        let mode = if operands.is_empty() {
            AddressMode::Implied
        } else {
            operands[0].mode()
        };

        if let Some(entry) = lookup_instruction(mnemonic, mode) {
            let mut bytes = vec![entry.opcode];
            if let Some(first) = operands.first() {
                bytes.extend(first.value_bytes());
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
        let upper_mnemonic = Self::upper_mnemonic(mnemonic);
        if Self::is_m65c02_only_mnemonic_for_65816(&upper_mnemonic) {
            return false;
        }

        has_mnemonic(mnemonic)
            || <crate::m65c02::M65C02CpuHandler as CpuHandler>::supports_mnemonic(
                &self.baseline,
                mnemonic,
            )
            || has_family_mnemonic(mnemonic)
    }
}

#[cfg(test)]
mod tests {
    use super::M65816CpuHandler;
    use crate::m65c02::instructions::CPU_INSTRUCTION_TABLE;
    use std::collections::BTreeSet;

    fn expected_m65c02_only_exclusions() -> BTreeSet<&'static str> {
        BTreeSet::from([
            "RMB0", "RMB1", "RMB2", "RMB3", "RMB4", "RMB5", "RMB6", "RMB7", "SMB0", "SMB1", "SMB2",
            "SMB3", "SMB4", "SMB5", "SMB6", "SMB7",
        ])
    }

    #[test]
    fn m65c02_exclusion_list_stays_in_sync_with_65c02_table() {
        let excluded = expected_m65c02_only_exclusions();

        let mut from_table = BTreeSet::new();
        for entry in CPU_INSTRUCTION_TABLE {
            let upper = entry.mnemonic.to_ascii_uppercase();
            if excluded.contains(upper.as_str()) {
                from_table.insert(upper);
            }
        }

        assert_eq!(
            from_table,
            excluded
                .iter()
                .map(|mnemonic| mnemonic.to_string())
                .collect(),
            "expected 65C02-only exclusion set should match mnemonics present in 65C02 table"
        );

        for mnemonic in &excluded {
            assert!(
                M65816CpuHandler::is_m65c02_only_mnemonic_for_65816(mnemonic),
                "{mnemonic} must remain excluded for 65816"
            );
        }
    }
}
