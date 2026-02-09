// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 65816 CPU handler implementation.

use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult};
use crate::families::mos6502::{
    has_mnemonic as has_family_mnemonic, AddressMode, FamilyOperand, Operand,
};
use crate::m65816::instructions::{has_mnemonic, lookup_instruction};
use crate::m65816::state;

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

    fn upper_mnemonic(mnemonic: &str) -> String {
        mnemonic.to_ascii_uppercase()
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

        if family_operands.len() == 1 {
            match &family_operands[0] {
                FamilyOperand::Immediate(expr) => {
                    return Ok(vec![self.resolve_immediate(mnemonic, expr, ctx)?]);
                }
                FamilyOperand::Direct(expr) => {
                    if matches!(
                        upper_mnemonic.as_str(),
                        "BRL" | "PER" | "PEA" | "JSL" | "JML"
                    ) {
                        return Ok(vec![self.resolve_direct(mnemonic, expr, ctx)?]);
                    }

                    let unresolved =
                        ctx.pass() == 1 && Self::expr_has_unresolved_symbols(expr, ctx);
                    if unresolved
                        && (ctx.current_address() > 0xFFFF || state::program_bank(ctx) != 0)
                        && lookup_instruction(&upper_mnemonic, AddressMode::AbsoluteLong).is_some()
                    {
                        return Ok(vec![Operand::AbsoluteLong(
                            0,
                            crate::core::assembler::expression::expr_span(expr),
                        )]);
                    }

                    let val = ctx.eval_expr(expr)?;
                    if (0..=0xFF_FFFF).contains(&val)
                        && val > 65535
                        && lookup_instruction(&upper_mnemonic, AddressMode::AbsoluteLong).is_some()
                    {
                        return Ok(vec![Operand::AbsoluteLong(
                            val as u32,
                            crate::core::assembler::expression::expr_span(expr),
                        )]);
                    }
                }
                FamilyOperand::DirectX(expr) => {
                    let unresolved =
                        ctx.pass() == 1 && Self::expr_has_unresolved_symbols(expr, ctx);
                    if unresolved
                        && (ctx.current_address() > 0xFFFF || state::program_bank(ctx) != 0)
                        && lookup_instruction(&upper_mnemonic, AddressMode::AbsoluteLongX).is_some()
                    {
                        return Ok(vec![Operand::AbsoluteLongX(
                            0,
                            crate::core::assembler::expression::expr_span(expr),
                        )]);
                    }

                    let val = ctx.eval_expr(expr)?;
                    if (0..=0xFF_FFFF).contains(&val)
                        && val > 65535
                        && lookup_instruction(&upper_mnemonic, AddressMode::AbsoluteLongX).is_some()
                    {
                        return Ok(vec![Operand::AbsoluteLongX(
                            val as u32,
                            crate::core::assembler::expression::expr_span(expr),
                        )]);
                    }
                }
                FamilyOperand::StackRelative(expr) => {
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
                    let val = ctx.eval_expr(expr)?;
                    let span = crate::core::assembler::expression::expr_span(expr);
                    if Self::upper_mnemonic(mnemonic) == "JML" {
                        if (0..=65535).contains(&val) {
                            return Ok(vec![Operand::IndirectLong(val as u16, span)]);
                        }
                        return Err(format!("JML indirect operand {} out of 16-bit range", val));
                    }
                    if (0..=255).contains(&val) {
                        return Ok(vec![Operand::DirectPageIndirectLong(val as u8, span)]);
                    }
                    return Err(format!(
                        "Bracketed direct-page indirect operand {} out of range (0-255)",
                        val
                    ));
                }
                FamilyOperand::IndirectLongY(expr) => {
                    let val = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&val) {
                        return Err(format!(
                            "Bracketed direct-page indirect indexed operand {} out of range (0-255)",
                            val
                        ));
                    }
                    return Ok(vec![Operand::DirectPageIndirectLongY(
                        val as u8,
                        crate::core::assembler::expression::expr_span(expr),
                    )]);
                }
                FamilyOperand::BlockMove { src, dst, span } => {
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
        has_mnemonic(mnemonic)
            || <crate::m65c02::M65C02CpuHandler as CpuHandler>::supports_mnemonic(
                &self.baseline,
                mnemonic,
            )
            || has_family_mnemonic(mnemonic)
    }
}
