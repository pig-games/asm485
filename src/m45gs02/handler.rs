// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 45GS02 CPU handler implementation.

use crate::core::assembler::expression::expr_span;
use crate::core::family::{AssemblerContext, CpuHandler, EncodeResult, FamilyHandler};
use crate::families::mos6502::{AddressMode, FamilyOperand, MOS6502FamilyHandler, Operand};
use crate::m45gs02::instructions::{has_mnemonic, lookup_instruction};

const OPCODE_NEG: u8 = 0x42;
const OPCODE_NOP: u8 = 0xEA;

#[derive(Debug)]
pub struct M45GS02CpuHandler {
    baseline: crate::m65c02::M65C02CpuHandler,
}

impl Default for M45GS02CpuHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl M45GS02CpuHandler {
    pub fn new() -> Self {
        Self {
            baseline: crate::m65c02::M65C02CpuHandler::new(),
        }
    }

    fn upper_mnemonic(mnemonic: &str) -> String {
        mnemonic.to_ascii_uppercase()
    }

    fn map_q_mnemonic(mnemonic: &str) -> Option<&'static str> {
        match mnemonic.to_ascii_uppercase().as_str() {
            "LDQ" => Some("LDA"),
            "STQ" => Some("STA"),
            "ADCQ" => Some("ADC"),
            "ANDQ" => Some("AND"),
            "CMPQ" => Some("CMP"),
            "EORQ" => Some("EOR"),
            "LDAQ" => Some("LDA"),
            "ORAQ" => Some("ORA"),
            "SBCQ" => Some("SBC"),
            _ => None,
        }
    }

    fn map_mnemonic(mnemonic: &str) -> (&str, bool) {
        if let Some(mapped) = Self::map_q_mnemonic(mnemonic) {
            (mapped, true)
        } else {
            (mnemonic, false)
        }
    }

    fn supports_relfar_branch(mnemonic: &str) -> bool {
        matches!(
            mnemonic,
            "BPL" | "BMI" | "BVC" | "BSR" | "BVS" | "BRA" | "BCC" | "BCS" | "BNE" | "BEQ"
        )
    }
}

impl CpuHandler for M45GS02CpuHandler {
    type Family = MOS6502FamilyHandler;

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

        if family_operands.len() == 1
            && Self::supports_relfar_branch(&upper_mnemonic)
            && matches!(family_operands[0], FamilyOperand::Direct(_))
        {
            let expr = match &family_operands[0] {
                FamilyOperand::Direct(expr) => expr,
                _ => unreachable!(),
            };

            let target = ctx.eval_expr(expr)?;
            let span = expr_span(expr);

            if upper_mnemonic == "BSR" {
                let far_offset = target - (ctx.current_address() as i64 + 3);
                if !(-32768..=32767).contains(&far_offset) {
                    if ctx.pass() > 1 {
                        return Err(format!(
                            "Far branch target out of range: offset {}",
                            far_offset
                        ));
                    }
                    return Ok(vec![Operand::RelativeLong(0, span)]);
                }
                return Ok(vec![Operand::RelativeLong(far_offset as i16, span)]);
            }

            let short_offset = target - (ctx.current_address() as i64 + 2);
            if (-128..=127).contains(&short_offset) {
                return Ok(vec![Operand::Relative(short_offset as i8, span)]);
            }

            let far_offset = target - (ctx.current_address() as i64 + 3);
            if !(-32768..=32767).contains(&far_offset) {
                if ctx.pass() > 1 {
                    return Err(format!(
                        "Far branch target out of range: offset {}",
                        far_offset
                    ));
                }
                return Ok(vec![Operand::RelativeLong(0, span)]);
            }

            return Ok(vec![Operand::RelativeLong(far_offset as i16, span)]);
        }

        if family_operands.is_empty() {
            return Ok(vec![Operand::Implied]);
        }

        if family_operands.len() == 1 {
            match &family_operands[0] {
                FamilyOperand::IndirectIndexedZ(expr) => {
                    let value = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&value) {
                        return Err(format!(
                            "Indirect indexed Z address {} out of zero page range",
                            value
                        ));
                    }
                    return Ok(vec![Operand::IndirectIndexedZ(
                        value as u8,
                        expr_span(expr),
                    )]);
                }
                FamilyOperand::IndirectLongZ(expr) => {
                    let value = ctx.eval_expr(expr)?;
                    if !(0..=255).contains(&value) {
                        return Err(format!(
                            "Bracketed indexed Z address {} out of zero page range",
                            value
                        ));
                    }
                    return Ok(vec![Operand::DirectPageIndirectLongZ(
                        value as u8,
                        expr_span(expr),
                    )]);
                }
                _ => {}
            }
        }

        let (mapped_mnemonic, _is_q_mode) = Self::map_mnemonic(mnemonic);
        <crate::m65c02::M65C02CpuHandler as CpuHandler>::resolve_operands(
            &self.baseline,
            mapped_mnemonic,
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
        let upper = Self::upper_mnemonic(mnemonic);
        let mode = if operands.is_empty() {
            AddressMode::Implied
        } else {
            operands[0].mode()
        };

        if let Some(entry) = lookup_instruction(&upper, mode) {
            let mut bytes = vec![entry.opcode];
            if let Some(operand) = operands.first() {
                bytes.extend(operand.value_bytes());
            }
            return EncodeResult::Ok(bytes);
        }

        let (mapped_mnemonic, q_prefix) = Self::map_mnemonic(&upper);
        let mut prefixes = Vec::new();
        if q_prefix {
            prefixes.push(OPCODE_NEG);
            prefixes.push(OPCODE_NEG);
        }

        let mut mapped_operands = Vec::with_capacity(operands.len());
        for operand in operands {
            match operand {
                Operand::IndirectIndexedZ(value, span) => {
                    prefixes.push(OPCODE_NOP);
                    mapped_operands.push(Operand::IndirectIndexedY(*value, *span));
                }
                Operand::DirectPageIndirectLongZ(value, span) => {
                    prefixes.push(OPCODE_NOP);
                    mapped_operands.push(Operand::IndirectIndexedY(*value, *span));
                }
                _ => mapped_operands.push(operand.clone()),
            }
        }

        let encoded = match <crate::m65c02::M65C02CpuHandler as CpuHandler>::encode_instruction(
            &self.baseline,
            mapped_mnemonic,
            &mapped_operands,
            ctx,
        ) {
            EncodeResult::NotFound => <MOS6502FamilyHandler as FamilyHandler>::encode_instruction(
                self.family(),
                mapped_mnemonic,
                &mapped_operands,
                ctx,
            ),
            other => other,
        };

        match encoded {
            EncodeResult::Ok(mut bytes) => {
                if prefixes.is_empty() {
                    EncodeResult::Ok(bytes)
                } else {
                    let mut prefixed = prefixes;
                    prefixed.append(&mut bytes);
                    EncodeResult::Ok(prefixed)
                }
            }
            other => other,
        }
    }

    fn supports_mnemonic(&self, mnemonic: &str) -> bool {
        has_mnemonic(mnemonic)
            || <crate::m65c02::M65C02CpuHandler as CpuHandler>::supports_mnemonic(
                &self.baseline,
                mnemonic,
            )
            || Self::map_q_mnemonic(mnemonic).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::parser::Expr;
    use crate::core::symbol_table::SymbolTable;
    use crate::core::tokenizer::Span;

    struct TestContext {
        symbols: SymbolTable,
        current_address: u32,
    }

    impl Default for TestContext {
        fn default() -> Self {
            Self {
                symbols: SymbolTable::new(),
                current_address: 0,
            }
        }
    }

    impl AssemblerContext for TestContext {
        fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
            match expr {
                Expr::Number(text, _) => text
                    .parse::<i64>()
                    .map_err(|_| format!("unable to parse numeric literal '{text}'")),
                _ => Err("unsupported expression for test context".to_string()),
            }
        }

        fn symbols(&self) -> &SymbolTable {
            &self.symbols
        }

        fn has_symbol(&self, _name: &str) -> bool {
            false
        }

        fn symbol_is_finalized(&self, _name: &str) -> Option<bool> {
            None
        }

        fn current_address(&self) -> u32 {
            self.current_address
        }

        fn pass(&self) -> u8 {
            2
        }
    }

    #[test]
    fn encodes_map_eom_neg() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        assert!(matches!(
            handler.encode_instruction("map", &[], &ctx),
            EncodeResult::Ok(bytes) if bytes == vec![0x5C]
        ));
        assert!(matches!(
            handler.encode_instruction("eom", &[], &ctx),
            EncodeResult::Ok(bytes) if bytes == vec![0xEA]
        ));
        assert!(matches!(
            handler.encode_instruction("neg", &[], &ctx),
            EncodeResult::Ok(bytes) if bytes == vec![0x42]
        ));
    }

    #[test]
    fn encodes_q_prefix_sugar() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let operand = Operand::Immediate(0x01, Span::default());
        match handler.encode_instruction("adcq", &[operand], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x42, 0x42, 0x69, 0x01]),
            EncodeResult::NotFound => panic!("adcq encoding not found"),
            EncodeResult::Error(message, _span) => panic!("adcq encoding failed: {message}"),
        }
    }

    #[test]
    fn encodes_flat_z_with_nop_prefix() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let operand = Operand::IndirectIndexedZ(0x20, Span::default());
        match handler.encode_instruction("lda", &[operand], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xEA, 0xB1, 0x20]),
            EncodeResult::NotFound => panic!("lda flat-z encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("lda flat-z encoding failed: {message}")
            }
        }
    }

    #[test]
    fn resolves_indirect_indexed_z_operand() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let family_operands = vec![FamilyOperand::IndirectIndexedZ(Expr::Number(
            "32".to_string(),
            Span::default(),
        ))];

        let resolved = handler
            .resolve_operands("lda", &family_operands, &ctx)
            .expect("resolve operands");
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            Operand::IndirectIndexedZ(value, _) => assert_eq!(*value, 32),
            other => panic!("unexpected operand: {other:?}"),
        }
    }

    #[test]
    fn resolves_relfar_when_short_branch_is_out_of_range() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let family_operands = vec![FamilyOperand::Direct(Expr::Number(
            "256".to_string(),
            Span::default(),
        ))];

        let resolved = handler
            .resolve_operands("bpl", &family_operands, &ctx)
            .expect("resolve relfar branch");
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            Operand::RelativeLong(value, _) => assert_eq!(*value, 253),
            other => panic!("expected RelativeLong, got {other:?}"),
        }
    }

    #[test]
    fn resolves_short_branch_when_offset_fits() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let family_operands = vec![FamilyOperand::Direct(Expr::Number(
            "5".to_string(),
            Span::default(),
        ))];

        let resolved = handler
            .resolve_operands("bpl", &family_operands, &ctx)
            .expect("resolve short branch");
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            Operand::Relative(value, _) => assert_eq!(*value, 3),
            other => panic!("expected Relative, got {other:?}"),
        }
    }

    #[test]
    fn encodes_relfar_branch_operand() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let operand = Operand::RelativeLong(253, Span::default());

        match handler.encode_instruction("bpl", &[operand], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x13, 0xFD, 0x00]),
            EncodeResult::NotFound => panic!("bpl relfar encoding not found"),
            EncodeResult::Error(message, _span) => panic!("bpl relfar encoding failed: {message}"),
        }
    }
}
