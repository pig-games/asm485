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
            return EncodeResult::Ok(vec![entry.opcode]);
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
}
