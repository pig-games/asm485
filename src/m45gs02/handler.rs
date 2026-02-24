// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! 45GS02 CPU handler implementation.

use crate::core::assembler::expression::expr_span;
use crate::core::family::{
    expr_has_unstable_symbols, AssemblerContext, CpuHandler, EncodeResult, FamilyHandler,
};
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

    fn has_cpu_mode(mnemonic: &str, mode: AddressMode) -> bool {
        lookup_instruction(mnemonic, mode).is_some()
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

        let (mapped_mnemonic, _is_q_mode) = Self::map_mnemonic(mnemonic);
        let mapped_upper = Self::upper_mnemonic(mapped_mnemonic);

        if family_operands.len() == 1 {
            match &family_operands[0] {
                FamilyOperand::Immediate(expr) if upper_mnemonic == "PHW" => {
                    let value = ctx.eval_expr(expr)?;
                    if !(0..=65535).contains(&value) {
                        return Err(format!("Immediate value {} out of range (0-65535)", value));
                    }
                    return Ok(vec![Operand::ImmediateWord(value as u16, expr_span(expr))]);
                }
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
                FamilyOperand::Direct(expr) => {
                    if upper_mnemonic == "PHW" {
                        let value = ctx.eval_expr(expr)?;
                        if !(0..=65535).contains(&value) {
                            return Err(format!("Address {} out of 16-bit range", value));
                        }
                        return Ok(vec![Operand::Absolute(value as u16, expr_span(expr))]);
                    }

                    if Self::has_cpu_mode(&mapped_upper, AddressMode::ZeroPage)
                        || Self::has_cpu_mode(&mapped_upper, AddressMode::Absolute)
                    {
                        let value = ctx.eval_expr(expr)?;
                        let span = expr_span(expr);

                        if !(0..=65535).contains(&value) {
                            return Err(format!("Address {} out of 16-bit range", value));
                        }

                        let has_zp = Self::has_cpu_mode(&mapped_upper, AddressMode::ZeroPage);
                        let has_abs = Self::has_cpu_mode(&mapped_upper, AddressMode::Absolute);
                        let unstable = expr_has_unstable_symbols(expr, ctx);

                        if (0..=255).contains(&value) {
                            if (!has_zp || unstable) && has_abs {
                                return Ok(vec![Operand::Absolute(value as u16, span)]);
                            }
                            if has_zp {
                                return Ok(vec![Operand::ZeroPage(value as u8, span)]);
                            }
                        }

                        if has_abs {
                            return Ok(vec![Operand::Absolute(value as u16, span)]);
                        }
                    }
                }
                FamilyOperand::DirectX(expr) => {
                    if Self::has_cpu_mode(&mapped_upper, AddressMode::ZeroPageX)
                        || Self::has_cpu_mode(&mapped_upper, AddressMode::AbsoluteX)
                    {
                        let value = ctx.eval_expr(expr)?;
                        let span = expr_span(expr);

                        if !(0..=65535).contains(&value) {
                            return Err(format!("Address {} out of 16-bit range", value));
                        }

                        let has_zp_x = Self::has_cpu_mode(&mapped_upper, AddressMode::ZeroPageX);
                        let has_abs_x = Self::has_cpu_mode(&mapped_upper, AddressMode::AbsoluteX);
                        let unstable = expr_has_unstable_symbols(expr, ctx);

                        if (0..=255).contains(&value) {
                            if (!has_zp_x || unstable) && has_abs_x {
                                return Ok(vec![Operand::AbsoluteX(value as u16, span)]);
                            }
                            if has_zp_x {
                                return Ok(vec![Operand::ZeroPageX(value as u8, span)]);
                            }
                        }

                        if has_abs_x {
                            return Ok(vec![Operand::AbsoluteX(value as u16, span)]);
                        }
                    }
                }
                FamilyOperand::DirectY(expr) => {
                    if Self::has_cpu_mode(&mapped_upper, AddressMode::ZeroPageY)
                        || Self::has_cpu_mode(&mapped_upper, AddressMode::AbsoluteY)
                    {
                        let value = ctx.eval_expr(expr)?;
                        let span = expr_span(expr);

                        if !(0..=65535).contains(&value) {
                            return Err(format!("Address {} out of 16-bit range", value));
                        }

                        let has_zp_y = Self::has_cpu_mode(&mapped_upper, AddressMode::ZeroPageY);
                        let has_abs_y = Self::has_cpu_mode(&mapped_upper, AddressMode::AbsoluteY);
                        let unstable = expr_has_unstable_symbols(expr, ctx);

                        if (0..=255).contains(&value) {
                            if (!has_zp_y || unstable) && has_abs_y {
                                return Ok(vec![Operand::AbsoluteY(value as u16, span)]);
                            }
                            if has_zp_y {
                                return Ok(vec![Operand::ZeroPageY(value as u8, span)]);
                            }
                        }

                        if has_abs_y {
                            return Ok(vec![Operand::AbsoluteY(value as u16, span)]);
                        }
                    }
                }
                FamilyOperand::IndexedIndirectX(expr)
                    if mapped_upper == "JSR"
                        && Self::has_cpu_mode(
                            &mapped_upper,
                            AddressMode::AbsoluteIndexedIndirect,
                        ) =>
                {
                    let value = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    if !(0..=65535).contains(&value) {
                        return Err(format!(
                            "Absolute indexed indirect address {} out of 16-bit range",
                            value
                        ));
                    }
                    return Ok(vec![Operand::AbsoluteIndexedIndirect(value as u16, span)]);
                }
                FamilyOperand::Indirect(expr)
                    if mapped_upper == "JSR"
                        && Self::has_cpu_mode(&mapped_upper, AddressMode::Indirect) =>
                {
                    let value = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    if !(0..=65535).contains(&value) {
                        return Err(format!("Indirect address {} out of 16-bit range", value));
                    }
                    return Ok(vec![Operand::Indirect(value as u16, span)]);
                }
                FamilyOperand::StackRelativeIndirectIndexedY(expr)
                    if Self::has_cpu_mode(
                        &mapped_upper,
                        AddressMode::StackRelativeIndirectIndexedY,
                    ) =>
                {
                    let value = ctx.eval_expr(expr)?;
                    let span = expr_span(expr);
                    if !(0..=255).contains(&value) {
                        return Err(format!(
                            "Stack-relative indirect indexed address {} out of 8-bit range",
                            value
                        ));
                    }
                    return Ok(vec![Operand::StackRelativeIndirectIndexedY(
                        value as u8,
                        span,
                    )]);
                }
                _ => {}
            }
        }

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

    #[test]
    fn encodes_implied_extension_mnemonics() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let cases = [
            ("cle", 0x02),
            ("see", 0x03),
            ("inz", 0x0B),
            ("tys", 0x1B),
            ("dez", 0x2B),
            ("taz", 0x3B),
            ("tab", 0x4B),
            ("tza", 0x5B),
            ("tba", 0x6B),
            ("phz", 0xCB),
            ("plz", 0xEB),
            ("tsy", 0xFB),
        ];

        for (mnemonic, opcode) in cases {
            match handler.encode_instruction(mnemonic, &[], &ctx) {
                EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![opcode], "mnemonic={mnemonic}"),
                EncodeResult::NotFound => panic!("{mnemonic} encoding not found"),
                EncodeResult::Error(message, _span) => {
                    panic!("{mnemonic} encoding failed: {message}")
                }
            }
        }
    }

    #[test]
    fn encodes_ldz_and_cpz_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let ldz_imm = Operand::Immediate(0x34, Span::default());
        match handler.encode_instruction("ldz", &[ldz_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xA3, 0x34]),
            EncodeResult::NotFound => panic!("ldz immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("ldz immediate encoding failed: {message}")
            }
        }

        let ldz_abs = Operand::Absolute(0x1234, Span::default());
        match handler.encode_instruction("ldz", &[ldz_abs], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x9B, 0x34, 0x12]),
            EncodeResult::NotFound => panic!("ldz absolute encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("ldz absolute encoding failed: {message}")
            }
        }

        let cpz_zp = Operand::ZeroPage(0x20, Span::default());
        match handler.encode_instruction("cpz", &[cpz_zp], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xD4, 0x20]),
            EncodeResult::NotFound => panic!("cpz zero-page encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("cpz zero-page encoding failed: {message}")
            }
        }
    }

    #[test]
    fn encodes_rts_immediate_form() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let rts_imm = Operand::Immediate(0x34, Span::default());
        match handler.encode_instruction("rts", &[rts_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x62, 0x34]),
            EncodeResult::NotFound => panic!("rts immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("rts immediate encoding failed: {message}")
            }
        }
    }

    #[test]
    fn encodes_stz_absolute_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let stz_abs = Operand::Absolute(0x2000, Span::default());
        match handler.encode_instruction("stz", &[stz_abs], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x8C, 0x00, 0x20]),
            EncodeResult::NotFound => panic!("stz absolute encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("stz absolute encoding failed: {message}")
            }
        }

        let stz_abs_x = Operand::AbsoluteX(0x2002, Span::default());
        match handler.encode_instruction("stz", &[stz_abs_x], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x8E, 0x02, 0x20]),
            EncodeResult::NotFound => panic!("stz absolute x encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("stz absolute x encoding failed: {message}")
            }
        }
    }

    #[test]
    fn encodes_ora_and_sbc_immediate_overrides() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let ora_imm = Operand::Immediate(0x12, Span::default());
        match handler.encode_instruction("ora", &[ora_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xF9, 0x12]),
            EncodeResult::NotFound => panic!("ora immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("ora immediate encoding failed: {message}")
            }
        }

        let sbc_imm = Operand::Immediate(0x34, Span::default());
        match handler.encode_instruction("sbc", &[sbc_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xD9, 0x34]),
            EncodeResult::NotFound => panic!("sbc immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("sbc immediate encoding failed: {message}")
            }
        }
    }

    #[test]
    fn encodes_additional_immediate_overrides() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let and_imm = Operand::Immediate(0x11, Span::default());
        match handler.encode_instruction("and", &[and_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x19, 0x11]),
            EncodeResult::NotFound => panic!("and immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("and immediate encoding failed: {message}")
            }
        }

        let eor_imm = Operand::Immediate(0x22, Span::default());
        match handler.encode_instruction("eor", &[eor_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x39, 0x22]),
            EncodeResult::NotFound => panic!("eor immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("eor immediate encoding failed: {message}")
            }
        }

        let adc_imm = Operand::Immediate(0x33, Span::default());
        match handler.encode_instruction("adc", &[adc_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x59, 0x33]),
            EncodeResult::NotFound => panic!("adc immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("adc immediate encoding failed: {message}")
            }
        }

        let lda_imm = Operand::Immediate(0x44, Span::default());
        match handler.encode_instruction("lda", &[lda_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x99, 0x44]),
            EncodeResult::NotFound => panic!("lda immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("lda immediate encoding failed: {message}")
            }
        }

        let bit_imm = Operand::Immediate(0x55, Span::default());
        match handler.encode_instruction("bit", &[bit_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x79, 0x55]),
            EncodeResult::NotFound => panic!("bit immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("bit immediate encoding failed: {message}")
            }
        }

        let cmp_imm = Operand::Immediate(0x66, Span::default());
        match handler.encode_instruction("cmp", &[cmp_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xB9, 0x66]),
            EncodeResult::NotFound => panic!("cmp immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("cmp immediate encoding failed: {message}")
            }
        }
    }

    #[test]
    fn encodes_absolute_y_overrides() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let ora_abs_y = Operand::AbsoluteY(0x2000, Span::default());
        match handler.encode_instruction("ora", &[ora_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x09, 0x00, 0x20]),
            EncodeResult::NotFound => panic!("ora absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("ora absolute y encoding failed: {message}")
            }
        }

        let and_abs_y = Operand::AbsoluteY(0x2002, Span::default());
        match handler.encode_instruction("and", &[and_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x29, 0x02, 0x20]),
            EncodeResult::NotFound => panic!("and absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("and absolute y encoding failed: {message}")
            }
        }

        let eor_abs_y = Operand::AbsoluteY(0x2004, Span::default());
        match handler.encode_instruction("eor", &[eor_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x49, 0x04, 0x20]),
            EncodeResult::NotFound => panic!("eor absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("eor absolute y encoding failed: {message}")
            }
        }

        let adc_abs_y = Operand::AbsoluteY(0x2006, Span::default());
        match handler.encode_instruction("adc", &[adc_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x69, 0x06, 0x20]),
            EncodeResult::NotFound => panic!("adc absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("adc absolute y encoding failed: {message}")
            }
        }

        let sta_abs_y = Operand::AbsoluteY(0x2008, Span::default());
        match handler.encode_instruction("sta", &[sta_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x89, 0x08, 0x20]),
            EncodeResult::NotFound => panic!("sta absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("sta absolute y encoding failed: {message}")
            }
        }

        let lda_abs_y = Operand::AbsoluteY(0x200A, Span::default());
        match handler.encode_instruction("lda", &[lda_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xA9, 0x0A, 0x20]),
            EncodeResult::NotFound => panic!("lda absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("lda absolute y encoding failed: {message}")
            }
        }

        let cmp_abs_y = Operand::AbsoluteY(0x200C, Span::default());
        match handler.encode_instruction("cmp", &[cmp_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xC9, 0x0C, 0x20]),
            EncodeResult::NotFound => panic!("cmp absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("cmp absolute y encoding failed: {message}")
            }
        }

        let sbc_abs_y = Operand::AbsoluteY(0x200E, Span::default());
        match handler.encode_instruction("sbc", &[sbc_abs_y], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xE9, 0x0E, 0x20]),
            EncodeResult::NotFound => panic!("sbc absolute y encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("sbc absolute y encoding failed: {message}")
            }
        }
    }

    #[test]
    fn resolves_jsr_indirect_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let jsr_ind = vec![FamilyOperand::Indirect(Expr::Number(
            "8192".to_string(),
            Span::default(),
        ))];
        let resolved_ind = handler
            .resolve_operands("jsr", &jsr_ind, &ctx)
            .expect("resolve jsr indirect");
        match &resolved_ind[0] {
            Operand::Indirect(value, _) => assert_eq!(*value, 8192),
            other => panic!("expected Indirect, got {other:?}"),
        }

        let jsr_ind_x = vec![FamilyOperand::IndexedIndirectX(Expr::Number(
            "8194".to_string(),
            Span::default(),
        ))];
        let resolved_ind_x = handler
            .resolve_operands("jsr", &jsr_ind_x, &ctx)
            .expect("resolve jsr indexed indirect");
        match &resolved_ind_x[0] {
            Operand::AbsoluteIndexedIndirect(value, _) => assert_eq!(*value, 8194),
            other => panic!("expected AbsoluteIndexedIndirect, got {other:?}"),
        }
    }

    #[test]
    fn encodes_jsr_indirect_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let jsr_ind = Operand::Indirect(0x2000, Span::default());
        match handler.encode_instruction("jsr", &[jsr_ind], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x22, 0x00, 0x20]),
            EncodeResult::NotFound => panic!("jsr indirect encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("jsr indirect encoding failed: {message}")
            }
        }

        let jsr_ind_x = Operand::AbsoluteIndexedIndirect(0x2002, Span::default());
        match handler.encode_instruction("jsr", &[jsr_ind_x], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x23, 0x02, 0x20]),
            EncodeResult::NotFound => panic!("jsr absolute indexed indirect encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("jsr absolute indexed indirect encoding failed: {message}")
            }
        }
    }

    #[test]
    fn resolves_stack_relative_indirect_indexed_y_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let sta_ops = vec![FamilyOperand::StackRelativeIndirectIndexedY(Expr::Number(
            "32".to_string(),
            Span::default(),
        ))];
        let resolved_sta = handler
            .resolve_operands("sta", &sta_ops, &ctx)
            .expect("resolve sta stack-relative indirect indexed y");
        match &resolved_sta[0] {
            Operand::StackRelativeIndirectIndexedY(value, _) => assert_eq!(*value, 32),
            other => panic!("expected StackRelativeIndirectIndexedY, got {other:?}"),
        }

        let lda_ops = vec![FamilyOperand::StackRelativeIndirectIndexedY(Expr::Number(
            "33".to_string(),
            Span::default(),
        ))];
        let resolved_lda = handler
            .resolve_operands("lda", &lda_ops, &ctx)
            .expect("resolve lda stack-relative indirect indexed y");
        match &resolved_lda[0] {
            Operand::StackRelativeIndirectIndexedY(value, _) => assert_eq!(*value, 33),
            other => panic!("expected StackRelativeIndirectIndexedY, got {other:?}"),
        }
    }

    #[test]
    fn encodes_stack_relative_indirect_indexed_y_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let sta_operand = Operand::StackRelativeIndirectIndexedY(0x20, Span::default());
        match handler.encode_instruction("sta", &[sta_operand], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0x82, 0x20]),
            EncodeResult::NotFound => {
                panic!("sta stack-relative indirect indexed y encoding not found")
            }
            EncodeResult::Error(message, _span) => {
                panic!("sta stack-relative indirect indexed y encoding failed: {message}")
            }
        }

        let lda_operand = Operand::StackRelativeIndirectIndexedY(0x21, Span::default());
        match handler.encode_instruction("lda", &[lda_operand], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xE2, 0x21]),
            EncodeResult::NotFound => {
                panic!("lda stack-relative indirect indexed y encoding not found")
            }
            EncodeResult::Error(message, _span) => {
                panic!("lda stack-relative indirect indexed y encoding failed: {message}")
            }
        }
    }

    #[test]
    fn resolves_ldz_directx_to_absolutex_when_zero_page_x_mode_is_unavailable() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();
        let family_operands = vec![FamilyOperand::DirectX(Expr::Number(
            "32".to_string(),
            Span::default(),
        ))];

        let resolved = handler
            .resolve_operands("ldz", &family_operands, &ctx)
            .expect("resolve ldz directx");
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            Operand::AbsoluteX(value, _) => assert_eq!(*value, 32),
            other => panic!("expected AbsoluteX, got {other:?}"),
        }
    }

    #[test]
    fn resolves_cpz_direct_to_absolute_for_unstable_symbol() {
        struct UnstableSymbolContext {
            symbols: SymbolTable,
        }

        impl AssemblerContext for UnstableSymbolContext {
            fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
                match expr {
                    Expr::Identifier(name, _) if name.eq_ignore_ascii_case("target") => Ok(32),
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
                0
            }

            fn pass(&self) -> u8 {
                1
            }
        }

        let handler = M45GS02CpuHandler::new();
        let ctx = UnstableSymbolContext {
            symbols: SymbolTable::new(),
        };
        let family_operands = vec![FamilyOperand::Direct(Expr::Identifier(
            "target".to_string(),
            Span::default(),
        ))];

        let resolved = handler
            .resolve_operands("cpz", &family_operands, &ctx)
            .expect("resolve cpz direct unstable");
        assert_eq!(resolved.len(), 1);
        match &resolved[0] {
            Operand::Absolute(value, _) => assert_eq!(*value, 32),
            other => panic!("expected Absolute, got {other:?}"),
        }
    }

    #[test]
    fn resolves_phw_immediate_and_absolute_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let immediate_operands = vec![FamilyOperand::Immediate(Expr::Number(
            "4660".to_string(),
            Span::default(),
        ))];
        let resolved_imm = handler
            .resolve_operands("phw", &immediate_operands, &ctx)
            .expect("resolve phw immediate");
        match &resolved_imm[0] {
            Operand::ImmediateWord(value, _) => assert_eq!(*value, 4660),
            other => panic!("expected ImmediateWord, got {other:?}"),
        }

        let absolute_operands = vec![FamilyOperand::Direct(Expr::Number(
            "8192".to_string(),
            Span::default(),
        ))];
        let resolved_abs = handler
            .resolve_operands("phw", &absolute_operands, &ctx)
            .expect("resolve phw absolute");
        match &resolved_abs[0] {
            Operand::Absolute(value, _) => assert_eq!(*value, 8192),
            other => panic!("expected Absolute, got {other:?}"),
        }
    }

    #[test]
    fn encodes_phw_immediate_and_absolute_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let phw_imm = Operand::ImmediateWord(0x1234, Span::default());
        match handler.encode_instruction("phw", &[phw_imm], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xF4, 0x34, 0x12]),
            EncodeResult::NotFound => panic!("phw immediate encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("phw immediate encoding failed: {message}")
            }
        }

        let phw_abs = Operand::Absolute(0x2000, Span::default());
        match handler.encode_instruction("phw", &[phw_abs], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xEC, 0x00, 0x20]),
            EncodeResult::NotFound => panic!("phw absolute encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("phw absolute encoding failed: {message}")
            }
        }
    }

    #[test]
    fn encodes_dew_and_inw_zero_page_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let dew = Operand::ZeroPage(0x20, Span::default());
        match handler.encode_instruction("dew", &[dew], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xC3, 0x20]),
            EncodeResult::NotFound => panic!("dew encoding not found"),
            EncodeResult::Error(message, _span) => panic!("dew encoding failed: {message}"),
        }

        let inw = Operand::ZeroPage(0x21, Span::default());
        match handler.encode_instruction("inw", &[inw], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xE3, 0x21]),
            EncodeResult::NotFound => panic!("inw encoding not found"),
            EncodeResult::Error(message, _span) => panic!("inw encoding failed: {message}"),
        }
    }

    #[test]
    fn encodes_asw_and_row_absolute_forms() {
        let handler = M45GS02CpuHandler::new();
        let ctx = TestContext::default();

        let asw_abs = Operand::Absolute(0x2000, Span::default());
        match handler.encode_instruction("asw", &[asw_abs], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xBB, 0x00, 0x20]),
            EncodeResult::NotFound => panic!("asw absolute encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("asw absolute encoding failed: {message}")
            }
        }

        let row_abs = Operand::Absolute(0x2002, Span::default());
        match handler.encode_instruction("row", &[row_abs], &ctx) {
            EncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xDB, 0x02, 0x20]),
            EncodeResult::NotFound => panic!("row absolute encoding not found"),
            EncodeResult::Error(message, _span) => {
                panic!("row absolute encoding failed: {message}")
            }
        }
    }
}
