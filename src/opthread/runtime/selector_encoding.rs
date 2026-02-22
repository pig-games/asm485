use crate::core::family::AssemblerContext;
use crate::core::parser::Expr;
use crate::core::registry::VmEncodeCandidate;
use crate::families::mos6502::{AddressMode, OperandForce};
use crate::m65816::state;
use crate::opthread::package::ModeSelectorDescriptor;

use super::force_suffix;
use super::selector_bridge::{SelectorExprContext, SelectorInput};

pub(super) fn input_shape_requires_m65816(shape_key: &str) -> bool {
    shape_key.eq_ignore_ascii_case("stack_relative")
        || shape_key.eq_ignore_ascii_case("stack_relative_indirect_y")
        || shape_key.eq_ignore_ascii_case("indirect_long")
        || shape_key.eq_ignore_ascii_case("indirect_long_y")
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

fn bank_unknown_error(assumed_bank_key: &str, upper_mnemonic: &str) -> String {
    let mut message = format!(
        "Unable to resolve 24-bit bank because .assume {assumed_bank_key}=... is unknown; set .assume {assumed_bank_key}=$00..$FF or {assumed_bank_key}=auto"
    );
    message.push_str(
        ". If this source relied on removed stack-sequence inference, update .assume near this site",
    );
    let has_long = matches!(
        upper_mnemonic,
        "ORA" | "AND" | "EOR" | "ADC" | "STA" | "LDA" | "CMP" | "SBC" | "JML" | "JSL"
    );
    if has_long {
        message.push_str("; long-capable operands can be forced with ',l'");
    }
    message.push('.');
    message
}

pub(super) fn selector_to_candidate(
    selector: &ModeSelectorDescriptor,
    input: &SelectorInput<'_>,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Option<VmEncodeCandidate>, String> {
    let mode_key = selector.mode_key.to_ascii_lowercase();
    let Some(mode) = parse_mode_key_lower(mode_key.as_str()) else {
        return Ok(None);
    };
    let operand_bytes = match selector.operand_plan.as_str() {
        "none" => Vec::new(),
        "u8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u8(expr0, expr_ctx)?]
        }
        "u16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u16(expr0, expr_ctx)?]
        }
        "u24" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u24(expr0, expr_ctx)?]
        }
        "force_l_u24" => vec![encode_expr_force_u24(
            input
                .expr0
                .ok_or_else(|| "missing force-l operand".to_string())?,
            expr_ctx,
        )?],
        "m65816_long_pref_u24" => {
            let expr0 = input
                .expr0
                .ok_or_else(|| "missing unresolved-long operand".to_string())?;
            if !prefer_long_for_expr(expr0, upper_mnemonic, expr_ctx)? {
                return Ok(None);
            }
            vec![encode_expr_force_u24(expr0, expr_ctx)?]
        }
        "m65816_abs16_bank_fold_dbr" => {
            let expr0 = input
                .expr0
                .ok_or_else(|| "missing bank-fold operand".to_string())?;
            if should_defer_abs16_to_other_candidates(expr0, upper_mnemonic, expr_ctx)? {
                return Ok(None);
            }
            vec![encode_expr_abs16_bank_fold(
                expr0,
                upper_mnemonic,
                expr_ctx,
            )?]
        }
        "rel8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel8(expr0, expr_ctx, 2)?]
        }
        "rel16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel16(expr0, expr_ctx, 3)?]
        }
        "pair_u8_rel8" => vec![
            encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                expr_ctx,
            )?,
            encode_expr_rel8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                expr_ctx,
                3,
            )?,
        ],
        "u8u8_packed" => vec![{
            let mut packed = encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                expr_ctx,
            )?;
            packed.extend(encode_expr_u8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                expr_ctx,
            )?);
            packed
        }],
        "force_d_u8" => vec![encode_expr_force_d_u8(
            input
                .expr0
                .ok_or_else(|| "missing force-d operand".to_string())?,
            expr_ctx,
        )?],
        "force_b_abs16_dbr" => {
            if matches!(upper_mnemonic, "JMP" | "JSR") {
                return Ok(None);
            }
            vec![encode_expr_force_abs16(
                input
                    .expr0
                    .ok_or_else(|| "missing force-b operand".to_string())?,
                false,
                OperandForce::DataBank,
                upper_mnemonic,
                expr_ctx,
            )?]
        }
        "force_k_abs16_pbr" => {
            if !matches!(upper_mnemonic, "JMP" | "JSR") {
                return Ok(None);
            }
            vec![encode_expr_force_abs16(
                input
                    .expr0
                    .ok_or_else(|| "missing force-k operand".to_string())?,
                true,
                OperandForce::ProgramBank,
                upper_mnemonic,
                expr_ctx,
            )?]
        }
        "imm_mx" => vec![encode_expr_m65816_immediate(
            input
                .expr0
                .ok_or_else(|| "missing immediate operand".to_string())?,
            upper_mnemonic,
            expr_ctx,
        )?],
        _ => return Ok(None),
    };

    if mode.operand_size() == 0 && !operand_bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(VmEncodeCandidate {
        mode_key,
        operand_bytes,
    }))
}

fn parse_mode_key_lower(mode_key_lower: &str) -> Option<AddressMode> {
    match mode_key_lower {
        "implied" => Some(AddressMode::Implied),
        "accumulator" => Some(AddressMode::Accumulator),
        "immediate" => Some(AddressMode::Immediate),
        "zeropage" => Some(AddressMode::ZeroPage),
        "zeropagex" => Some(AddressMode::ZeroPageX),
        "zeropagey" => Some(AddressMode::ZeroPageY),
        "absolute" => Some(AddressMode::Absolute),
        "absolutex" => Some(AddressMode::AbsoluteX),
        "absolutey" => Some(AddressMode::AbsoluteY),
        "indirect" => Some(AddressMode::Indirect),
        "indexedindirectx" => Some(AddressMode::IndexedIndirectX),
        "indirectindexedy" => Some(AddressMode::IndirectIndexedY),
        "relative" => Some(AddressMode::Relative),
        "relativelong" => Some(AddressMode::RelativeLong),
        "zeropageindirect" => Some(AddressMode::ZeroPageIndirect),
        "absoluteindexedindirect" => Some(AddressMode::AbsoluteIndexedIndirect),
        "stackrelative" => Some(AddressMode::StackRelative),
        "stackrelativeindirectindexedy" => Some(AddressMode::StackRelativeIndirectIndexedY),
        "absolutelong" => Some(AddressMode::AbsoluteLong),
        "absolutelongx" => Some(AddressMode::AbsoluteLongX),
        "indirectlong" => Some(AddressMode::IndirectLong),
        "directpageindirectlong" => Some(AddressMode::DirectPageIndirectLong),
        "directpageindirectlongy" => Some(AddressMode::DirectPageIndirectLongY),
        "blockmove" => Some(AddressMode::BlockMove),
        _ => None,
    }
}

fn encode_expr_u8(expr: &Expr, expr_ctx: &SelectorExprContext<'_>) -> Result<Vec<u8>, String> {
    encode_expr_fixed_width(expr, expr_ctx, 1, 0xFF, "invalid u8 operand")
}

fn encode_expr_u16(expr: &Expr, expr_ctx: &SelectorExprContext<'_>) -> Result<Vec<u8>, String> {
    encode_expr_fixed_width(expr, expr_ctx, 2, 0xFFFF, "invalid u16 operand")
}

fn encode_expr_u24(expr: &Expr, expr_ctx: &SelectorExprContext<'_>) -> Result<Vec<u8>, String> {
    encode_expr_fixed_width(expr, expr_ctx, 3, 0xFF_FFFF, "invalid u24 operand")
}

fn encode_expr_fixed_width(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    byte_count: usize,
    max_value: i64,
    error_message: &str,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    if !(0..=max_value).contains(&value) {
        return Err(error_message.to_string());
    }
    Ok(encode_le_bytes(value as u32, byte_count))
}

fn encode_le_bytes(value: u32, byte_count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(byte_count);
    let mut remaining = value;
    for _ in 0..byte_count {
        bytes.push((remaining & 0xFF) as u8);
        remaining >>= 8;
    }
    bytes
}

fn encode_expr_force_d_u8(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(vec![0]);
    }
    let value = expr_ctx.eval_expr(expr)?;
    if (0..=255).contains(&value) {
        return Ok(vec![value as u8]);
    }
    if !(0..=0xFFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 16-bit range for explicit ',d'",
            value
        ));
    }
    let absolute_value = value as u16;
    let Some(dp_offset) =
        direct_page_offset_for_absolute_address(absolute_value, expr_ctx.assembler_ctx)
    else {
        return Err(format!(
            "Address ${absolute_value:04X} is outside the direct-page window for explicit ',d'"
        ));
    };
    Ok(vec![dp_offset])
}

fn encode_expr_force_u24(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(vec![0, 0, 0]);
    }
    let value = expr_ctx.eval_expr(expr)?;
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 24-bit range for explicit ',l'",
            value
        ));
    }
    Ok(encode_le_bytes(value as u32, 3))
}

fn prefer_long_for_expr(
    expr: &Expr,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<bool, String> {
    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, expr_ctx.assembler_ctx);
    let symbol_based = expr_has_symbol_references(expr);

    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(expr_ctx.assembler_ctx.current_address() > 0xFFFF
            || !assumed_known
            || assumed_bank != 0);
    }

    let value = expr_ctx.eval_expr(expr)?;
    if symbol_based && (0..=0xFFFF).contains(&value) && (!assumed_known || assumed_bank != 0) {
        return Ok(true);
    }
    if (0x1_0000..=0xFF_FFFF).contains(&value) {
        let absolute_bank = ((value as u32) >> 16) as u8;
        if !assumed_known || absolute_bank != assumed_bank {
            return Ok(true);
        }
    }
    Ok(false)
}

fn should_defer_abs16_to_other_candidates(
    expr: &Expr,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<bool, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(true);
    }
    let value = expr_ctx.eval_expr(expr)?;
    if value <= 0xFFFF {
        return Ok(true);
    }
    if value > 0xFF_FFFF {
        return Ok(false);
    }
    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, expr_ctx.assembler_ctx);
    let absolute_bank = ((value as u32) >> 16) as u8;
    Ok(!assumed_known || absolute_bank != assumed_bank)
}

fn encode_expr_abs16_bank_fold(
    expr: &Expr,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!("Address {} out of 24-bit range", value));
    }
    if value <= 0xFFFF {
        let absolute = value as u16;
        return Ok(encode_le_bytes(absolute as u32, 2));
    }

    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, expr_ctx.assembler_ctx);
    let assumed_key = if matches!(upper_mnemonic, "JMP" | "JSR") {
        "pbr"
    } else {
        "dbr"
    };
    if !assumed_known {
        return Err(bank_unknown_error(assumed_key, upper_mnemonic));
    }
    let absolute_bank = ((value as u32) >> 16) as u8;
    if absolute_bank != assumed_bank {
        return Err(bank_mismatch_error(
            value as u32,
            absolute_bank,
            assumed_bank,
            assumed_key,
        ));
    }
    let absolute = (value as u32 & 0xFFFF) as u16;
    Ok(encode_le_bytes(absolute as u32, 2))
}

fn assumed_bank_state(upper_mnemonic: &str, ctx: &dyn AssemblerContext) -> (u8, bool) {
    if matches!(upper_mnemonic, "JMP" | "JSR") {
        (state::program_bank(ctx), state::program_bank_known(ctx))
    } else {
        (state::data_bank(ctx), state::data_bank_known(ctx))
    }
}

fn expr_has_symbol_references(expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(_, _) | Expr::Register(_, _) => true,
        Expr::Indirect(inner, _) | Expr::Immediate(inner, _) | Expr::IndirectLong(inner, _) => {
            expr_has_symbol_references(inner)
        }
        Expr::Tuple(items, _) => items.iter().any(expr_has_symbol_references),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            expr_has_symbol_references(cond)
                || expr_has_symbol_references(then_expr)
                || expr_has_symbol_references(else_expr)
        }
        Expr::Unary { expr, .. } => expr_has_symbol_references(expr),
        Expr::Binary { left, right, .. } => {
            expr_has_symbol_references(left) || expr_has_symbol_references(right)
        }
        Expr::Number(_, _) | Expr::Dollar(_) | Expr::String(_, _) | Expr::Error(_, _) => false,
    }
}

fn encode_expr_force_abs16(
    expr: &Expr,
    use_program_bank: bool,
    force: OperandForce,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(vec![0, 0]);
    }
    let value = expr_ctx.eval_expr(expr)?;
    if (0..=65535).contains(&value) {
        return Ok(encode_le_bytes(value as u32, 2));
    }
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 24-bit range for explicit ',{}'",
            value,
            force_suffix(force)
        ));
    }
    let assumed_bank_key = if use_program_bank { "pbr" } else { "dbr" };
    let assumed_known = if use_program_bank {
        state::program_bank_known(expr_ctx.assembler_ctx)
    } else {
        state::data_bank_known(expr_ctx.assembler_ctx)
    };
    if !assumed_known {
        return Err(bank_unknown_error(assumed_bank_key, upper_mnemonic));
    }
    let assumed_bank = if use_program_bank {
        state::program_bank(expr_ctx.assembler_ctx)
    } else {
        state::data_bank(expr_ctx.assembler_ctx)
    };
    let absolute_bank = ((value as u32) >> 16) as u8;
    if absolute_bank != assumed_bank {
        return Err(bank_mismatch_error(
            value as u32,
            absolute_bank,
            assumed_bank,
            assumed_bank_key,
        ));
    }
    let absolute = (value as u32 & 0xFFFF) as u16;
    Ok(vec![
        (absolute & 0xFF) as u8,
        ((absolute >> 8) & 0xFF) as u8,
    ])
}

fn direct_page_offset_for_absolute_address(address: u16, ctx: &dyn AssemblerContext) -> Option<u8> {
    if !state::direct_page_known(ctx) || address <= 0x00FF {
        return None;
    }
    let dp = state::direct_page(ctx);
    let offset = address.wrapping_sub(dp);
    (offset <= 0x00FF).then_some(offset as u8)
}

fn encode_expr_rel8(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    instr_len: i64,
) -> Result<Vec<u8>, String> {
    encode_expr_relative(
        expr,
        expr_ctx,
        instr_len,
        -128,
        127,
        1,
        "Branch target out of range",
    )
}

fn encode_expr_rel16(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    instr_len: i64,
) -> Result<Vec<u8>, String> {
    encode_expr_relative(
        expr,
        expr_ctx,
        instr_len,
        -32768,
        32767,
        2,
        "Long branch target out of range",
    )
}

fn encode_expr_relative(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    instr_len: i64,
    min_offset: i64,
    max_offset: i64,
    byte_count: usize,
    error_label: &str,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    let current = expr_ctx.assembler_ctx.current_address() as i64 + instr_len;
    let offset = value - current;
    if !(min_offset..=max_offset).contains(&offset) {
        if expr_ctx.assembler_ctx.pass() > 1 {
            return Err(format!("{}: offset {}", error_label, offset));
        }
        return Ok(vec![0; byte_count]);
    }
    let mut bytes = Vec::with_capacity(byte_count);
    let mut remaining = offset as i32 as u32;
    for _ in 0..byte_count {
        bytes.push((remaining & 0xFF) as u8);
        remaining >>= 8;
    }
    Ok(bytes)
}

fn encode_expr_m65816_immediate(
    expr: &Expr,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    let acc_imm = matches!(
        upper_mnemonic,
        "ADC" | "AND" | "BIT" | "CMP" | "EOR" | "LDA" | "ORA" | "SBC"
    );
    let idx_imm = matches!(upper_mnemonic, "CPX" | "CPY" | "LDX" | "LDY");
    if acc_imm {
        if state::accumulator_is_8bit(expr_ctx.assembler_ctx) {
            if !(0..=255).contains(&value) {
                return Err(format!(
                    "Accumulator immediate value {} out of range (0-255) in 8-bit mode",
                    value
                ));
            }
            return Ok(vec![value as u8]);
        }
        if !(0..=65535).contains(&value) {
            return Err(format!(
                "Accumulator immediate value {} out of range (0-65535) in 16-bit mode",
                value
            ));
        }
        return Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ]);
    }
    if idx_imm {
        if state::index_is_8bit(expr_ctx.assembler_ctx) {
            if !(0..=255).contains(&value) {
                return Err(format!(
                    "Index immediate value {} out of range (0-255) in 8-bit mode",
                    value
                ));
            }
            return Ok(vec![value as u8]);
        }
        if !(0..=65535).contains(&value) {
            return Err(format!(
                "Index immediate value {} out of range (0-65535) in 16-bit mode",
                value
            ));
        }
        return Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ]);
    }
    if !(0..=255).contains(&value) {
        return Err(format!("Immediate value {} out of range (0-255)", value));
    }
    Ok(vec![value as u8])
}
