// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8080 family handler implementation.

use crate::core::assembler::expression::{binary_op_text, expr_text};
use crate::core::family::{
    AssemblerContext, EncodeResult, FamilyEncodeResult, FamilyHandler, FamilyParseError,
};
use crate::core::parser::{BinaryOp, Expr};

use super::operand::{expr_span, FamilyOperand, Operand};
use super::table::{has_mnemonic, lookup_instruction, ArgType};
use super::{is_condition, is_index_register, is_register};

/// Family handler for Intel 8080 family (8080, 8085, Z80).
#[derive(Debug)]
pub struct Intel8080FamilyHandler;

impl FamilyHandler for Intel8080FamilyHandler {
    type FamilyOperand = FamilyOperand;
    type Operand = Operand;

    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Vec<Self::FamilyOperand>, FamilyParseError> {
        let mut result = Vec::new();

        let upper = mnemonic.to_ascii_uppercase();

        for expr in exprs {
            if upper == "RST" {
                result.push(FamilyOperand::RstVector(expr.clone()));
                continue;
            }
            match expr {
                // Register reference
                Expr::Identifier(name, span) if is_register(name) => {
                    result.push(FamilyOperand::Register(name.to_uppercase(), *span));
                }

                // Condition code
                Expr::Identifier(name, span) if is_condition(name) => {
                    result.push(FamilyOperand::Condition(name.to_uppercase(), *span));
                }

                // Plain identifier (label reference) - becomes immediate
                Expr::Identifier(_, _) => {
                    result.push(FamilyOperand::Immediate(expr.clone()));
                }

                // Numeric immediate
                Expr::Number(_, _) => {
                    result.push(FamilyOperand::Immediate(expr.clone()));
                }

                // Expression parse error - treat as immediate to preserve legacy errors
                Expr::Error(_, _) => {
                    result.push(FamilyOperand::Immediate(expr.clone()));
                }

                // String literal (single or double char) - treat as immediate
                Expr::String(_, _) => {
                    result.push(FamilyOperand::Immediate(expr.clone()));
                }

                // Current address
                Expr::Dollar(_) => {
                    result.push(FamilyOperand::Immediate(expr.clone()));
                }

                // Expression
                Expr::Binary { .. } | Expr::Unary { .. } | Expr::Ternary { .. } => {
                    result.push(FamilyOperand::Immediate(expr.clone()));
                }

                // Indirect addressing: (BC), (DE), (HL), (IX), (IY), (IX+d), (IY+d), (nn)
                Expr::Indirect(inner, span) => {
                    match inner.as_ref() {
                        // Simple indirect via register: (BC), (DE), (HL), (SP), (IX), (IY)
                        Expr::Identifier(name, _) => {
                            let upper = name.to_uppercase();
                            if is_index_register(&upper) {
                                // (IX) or (IY) with implicit zero offset
                                result.push(FamilyOperand::Indexed {
                                    base: upper,
                                    offset: Expr::Number("0".to_string(), *span),
                                    span: *span,
                                });
                            } else {
                                // (BC), (DE), (HL), (SP) - regular indirect
                                result.push(FamilyOperand::Indirect(upper, *span));
                            }
                        }

                        // Indexed addressing: (IX+d) or (IY+d) or (IX-d) or (IY-d)
                        Expr::Binary {
                            op,
                            left,
                            right,
                            span: inner_span,
                        } => {
                            let base_name = match left.as_ref() {
                                Expr::Identifier(name, _) | Expr::Register(name, _) => {
                                    Some(name.to_uppercase())
                                }
                                _ => None,
                            };
                            if let Some(upper) = base_name {
                                if is_index_register(&upper)
                                    && (*op == BinaryOp::Add || *op == BinaryOp::Subtract)
                                {
                                    // Convert subtraction to addition of negative
                                    let offset = if *op == BinaryOp::Subtract {
                                        Expr::Unary {
                                            op: crate::core::parser::UnaryOp::Minus,
                                            expr: right.clone(),
                                            span: *inner_span,
                                        }
                                    } else {
                                        *right.clone()
                                    };
                                    result.push(FamilyOperand::Indexed {
                                        base: upper,
                                        offset,
                                        span: *span,
                                    });
                                } else {
                                    // Not an index register, treat as indirect address (nn)
                                    result.push(FamilyOperand::Immediate(expr.clone()));
                                }
                            } else {
                                // Left side is not a simple identifier, treat as indirect address
                                result.push(FamilyOperand::Immediate(expr.clone()));
                            }
                        }

                        // Register form: might come from parser as Register variant
                        Expr::Register(name, _) => {
                            let upper = name.to_uppercase();
                            if is_index_register(&upper) {
                                result.push(FamilyOperand::Indexed {
                                    base: upper,
                                    offset: Expr::Number("0".to_string(), *span),
                                    span: *span,
                                });
                            } else {
                                result.push(FamilyOperand::Indirect(upper, *span));
                            }
                        }

                        // Indirect address: (nnnn) - treat as immediate for address
                        Expr::Number(_, _) | Expr::Dollar(_) => {
                            result.push(FamilyOperand::Immediate(expr.clone()));
                        }

                        _ => {
                            // Other expressions inside parens become immediate (address)
                            result.push(FamilyOperand::Immediate(expr.clone()));
                        }
                    }
                }

                // Register specified as explicit register (from parser)
                Expr::Register(name, span) => {
                    result.push(FamilyOperand::Register(name.to_uppercase(), *span));
                }

                // Immediate prefix (#value)
                Expr::Immediate(inner, _span) => {
                    // For 8080/Z80, immediate is just the value
                    result.push(FamilyOperand::Immediate(*inner.clone()));
                }

                _ => {
                    return Err(FamilyParseError {
                        message: format!("unsupported operand: {:?}", expr),
                        span: expr_span(expr),
                    });
                }
            }
        }

        Ok(result)
    }

    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Self::Operand],
        _ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>> {
        let upper = mnemonic.to_ascii_uppercase();

        // Z80 undocumented half-index register forms are encoded by the Z80 CPU
        // handler.
        if operands.iter().any(operand_uses_half_index_register) {
            return EncodeResult::NotFound;
        }

        // Z80 indexed memory forms `(IX+d)/(IY+d)` are encoded by the Z80 CPU handler.
        if operands
            .iter()
            .any(|operand| matches!(operand, Operand::Indexed { .. }))
        {
            return EncodeResult::NotFound;
        }

        // Z80 two-operand I/O forms are encoded by the Z80 CPU handler.
        if matches!(upper.as_str(), "IN" | "OUT") && operands.len() == 2 {
            return EncodeResult::NotFound;
        }

        // Z80 jump-through-index forms are encoded by the Z80 CPU handler.
        if upper == "JP" && operands.len() == 1 {
            match &operands[0] {
                Operand::Register(name, _) if is_index_register(name) => {
                    return EncodeResult::NotFound;
                }
                Operand::Indexed { base, .. } if is_index_register(base) => {
                    return EncodeResult::NotFound;
                }
                _ => {}
            }
        }

        // Check if mnemonic is in family table
        if !has_mnemonic(mnemonic) {
            return EncodeResult::NotFound;
        }

        // Extract register names from operands
        let reg1 = operands.first().and_then(|op| op.as_register());
        let reg2 = operands.get(1).and_then(|op| op.as_register());

        // Look up instruction
        let entry = match lookup_instruction(mnemonic, reg1, reg2) {
            Some(e) => e,
            None => return EncodeResult::NotFound,
        };

        // Build output bytes
        let mut bytes = vec![entry.opcode];

        // Add immediate value if needed
        match entry.arg_type {
            ArgType::None => {}
            ArgType::Byte => {
                // Find the immediate operand (skip register operands)
                let imm_index = entry.num_regs as usize;
                if let Some(op) = operands.get(imm_index) {
                    match op {
                        Operand::Immediate8(val, _) => bytes.push(*val),
                        Operand::Port(val, _) => bytes.push(*val),
                        _ => {
                            return EncodeResult::error(format!(
                                "expected 8-bit immediate, got {:?}",
                                op
                            ));
                        }
                    }
                } else {
                    return EncodeResult::error("missing immediate operand");
                }
            }
            ArgType::Word => {
                // Find the immediate operand (skip register operands)
                let imm_index = entry.num_regs as usize;
                if let Some(op) = operands.get(imm_index) {
                    match op {
                        Operand::Immediate16(val, _) => {
                            bytes.push(*val as u8);
                            bytes.push((*val >> 8) as u8);
                        }
                        _ => {
                            return EncodeResult::error(format!(
                                "expected 16-bit immediate, got {:?}",
                                op
                            ));
                        }
                    }
                } else {
                    return EncodeResult::error("missing immediate operand");
                }
            }
            ArgType::Relative => {
                // Relative jump offset (Z80 JR/DJNZ) - handled by Z80 CPU handler
                return EncodeResult::NotFound;
            }
            ArgType::Im => {
                // Interrupt mode (Z80 IM) - handled by Z80 CPU handler
                return EncodeResult::NotFound;
            }
        }

        EncodeResult::Ok(bytes)
    }

    fn encode_family_operands(
        &self,
        canonical_mnemonic: &str,
        display_mnemonic: &str,
        operands: &[Self::FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> FamilyEncodeResult<Vec<u8>> {
        encode_intel8080_family_operands(canonical_mnemonic, display_mnemonic, operands, ctx)
    }

    fn is_register(&self, name: &str) -> bool {
        is_register(name)
    }

    fn is_condition(&self, name: &str) -> bool {
        is_condition(name)
    }
}

fn encode_intel8080_family_operands(
    canonical_mnemonic: &str,
    display_mnemonic: &str,
    operands: &[FamilyOperand],
    ctx: &dyn AssemblerContext,
) -> FamilyEncodeResult<Vec<u8>> {
    let upper = canonical_mnemonic.to_ascii_uppercase();

    // Z80 undocumented half-index register forms are encoded by the Z80 CPU
    // handler and should not be interpreted as 8080 family operands.
    if operands_use_half_index_registers(operands) {
        return FamilyEncodeResult::NotFound;
    }

    // Z80 indexed memory forms `(IX+d)/(IY+d)` are CPU-specific encodings.
    if operands
        .iter()
        .any(|operand| matches!(operand, FamilyOperand::Indexed { .. }))
    {
        return FamilyEncodeResult::NotFound;
    }

    if upper == "RST" {
        return encode_rst(operands);
    }

    // Z80 two-operand I/O forms (`IN r,(C)` / `OUT (C),r`) are CPU extensions.
    if matches!(upper.as_str(), "IN" | "OUT") && operands.len() == 2 {
        return FamilyEncodeResult::NotFound;
    }

    // Z80 `JP IX/IY` and `JP (IX)/(IY)` must be handled by the Z80 CPU layer.
    if upper == "JP" && operands.len() == 1 {
        match &operands[0] {
            FamilyOperand::Register(name, _) if is_index_register(name) => {
                return FamilyEncodeResult::NotFound;
            }
            FamilyOperand::Indexed { base, .. } if is_index_register(base) => {
                return FamilyEncodeResult::NotFound;
            }
            _ => {}
        }
    }

    // RLC/RRC overlap between 8080 single-byte accumulator forms and
    // Z80 CB-prefixed register/memory forms. Defer non-zero-operand forms
    // to the Z80 CPU handler.
    if matches!(upper.as_str(), "RLC" | "RRC") && !operands.is_empty() {
        return FamilyEncodeResult::NotFound;
    }

    let entry = match find_intel8080_family_entry(&upper, operands) {
        Some(entry) => entry,
        None => return FamilyEncodeResult::NotFound,
    };

    let mut bytes = Vec::new();
    emit_intel8080_prefix(&mut bytes, entry.prefix);
    bytes.push(entry.opcode);

    match entry.arg_type {
        ArgType::None => {
            let expected_regs = entry.num_regs as usize;
            if operands.len() < expected_regs {
                return FamilyEncodeResult::error(
                    Vec::new(),
                    "Wrong arguments for instruction",
                    None,
                    Some(display_mnemonic.to_string()),
                );
            }

            if operands.len() > expected_regs {
                if expected_regs == 0 {
                    if let Some(extra) = operands.first() {
                        if family_operand_is_register_like(extra) {
                            return FamilyEncodeResult::error(
                                Vec::new(),
                                "Wrong arguments for instruction",
                                None,
                                Some(display_mnemonic.to_string()),
                            );
                        }

                        let param = family_operand_text(extra);
                        return FamilyEncodeResult::error(
                            bytes,
                            "Additional arguments after instruction",
                            Some(extra.span()),
                            param,
                        );
                    }
                }

                return FamilyEncodeResult::error(
                    Vec::new(),
                    "Wrong arguments for instruction",
                    None,
                    Some(display_mnemonic.to_string()),
                );
            }

            FamilyEncodeResult::Ok(bytes)
        }
        ArgType::Byte | ArgType::Word => {
            let imm_index = entry.num_regs as usize;
            let expected_count = imm_index + 1;
            let expected_bits = if entry.arg_type == ArgType::Word {
                16
            } else {
                8
            };

            let imm_operand = match operands.get(imm_index) {
                Some(op) => op,
                None => {
                    return FamilyEncodeResult::error(
                        bytes,
                        "missing immediate operand",
                        None,
                        None,
                    );
                }
            };

            if let Some(kind) = family_operand_kind(imm_operand) {
                return FamilyEncodeResult::error(
                    bytes,
                    format!("expected {expected_bits}-bit immediate, got {kind}"),
                    Some(imm_operand.span()),
                    None,
                );
            }

            let expr = match family_operand_expr_for_immediate(imm_operand) {
                Some(expr) => expr,
                None => {
                    return FamilyEncodeResult::error(
                        Vec::new(),
                        "Wrong arguments for instruction",
                        None,
                        Some(display_mnemonic.to_string()),
                    );
                }
            };

            let value = match ctx.eval_expr(&expr) {
                Ok(value) => value,
                Err(msg) => {
                    return FamilyEncodeResult::error(bytes, msg, Some(expr_span(&expr)), None);
                }
            };

            match entry.arg_type {
                ArgType::Byte => bytes.push(value as u8),
                ArgType::Word => {
                    bytes.push(value as u8);
                    bytes.push((value >> 8) as u8);
                }
                _ => {}
            }

            if operands.len() > expected_count {
                let extra = &operands[expected_count];
                let param = family_operand_text(extra);
                return FamilyEncodeResult::error(
                    bytes,
                    "Additional arguments after instruction",
                    Some(extra.span()),
                    param,
                );
            }

            FamilyEncodeResult::Ok(bytes)
        }
        ArgType::Relative | ArgType::Im => FamilyEncodeResult::error(
            Vec::new(),
            "Wrong arguments for instruction",
            None,
            Some(display_mnemonic.to_string()),
        ),
    }
}

fn operands_use_half_index_registers(operands: &[FamilyOperand]) -> bool {
    operands.iter().any(|operand| match operand {
        FamilyOperand::Register(name, _) | FamilyOperand::Indirect(name, _) => {
            is_half_index_register(name)
        }
        FamilyOperand::Indexed { base, .. } => is_half_index_register(base),
        _ => false,
    })
}

fn is_half_index_register(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "IXH" | "IXL" | "IYH" | "IYL"
    )
}

fn operand_uses_half_index_register(operand: &Operand) -> bool {
    match operand {
        Operand::Register(name, _) | Operand::Indirect(name, _) => is_half_index_register(name),
        Operand::Indexed { base, .. } => is_half_index_register(base),
        _ => false,
    }
}

fn encode_rst(operands: &[FamilyOperand]) -> FamilyEncodeResult<Vec<u8>> {
    let arg = match operands.first() {
        Some(expr) => expr,
        None => {
            return FamilyEncodeResult::error(
                Vec::new(),
                "RST instruction argument must be 0-7",
                None,
                None,
            )
        }
    };

    let expr = match arg {
        FamilyOperand::RstVector(expr) | FamilyOperand::Immediate(expr) => expr,
        _ => {
            let arg_text = family_operand_text(arg).unwrap_or_default();
            return FamilyEncodeResult::error(
                Vec::new(),
                "RST instruction argument must be 0-7",
                Some(arg.span()),
                Some(arg_text),
            );
        }
    };

    let arg_text = expr_text(expr).unwrap_or_default();
    let is_number = matches!(expr, Expr::Number(_, _));

    if let Expr::Binary { op, left, span, .. } = expr {
        if let Expr::Number(text, _) = &**left {
            if text.len() == 1 && matches!(text.as_bytes().first(), Some(b'0'..=b'7')) {
                let val = text.as_bytes()[0] - b'0';
                let bytes = vec![0xc7 | (val << 3)];
                let op_text = binary_op_text(*op);
                return FamilyEncodeResult::error(
                    bytes,
                    "Found extra arguments after RST instruction",
                    Some(*span),
                    Some(op_text.to_string()),
                );
            }
        }
    }

    if !is_number
        || arg_text.len() != 1
        || !matches!(arg_text.as_bytes().first(), Some(b'0'..=b'7'))
    {
        return FamilyEncodeResult::error(
            Vec::new(),
            "RST instruction argument must be 0-7",
            Some(expr_span(expr)),
            Some(arg_text),
        );
    }

    let val = arg_text.as_bytes()[0] - b'0';
    let bytes = vec![0xc7 | (val << 3)];

    if operands.len() > 1 {
        let Some(extra) = operands.get(1) else {
            return FamilyEncodeResult::error(
                bytes,
                "Found extra arguments after RST instruction",
                Some(expr_span(expr)),
                None,
            );
        };
        let extra_text = family_operand_text(extra).unwrap_or_default();
        return FamilyEncodeResult::error(
            bytes,
            "Found extra arguments after RST instruction",
            Some(extra.span()),
            Some(extra_text),
        );
    }

    FamilyEncodeResult::Ok(bytes)
}

fn find_intel8080_family_entry(
    mnemonic: &str,
    operands: &[FamilyOperand],
) -> Option<&'static super::table::InstructionEntry> {
    let upper = mnemonic.to_ascii_uppercase();
    for entry in super::table::FAMILY_INSTRUCTION_TABLE {
        if !entry.mnemonic.eq_ignore_ascii_case(&upper) {
            continue;
        }

        match entry.num_regs {
            0 => return Some(entry),
            1 => {
                let reg1 = operands.first().and_then(family_operand_register);
                if let Some(reg) = reg1 {
                    if entry.reg1.eq_ignore_ascii_case(reg) {
                        return Some(entry);
                    }
                }
            }
            2 => {
                let reg1 = operands.first().and_then(family_operand_register);
                let reg2 = operands.get(1).and_then(family_operand_register);
                if let (Some(reg1), Some(reg2)) = (reg1, reg2) {
                    if entry.reg1.eq_ignore_ascii_case(reg1)
                        && entry.reg2.eq_ignore_ascii_case(reg2)
                    {
                        return Some(entry);
                    }
                }
            }
            _ => {}
        }
    }

    None
}

fn emit_intel8080_prefix(bytes: &mut Vec<u8>, prefix: super::table::Prefix) {
    match prefix {
        super::table::Prefix::None => {}
        super::table::Prefix::Cb => bytes.push(0xCB),
        super::table::Prefix::Dd => bytes.push(0xDD),
        super::table::Prefix::Ed => bytes.push(0xED),
        super::table::Prefix::Fd => bytes.push(0xFD),
        super::table::Prefix::DdCb => {
            bytes.push(0xDD);
            bytes.push(0xCB);
        }
        super::table::Prefix::FdCb => {
            bytes.push(0xFD);
            bytes.push(0xCB);
        }
    }
}

fn family_operand_register(operand: &FamilyOperand) -> Option<&str> {
    match operand {
        FamilyOperand::Register(name, _) => Some(name.as_str()),
        _ => None,
    }
}

fn family_operand_is_register_like(operand: &FamilyOperand) -> bool {
    matches!(
        operand,
        FamilyOperand::Register(_, _)
            | FamilyOperand::Condition(_, _)
            | FamilyOperand::Indirect(_, _)
            | FamilyOperand::Indexed { .. }
    )
}

fn family_operand_text(operand: &FamilyOperand) -> Option<String> {
    match operand {
        FamilyOperand::Register(name, _) | FamilyOperand::Condition(name, _) => Some(name.clone()),
        FamilyOperand::Indirect(name, _) => Some(format!("({})", name)),
        FamilyOperand::Immediate(expr)
        | FamilyOperand::RstVector(expr)
        | FamilyOperand::InterruptMode(expr)
        | FamilyOperand::BitNumber(expr)
        | FamilyOperand::Port(expr) => expr_text(expr),
        FamilyOperand::Indexed { base, offset, .. } => {
            expr_text(offset).map(|off| format!("({}+{off})", base))
        }
    }
}

fn family_operand_expr_for_immediate(operand: &FamilyOperand) -> Option<Expr> {
    match operand {
        FamilyOperand::Immediate(expr)
        | FamilyOperand::RstVector(expr)
        | FamilyOperand::InterruptMode(expr)
        | FamilyOperand::BitNumber(expr)
        | FamilyOperand::Port(expr) => Some(expr.clone()),
        FamilyOperand::Register(name, span)
        | FamilyOperand::Condition(name, span)
        | FamilyOperand::Indirect(name, span) => Some(Expr::Identifier(name.clone(), *span)),
        FamilyOperand::Indexed { .. } => None,
    }
}

fn family_operand_kind(operand: &FamilyOperand) -> Option<String> {
    match operand {
        FamilyOperand::Register(name, _) => Some(format!("register {name}")),
        FamilyOperand::Condition(name, _) => Some(format!("condition {name}")),
        FamilyOperand::Indirect(name, _) => Some(format!("indirect ({name})")),
        FamilyOperand::Indexed { base, .. } => Some(format!("indexed ({base})")),
        _ => None,
    }
}

/// Resolve family operands to final operands by evaluating expressions.
pub fn resolve_operands(
    mnemonic: &str,
    operands: &[FamilyOperand],
    ctx: &dyn AssemblerContext,
) -> Result<Vec<Operand>, FamilyParseError> {
    let mut result = Vec::new();

    for operand in operands {
        let resolved = resolve_operand(mnemonic, operand, ctx)?;
        result.push(resolved);
    }

    Ok(result)
}

/// Resolve a single family operand to a final operand.
fn resolve_operand(
    mnemonic: &str,
    operand: &FamilyOperand,
    ctx: &dyn AssemblerContext,
) -> Result<Operand, FamilyParseError> {
    match operand {
        FamilyOperand::Register(name, span) => Ok(Operand::Register(name.clone(), *span)),

        FamilyOperand::Indirect(name, span) => Ok(Operand::Indirect(name.clone(), *span)),

        FamilyOperand::Condition(name, span) => Ok(Operand::Condition(name.clone(), *span)),

        FamilyOperand::Immediate(expr) => {
            let value = ctx.eval_expr(expr).map_err(|e| FamilyParseError {
                message: e,
                span: operand.span(),
            })?;

            // Determine if 8-bit or 16-bit based on mnemonic
            let span = operand.span();
            let upper = mnemonic.to_uppercase();
            if needs_16bit_immediate(&upper) {
                Ok(Operand::Immediate16(value as u16, span))
            } else {
                Ok(Operand::Immediate8(value as u8, span))
            }
        }

        FamilyOperand::Indexed { base, offset, span } => {
            let offset_value = ctx.eval_expr(offset).map_err(|e| FamilyParseError {
                message: e,
                span: *span,
            })?;
            if !(-128..=127).contains(&offset_value) {
                return Err(FamilyParseError {
                    message: format!("Index offset {} out of range (-128..127)", offset_value),
                    span: *span,
                });
            }
            Ok(Operand::Indexed {
                base: base.clone(),
                offset: offset_value as i8,
                span: *span,
            })
        }

        FamilyOperand::RstVector(expr) => {
            let value = ctx.eval_expr(expr).map_err(|e| FamilyParseError {
                message: e,
                span: operand.span(),
            })?;
            if value > 7 {
                return Err(FamilyParseError {
                    message: format!("RST vector {} out of range (0-7)", value),
                    span: operand.span(),
                });
            }
            Ok(Operand::RstVector(value as u8, operand.span()))
        }

        FamilyOperand::InterruptMode(expr) => {
            let value = ctx.eval_expr(expr).map_err(|e| FamilyParseError {
                message: e,
                span: operand.span(),
            })?;
            if value > 2 {
                return Err(FamilyParseError {
                    message: format!("interrupt mode {} out of range (0-2)", value),
                    span: operand.span(),
                });
            }
            Ok(Operand::InterruptMode(value as u8, operand.span()))
        }

        FamilyOperand::BitNumber(expr) => {
            let value = ctx.eval_expr(expr).map_err(|e| FamilyParseError {
                message: e,
                span: operand.span(),
            })?;
            if value > 7 {
                return Err(FamilyParseError {
                    message: format!("bit number {} out of range (0-7)", value),
                    span: operand.span(),
                });
            }
            Ok(Operand::BitNumber(value as u8, operand.span()))
        }

        FamilyOperand::Port(expr) => {
            let value = ctx.eval_expr(expr).map_err(|e| FamilyParseError {
                message: e,
                span: operand.span(),
            })?;
            if value > 255 {
                return Err(FamilyParseError {
                    message: format!("port number {} out of range (0-255)", value),
                    span: operand.span(),
                });
            }
            Ok(Operand::Port(value as u8, operand.span()))
        }
    }
}

/// Check if a mnemonic requires a 16-bit immediate operand.
fn needs_16bit_immediate(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        // Intel 8080/8085 mnemonics
        "LXI"
            | "LHLD"
            | "SHLD"
            | "STA"
            | "LDA"
            | "JMP"
            | "JNZ"
            | "JZ"
            | "JNC"
            | "JC"
            | "JPO"
            | "JPE"
            | "JP"
            | "JM"
            | "CALL"
            | "CNZ"
            | "CZ"
            | "CNC"
            | "CC"
            | "CPO"
            | "CPE"
            | "CP"
            | "CM"
            // Z80 mnemonics (LD and JP already covered above)
            | "LD"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tokenizer::Span;

    fn span() -> Span {
        Span {
            line: 1,
            col_start: 1,
            col_end: 2,
        }
    }

    #[test]
    fn encode_rst_accepts_vector_zero_to_seven() {
        let operand = FamilyOperand::RstVector(Expr::Number("7".to_string(), span()));
        let result = encode_rst(&[operand]);
        match result {
            FamilyEncodeResult::Ok(bytes) => assert_eq!(bytes, vec![0xFF]),
            other => panic!("expected successful RST encode, got {other:?}"),
        }
    }

    #[test]
    fn encode_rst_rejects_out_of_range_vector() {
        let operand = FamilyOperand::RstVector(Expr::Number("8".to_string(), span()));
        let result = encode_rst(&[operand]);
        match result {
            FamilyEncodeResult::Error { message, .. } => {
                assert!(message.contains("RST instruction argument must be 0-7"));
            }
            other => panic!("expected RST validation failure, got {other:?}"),
        }
    }

    #[test]
    fn encode_rst_rejects_extra_arguments() {
        let args = vec![
            FamilyOperand::RstVector(Expr::Number("1".to_string(), span())),
            FamilyOperand::Immediate(Expr::Number("2".to_string(), span())),
        ];
        let result = encode_rst(&args);
        match result {
            FamilyEncodeResult::Error { message, .. } => {
                assert!(message.contains("Found extra arguments after RST instruction"));
            }
            other => panic!("expected extra-argument failure, got {other:?}"),
        }
    }
}
