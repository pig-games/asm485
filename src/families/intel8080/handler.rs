// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Intel 8080 family handler implementation.

use crate::core::family::{AssemblerContext, EncodeResult, FamilyHandler, FamilyParseError};
use crate::core::parser::{BinaryOp, Expr};

use super::operand::{expr_span, FamilyOperand, Operand};
use super::table::{lookup_instruction, has_mnemonic, ArgType};
use super::{is_condition, is_index_register, is_register};

/// Family handler for Intel 8080 family (8080, 8085, Z80).
#[derive(Debug)]
pub struct Intel8080FamilyHandler;

impl FamilyHandler for Intel8080FamilyHandler {
    type FamilyOperand = FamilyOperand;
    type Operand = Operand;

    fn parse_operands(
        &self,
        _mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Vec<Self::FamilyOperand>, FamilyParseError> {
        let mut result = Vec::new();

        for expr in exprs {
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
                        Expr::Binary { op, left, right, span: inner_span } => {
                            if let Expr::Identifier(name, _) = left.as_ref() {
                                let upper = name.to_uppercase();
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

    fn is_register(&self, name: &str) -> bool {
        is_register(name)
    }

    fn is_condition(&self, name: &str) -> bool {
        is_condition(name)
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
