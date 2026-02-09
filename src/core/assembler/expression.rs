// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Expression evaluation for the assembler.

use crate::core::parser::{AssignOp, BinaryOp, Expr, UnaryOp};
use crate::core::tokenizer::Span;

use super::error::{AsmError, AsmErrorKind};

/// Error from expression evaluation with source span.
pub struct AstEvalError {
    pub error: AsmError,
    pub span: Span,
}

/// Parse a number literal from text.
pub fn parse_number_text(text: &str, span: Span) -> Result<u32, AstEvalError> {
    let upper = text.to_ascii_uppercase();
    let cleaned = upper.replace('_', "");
    let (digits, base) = if let Some(rest) = cleaned.strip_prefix('$') {
        (rest.to_string(), 16)
    } else if let Some(rest) = cleaned.strip_prefix('%') {
        (rest.to_string(), 2)
    } else {
        match cleaned.chars().last() {
            Some('H') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 16),
            Some('B') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 2),
            Some('O') | Some('Q') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 8),
            Some('D') => (cleaned[..cleaned.len().saturating_sub(1)].to_string(), 10),
            _ => (cleaned, 10),
        }
    };

    if digits.is_empty() {
        return Err(AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Expression,
                "Illegal character in constant",
                Some(text),
            ),
            span,
        });
    }

    let valid = match base {
        2 => digits.chars().all(|c| c == '0' || c == '1'),
        8 => digits.chars().all(|c| matches!(c, '0'..='7')),
        10 => digits.chars().all(|c| c.is_ascii_digit()),
        16 => digits.chars().all(|c| c.is_ascii_hexdigit()),
        _ => false,
    };

    if !valid {
        let msg = match base {
            10 => "Illegal character in decimal constant",
            2 => "Illegal character in binary constant",
            8 => "Illegal character in octal constant",
            16 => "Illegal character in hex constant",
            _ => "Illegal character in constant",
        };
        return Err(AstEvalError {
            error: AsmError::new(AsmErrorKind::Expression, msg, Some(text)),
            span,
        });
    }

    let value = u32::from_str_radix(&digits, base).map_err(|_| AstEvalError {
        error: AsmError::new(
            AsmErrorKind::Expression,
            "Illegal character in constant",
            Some(text),
        ),
        span,
    })?;

    Ok(value)
}

/// Concatenate two values by shifting left to make room for right.
pub fn concat_values(left: u32, right: u32) -> u32 {
    let width = if right == 0 {
        1
    } else {
        (32 - right.leading_zeros()).div_ceil(8).min(4)
    };
    let shift = (width * 8).min(32);
    let mask = if shift >= 32 {
        u64::MAX
    } else {
        (1u64 << shift) - 1
    };
    let combined = ((left as u64) << shift) | ((right as u64) & mask);
    combined as u32
}

/// Repeat a byte value a number of times.
pub fn repeat_value(left: u32, right: u32) -> u32 {
    let count = right.min(4);
    let byte = left & 0xff;
    let mut result = 0u32;
    for _ in 0..count {
        result = (result << 8) | byte;
    }
    result
}

/// Apply an assignment operator to compute a new value.
pub fn apply_assignment_op(
    op: AssignOp,
    left: u32,
    right: u32,
    span: Span,
) -> Result<u32, AstEvalError> {
    let val = match op {
        AssignOp::Add => left.wrapping_add(right),
        AssignOp::Sub => left.wrapping_sub(right),
        AssignOp::Mul => left.wrapping_mul(right),
        AssignOp::Div => {
            if right == 0 {
                return Err(AstEvalError {
                    error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                    span,
                });
            }
            left / right
        }
        AssignOp::Mod => {
            if right == 0 {
                return Err(AstEvalError {
                    error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                    span,
                });
            }
            left % right
        }
        AssignOp::Pow => left.wrapping_pow(right),
        AssignOp::BitOr => left | right,
        AssignOp::BitXor => left ^ right,
        AssignOp::BitAnd => left & right,
        AssignOp::LogicOr => {
            if left != 0 || right != 0 {
                1
            } else {
                0
            }
        }
        AssignOp::LogicAnd => {
            if left != 0 && right != 0 {
                1
            } else {
                0
            }
        }
        AssignOp::Shl => {
            let shift = right & 0x1f;
            left.wrapping_shl(shift)
        }
        AssignOp::Shr => {
            let shift = right & 0x1f;
            left >> shift
        }
        AssignOp::Concat => concat_values(left, right),
        AssignOp::Min => left.min(right),
        AssignOp::Max => left.max(right),
        AssignOp::Repeat => repeat_value(left, right),
        AssignOp::Member => right,
        AssignOp::Const | AssignOp::Var | AssignOp::VarIfUndef => right,
    };
    Ok(val)
}

/// Evaluate a unary operator.
pub fn eval_unary_op(op: UnaryOp, inner: u32) -> u32 {
    match op {
        UnaryOp::Plus => inner,
        UnaryOp::Minus => 0u32.wrapping_sub(inner),
        UnaryOp::BitNot => !inner,
        UnaryOp::LogicNot => {
            if inner != 0 {
                0
            } else {
                1
            }
        }
        UnaryOp::High => (inner >> 8) & 0xff,
        UnaryOp::Low => inner & 0xff,
    }
}

/// Evaluate a binary operator.
pub fn eval_binary_op(
    op: BinaryOp,
    left_val: u32,
    right_val: u32,
    span: Span,
    line_end_span: Option<Span>,
) -> Result<u32, AstEvalError> {
    let val = match op {
        BinaryOp::Multiply => left_val.wrapping_mul(right_val),
        BinaryOp::Divide => {
            if right_val == 0 {
                let span = line_end_span.unwrap_or(span);
                return Err(AstEvalError {
                    error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                    span,
                });
            }
            left_val / right_val
        }
        BinaryOp::Mod => {
            if right_val == 0 {
                let span = line_end_span.unwrap_or(span);
                return Err(AstEvalError {
                    error: AsmError::new(AsmErrorKind::Expression, "Divide by zero", None),
                    span,
                });
            }
            left_val % right_val
        }
        BinaryOp::Power => left_val.wrapping_pow(right_val),
        BinaryOp::Shl => {
            let shift = right_val & 0x1f;
            left_val.wrapping_shl(shift)
        }
        BinaryOp::Shr => {
            let shift = right_val & 0x1f;
            left_val >> shift
        }
        BinaryOp::Add => left_val.wrapping_add(right_val),
        BinaryOp::Subtract => left_val.wrapping_sub(right_val),
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Ge | BinaryOp::Gt | BinaryOp::Le | BinaryOp::Lt => {
            let result = match op {
                BinaryOp::Eq => left_val == right_val,
                BinaryOp::Ne => left_val != right_val,
                BinaryOp::Ge => left_val >= right_val,
                BinaryOp::Gt => left_val > right_val,
                BinaryOp::Le => left_val <= right_val,
                BinaryOp::Lt => left_val < right_val,
                _ => false,
            };
            if result {
                1
            } else {
                0
            }
        }
        BinaryOp::BitAnd => left_val & right_val,
        BinaryOp::BitOr => left_val | right_val,
        BinaryOp::BitXor => left_val ^ right_val,
        BinaryOp::LogicAnd => {
            if left_val != 0 && right_val != 0 {
                1
            } else {
                0
            }
        }
        BinaryOp::LogicOr => {
            if left_val != 0 || right_val != 0 {
                1
            } else {
                0
            }
        }
        BinaryOp::LogicXor => {
            let left_true = left_val != 0;
            let right_true = right_val != 0;
            if left_true ^ right_true {
                1
            } else {
                0
            }
        }
    };
    Ok(val)
}

/// Get the span of an expression.
pub fn expr_span(expr: &Expr) -> Span {
    match expr {
        Expr::Number(_, span)
        | Expr::Identifier(_, span)
        | Expr::Register(_, span)
        | Expr::Indirect(_, span)
        | Expr::IndirectLong(_, span)
        | Expr::Immediate(_, span)
        | Expr::Tuple(_, span)
        | Expr::Dollar(span)
        | Expr::String(_, span)
        | Expr::Error(_, span) => *span,
        Expr::Unary { span, .. } | Expr::Binary { span, .. } | Expr::Ternary { span, .. } => *span,
    }
}

/// Get the text representation of an expression (for error messages).
pub fn expr_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Number(text, _) => Some(text.clone()),
        Expr::Identifier(name, _) | Expr::Register(name, _) => Some(name.clone()),
        Expr::Indirect(inner, _) => expr_text(inner).map(|s| format!("({})", s)),
        Expr::IndirectLong(inner, _) => expr_text(inner).map(|s| format!("[{}]", s)),
        Expr::Immediate(inner, _) => expr_text(inner).map(|s| format!("#{}", s)),
        Expr::Tuple(elements, _) => {
            let parts: Vec<_> = elements.iter().filter_map(expr_text).collect();
            if parts.len() == elements.len() {
                Some(format!("({})", parts.join(", ")))
            } else {
                None
            }
        }
        Expr::Dollar(_) => Some("$".to_string()),
        Expr::String(_, _) => Some("<string>".to_string()),
        Expr::Error(_, _) => None,
        Expr::Unary { .. } | Expr::Binary { .. } | Expr::Ternary { .. } => None,
    }
}

/// Get the text representation of a binary operator.
pub fn binary_op_text(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Subtract => "-",
        BinaryOp::Multiply => "*",
        BinaryOp::Power => "**",
        BinaryOp::Divide => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Eq => "==",
        BinaryOp::Ne => "!=",
        BinaryOp::Ge => ">=",
        BinaryOp::Gt => ">",
        BinaryOp::Le => "<=",
        BinaryOp::Lt => "<",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitOr => "|",
        BinaryOp::BitXor => "^",
        BinaryOp::LogicAnd => "&&",
        BinaryOp::LogicOr => "||",
        BinaryOp::LogicXor => "^^",
    }
}
