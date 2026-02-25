// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Generic expression evaluation.
//!
//! This module provides a shared expression evaluator that can be used by
//! all CPU syntax modules and the assembler. It consolidates the duplicated
//! `eval_expr`, `parse_number`, `apply_unary`, and `apply_binary` functions.

use crate::core::parser::{BinaryOp, Expr, UnaryOp};
use crate::core::tokenizer::Span;

/// Error returned from expression evaluation.
#[derive(Debug, Clone)]
pub struct EvalError {
    pub message: String,
    pub span: Option<Span>,
}

impl EvalError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
        }
    }

    pub fn with_span(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span: Some(span),
        }
    }
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EvalError {}

/// Context for expression evaluation.
///
/// This trait provides the evaluation context needed to resolve symbols
/// and the current address (`$`) during expression evaluation.
pub trait EvalContext {
    /// Look up a symbol's value by name.
    fn lookup_symbol(&self, name: &str) -> Option<i64>;

    /// Get the current address (`$`).
    fn current_address(&self) -> Option<i64>;
}

/// Evaluate an expression to a numeric value.
pub fn eval_expr(expr: &Expr, ctx: &dyn EvalContext) -> Result<i64, EvalError> {
    match expr {
        Expr::Number(text, span) => parse_number(text)
            .ok_or_else(|| EvalError::with_span(format!("Invalid number: {}", text), *span)),

        Expr::Identifier(name, span) => ctx
            .lookup_symbol(name)
            .ok_or_else(|| EvalError::with_span(format!("Undefined symbol: {}", name), *span)),

        Expr::Register(name, span) => {
            // Try to look up as a symbol first (some assemblers allow register names as symbols)
            ctx.lookup_symbol(name).ok_or_else(|| {
                EvalError::with_span(
                    format!("Register {} cannot be used as a value", name),
                    *span,
                )
            })
        }

        Expr::Dollar(span) => ctx
            .current_address()
            .ok_or_else(|| EvalError::with_span("Current address ($) not available", *span)),

        Expr::String(bytes, span) => {
            // Expression string literals intentionally support only byte-sized
            // and word-sized forms for legacy assembler semantics:
            // - 1 byte  => that byte value
            // - 2 bytes => big-endian packed word
            // Longer strings are rejected in expression context.
            if bytes.is_empty() {
                Err(EvalError::with_span(
                    "Empty string not allowed in expression",
                    *span,
                ))
            } else if bytes.len() == 1 {
                Ok(bytes[0] as i64)
            } else if bytes.len() == 2 {
                Ok(((bytes[0] as i64) << 8) | (bytes[1] as i64))
            } else {
                Err(EvalError::with_span(
                    "Multi-character string not allowed in expression",
                    *span,
                ))
            }
        }

        Expr::Unary { op, expr, span } => {
            let val = eval_expr(expr, ctx)?;
            apply_unary(*op, val, *span)
        }

        Expr::Binary {
            op,
            left,
            right,
            span,
        } => {
            let l = eval_expr(left, ctx)?;
            let r = eval_expr(right, ctx)?;
            apply_binary(*op, l, r, *span)
        }

        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            let cond_val = eval_expr(cond, ctx)?;
            if cond_val != 0 {
                eval_expr(then_expr, ctx)
            } else {
                eval_expr(else_expr, ctx)
            }
        }

        // Addressing modes - these should be handled by CPU-specific code,
        // not the generic expression evaluator. Return an error if encountered.
        Expr::Immediate(_, span) => Err(EvalError::with_span(
            "Immediate addressing mode cannot be evaluated as expression",
            *span,
        )),

        Expr::Indirect(inner, _) => eval_expr(inner, ctx),
        Expr::IndirectLong(inner, _) => eval_expr(inner, ctx),

        Expr::Tuple(_, span) => Err(EvalError::with_span(
            "Tuple cannot be evaluated as expression",
            *span,
        )),

        Expr::Error(msg, span) => Err(EvalError::with_span(msg.clone(), *span)),
    }
}

/// Apply a unary operator to a value.
pub fn apply_unary(op: UnaryOp, val: i64, _span: Span) -> Result<i64, EvalError> {
    Ok(match op {
        UnaryOp::Plus => val,
        UnaryOp::Minus => -val,
        UnaryOp::BitNot => !val,
        UnaryOp::LogicNot => {
            if val == 0 {
                1
            } else {
                0
            }
        }
        UnaryOp::Low => val & 0xff,
        UnaryOp::High => (val >> 8) & 0xff,
    })
}

/// Apply a binary operator to two values.
pub fn apply_binary(op: BinaryOp, l: i64, r: i64, span: Span) -> Result<i64, EvalError> {
    Ok(match op {
        BinaryOp::Add => l.wrapping_add(r),
        BinaryOp::Subtract => l.wrapping_sub(r),
        BinaryOp::Multiply => l.wrapping_mul(r),
        BinaryOp::Divide => {
            if r == 0 {
                return Err(EvalError::with_span("Division by zero", span));
            }
            l / r
        }
        BinaryOp::Mod => {
            if r == 0 {
                return Err(EvalError::with_span("Modulo by zero", span));
            }
            l % r
        }
        BinaryOp::Power => {
            if r < 0 {
                return Err(EvalError::with_span(
                    "Negative exponent in integer power",
                    span,
                ));
            }
            if r > u32::MAX as i64 {
                return Err(EvalError::with_span(
                    "Exponent out of range for integer power",
                    span,
                ));
            }
            l.wrapping_pow(r as u32)
        }
        BinaryOp::BitAnd => l & r,
        BinaryOp::BitOr => l | r,
        BinaryOp::BitXor => l ^ r,
        // Mask shift amount to 0x1f (0–31) to match the assembler's 32-bit value
        // domain and align with core::assembler::expression::eval_binary_op.
        BinaryOp::Shl => l.wrapping_shl((r & 0x1f) as u32),
        BinaryOp::Shr => ((l as u64).wrapping_shr((r & 0x1f) as u32)) as i64,
        BinaryOp::Eq => (l == r) as i64,
        BinaryOp::Ne => (l != r) as i64,
        BinaryOp::Lt => (l < r) as i64,
        BinaryOp::Le => (l <= r) as i64,
        BinaryOp::Gt => (l > r) as i64,
        BinaryOp::Ge => (l >= r) as i64,
        BinaryOp::LogicAnd => ((l != 0) && (r != 0)) as i64,
        BinaryOp::LogicOr => ((l != 0) || (r != 0)) as i64,
        BinaryOp::LogicXor => ((l != 0) ^ (r != 0)) as i64,
    })
}

/// Parse a number literal (decimal, hex, binary, octal).
///
/// Supports multiple formats:
/// - Decimal: `42`
/// - Hex: `0x2A`, `$2A`, `2Ah`
/// - Binary: `0b101010`, `101010b`
/// - Octal: `0o52`, `52o`, `52q`
pub fn parse_number(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    // Handle negative numbers
    let (is_neg, text) = if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text)
    };

    // Strip underscores (visual separators)
    let text: String = text.chars().filter(|&c| c != '_').collect();
    let text = text.as_str();

    // Prefix-based notations are checked first so that suffix heuristics
    // (e.g. trailing 'B' for binary) never misinterpret a prefixed literal
    // like $BB or %0101.
    let val = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(oct) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        i64::from_str_radix(oct, 8).ok()?
    } else if let Some(bin) = text.strip_prefix('%') {
        i64::from_str_radix(bin, 2).ok()?
    } else if let Some(hex) = text.strip_prefix('$') {
        i64::from_str_radix(hex, 16).ok()?
    } else if text.ends_with('h') || text.ends_with('H') {
        i64::from_str_radix(&text[..text.len() - 1], 16).ok()?
    } else if let Some(bin) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        // Keep `0b`/`0B` as binary-prefix notation, but only when the suffix is
        // a valid binary payload. This prevents values like `0B8H` from being
        // misclassified as binary and allows the hex-suffix path above to apply.
        if !bin.is_empty() && bin.chars().all(|c| c == '0' || c == '1') {
            i64::from_str_radix(bin, 2).ok()?
        } else {
            return None;
        }
    } else if text.ends_with('b') || text.ends_with('B') {
        // Could be binary or hex digit - check if all chars are 0/1
        let inner = &text[..text.len() - 1];
        if inner.chars().all(|c| c == '0' || c == '1') {
            i64::from_str_radix(inner, 2).ok()?
        } else {
            // Treat as hex
            i64::from_str_radix(&text[..text.len() - 1], 16).ok()?
        }
    } else if text.ends_with('o')
        || text.ends_with('O')
        || text.ends_with('q')
        || text.ends_with('Q')
    {
        i64::from_str_radix(&text[..text.len() - 1], 8).ok()?
    } else if text.ends_with('d') || text.ends_with('D') {
        text[..text.len() - 1].parse::<i64>().ok()?
    } else {
        text.parse::<i64>().ok()?
    };

    Some(if is_neg { -val } else { val })
}

/// Returns true if the value fits in a signed or unsigned 8-bit byte (-128..=255).
pub fn value_fits_byte(value: i64) -> bool {
    (-128..=0xff).contains(&value)
}

/// Returns true if the value fits in a signed or unsigned 16-bit word (-32768..=65535).
pub fn value_fits_word(value: i64) -> bool {
    (-32768..=0xffff).contains(&value)
}

/// Simple evaluation context that wraps a symbol table lookup function.
pub struct SimpleEvalContext<F>
where
    F: Fn(&str) -> Option<i64>,
{
    lookup: F,
    addr: Option<i64>,
}

impl<F> SimpleEvalContext<F>
where
    F: Fn(&str) -> Option<i64>,
{
    /// Create a new context with a symbol lookup function.
    pub fn new(lookup: F) -> Self {
        Self { lookup, addr: None }
    }

    /// Create a new context with symbol lookup and current address.
    pub fn with_address(lookup: F, addr: i64) -> Self {
        Self {
            lookup,
            addr: Some(addr),
        }
    }
}

impl<F> EvalContext for SimpleEvalContext<F>
where
    F: Fn(&str) -> Option<i64>,
{
    fn lookup_symbol(&self, name: &str) -> Option<i64> {
        (self.lookup)(name)
    }

    fn current_address(&self) -> Option<i64> {
        self.addr
    }
}

/// Evaluation context using a SymbolTable reference.
pub struct SymbolTableContext<'a> {
    symbols: &'a crate::core::symbol_table::SymbolTable,
    addr: Option<i64>,
}

impl<'a> SymbolTableContext<'a> {
    /// Create a new context with a symbol table reference.
    pub fn new(symbols: &'a crate::core::symbol_table::SymbolTable) -> Self {
        Self {
            symbols,
            addr: None,
        }
    }

    /// Create a new context with symbol table and current address.
    pub fn with_address(symbols: &'a crate::core::symbol_table::SymbolTable, addr: i64) -> Self {
        Self {
            symbols,
            addr: Some(addr),
        }
    }
}

impl EvalContext for SymbolTableContext<'_> {
    fn lookup_symbol(&self, name: &str) -> Option<i64> {
        self.symbols.entry(name).map(|e| e.val as i64)
    }

    fn current_address(&self) -> Option<i64> {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn with_grouped_underscores(value: &str, group: usize) -> String {
        let mut out = String::with_capacity(value.len() + value.len() / group);
        for (idx, ch) in value.chars().rev().enumerate() {
            if idx != 0 && idx % group == 0 {
                out.push('_');
            }
            out.push(ch);
        }
        out.chars().rev().collect()
    }

    #[test]
    fn parse_number_decimal() {
        assert_eq!(parse_number("42"), Some(42));
        assert_eq!(parse_number("55D"), Some(55));
        assert_eq!(parse_number("55d"), Some(55));
        assert_eq!(parse_number("0"), Some(0));
        assert_eq!(parse_number("-10"), Some(-10));
        assert_eq!(parse_number("-10D"), Some(-10));
    }

    #[test]
    fn parse_number_hex() {
        assert_eq!(parse_number("0x2A"), Some(42));
        assert_eq!(parse_number("0X2a"), Some(42));
        assert_eq!(parse_number("$2A"), Some(42));
        assert_eq!(parse_number("2Ah"), Some(42));
        assert_eq!(parse_number("2AH"), Some(42));
        assert_eq!(parse_number("0B8H"), Some(0x0B8));
    }

    #[test]
    fn parse_number_dollar_hex_ending_in_b() {
        // Regression: $BB was misinterpreted as a binary-suffixed literal
        // because the ends_with('B') branch fired before the '$' prefix branch.
        assert_eq!(parse_number("$BB"), Some(0xBB));
        assert_eq!(parse_number("$AB"), Some(0xAB));
        assert_eq!(parse_number("$0B"), Some(0x0B));
        assert_eq!(parse_number("$1B"), Some(0x1B));
        assert_eq!(parse_number("$FB"), Some(0xFB));
    }

    #[test]
    fn parse_number_binary() {
        assert_eq!(parse_number("0b101010"), Some(42));
        assert_eq!(parse_number("0B101010"), Some(42));
        assert_eq!(parse_number("101010b"), Some(42));
        assert_eq!(parse_number("%101010"), Some(42));
    }

    #[test]
    fn parse_number_octal() {
        assert_eq!(parse_number("0o52"), Some(42));
        assert_eq!(parse_number("52o"), Some(42));
        assert_eq!(parse_number("52q"), Some(42));
        assert_eq!(parse_number("52Q"), Some(42));
    }

    #[test]
    fn parse_number_with_underscores() {
        assert_eq!(parse_number("1_000"), Some(1000));
        assert_eq!(parse_number("0xFF_FF"), Some(0xFFFF));
        assert_eq!(parse_number("0b1010_1010"), Some(0xAA));
    }

    proptest! {
        #[test]
        fn parse_number_decimal_round_trip_u32(value in any::<u32>()) {
            let text = value.to_string();
            prop_assert_eq!(parse_number(&text), Some(value as i64));
        }

        #[test]
        fn parse_number_hex_round_trip_u32(value in any::<u32>()) {
            let text = format!("0x{:X}", value);
            prop_assert_eq!(parse_number(&text), Some(value as i64));
        }

        #[test]
        fn parse_number_binary_round_trip_u16(value in any::<u16>()) {
            let text = format!("0b{:b}", value);
            prop_assert_eq!(parse_number(&text), Some(value as i64));
        }

        #[test]
        fn parse_number_decimal_underscores_match_plain_u32(value in any::<u32>()) {
            let plain = value.to_string();
            let underscored = with_grouped_underscores(&plain, 3);
            prop_assert_eq!(parse_number(&underscored), parse_number(&plain));
        }

        #[test]
        fn parse_number_hex_underscores_match_plain_u32(value in any::<u32>()) {
            let hex = format!("{:X}", value);
            let grouped = with_grouped_underscores(&hex, 2);
            let plain = format!("0x{}", hex);
            let underscored = format!("0x{}", grouped);
            prop_assert_eq!(parse_number(&underscored), parse_number(&plain));
        }
    }

    #[test]
    fn value_fits_byte_range() {
        assert!(value_fits_byte(0));
        assert!(value_fits_byte(255));
        assert!(!value_fits_byte(256));
        assert!(value_fits_byte(-1));
        assert!(value_fits_byte(-128));
        assert!(!value_fits_byte(-129));
    }

    #[test]
    fn value_fits_word_range() {
        assert!(value_fits_word(0));
        assert!(value_fits_word(65535));
        assert!(!value_fits_word(65536));
        assert!(value_fits_word(-1));
        assert!(value_fits_word(-32768));
        assert!(!value_fits_word(-32769));
    }

    #[test]
    fn apply_unary_ops() {
        let span = Span::default();
        assert_eq!(apply_unary(UnaryOp::Plus, 42, span).unwrap(), 42);
        assert_eq!(apply_unary(UnaryOp::Minus, 42, span).unwrap(), -42);
        assert_eq!(apply_unary(UnaryOp::BitNot, 0, span).unwrap(), -1);
        assert_eq!(apply_unary(UnaryOp::LogicNot, 0, span).unwrap(), 1);
        assert_eq!(apply_unary(UnaryOp::LogicNot, 42, span).unwrap(), 0);
        assert_eq!(apply_unary(UnaryOp::Low, 0x1234, span).unwrap(), 0x34);
        assert_eq!(apply_unary(UnaryOp::High, 0x1234, span).unwrap(), 0x12);
    }

    #[test]
    fn apply_binary_ops() {
        let span = Span::default();
        assert_eq!(apply_binary(BinaryOp::Add, 10, 5, span).unwrap(), 15);
        assert_eq!(apply_binary(BinaryOp::Subtract, 10, 5, span).unwrap(), 5);
        assert_eq!(apply_binary(BinaryOp::Multiply, 10, 5, span).unwrap(), 50);
        assert_eq!(apply_binary(BinaryOp::Divide, 10, 5, span).unwrap(), 2);
        assert_eq!(apply_binary(BinaryOp::Mod, 10, 3, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::Power, 2, 8, span).unwrap(), 256);
        assert_eq!(
            apply_binary(BinaryOp::BitAnd, 0xFF, 0x0F, span).unwrap(),
            0x0F
        );
        assert_eq!(
            apply_binary(BinaryOp::BitOr, 0xF0, 0x0F, span).unwrap(),
            0xFF
        );
        assert_eq!(
            apply_binary(BinaryOp::BitXor, 0xFF, 0x0F, span).unwrap(),
            0xF0
        );
        assert_eq!(apply_binary(BinaryOp::Shl, 1, 4, span).unwrap(), 16);
        assert_eq!(apply_binary(BinaryOp::Shr, 16, 4, span).unwrap(), 1);
    }

    #[test]
    fn apply_binary_comparisons() {
        let span = Span::default();
        assert_eq!(apply_binary(BinaryOp::Eq, 5, 5, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::Eq, 5, 6, span).unwrap(), 0);
        assert_eq!(apply_binary(BinaryOp::Ne, 5, 6, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::Lt, 5, 6, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::Le, 5, 5, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::Gt, 6, 5, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::Ge, 5, 5, span).unwrap(), 1);
    }

    #[test]
    fn apply_binary_logic() {
        let span = Span::default();
        assert_eq!(apply_binary(BinaryOp::LogicAnd, 1, 1, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::LogicAnd, 1, 0, span).unwrap(), 0);
        assert_eq!(apply_binary(BinaryOp::LogicOr, 0, 1, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::LogicOr, 0, 0, span).unwrap(), 0);
        assert_eq!(apply_binary(BinaryOp::LogicXor, 1, 0, span).unwrap(), 1);
        assert_eq!(apply_binary(BinaryOp::LogicXor, 1, 1, span).unwrap(), 0);
    }

    #[test]
    fn division_by_zero() {
        let span = Span::default();
        assert!(apply_binary(BinaryOp::Divide, 10, 0, span).is_err());
        assert!(apply_binary(BinaryOp::Mod, 10, 0, span).is_err());
    }

    #[test]
    fn eval_expr_string_accepts_single_byte() {
        let span = Span::default();
        let expr = Expr::String(vec![0x41], span);
        let ctx = SimpleEvalContext::new(|_| None);
        assert_eq!(eval_expr(&expr, &ctx).unwrap(), 0x41);
    }

    #[test]
    fn eval_expr_string_accepts_two_bytes_as_word() {
        let span = Span::default();
        let expr = Expr::String(vec![0x12, 0x34], span);
        let ctx = SimpleEvalContext::new(|_| None);
        assert_eq!(eval_expr(&expr, &ctx).unwrap(), 0x1234);
    }

    #[test]
    fn eval_expr_string_rejects_empty() {
        let span = Span::default();
        let expr = Expr::String(Vec::new(), span);
        let ctx = SimpleEvalContext::new(|_| None);
        let err = eval_expr(&expr, &ctx).unwrap_err();
        assert!(err.message.contains("Empty string"));
    }

    #[test]
    fn eval_expr_string_rejects_more_than_two_bytes() {
        let span = Span::default();
        let expr = Expr::String(vec![0x01, 0x02, 0x03], span);
        let ctx = SimpleEvalContext::new(|_| None);
        let err = eval_expr(&expr, &ctx).unwrap_err();
        assert!(err.message.contains("Multi-character string"));
    }
}
