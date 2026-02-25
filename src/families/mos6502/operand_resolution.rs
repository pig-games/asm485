// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::assembler::expression::expr_span;
use crate::core::family::{expr_has_unstable_symbols, AssemblerContext};
use crate::core::parser::Expr;
use crate::core::tokenizer::Span;

use super::{AddressMode, Operand};

struct DirectResolutionSpec {
    zero_page_mode: AddressMode,
    absolute_mode: AddressMode,
    zero_page_ctor: fn(u8, Span) -> Operand,
    absolute_ctor: fn(u16, Span) -> Operand,
}

pub(crate) fn resolve_direct(
    mnemonic: &str,
    expr: &Expr,
    ctx: &dyn AssemblerContext,
    has_mode: impl Fn(&str, AddressMode) -> bool,
) -> Result<Operand, String> {
    resolve_direct_or_absolute(
        mnemonic,
        expr,
        ctx,
        DirectResolutionSpec {
            zero_page_mode: AddressMode::ZeroPage,
            absolute_mode: AddressMode::Absolute,
            zero_page_ctor: Operand::ZeroPage,
            absolute_ctor: Operand::Absolute,
        },
        has_mode,
    )
}

pub(crate) fn resolve_direct_x(
    mnemonic: &str,
    expr: &Expr,
    ctx: &dyn AssemblerContext,
    has_mode: impl Fn(&str, AddressMode) -> bool,
) -> Result<Operand, String> {
    resolve_direct_or_absolute(
        mnemonic,
        expr,
        ctx,
        DirectResolutionSpec {
            zero_page_mode: AddressMode::ZeroPageX,
            absolute_mode: AddressMode::AbsoluteX,
            zero_page_ctor: Operand::ZeroPageX,
            absolute_ctor: Operand::AbsoluteX,
        },
        has_mode,
    )
}

pub(crate) fn resolve_direct_y(
    mnemonic: &str,
    expr: &Expr,
    ctx: &dyn AssemblerContext,
    has_mode: impl Fn(&str, AddressMode) -> bool,
) -> Result<Operand, String> {
    resolve_direct_or_absolute(
        mnemonic,
        expr,
        ctx,
        DirectResolutionSpec {
            zero_page_mode: AddressMode::ZeroPageY,
            absolute_mode: AddressMode::AbsoluteY,
            zero_page_ctor: Operand::ZeroPageY,
            absolute_ctor: Operand::AbsoluteY,
        },
        has_mode,
    )
}

fn resolve_direct_or_absolute(
    mnemonic: &str,
    expr: &Expr,
    ctx: &dyn AssemblerContext,
    spec: DirectResolutionSpec,
    has_mode: impl Fn(&str, AddressMode) -> bool,
) -> Result<Operand, String> {
    let val = ctx.eval_expr(expr)?;
    let span = expr_span(expr);
    let has_zero_page = has_mode(mnemonic, spec.zero_page_mode);
    let has_absolute = has_mode(mnemonic, spec.absolute_mode);

    if (0..=255).contains(&val) {
        if (!has_zero_page || expr_has_unstable_symbols(expr, ctx)) && has_absolute {
            return Ok((spec.absolute_ctor)(val as u16, span));
        }
        return Ok((spec.zero_page_ctor)(val as u8, span));
    }

    if (0..=65535).contains(&val) && has_absolute {
        return Ok((spec.absolute_ctor)(val as u16, span));
    }

    Err(format!("Address {} out of 16-bit range", val))
}

#[cfg(test)]
mod tests {
    use super::{resolve_direct, AddressMode, AssemblerContext, Expr, Operand};
    use crate::core::symbol_table::SymbolTable;
    use crate::core::tokenizer::Span;
    use std::collections::{HashMap, HashSet};

    struct TestCtx {
        values: HashMap<String, i64>,
        defined_symbols: HashSet<String>,
        finalized_symbols: HashMap<String, bool>,
    }

    impl AssemblerContext for TestCtx {
        fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
            match expr {
                Expr::Number(text, _) => {
                    let parsed = if let Some(hex) = text.strip_prefix('$') {
                        i64::from_str_radix(hex, 16).map_err(|_| "invalid number".to_string())?
                    } else {
                        text.parse::<i64>()
                            .map_err(|_| "invalid number".to_string())?
                    };
                    Ok(parsed)
                }
                Expr::Identifier(name, _) | Expr::Register(name, _) => self
                    .values
                    .get(name)
                    .copied()
                    .ok_or_else(|| format!("missing value for {name}")),
                _ => Err("unsupported test expr".to_string()),
            }
        }

        fn symbols(&self) -> &SymbolTable {
            panic!("not needed")
        }

        fn has_symbol(&self, name: &str) -> bool {
            self.defined_symbols.contains(name)
        }

        fn symbol_is_finalized(&self, name: &str) -> Option<bool> {
            self.finalized_symbols.get(name).copied()
        }

        fn current_address(&self) -> u32 {
            0
        }

        fn pass(&self) -> u8 {
            2
        }
    }

    fn span() -> Span {
        Span {
            line: 1,
            col_start: 1,
            col_end: 4,
        }
    }

    #[test]
    fn resolve_direct_prefers_zero_page_for_stable_small_values() {
        let ctx = TestCtx {
            values: HashMap::new(),
            defined_symbols: HashSet::new(),
            finalized_symbols: HashMap::new(),
        };
        let expr = Expr::Number("$20".to_string(), span());
        let operand = resolve_direct("LDA", &expr, &ctx, |_mnemonic, _mode| true)
            .expect("resolve should succeed");
        assert!(matches!(operand, Operand::ZeroPage(0x20, _)));
    }

    #[test]
    fn resolve_direct_uses_absolute_for_unstable_symbol_when_mode_available() {
        let ctx = TestCtx {
            values: HashMap::from([("label".to_string(), 0x20)]),
            defined_symbols: HashSet::from(["label".to_string()]),
            finalized_symbols: HashMap::from([("label".to_string(), false)]),
        };
        let expr = Expr::Identifier("label".to_string(), span());
        let operand = resolve_direct("LDA", &expr, &ctx, |_mnemonic, mode| {
            mode == AddressMode::Absolute
        })
        .expect("resolve should succeed");
        assert!(matches!(operand, Operand::Absolute(0x20, _)));
    }

    #[test]
    fn resolve_direct_promotes_values_above_zero_page() {
        let ctx = TestCtx {
            values: HashMap::new(),
            defined_symbols: HashSet::new(),
            finalized_symbols: HashMap::new(),
        };
        let expr = Expr::Number("$1234".to_string(), span());
        let operand = resolve_direct("LDA", &expr, &ctx, |_mnemonic, _mode| true)
            .expect("resolve should succeed");
        assert!(matches!(operand, Operand::Absolute(0x1234, _)));
    }

    #[test]
    fn resolve_direct_uses_absolute_when_zero_page_mode_is_unavailable() {
        let ctx = TestCtx {
            values: HashMap::new(),
            defined_symbols: HashSet::new(),
            finalized_symbols: HashMap::new(),
        };
        let expr = Expr::Number("$20".to_string(), span());
        let operand = resolve_direct("LDA", &expr, &ctx, |_mnemonic, mode| {
            mode == AddressMode::Absolute
        })
        .expect("resolve should succeed");
        assert!(matches!(operand, Operand::Absolute(0x20, _)));
    }
}
