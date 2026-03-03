// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;
use crate::core::AsmValue;

pub(crate) const DEFAULT_MAX_LOOP_ITERATIONS: u32 = 65_536;

pub(crate) struct ForPlan {
    pub(crate) var_name: Option<String>,
    pub(crate) values: Vec<u32>,
}

pub(crate) fn parse_line_ast_for_repetition(
    asm_line: &AsmLine<'_>,
    src: &str,
    line_num: u32,
) -> Result<LineAst, ParseError> {
    let mut parser = asm_parser::Parser::from_line_with_registers(
        src,
        line_num,
        asm_line.register_checker.clone(),
    )?;
    parser.parse_line()
}

pub(crate) fn statement_parts(ast: &LineAst) -> Option<(Option<Label>, String, Vec<Expr>)> {
    let LineAst::Statement {
        label,
        mnemonic,
        operands,
    } = ast
    else {
        return None;
    };
    let Some(mnemonic) = mnemonic else {
        return None;
    };
    Some((label.clone(), mnemonic.clone(), operands.clone()))
}

pub(crate) fn is_for_directive_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(".for")
}

pub(crate) fn is_for_like_directive_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(".for") || name.eq_ignore_ascii_case(".bfor")
}

pub(crate) fn is_endfor_directive_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(".endfor")
}

pub(crate) fn find_matching_endfor(
    lines: &[String],
    asm_line: &AsmLine<'_>,
    start_idx: usize,
    end_idx_exclusive: usize,
) -> Option<usize> {
    let mut depth = 1usize;
    for (idx, line) in lines
        .iter()
        .enumerate()
        .take(end_idx_exclusive)
        .skip(start_idx)
    {
        let line_num = (idx as u32).saturating_add(1);
        let Ok(ast) = parse_line_ast_for_repetition(asm_line, line, line_num) else {
            continue;
        };
        let Some((_, mnemonic, _)) = statement_parts(&ast) else {
            continue;
        };
        if is_for_like_directive_name(&mnemonic) {
            depth = depth.saturating_add(1);
            continue;
        }
        if is_endfor_directive_name(&mnemonic) {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

pub(crate) fn evaluate_for_plan(
    asm_line: &AsmLine<'_>,
    operands: &[Expr],
    max_loop_iterations: u32,
) -> Result<ForPlan, AstEvalError> {
    if operands.is_empty() {
        return Err(AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Directive,
                "Missing loop expression for .for",
                None,
            ),
            span: Span::default(),
        });
    }

    let (var_name, values) = if operands.len() == 1 {
        let count = asm_line.eval_expr_for_non_negative_directive(&operands[0], ".for count")?;
        let values = (0..count).collect::<Vec<_>>();
        (None, values)
    } else if operands.len() == 2 {
        let var_name = match &operands[0] {
            Expr::Identifier(name, _) | Expr::Register(name, _) => name.clone(),
            _ => {
                return Err(AstEvalError {
                    error: AsmError::new(
                        AsmErrorKind::Directive,
                        "Expected loop variable name before 'in'",
                        None,
                    ),
                    span: expr_span(&operands[0]),
                });
            }
        };
        let iterable = asm_line.eval_value_ast(&operands[1])?;
        let mut values = Vec::new();
        match iterable {
            AsmValue::List(items) => {
                for value in items {
                    let converted = u32::try_from(value).map_err(|_| AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "loop iterator value out of supported range",
                            None,
                        ),
                        span: expr_span(&operands[1]),
                    })?;
                    values.push(converted);
                }
            }
            AsmValue::Range { start, end, step } => {
                let iterable = AsmValue::Range { start, end, step };
                if let Some(iter) = iterable.iter() {
                    for value in iter {
                        let converted = u32::try_from(value).map_err(|_| AstEvalError {
                            error: AsmError::new(
                                AsmErrorKind::Expression,
                                "loop iterator value out of supported range",
                                None,
                            ),
                            span: expr_span(&operands[1]),
                        })?;
                        values.push(converted);
                    }
                }
            }
            AsmValue::Scalar(_) | AsmValue::Struct(_) => {
                return Err(AstEvalError {
                    error: AsmError::new(
                        AsmErrorKind::Directive,
                        "expected range or list after 'in', found scalar",
                        None,
                    ),
                    span: expr_span(&operands[1]),
                });
            }
        }
        (Some(var_name), values)
    } else {
        return Err(AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Directive,
                "Expected '.for <count>' or '.for <var> in <iterable>'",
                None,
            ),
            span: expr_span(&operands[0]),
        });
    };

    let iter_count = u32::try_from(values.len()).unwrap_or(u32::MAX);
    if iter_count > max_loop_iterations {
        return Err(AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Directive,
                &format!("loop exceeded maximum iteration limit ({max_loop_iterations})"),
                None,
            ),
            span: expr_span(&operands[0]),
        });
    }

    Ok(ForPlan { var_name, values })
}

pub(crate) fn line_label(ast: &LineAst) -> Option<Label> {
    match ast {
        LineAst::Assignment { label, .. } => Some(label.clone()),
        LineAst::Statement { label, .. } => label.clone(),
        _ => None,
    }
}
