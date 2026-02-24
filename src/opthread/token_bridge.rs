// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::sync::OnceLock;

use crate::core::parser::{AssignOp, Expr, Label, LineAst, ParseError};
use crate::core::registry::ModuleRegistry;
use crate::core::text_utils::is_ident_start;
use crate::core::tokenizer::{
    register_checker_none, OperatorKind, RegisterChecker, Span, Token, TokenKind,
};
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::opthread::builder::build_hierarchy_package_from_registry;
use crate::opthread::runtime::{HierarchyExecutionModel, PortableLineAst, PortableToken};
use crate::z80::module::Z80CpuModule;

#[cfg(test)]
use crate::opthread::package::{ParserVmOpcode, PARSER_VM_OPCODE_VERSION_V1};
#[cfg(test)]
use crate::opthread::runtime::RuntimeParserVmProgram;

// Use an authoritative rollout lane so bootstrap/macro token bridge paths
// exercise strict VM tokenizer entrypoints by default.
const DEFAULT_TOKENIZER_CPU_ID: &str = "m6502";
const HOST_PARSER_UNEXPECTED_END_OF_EXPRESSION: &str = "Unexpected end of expression";

mod directives;
mod expr_helpers;
mod parser_vm;

use directives::parse_dot_directive_line_from_tokens;
use expr_helpers::{
    parse_expr_with_vm_contract, parse_expr_with_vm_contract_and_boundary,
    parse_operand_expr_range, split_top_level_comma_ranges, update_group_depths_for_token,
};
use parser_vm::parse_line_with_parser_vm;

#[cfg(test)]
use directives::{
    parse_pack_directive_from_tokens, parse_place_directive_from_tokens,
    parse_use_directive_from_tokens,
};
#[cfg(test)]
use expr_helpers::parse_expr_program_ref_with_vm_contract;

/// Tokenize one source line via the runtime tokenizer model and convert back to core tokens.
pub(crate) fn tokenize_parser_tokens_with_model(
    model: &HierarchyExecutionModel,
    cpu_id: &str,
    dialect_override: Option<&str>,
    line: &str,
    line_num: u32,
    register_checker: &RegisterChecker,
) -> Result<(Vec<Token>, Span, Option<String>), ParseError> {
    validate_line_column_one(line, line_num)?;
    let portable_tokens = model
        .tokenize_portable_statement_for_assembler(cpu_id, dialect_override, line, line_num)
        .map_err(|err| parse_error_at_end(line, line_num, err.to_string()))?;

    let core_tokens =
        runtime_tokens_to_core_tokens_with_source(&portable_tokens, Some(line), register_checker)?;
    let (end_span, end_token_text) = parser_end_metadata(line, line_num, &core_tokens);
    Ok((core_tokens, end_span, end_token_text))
}

/// Parse one source line using the default runtime model and canonical bridge CPU.
pub(crate) fn parse_line_with_default_model(
    line: &str,
    line_num: u32,
) -> Result<LineAst, ParseError> {
    let model = default_runtime_model().ok_or_else(|| ParseError {
        message: "VM tokenizer runtime model is unavailable".to_string(),
        span: Span {
            line: line_num,
            col_start: 1,
            col_end: 1,
        },
    })?;
    let register_checker = register_checker_none();
    let (line_ast, _, _) = parse_line_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        line,
        line_num,
        &register_checker,
    )?;
    Ok(line_ast)
}

/// Parse one source line using runtime tokenizer + parser VM contracts for a selected CPU pipeline.
pub(crate) fn parse_line_with_model(
    model: &HierarchyExecutionModel,
    cpu_id: &str,
    dialect_override: Option<&str>,
    line: &str,
    line_num: u32,
    register_checker: &RegisterChecker,
) -> Result<(LineAst, Span, Option<String>), ParseError> {
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        cpu_id,
        dialect_override,
        line,
        line_num,
        register_checker,
    )?;
    let parser_contract = model
        .validate_parser_contract_for_assembler(cpu_id, dialect_override, tokens.len())
        .map_err(|err| parse_error_at_end(line, line_num, err.to_string()))?;
    let parser_vm_program = model
        .resolve_parser_vm_program(cpu_id, dialect_override)
        .map_err(|err| parse_error_at_end(line, line_num, err.to_string()))?
        .ok_or_else(|| {
            parse_error_at_end(
                line,
                line_num,
                format!(
                    "{}: missing parser VM program for active CPU pipeline",
                    parser_contract.diagnostics.invalid_statement
                ),
            )
        })?;
    model
        .enforce_parser_vm_program_budget_for_assembler(&parser_contract, &parser_vm_program)
        .map_err(|err| parse_error_at_end(line, line_num, err.to_string()))?;
    let line_ast = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text.clone(),
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: line,
            line_num,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id,
                dialect_override,
            },
        },
    )?;
    Ok((line_ast, end_span, end_token_text))
}

/// Tokenize one source line with the default runtime model and canonical bridge CPU.
pub(crate) fn tokenize_line_with_default_model(
    line: &str,
    line_num: u32,
) -> Result<Vec<Token>, ParseError> {
    let model = default_runtime_model().ok_or_else(|| ParseError {
        message: "VM tokenizer runtime model is unavailable".to_string(),
        span: Span {
            line: line_num,
            col_start: 1,
            col_end: 1,
        },
    })?;
    let register_checker = register_checker_none();
    let (tokens, _, _) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        line,
        line_num,
        &register_checker,
    )?;
    Ok(tokens)
}

fn parse_error_at_end(line: &str, line_num: u32, message: impl Into<String>) -> ParseError {
    let (end_span, _) = parser_end_metadata(line, line_num, &[]);
    ParseError {
        message: message.into(),
        span: end_span,
    }
}

#[derive(Clone, Copy)]
struct VmExprParseContext<'a> {
    model: &'a HierarchyExecutionModel,
    cpu_id: &'a str,
    dialect_override: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct ParserVmExecContext<'a> {
    source_line: &'a str,
    line_num: u32,
    expr_parse_ctx: VmExprParseContext<'a>,
}

fn parse_statement_envelope_from_tokens(
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<PortableLineAst, ParseError> {
    if tokens.is_empty() {
        return Ok(PortableLineAst::Empty);
    }

    let (label, idx) = parse_optional_leading_label(tokens);

    if idx >= tokens.len() {
        return Ok(PortableLineAst::from_core_line_ast(&LineAst::Statement {
            label,
            mnemonic: None,
            operands: Vec::new(),
        }));
    }

    if let Some(line) = parse_star_org_at(
        tokens,
        idx,
        label.clone(),
        end_span,
        end_token_text.clone(),
        expr_parse_ctx,
    )? {
        return Ok(PortableLineAst::from_core_line_ast(&line));
    }
    if let Some(line) = parse_assignment_at(
        tokens,
        idx,
        label.clone(),
        end_span,
        end_token_text.clone(),
        expr_parse_ctx,
    )? {
        return Ok(PortableLineAst::from_core_line_ast(&line));
    }
    if matches!(
        tokens.get(idx),
        Some(Token {
            kind: TokenKind::Dot,
            ..
        })
    ) {
        return parse_dot_directive_line_from_tokens(
            tokens,
            idx,
            label,
            end_span,
            end_token_text,
            expr_parse_ctx,
        )
        .map(|line| PortableLineAst::from_core_line_ast(&line));
    }
    if let Some(line) =
        parse_instruction_at(tokens, idx, label, end_span, end_token_text, expr_parse_ctx)?
    {
        return Ok(PortableLineAst::from_core_line_ast(&line));
    }
    let span = tokens.get(idx).map(|token| token.span).unwrap_or(end_span);
    Err(ParseError {
        message: "Expected mnemonic identifier".to_string(),
        span,
    })
}

fn parse_optional_leading_label(tokens: &[Token]) -> (Option<Label>, usize) {
    let Some(first) = tokens.first() else {
        return (None, 0);
    };
    let label_name = match &first.kind {
        TokenKind::Identifier(name) | TokenKind::Register(name) => Some(name.clone()),
        _ => None,
    };
    let Some(name) = label_name else {
        return (None, 0);
    };
    if first.span.col_start != 1 {
        return (None, 0);
    }
    if let Some(colon) = tokens.get(1) {
        if matches!(colon.kind, TokenKind::Colon) && colon.span.col_start == first.span.col_end {
            return (
                Some(Label {
                    name,
                    span: first.span,
                }),
                2,
            );
        }
        return (
            Some(Label {
                name,
                span: first.span,
            }),
            1,
        );
    }
    (
        Some(Label {
            name,
            span: first.span,
        }),
        1,
    )
}

fn parse_dot_directive_envelope_from_tokens(
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let (label, idx) = parse_optional_leading_label(tokens);
    if !matches!(
        tokens.get(idx),
        Some(Token {
            kind: TokenKind::Dot,
            ..
        })
    ) {
        return Ok(None);
    }
    if match_assignment_op_at(tokens, idx).is_some() {
        return Ok(None);
    }
    parse_dot_directive_line_from_tokens(
        tokens,
        idx,
        label,
        end_span,
        end_token_text,
        expr_parse_ctx,
    )
    .map(Some)
}

fn parse_star_org_envelope_from_tokens(
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let (label, idx) = parse_optional_leading_label(tokens);
    parse_star_org_at(tokens, idx, label, end_span, end_token_text, expr_parse_ctx)
}

fn parse_star_org_at(
    tokens: &[Token],
    idx: usize,
    label: Option<Label>,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    if label.is_some() || !is_star_org_assignment(tokens, idx) {
        return Ok(None);
    }
    if idx.saturating_add(2) >= tokens.len() {
        return Err(ParseError {
            message: "Expected expression".to_string(),
            span: end_span,
        });
    }
    let expr = parse_expr_with_vm_contract(
        expr_parse_ctx,
        &tokens[idx.saturating_add(2)..],
        end_span,
        end_token_text,
    )?;
    Ok(Some(LineAst::Statement {
        label: None,
        mnemonic: Some(".org".to_string()),
        operands: vec![expr],
    }))
}

fn parse_assignment_envelope_from_tokens(
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let (label, idx) = parse_optional_leading_label(tokens);
    parse_assignment_at(tokens, idx, label, end_span, end_token_text, expr_parse_ctx)
}

fn parse_assignment_at(
    tokens: &[Token],
    idx: usize,
    label: Option<Label>,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    let Some(label) = label else {
        return Ok(None);
    };
    let Some((op, span, consumed)) = match_assignment_op_at(tokens, idx) else {
        return Ok(None);
    };
    let expr = match tokens.get(idx.saturating_add(consumed)) {
        Some(_) => match parse_expr_with_vm_contract(
            expr_parse_ctx,
            &tokens[idx.saturating_add(consumed)..],
            end_span,
            end_token_text,
        ) {
            Ok(expr) => expr,
            Err(err) => Expr::Error(err.message, err.span),
        },
        None => Expr::Error("Expected expression".to_string(), end_span),
    };
    Ok(Some(LineAst::Assignment {
        label,
        op,
        expr,
        span,
    }))
}

fn parse_instruction_envelope_from_tokens(
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let (label, idx) = parse_optional_leading_label(tokens);
    if label.is_none() && is_star_org_assignment(tokens, idx) {
        return Ok(None);
    }
    if match_assignment_op_at(tokens, idx).is_some() {
        return Ok(None);
    }
    if matches!(
        tokens.get(idx),
        Some(Token {
            kind: TokenKind::Dot,
            ..
        })
    ) {
        return Ok(None);
    }
    parse_instruction_at(tokens, idx, label, end_span, end_token_text, expr_parse_ctx)
}

fn parse_instruction_at(
    tokens: &[Token],
    idx: usize,
    label: Option<Label>,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<Option<LineAst>, ParseError> {
    if idx >= tokens.len() {
        return Ok(Some(LineAst::Statement {
            label,
            mnemonic: None,
            operands: Vec::new(),
        }));
    }

    let mnemonic = match tokens.get(idx) {
        Some(Token {
            kind: TokenKind::Identifier(name),
            ..
        }) => name.clone(),
        _ => return Ok(None),
    };
    let idx = idx.saturating_add(1);

    let mut operands: Vec<Expr> = Vec::new();
    if idx < tokens.len() {
        for (start, end) in split_top_level_comma_ranges(tokens, idx, tokens.len()) {
            parse_operand_expr_range(
                tokens,
                start,
                end,
                end_span,
                end_token_text.clone(),
                expr_parse_ctx,
                &mut operands,
            )?;
            if matches!(operands.last(), Some(Expr::Error(_, _))) {
                break;
            }
        }
    }

    Ok(Some(LineAst::Statement {
        label,
        mnemonic: Some(mnemonic),
        operands,
    }))
}

fn is_star_org_assignment(tokens: &[Token], idx: usize) -> bool {
    matches!(
        tokens.get(idx),
        Some(Token {
            kind: TokenKind::Operator(OperatorKind::Multiply),
            ..
        })
    ) && matches!(
        tokens.get(idx.saturating_add(1)),
        Some(Token {
            kind: TokenKind::Operator(OperatorKind::Eq),
            ..
        })
    )
}

fn match_assignment_op_at(tokens: &[Token], idx: usize) -> Option<(AssignOp, Span, usize)> {
    let token = tokens.get(idx)?;
    let next = tokens.get(idx.saturating_add(1));
    let next2 = tokens.get(idx.saturating_add(2));
    match &token.kind {
        TokenKind::Operator(OperatorKind::Eq) => Some((AssignOp::Const, token.span, 1)),
        TokenKind::Colon => {
            if matches!(
                next,
                Some(Token {
                    kind: TokenKind::Question,
                    ..
                })
            ) && matches!(
                next2,
                Some(Token {
                    kind: TokenKind::Operator(OperatorKind::Eq),
                    ..
                })
            ) {
                Some((AssignOp::VarIfUndef, token.span, 3))
            } else if matches!(
                next,
                Some(Token {
                    kind: TokenKind::Operator(OperatorKind::Eq),
                    ..
                })
            ) {
                Some((AssignOp::Var, token.span, 2))
            } else {
                None
            }
        }
        TokenKind::Operator(kind) => {
            let op = match kind {
                OperatorKind::Plus => AssignOp::Add,
                OperatorKind::Minus => AssignOp::Sub,
                OperatorKind::Multiply => AssignOp::Mul,
                OperatorKind::Divide => AssignOp::Div,
                OperatorKind::Mod => AssignOp::Mod,
                OperatorKind::Power => AssignOp::Pow,
                OperatorKind::BitOr => AssignOp::BitOr,
                OperatorKind::BitXor => AssignOp::BitXor,
                OperatorKind::BitAnd => AssignOp::BitAnd,
                OperatorKind::LogicOr => AssignOp::LogicOr,
                OperatorKind::LogicAnd => AssignOp::LogicAnd,
                OperatorKind::Shl => AssignOp::Shl,
                OperatorKind::Shr => AssignOp::Shr,
                OperatorKind::Lt => {
                    if matches!(
                        next,
                        Some(Token {
                            kind: TokenKind::Question,
                            ..
                        })
                    ) && matches!(
                        next2,
                        Some(Token {
                            kind: TokenKind::Operator(OperatorKind::Eq),
                            ..
                        })
                    ) {
                        return Some((AssignOp::Min, token.span, 3));
                    }
                    return None;
                }
                OperatorKind::Gt => {
                    if matches!(
                        next,
                        Some(Token {
                            kind: TokenKind::Question,
                            ..
                        })
                    ) && matches!(
                        next2,
                        Some(Token {
                            kind: TokenKind::Operator(OperatorKind::Eq),
                            ..
                        })
                    ) {
                        return Some((AssignOp::Max, token.span, 3));
                    }
                    return None;
                }
                _ => return None,
            };
            if matches!(
                next,
                Some(Token {
                    kind: TokenKind::Operator(OperatorKind::Eq),
                    ..
                })
            ) {
                Some((op, token.span, 2))
            } else {
                None
            }
        }
        TokenKind::Dot => {
            if matches!(
                next,
                Some(Token {
                    kind: TokenKind::Dot,
                    ..
                })
            ) && matches!(
                next2,
                Some(Token {
                    kind: TokenKind::Operator(OperatorKind::Eq),
                    ..
                })
            ) {
                Some((AssignOp::Concat, token.span, 3))
            } else if matches!(
                next,
                Some(Token {
                    kind: TokenKind::Operator(OperatorKind::Eq),
                    ..
                })
            ) {
                Some((AssignOp::Member, token.span, 2))
            } else {
                None
            }
        }
        TokenKind::Identifier(name) => {
            if name.eq_ignore_ascii_case("x")
                && matches!(
                    next,
                    Some(Token {
                        kind: TokenKind::Operator(OperatorKind::Eq),
                        ..
                    })
                )
            {
                Some((AssignOp::Repeat, token.span, 2))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn default_runtime_model() -> Option<&'static HierarchyExecutionModel> {
    static MODEL: OnceLock<Option<HierarchyExecutionModel>> = OnceLock::new();
    MODEL.get_or_init(build_default_runtime_model).as_ref()
}

fn build_default_runtime_model() -> Option<HierarchyExecutionModel> {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let package_bytes = build_hierarchy_package_from_registry(&registry).ok()?;
    HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice()).ok()
}

fn validate_line_column_one(line: &str, line_num: u32) -> Result<(), ParseError> {
    if let Some(first) = line.as_bytes().first().copied() {
        if !first.is_ascii_whitespace()
            && first != b';'
            && first != b'.'
            && first != b'*'
            && !is_ident_start(first)
        {
            return Err(ParseError {
                message: format!(
                    "Illegal character in column 1. Must be symbol, '.', '*', comment, or space. Found: {}",
                    line
                ),
                span: Span {
                    line: line_num,
                    col_start: 1,
                    col_end: 1,
                },
            });
        }
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
/// Convert runtime portable tokens into core tokenizer tokens with span and lexeme validation.
pub(crate) fn runtime_tokens_to_core_tokens(
    tokens: &[PortableToken],
    register_checker: &RegisterChecker,
) -> Result<Vec<Token>, ParseError> {
    runtime_tokens_to_core_tokens_with_source(tokens, None, register_checker)
}

fn runtime_tokens_to_core_tokens_with_source(
    tokens: &[PortableToken],
    source_line: Option<&str>,
    register_checker: &RegisterChecker,
) -> Result<Vec<Token>, ParseError> {
    let mut core_tokens = Vec::with_capacity(tokens.len());
    for token in tokens {
        let span: Span = token.span.into();
        if span.col_start == 0 || span.col_end < span.col_start {
            return Err(ParseError {
                message: "runtime tokenizer produced invalid token span".to_string(),
                span,
            });
        }
        let mut core_token = token.to_core_token();
        if let Some(lexeme_text) = source_line
            .and_then(|line| source_slice_for_span(line, &span))
            .filter(|text| !text.is_empty())
        {
            match &mut core_token.kind {
                TokenKind::Identifier(name) | TokenKind::Register(name) => {
                    *name = lexeme_text.clone();
                }
                TokenKind::Number(number) => {
                    number.text = lexeme_text.clone();
                }
                TokenKind::String(string) => {
                    string.raw = lexeme_text;
                }
                _ => {}
            }
        }
        if let TokenKind::Identifier(name) = &core_token.kind {
            if register_checker(name.to_ascii_uppercase().as_str()) {
                core_token.kind = TokenKind::Register(name.clone());
            }
        }
        core_tokens.push(core_token);
    }
    Ok(core_tokens)
}

fn source_slice_for_span(line: &str, span: &Span) -> Option<String> {
    let start = span.col_start.checked_sub(1)?;
    let end = span.col_end.checked_sub(1)?;
    if start >= end {
        return None;
    }
    let bytes = line.as_bytes();
    if end > bytes.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[start..end]).to_string())
}

fn parser_end_metadata(line: &str, line_num: u32, tokens: &[Token]) -> (Span, Option<String>) {
    let mut end_col = line.len().saturating_add(1);
    let mut end_token_text = None;
    if let Some(comment_idx) = first_comment_semicolon_outside_quotes(line) {
        end_col = comment_idx.saturating_add(1);
        end_token_text = Some(";".to_string());
    }
    if let Some(last_token) = tokens.last() {
        if last_token.span.col_end >= end_col {
            end_col = last_token.span.col_end;
            end_token_text = None;
        }
    }
    (
        Span {
            line: line_num,
            col_start: end_col,
            col_end: end_col,
        },
        end_token_text,
    )
}

fn first_comment_semicolon_outside_quotes(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    let mut quote: Option<u8> = None;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if let Some(active_quote) = quote {
            if byte == b'\\' {
                idx = idx.saturating_add(2);
                continue;
            }
            if byte == active_quote {
                quote = None;
            }
            idx = idx.saturating_add(1);
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b';' => return Some(idx),
            _ => {}
        }
        idx = idx.saturating_add(1);
    }
    None
}

#[cfg(test)]
mod tests;
