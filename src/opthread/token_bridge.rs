// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::sync::OnceLock;

use crate::core::expr_vm::{PortableExprProgram, PortableExprRef};
use crate::core::parser::{
    AssignOp, Expr, Label, LineAst, ParseError, SignatureAtom, StatementSignature, UseItem,
    UseParam,
};
use crate::core::registry::ModuleRegistry;
use crate::core::text_utils::is_ident_start;
use crate::core::tokenizer::{
    register_checker_none, ConditionalKind, OperatorKind, RegisterChecker, Span, Token, TokenKind,
};
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::opthread::builder::build_hierarchy_package_from_registry;
use crate::opthread::package::{ParserVmOpcode, PARSER_VM_OPCODE_VERSION_V1};
use crate::opthread::runtime::{
    HierarchyExecutionModel, PortableLineAst, PortableToken, RuntimeParserContract,
    RuntimeParserVmProgram,
};
use crate::z80::module::Z80CpuModule;

// Use an authoritative rollout lane so bootstrap/macro token bridge paths
// exercise strict VM tokenizer entrypoints by default.
const DEFAULT_TOKENIZER_CPU_ID: &str = "m6502";
const HOST_PARSER_UNEXPECTED_END_OF_EXPRESSION: &str = "Unexpected end of expression";

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
        message: "opThread tokenizer runtime model is unavailable".to_string(),
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
                    "{}: missing opThread parser VM program for active CPU pipeline",
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
        message: "opThread tokenizer runtime model is unavailable".to_string(),
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

fn parse_line_with_parser_vm(
    tokens: Vec<Token>,
    end_span: Span,
    end_token_text: Option<String>,
    parser_contract: &RuntimeParserContract,
    parser_vm_program: &RuntimeParserVmProgram,
    exec_ctx: ParserVmExecContext<'_>,
) -> Result<LineAst, ParseError> {
    if parser_contract.opcode_version != parser_vm_program.opcode_version {
        return Err(parse_error_at_end(
            exec_ctx.source_line,
            exec_ctx.line_num,
            format!(
                "{}: parser contract/program opcode version mismatch ({} != {})",
                parser_contract.diagnostics.invalid_statement,
                parser_contract.opcode_version,
                parser_vm_program.opcode_version
            ),
        ));
    }
    if parser_contract.opcode_version != PARSER_VM_OPCODE_VERSION_V1 {
        return Err(parse_error_at_end(
            exec_ctx.source_line,
            exec_ctx.line_num,
            format!(
                "{}: unsupported parser contract opcode version {}",
                parser_contract.diagnostics.invalid_statement, parser_contract.opcode_version
            ),
        ));
    }

    let mut pc = 0usize;
    let mut parsed_line: Option<LineAst> = if tokens.is_empty() {
        Some(LineAst::Empty)
    } else {
        None
    };

    while pc < parser_vm_program.program.len() {
        let opcode_byte = parser_vm_program.program[pc];
        pc = pc.saturating_add(1);
        let Some(opcode) = ParserVmOpcode::from_u8(opcode_byte) else {
            return Err(parse_error_at_end(
                exec_ctx.source_line,
                exec_ctx.line_num,
                format!(
                    "{}: invalid parser VM opcode 0x{opcode_byte:02X}",
                    parser_contract.diagnostics.invalid_statement
                ),
            ));
        };
        match opcode {
            ParserVmOpcode::End => {
                return parsed_line.ok_or_else(|| {
                    parse_error_at_end(
                        exec_ctx.source_line,
                        exec_ctx.line_num,
                        format!(
                            "{}: parser VM ended without producing an AST",
                            parser_contract.diagnostics.invalid_statement
                        ),
                    )
                });
            }
            ParserVmOpcode::ParseDotDirectiveEnvelope => {
                if parsed_line.is_some() {
                    continue;
                }
                if let Some(line) = parse_dot_directive_envelope_from_tokens(
                    &tokens,
                    end_span,
                    end_token_text.clone(),
                    &exec_ctx.expr_parse_ctx,
                )? {
                    parsed_line = Some(line);
                }
            }
            ParserVmOpcode::ParseStarOrgEnvelope => {
                if parsed_line.is_some() {
                    continue;
                }
                if let Some(line) = parse_star_org_envelope_from_tokens(
                    &tokens,
                    end_span,
                    end_token_text.clone(),
                    &exec_ctx.expr_parse_ctx,
                )? {
                    parsed_line = Some(line);
                }
            }
            ParserVmOpcode::ParseAssignmentEnvelope => {
                if parsed_line.is_some() {
                    continue;
                }
                if let Some(line) = parse_assignment_envelope_from_tokens(
                    &tokens,
                    end_span,
                    end_token_text.clone(),
                    &exec_ctx.expr_parse_ctx,
                )? {
                    parsed_line = Some(line);
                }
            }
            ParserVmOpcode::ParseInstructionEnvelope => {
                if parsed_line.is_some() {
                    continue;
                }
                if let Some(line) = parse_instruction_envelope_from_tokens(
                    &tokens,
                    end_span,
                    end_token_text.clone(),
                    &exec_ctx.expr_parse_ctx,
                )? {
                    parsed_line = Some(line);
                }
            }
            ParserVmOpcode::ParseStatementEnvelope => {
                if parsed_line.is_some() {
                    continue;
                }
                let envelope = parse_statement_envelope_from_tokens(
                    &tokens,
                    end_span,
                    end_token_text.clone(),
                    &exec_ctx.expr_parse_ctx,
                )?;
                parsed_line = Some(envelope.to_core_line_ast());
            }
            ParserVmOpcode::EmitDiag => {
                let slot = parser_vm_read_diag_slot(
                    parser_vm_program,
                    &mut pc,
                    exec_ctx,
                    parser_contract,
                    "EmitDiag",
                )?;
                let code = parser_diag_code_for_slot(&parser_contract.diagnostics, slot);
                return Err(parse_error_at_end(
                    exec_ctx.source_line,
                    exec_ctx.line_num,
                    format!("{code}: parser VM emitted diagnostic slot {slot}"),
                ));
            }
            ParserVmOpcode::EmitDiagIfNoAst => {
                let slot = parser_vm_read_diag_slot(
                    parser_vm_program,
                    &mut pc,
                    exec_ctx,
                    parser_contract,
                    "EmitDiagIfNoAst",
                )?;
                if parsed_line.is_some() {
                    continue;
                }
                let code = parser_diag_code_for_slot(&parser_contract.diagnostics, slot);
                return Err(parse_error_at_end(
                    exec_ctx.source_line,
                    exec_ctx.line_num,
                    format!("{code}: parser VM emitted diagnostic slot {slot}"),
                ));
            }
            ParserVmOpcode::Fail => {
                return Err(parse_error_at_end(
                    exec_ctx.source_line,
                    exec_ctx.line_num,
                    format!(
                        "{}: parser VM requested failure",
                        parser_contract.diagnostics.invalid_statement
                    ),
                ));
            }
        }
    }

    Err(parse_error_at_end(
        exec_ctx.source_line,
        exec_ctx.line_num,
        format!(
            "{}: parser VM program terminated without End opcode",
            parser_contract.diagnostics.invalid_statement
        ),
    ))
}

fn parser_diag_code_for_slot(
    diagnostics: &crate::opthread::runtime::RuntimeParserDiagnosticMap,
    slot: u8,
) -> &str {
    match slot {
        0 => diagnostics.unexpected_token.as_str(),
        1 => diagnostics.expected_expression.as_str(),
        2 => diagnostics.expected_operand.as_str(),
        _ => diagnostics.invalid_statement.as_str(),
    }
}

fn parser_vm_read_diag_slot(
    parser_vm_program: &RuntimeParserVmProgram,
    pc: &mut usize,
    exec_ctx: ParserVmExecContext<'_>,
    parser_contract: &RuntimeParserContract,
    opcode_name: &str,
) -> Result<u8, ParseError> {
    let Some(slot) = parser_vm_program.program.get(*pc).copied() else {
        return Err(parse_error_at_end(
            exec_ctx.source_line,
            exec_ctx.line_num,
            format!(
                "{}: parser VM {} missing slot operand",
                parser_contract.diagnostics.invalid_statement, opcode_name
            ),
        ));
    };
    *pc = pc.saturating_add(1);
    Ok(slot)
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

fn parse_dot_directive_line_from_tokens(
    tokens: &[Token],
    dot_index: usize,
    label: Option<Label>,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<LineAst, ParseError> {
    let mut cursor = dot_index.saturating_add(1);
    let (name, name_span) = parse_ident_like_at(
        tokens,
        &mut cursor,
        "Expected conditional after '.'",
        end_span,
    )?;
    let upper = name.to_ascii_uppercase();

    if upper.as_str() == "STATEMENT" {
        let keyword = match tokens.get(cursor) {
            Some(Token {
                kind: TokenKind::Identifier(keyword),
                ..
            }) => {
                cursor = cursor.saturating_add(1);
                keyword.clone()
            }
            Some(Token {
                kind: TokenKind::Register(keyword),
                ..
            }) => {
                cursor = cursor.saturating_add(1);
                keyword.clone()
            }
            Some(token) => {
                return Err(ParseError {
                    message: "Expected statement keyword".to_string(),
                    span: token.span,
                })
            }
            None => {
                return Err(ParseError {
                    message: "Expected statement keyword".to_string(),
                    span: end_span,
                })
            }
        };
        let signature =
            parse_statement_signature_from_tokens(tokens, &mut cursor, false, end_span)?;
        let tail_span = prev_span_at(tokens, cursor, end_span);
        return Ok(LineAst::StatementDef {
            keyword,
            signature,
            span: Span {
                line: name_span.line,
                col_start: name_span.col_start,
                col_end: tail_span.col_end,
            },
        });
    }

    if upper.as_str() == "ENDSTATEMENT" {
        if cursor < tokens.len() {
            return Err(ParseError {
                message: "Unexpected tokens after .endstatement".to_string(),
                span: tokens[cursor].span,
            });
        }
        return Ok(LineAst::StatementEnd { span: name_span });
    }

    if upper.as_str() == "USE" {
        return parse_use_directive_from_tokens(
            tokens,
            &mut cursor,
            name_span,
            end_span,
            end_token_text,
            expr_parse_ctx,
        );
    }
    if upper.as_str() == "PLACE" {
        return parse_place_directive_from_tokens(
            tokens,
            &mut cursor,
            name_span,
            end_span,
            end_token_text,
            expr_parse_ctx,
        );
    }
    if upper.as_str() == "PACK" {
        return parse_pack_directive_from_tokens(tokens, &mut cursor, name_span, end_span);
    }

    if matches!(
        upper.as_str(),
        "MACRO" | "SEGMENT" | "ENDMACRO" | "ENDSEGMENT" | "ENDM" | "ENDS"
    ) {
        return Ok(LineAst::Statement {
            label,
            mnemonic: Some(format!(".{name}")),
            operands: Vec::new(),
        });
    }

    if let Some((kind, needs_expr, list_exprs)) = dot_conditional_kind(&upper) {
        let mut exprs: Vec<Expr> = Vec::new();
        if needs_expr {
            if list_exprs {
                for (start, end) in split_top_level_comma_ranges(tokens, cursor, tokens.len()) {
                    parse_operand_expr_range(
                        tokens,
                        start,
                        end,
                        end_span,
                        end_token_text.clone(),
                        expr_parse_ctx,
                        &mut exprs,
                    )?;
                    if matches!(exprs.last(), Some(Expr::Error(_, _))) {
                        break;
                    }
                }
            } else {
                let expr = match parse_expr_with_vm_contract(
                    expr_parse_ctx,
                    &tokens[cursor..],
                    end_span,
                    end_token_text,
                ) {
                    Ok(expr) => expr,
                    Err(err) => Expr::Error(err.message, err.span),
                };
                exprs.push(expr);
            }
        }
        return Ok(LineAst::Conditional {
            kind,
            exprs,
            span: name_span,
        });
    }

    let mut operands: Vec<Expr> = Vec::new();
    if cursor < tokens.len() {
        for (start, end) in split_top_level_comma_ranges(tokens, cursor, tokens.len()) {
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

    Ok(LineAst::Statement {
        label,
        mnemonic: Some(format!(".{name}")),
        operands,
    })
}

fn parse_place_directive_from_tokens(
    tokens: &[Token],
    cursor: &mut usize,
    start_span: Span,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<LineAst, ParseError> {
    let (section, section_span) =
        parse_ident_like_at(tokens, cursor, "Expected section name for .place", end_span)?;
    let (in_kw, in_span) = parse_ident_like_at(
        tokens,
        cursor,
        "Expected 'in' in .place directive",
        end_span,
    )?;
    if !in_kw.eq_ignore_ascii_case("in") {
        return Err(ParseError {
            message: "Expected 'in' in .place directive".to_string(),
            span: in_span,
        });
    }
    let (region, _) =
        parse_ident_like_at(tokens, cursor, "Expected region name for .place", end_span)?;

    let mut align = None;
    if consume_kind_at(tokens, cursor, TokenKind::Comma) {
        let (key, key_span) = parse_ident_like_at(
            tokens,
            cursor,
            "Expected option key after ',' in .place directive",
            end_span,
        )?;
        if !key.eq_ignore_ascii_case("align") {
            return Err(ParseError {
                message: "Unknown .place option key".to_string(),
                span: key_span,
            });
        }
        if !match_operator_at(tokens, cursor, OperatorKind::Eq) {
            return Err(ParseError {
                message: "Expected '=' after align in .place directive".to_string(),
                span: current_span_at(tokens, *cursor, end_span),
            });
        }
        align = Some(parse_expr_with_vm_contract(
            expr_parse_ctx,
            &tokens[*cursor..],
            end_span,
            end_token_text,
        )?);
        *cursor = tokens.len();
    }

    if *cursor < tokens.len() {
        return Err(ParseError {
            message: "Unexpected trailing tokens".to_string(),
            span: tokens[*cursor].span,
        });
    }

    let tail_span = if *cursor == 0 {
        section_span
    } else {
        prev_span_at(tokens, *cursor, end_span)
    };
    Ok(LineAst::Place {
        section,
        region,
        align,
        span: Span {
            line: start_span.line,
            col_start: start_span.col_start,
            col_end: tail_span.col_end,
        },
    })
}

fn parse_pack_directive_from_tokens(
    tokens: &[Token],
    cursor: &mut usize,
    start_span: Span,
    end_span: Span,
) -> Result<LineAst, ParseError> {
    let (in_kw, in_span) =
        parse_ident_like_at(tokens, cursor, "Expected 'in' in .pack directive", end_span)?;
    if !in_kw.eq_ignore_ascii_case("in") {
        return Err(ParseError {
            message: "Expected 'in' in .pack directive".to_string(),
            span: in_span,
        });
    }
    let (region, _) =
        parse_ident_like_at(tokens, cursor, "Expected region name for .pack", end_span)?;
    if !consume_kind_at(tokens, cursor, TokenKind::Colon) {
        return Err(ParseError {
            message: "Expected ':' in .pack directive".to_string(),
            span: current_span_at(tokens, *cursor, end_span),
        });
    }

    let mut sections = Vec::new();
    let (first_section, _) = parse_ident_like_at(
        tokens,
        cursor,
        "Expected at least one section in .pack directive",
        end_span,
    )?;
    sections.push(first_section);
    while consume_kind_at(tokens, cursor, TokenKind::Comma) {
        let (name, _) = parse_ident_like_at(
            tokens,
            cursor,
            "Expected section name after ',' in .pack directive",
            end_span,
        )?;
        sections.push(name);
    }

    if *cursor < tokens.len() {
        return Err(ParseError {
            message: "Unexpected trailing tokens".to_string(),
            span: tokens[*cursor].span,
        });
    }
    let tail_span = prev_span_at(tokens, *cursor, start_span);
    Ok(LineAst::Pack {
        region,
        sections,
        span: Span {
            line: start_span.line,
            col_start: start_span.col_start,
            col_end: tail_span.col_end,
        },
    })
}

fn parse_use_directive_from_tokens(
    tokens: &[Token],
    cursor: &mut usize,
    start_span: Span,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
) -> Result<LineAst, ParseError> {
    let (module_id, _) =
        parse_ident_like_at(tokens, cursor, "Expected module id after .use", end_span)?;
    let mut alias = None;
    let mut items = Vec::new();
    let mut params = Vec::new();

    if match_keyword_at(tokens, cursor, "as") {
        let (name, _) = parse_ident_like_at(
            tokens,
            cursor,
            "Expected alias identifier after 'as'",
            end_span,
        )?;
        alias = Some(name);
    }

    if consume_kind_at(tokens, cursor, TokenKind::OpenParen) {
        if consume_kind_at(tokens, cursor, TokenKind::CloseParen) {
            return Err(ParseError {
                message: "Selective import list cannot be empty".to_string(),
                span: prev_span_at(tokens, *cursor, end_span),
            });
        }
        if match_operator_at(tokens, cursor, OperatorKind::Multiply) {
            let star_span = prev_span_at(tokens, *cursor, end_span);
            if match_keyword_at(tokens, cursor, "as") {
                return Err(ParseError {
                    message: "Wildcard import cannot have an alias".to_string(),
                    span: current_span_at(tokens, *cursor, end_span),
                });
            }
            if !consume_kind_at(tokens, cursor, TokenKind::CloseParen) {
                return Err(ParseError {
                    message: "Wildcard import must be the only selective item".to_string(),
                    span: current_span_at(tokens, *cursor, end_span),
                });
            }
            items.push(UseItem {
                name: "*".to_string(),
                alias: None,
                span: star_span,
            });
        } else {
            loop {
                let (name, span) = parse_ident_like_at(
                    tokens,
                    cursor,
                    "Expected identifier in selective import list",
                    end_span,
                )?;
                let mut item_alias = None;
                if match_keyword_at(tokens, cursor, "as") {
                    let (alias_name, _) = parse_ident_like_at(
                        tokens,
                        cursor,
                        "Expected alias in selective import list",
                        end_span,
                    )?;
                    item_alias = Some(alias_name);
                }
                items.push(UseItem {
                    name,
                    alias: item_alias,
                    span,
                });
                if consume_kind_at(tokens, cursor, TokenKind::CloseParen) {
                    break;
                }
                if !consume_kind_at(tokens, cursor, TokenKind::Comma) {
                    return Err(ParseError {
                        message: "Expected ',' or ')' in selective import list".to_string(),
                        span: current_span_at(tokens, *cursor, end_span),
                    });
                }
            }
        }
    }

    if match_keyword_at(tokens, cursor, "with") {
        if !consume_kind_at(tokens, cursor, TokenKind::OpenParen) {
            return Err(ParseError {
                message: "Expected '(' after 'with'".to_string(),
                span: current_span_at(tokens, *cursor, end_span),
            });
        }
        if consume_kind_at(tokens, cursor, TokenKind::CloseParen) {
            return Err(ParseError {
                message: "Parameter list cannot be empty".to_string(),
                span: prev_span_at(tokens, *cursor, end_span),
            });
        }
        loop {
            let (name, span) = parse_ident_like_at(
                tokens,
                cursor,
                "Expected parameter name in 'with' list",
                end_span,
            )?;
            if !match_operator_at(tokens, cursor, OperatorKind::Eq) {
                return Err(ParseError {
                    message: "Expected '=' in 'with' parameter".to_string(),
                    span: current_span_at(tokens, *cursor, end_span),
                });
            }
            let value_start = *cursor;
            let mut depth_paren = 0i32;
            let mut depth_bracket = 0i32;
            let mut depth_brace = 0i32;
            while *cursor < tokens.len() {
                let token = &tokens[*cursor];
                if matches!(token.kind, TokenKind::CloseParen)
                    && depth_paren == 0
                    && depth_bracket == 0
                    && depth_brace == 0
                {
                    break;
                }
                if matches!(token.kind, TokenKind::Comma)
                    && depth_paren == 0
                    && depth_bracket == 0
                    && depth_brace == 0
                {
                    break;
                }
                update_group_depths_for_token(
                    &token.kind,
                    &mut depth_paren,
                    &mut depth_bracket,
                    &mut depth_brace,
                );
                *cursor = cursor.saturating_add(1);
            }
            let expr_end_span = tokens
                .get(*cursor)
                .map(|token| token.span)
                .unwrap_or(end_span);
            let value = parse_expr_with_vm_contract_and_boundary(
                expr_parse_ctx,
                &tokens[value_start..*cursor],
                expr_end_span,
                end_token_text.clone(),
                tokens.get(*cursor),
            )?;
            params.push(UseParam { name, value, span });
            if consume_kind_at(tokens, cursor, TokenKind::CloseParen) {
                break;
            }
            if !consume_kind_at(tokens, cursor, TokenKind::Comma) {
                return Err(ParseError {
                    message: "Expected ',' or ')' in 'with' parameter list".to_string(),
                    span: current_span_at(tokens, *cursor, end_span),
                });
            }
        }
    }

    if *cursor < tokens.len() {
        return Err(ParseError {
            message: "Unexpected trailing tokens after .use".to_string(),
            span: tokens[*cursor].span,
        });
    }
    let tail_span = if *cursor == 0 {
        end_span
    } else {
        prev_span_at(tokens, *cursor, end_span)
    };
    Ok(LineAst::Use {
        module_id,
        alias,
        items,
        params,
        span: Span {
            line: start_span.line,
            col_start: start_span.col_start,
            col_end: tail_span.col_end,
        },
    })
}

fn parse_statement_signature_from_tokens(
    tokens: &[Token],
    cursor: &mut usize,
    in_boundary: bool,
    end_span: Span,
) -> Result<StatementSignature, ParseError> {
    let mut atoms = Vec::new();
    let mut closed = !in_boundary;
    while *cursor < tokens.len() {
        if in_boundary
            && peek_kind_at(tokens, *cursor, TokenKind::CloseBrace)
            && peek_kind_at(tokens, cursor.saturating_add(1), TokenKind::CloseBracket)
        {
            *cursor = cursor.saturating_add(2);
            closed = true;
            break;
        }

        if in_boundary && peek_kind_at(tokens, *cursor, TokenKind::CloseBrace) {
            return Err(ParseError {
                message: "Missing closing }]".to_string(),
                span: tokens[*cursor].span,
            });
        }

        if peek_kind_at(tokens, *cursor, TokenKind::OpenBracket)
            && peek_kind_at(tokens, cursor.saturating_add(1), TokenKind::OpenBrace)
        {
            let open_span = tokens[*cursor].span;
            *cursor = cursor.saturating_add(2);
            let inner = parse_statement_signature_from_tokens(tokens, cursor, true, end_span)?;
            let close_span = prev_span_at(tokens, *cursor, end_span);
            let span = Span {
                line: open_span.line,
                col_start: open_span.col_start,
                col_end: close_span.col_end,
            };
            atoms.push(SignatureAtom::Boundary {
                atoms: inner.atoms,
                span,
            });
            continue;
        }

        let token = tokens.get(*cursor).ok_or_else(|| ParseError {
            message: "Unexpected end of statement signature".to_string(),
            span: end_span,
        })?;
        *cursor = cursor.saturating_add(1);
        match &token.kind {
            TokenKind::String(lit) => {
                atoms.push(SignatureAtom::Literal(lit.bytes.clone(), token.span));
            }
            TokenKind::Dot => atoms.push(SignatureAtom::Literal(vec![b'.'], token.span)),
            TokenKind::Comma => {
                return Err(ParseError {
                    message: "Commas must be quoted in statement signatures".to_string(),
                    span: token.span,
                });
            }
            TokenKind::Identifier(type_name) | TokenKind::Register(type_name) => {
                if !is_valid_capture_type_name(type_name) {
                    return Err(ParseError {
                        message: format!("Unknown statement capture type: {type_name}"),
                        span: token.span,
                    });
                }
                let colon = tokens.get(*cursor).ok_or_else(|| ParseError {
                    message: "Expected ':' after capture type".to_string(),
                    span: end_span,
                })?;
                if !matches!(colon.kind, TokenKind::Colon) {
                    return Err(ParseError {
                        message: "Expected ':' after capture type".to_string(),
                        span: colon.span,
                    });
                }
                *cursor = cursor.saturating_add(1);
                let name_token = tokens.get(*cursor).ok_or_else(|| ParseError {
                    message: "Expected capture name after type".to_string(),
                    span: end_span,
                })?;
                let name = match &name_token.kind {
                    TokenKind::Identifier(name) | TokenKind::Register(name) => name.clone(),
                    _ => {
                        return Err(ParseError {
                            message: "Expected capture name after type".to_string(),
                            span: name_token.span,
                        });
                    }
                };
                *cursor = cursor.saturating_add(1);
                atoms.push(SignatureAtom::Capture {
                    type_name: type_name.clone(),
                    name,
                    span: Span {
                        line: token.span.line,
                        col_start: token.span.col_start,
                        col_end: name_token.span.col_end,
                    },
                });
            }
            _ => {
                return Err(ParseError {
                    message: "Unexpected token in statement signature".to_string(),
                    span: token.span,
                });
            }
        }
    }

    if !closed {
        return Err(ParseError {
            message: "Missing closing }]".to_string(),
            span: end_span,
        });
    }
    Ok(StatementSignature { atoms })
}

fn dot_conditional_kind(name_upper: &str) -> Option<(ConditionalKind, bool, bool)> {
    match name_upper {
        "IF" => Some((ConditionalKind::If, true, false)),
        "ELSEIF" => Some((ConditionalKind::ElseIf, true, false)),
        "ELSE" => Some((ConditionalKind::Else, false, false)),
        "ENDIF" => Some((ConditionalKind::EndIf, false, false)),
        "MATCH" => Some((ConditionalKind::Switch, true, false)),
        "CASE" => Some((ConditionalKind::Case, true, true)),
        "DEFAULT" => Some((ConditionalKind::Default, false, false)),
        "ENDMATCH" => Some((ConditionalKind::EndSwitch, false, false)),
        _ => None,
    }
}

fn is_valid_capture_type_name(type_name: &str) -> bool {
    matches!(
        type_name.to_ascii_lowercase().as_str(),
        "byte" | "word" | "char" | "str"
    )
}

fn parse_ident_like_at(
    tokens: &[Token],
    cursor: &mut usize,
    message: &str,
    end_span: Span,
) -> Result<(String, Span), ParseError> {
    match tokens.get(*cursor) {
        Some(Token {
            kind: TokenKind::Identifier(name),
            span,
        }) => {
            *cursor = cursor.saturating_add(1);
            Ok((name.clone(), *span))
        }
        Some(Token {
            kind: TokenKind::Register(name),
            span,
        }) => {
            *cursor = cursor.saturating_add(1);
            Ok((name.clone(), *span))
        }
        Some(token) => Err(ParseError {
            message: message.to_string(),
            span: token.span,
        }),
        None => Err(ParseError {
            message: message.to_string(),
            span: end_span,
        }),
    }
}

fn match_keyword_at(tokens: &[Token], cursor: &mut usize, keyword: &str) -> bool {
    match tokens.get(*cursor) {
        Some(Token {
            kind: TokenKind::Identifier(name),
            ..
        }) if name.eq_ignore_ascii_case(keyword) => {
            *cursor = cursor.saturating_add(1);
            true
        }
        _ => false,
    }
}

fn consume_kind_at(tokens: &[Token], cursor: &mut usize, kind: TokenKind) -> bool {
    if matches!(tokens.get(*cursor), Some(Token { kind: value, .. }) if *value == kind) {
        *cursor = cursor.saturating_add(1);
        return true;
    }
    false
}

fn match_operator_at(tokens: &[Token], cursor: &mut usize, op: OperatorKind) -> bool {
    if matches!(
        tokens.get(*cursor),
        Some(Token {
            kind: TokenKind::Operator(value),
            ..
        }) if *value == op
    ) {
        *cursor = cursor.saturating_add(1);
        return true;
    }
    false
}

fn peek_kind_at(tokens: &[Token], index: usize, kind: TokenKind) -> bool {
    matches!(tokens.get(index), Some(Token { kind: value, .. }) if *value == kind)
}

fn prev_span_at(tokens: &[Token], cursor: usize, fallback: Span) -> Span {
    if cursor == 0 {
        fallback
    } else {
        tokens
            .get(cursor.saturating_sub(1))
            .map(|token| token.span)
            .unwrap_or(fallback)
    }
}

fn current_span_at(tokens: &[Token], cursor: usize, fallback: Span) -> Span {
    tokens
        .get(cursor)
        .map(|token| token.span)
        .unwrap_or(fallback)
}

fn enforce_expr_token_budget(
    expr_parse_ctx: &VmExprParseContext<'_>,
    tokens: &[Token],
    end_span: Span,
) -> Result<(), ParseError> {
    let token_budget = expr_parse_ctx
        .model
        .runtime_budget_limits()
        .max_parser_tokens_per_line;
    if tokens.len() > token_budget {
        let fallback = format!(
            "parser token budget exceeded ({} > {})",
            tokens.len(),
            token_budget
        );
        let message = expr_parse_ctx
            .model
            .resolve_parser_contract(expr_parse_ctx.cpu_id, expr_parse_ctx.dialect_override)
            .ok()
            .flatten()
            .map(|contract| {
                format!(
                    "{}: parser token budget exceeded ({} > {})",
                    contract.diagnostics.invalid_statement,
                    tokens.len(),
                    token_budget
                )
            })
            .unwrap_or(fallback);
        return Err(ParseError {
            message,
            span: end_span,
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn parse_expr_program_ref_with_vm_contract(
    expr_parse_ctx: &VmExprParseContext<'_>,
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    parser_vm_opcode_version: Option<u16>,
) -> Result<(PortableExprRef, PortableExprProgram), ParseError> {
    enforce_expr_token_budget(expr_parse_ctx, tokens, end_span)?;
    let mut owned_tokens = Vec::with_capacity(tokens.len());
    owned_tokens.extend_from_slice(tokens);
    let program = expr_parse_ctx
        .model
        .compile_expression_program_with_parser_vm_opt_in_for_assembler(
            expr_parse_ctx.cpu_id,
            expr_parse_ctx.dialect_override,
            owned_tokens,
            end_span,
            end_token_text,
            parser_vm_opcode_version,
        )?;
    Ok((PortableExprRef { index: 0 }, program))
}

fn parse_expr_with_vm_contract(
    expr_parse_ctx: &VmExprParseContext<'_>,
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
) -> Result<Expr, ParseError> {
    enforce_expr_token_budget(expr_parse_ctx, tokens, end_span)?;
    expr_parse_ctx
        .model
        .validate_expression_parser_contract_for_assembler(
            expr_parse_ctx.cpu_id,
            expr_parse_ctx.dialect_override,
        )
        .map_err(|err| ParseError {
            message: err.to_string(),
            span: end_span,
        })?;

    let mut owned_tokens = Vec::with_capacity(tokens.len());
    owned_tokens.extend_from_slice(tokens);
    expr_parse_ctx.model.parse_expression_for_assembler(
        expr_parse_ctx.cpu_id,
        expr_parse_ctx.dialect_override,
        owned_tokens,
        end_span,
        end_token_text,
    )
}

fn parse_expr_with_vm_contract_and_boundary(
    expr_parse_ctx: &VmExprParseContext<'_>,
    tokens: &[Token],
    end_span: Span,
    end_token_text: Option<String>,
    boundary_token: Option<&Token>,
) -> Result<Expr, ParseError> {
    match parse_expr_with_vm_contract(expr_parse_ctx, tokens, end_span, end_token_text) {
        Ok(expr) => Ok(expr),
        Err(err)
            if err.message == HOST_PARSER_UNEXPECTED_END_OF_EXPRESSION
                && boundary_token.is_some() =>
        {
            let boundary_span = boundary_token.map(|token| token.span).unwrap_or(err.span);
            Err(ParseError {
                message: "Unexpected token in expression".to_string(),
                span: boundary_span,
            })
        }
        Err(err) => Err(err),
    }
}

fn parse_operand_expr_range(
    tokens: &[Token],
    start: usize,
    end: usize,
    end_span: Span,
    end_token_text: Option<String>,
    expr_parse_ctx: &VmExprParseContext<'_>,
    operands: &mut Vec<Expr>,
) -> Result<(), ParseError> {
    if start >= end {
        let span = tokens
            .get(start)
            .map(|token| token.span)
            .unwrap_or(end_span);
        operands.push(Expr::Error("Expected expression".to_string(), span));
        return Ok(());
    }
    let boundary_token = tokens.get(end);
    let expr_end_span = boundary_token.map(|token| token.span).unwrap_or(end_span);
    match parse_expr_with_vm_contract_and_boundary(
        expr_parse_ctx,
        &tokens[start..end],
        expr_end_span,
        end_token_text,
        boundary_token,
    ) {
        Ok(expr) => operands.push(expr),
        Err(err) => operands.push(Expr::Error(err.message, err.span)),
    }
    Ok(())
}

fn update_group_depths_for_token(
    kind: &TokenKind,
    depth_paren: &mut i32,
    depth_bracket: &mut i32,
    depth_brace: &mut i32,
) {
    match kind {
        TokenKind::OpenParen => *depth_paren = depth_paren.saturating_add(1),
        TokenKind::CloseParen => *depth_paren = depth_paren.saturating_sub(1),
        TokenKind::OpenBracket => *depth_bracket = depth_bracket.saturating_add(1),
        TokenKind::CloseBracket => *depth_bracket = depth_bracket.saturating_sub(1),
        TokenKind::OpenBrace => *depth_brace = depth_brace.saturating_add(1),
        TokenKind::CloseBrace => *depth_brace = depth_brace.saturating_sub(1),
        _ => {}
    }
}

fn split_top_level_comma_ranges(tokens: &[Token], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    if start >= end {
        return ranges;
    }

    let mut depth_paren = 0i32;
    let mut depth_bracket = 0i32;
    let mut depth_brace = 0i32;
    let mut current_start = start;

    for (cursor, token) in tokens.iter().enumerate().take(end).skip(start) {
        update_group_depths_for_token(
            &token.kind,
            &mut depth_paren,
            &mut depth_bracket,
            &mut depth_brace,
        );
        if matches!(token.kind, TokenKind::Comma)
            && depth_paren == 0
            && depth_bracket == 0
            && depth_brace == 0
        {
            ranges.push((current_start, cursor));
            current_start = cursor.saturating_add(1);
        }
    }

    ranges.push((current_start, end));
    ranges
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
