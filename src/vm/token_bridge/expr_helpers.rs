use crate::core::expr_vm::{PortableExprProgram, PortableExprRef};
use crate::core::parser::{Expr, ParseError};
use crate::core::tokenizer::{OperatorKind, Span, Token, TokenKind};

use super::{
    runtime_bridge_error_to_parse_error, VmExprParseContext,
    HOST_PARSER_UNEXPECTED_END_OF_EXPRESSION,
};
use crate::vm::runtime::{RuntimeBridgeDiagnostic, RuntimeBridgeError};

pub(super) fn enforce_expr_token_budget(
    expr_parse_ctx: &VmExprParseContext<'_>,
    tokens: &[Token],
    end_span: Span,
) -> Result<(), ParseError> {
    let token_budget = expr_parse_ctx
        .model
        .runtime_budget_limits()
        .max_parser_tokens_per_line;
    if tokens.len() > token_budget {
        let fallback_message = format!(
            "parser token budget exceeded ({} > {})",
            tokens.len(),
            token_budget
        );
        if let Some(contract) = expr_parse_ctx
            .model
            .resolve_parser_contract(expr_parse_ctx.cpu_id, expr_parse_ctx.dialect_override)
            .ok()
            .flatten()
        {
            return Err(runtime_bridge_error_to_parse_error(
                RuntimeBridgeError::Diagnostic(RuntimeBridgeDiagnostic::new(
                    contract.diagnostics.invalid_statement,
                    fallback_message,
                    Some(end_span),
                )),
                end_span,
            ));
        }
        return Err(ParseError {
            message: fallback_message,
            span: end_span,
        });
    }
    Ok(())
}

#[allow(dead_code)]
pub(super) fn parse_expr_program_ref_with_vm_contract(
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

pub(super) fn parse_expr_with_vm_contract(
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
        .map_err(|err| runtime_bridge_error_to_parse_error(err, end_span))?;

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

pub(super) fn parse_expr_with_vm_contract_and_boundary(
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

pub(super) fn parse_operand_expr_range(
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
    if let Some(expr) = parse_indexed_register_postfix_operand(&tokens[start..end]) {
        operands.push(expr);
        return Ok(());
    }
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

fn parse_indexed_register_postfix_operand(tokens: &[Token]) -> Option<Expr> {
    if tokens.len() < 2 || tokens.len() > 3 {
        return None;
    }
    let (name, start_span) = match &tokens[0].kind {
        TokenKind::Register(name) | TokenKind::Identifier(name) => (name.clone(), tokens[0].span),
        _ => return None,
    };
    let plus1 = matches!(tokens[1].kind, TokenKind::Operator(OperatorKind::Plus));
    if !plus1 {
        return None;
    }
    let suffix = if tokens.len() == 3 {
        if matches!(tokens[2].kind, TokenKind::Operator(OperatorKind::Plus)) {
            "++"
        } else {
            return None;
        }
    } else {
        "+"
    };
    let end_span = tokens[tokens.len() - 1].span;
    Some(Expr::Register(
        format!("{name}{suffix}"),
        Span {
            line: start_span.line,
            col_start: start_span.col_start,
            col_end: end_span.col_end,
        },
    ))
}

pub(super) fn update_group_depths_for_token(
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

pub(super) fn split_top_level_comma_ranges(
    tokens: &[Token],
    start: usize,
    end: usize,
) -> Vec<(usize, usize)> {
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
