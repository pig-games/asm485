use crate::core::parser::{Expr, Label, LineAst, ParseError, SignatureAtom, StatementSignature};
use crate::core::tokenizer::{ConditionalKind, OperatorKind, Span, Token, TokenKind};

use super::{
    parse_expr_with_vm_contract, parse_expr_with_vm_contract_and_boundary,
    parse_operand_expr_range, split_top_level_comma_ranges, update_group_depths_for_token,
    VmExprParseContext,
};

pub(super) fn parse_dot_directive_line_from_tokens(
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

pub(super) fn parse_place_directive_from_tokens(
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

pub(super) fn parse_pack_directive_from_tokens(
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

pub(super) fn parse_use_directive_from_tokens(
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
            items.push(crate::core::parser::UseItem {
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
                items.push(crate::core::parser::UseItem {
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
            params.push(crate::core::parser::UseParam { name, value, span });
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

pub(super) fn parse_statement_signature_from_tokens(
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

pub(super) fn dot_conditional_kind(name_upper: &str) -> Option<(ConditionalKind, bool, bool)> {
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

pub(super) fn is_valid_capture_type_name(type_name: &str) -> bool {
    matches!(
        type_name.to_ascii_lowercase().as_str(),
        "byte" | "word" | "char" | "str"
    )
}

pub(super) fn parse_ident_like_at(
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

pub(super) fn match_keyword_at(tokens: &[Token], cursor: &mut usize, keyword: &str) -> bool {
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

pub(super) fn consume_kind_at(tokens: &[Token], cursor: &mut usize, kind: TokenKind) -> bool {
    if matches!(tokens.get(*cursor), Some(Token { kind: value, .. }) if *value == kind) {
        *cursor = cursor.saturating_add(1);
        return true;
    }
    false
}

pub(super) fn match_operator_at(tokens: &[Token], cursor: &mut usize, op: OperatorKind) -> bool {
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

pub(super) fn peek_kind_at(tokens: &[Token], index: usize, kind: TokenKind) -> bool {
    matches!(tokens.get(index), Some(Token { kind: value, .. }) if *value == kind)
}

pub(super) fn prev_span_at(tokens: &[Token], cursor: usize, fallback: Span) -> Span {
    if cursor == 0 {
        fallback
    } else {
        tokens
            .get(cursor.saturating_sub(1))
            .map(|token| token.span)
            .unwrap_or(fallback)
    }
}

pub(super) fn current_span_at(tokens: &[Token], cursor: usize, fallback: Span) -> Span {
    tokens
        .get(cursor)
        .map(|token| token.span)
        .unwrap_or(fallback)
}
