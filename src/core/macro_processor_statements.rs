// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::parser::{
    match_statement_signature, select_statement_signature, LineAst, StatementSignature,
};
use crate::core::text_utils::{is_ident_start, to_upper, Cursor};
use crate::core::tokenizer::{Span, Token, TokenKind};
use std::collections::HashMap;

use super::macro_processor_args_subst::{substitute_line, token_text_for_substitution};
use super::{MacroArgs, MacroError, MacroProcessor, StatementDef};

pub(super) fn parse_statement_def_line(
    code: &str,
    line_num: u32,
) -> Result<(String, StatementSignature), MacroError> {
    let line_ast = crate::vm::token_bridge::parse_line_with_default_model(code, line_num)
        .map_err(|err| MacroError::new(err.message, Some(line_num), Some(err.span.col_start)))?;
    match line_ast {
        LineAst::StatementDef {
            keyword, signature, ..
        } => Ok((keyword, signature)),
        _ => Err(MacroError::new(
            "Expected .statement definition",
            Some(line_num),
            Some(1),
        )),
    }
}

pub(super) fn expand_statement_invocation(
    code: &str,
    line_num: u32,
    depth: usize,
    processor: &mut MacroProcessor,
) -> Result<Option<Vec<String>>, MacroError> {
    if processor.statements.is_empty() {
        return Ok(None);
    }

    let mut cursor = Cursor::new(code);
    cursor.skip_ws();
    if cursor.peek().is_none() || cursor.peek() == Some(b'.') {
        return Ok(None);
    }

    let Some((label, mnemonic_text, mnemonic_end, _mnemonic_col_start)) =
        scan_statement_invocation(code)
    else {
        return Ok(None);
    };

    let mnemonic_upper = mnemonic_text.to_ascii_uppercase();

    let mut best_match: Option<(&String, &Vec<StatementDef>)> = None;
    for (keyword_upper, defs) in &processor.statements {
        if !mnemonic_upper.starts_with(keyword_upper) {
            continue;
        }
        match best_match {
            None => best_match = Some((keyword_upper, defs)),
            Some((best_keyword, _)) => {
                if keyword_upper.len() > best_keyword.len() {
                    best_match = Some((keyword_upper, defs));
                }
            }
        }
    }

    let Some((keyword_upper, defs)) = best_match else {
        return Ok(None);
    };

    let remainder = &mnemonic_text[keyword_upper.len()..];
    let tail = code.get(mnemonic_end..).unwrap_or("");
    let match_text = format!("{}{}", remainder, tail);

    let match_tokens = tokenize_line(&match_text, line_num)?;
    let signatures: Vec<StatementSignature> =
        defs.iter().map(|def| def.signature.clone()).collect();
    let (selection, tokens_for_match) = match select_statement_signature(&signatures, &match_tokens)
        .map_err(|err| MacroError::new(err.message, Some(line_num), Some(err.span.col_start)))?
    {
        Some(idx) => (Some(idx), match_tokens),
        None => {
            let split_tokens = split_single_letter_digit_tokens(&match_tokens);
            let selection =
                select_statement_signature(&signatures, &split_tokens).map_err(|err| {
                    MacroError::new(err.message, Some(line_num), Some(err.span.col_start))
                })?;
            (selection, split_tokens)
        }
    };

    let Some(idx) = selection else {
        return Ok(None);
    };

    let signature = &defs[idx].signature;
    let statement_match =
        match_statement_signature(signature, &tokens_for_match).ok_or_else(|| {
            MacroError::new("Statement signature match failed", Some(line_num), Some(1))
        })?;

    let args = build_statement_args(&statement_match);
    let mut expanded = Vec::new();
    for line in &defs[idx].body {
        expanded.push(substitute_line(line, &args));
    }

    if let Some(label) = &label {
        attach_label_to_expansion(label, &mut expanded);
    }

    let nested = processor.expand_lines(&expanded, depth + 1)?;
    Ok(Some(nested))
}

fn tokenize_line(line: &str, line_num: u32) -> Result<Vec<Token>, MacroError> {
    crate::vm::token_bridge::tokenize_line_with_default_model(line, line_num)
        .map_err(|err| MacroError::new(err.message, Some(line_num), Some(err.span.col_start)))
}

fn split_single_letter_digit_tokens(tokens: &[Token]) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        match &token.kind {
            TokenKind::Identifier(name) | TokenKind::Register(name) => {
                if name.len() >= 2 {
                    let mut chars = name.chars();
                    if let Some(first) = chars.next() {
                        let rest: String = chars.collect();
                        if first.is_ascii_alphabetic()
                            && !rest.is_empty()
                            && rest.chars().all(|c| c.is_ascii_digit())
                        {
                            let first_kind = if matches!(token.kind, TokenKind::Register(_)) {
                                TokenKind::Register(first.to_string())
                            } else {
                                TokenKind::Identifier(first.to_string())
                            };
                            let first_start = token.span.col_start;
                            let first_end = first_start + 1;
                            let second_start = first_end;
                            let second_end = token.span.col_end;
                            out.push(Token {
                                kind: first_kind,
                                span: Span {
                                    line: token.span.line,
                                    col_start: first_start,
                                    col_end: first_end,
                                },
                            });
                            out.push(Token {
                                kind: TokenKind::Number(crate::core::tokenizer::NumberLiteral {
                                    text: rest,
                                    base: 10,
                                }),
                                span: Span {
                                    line: token.span.line,
                                    col_start: second_start,
                                    col_end: second_end,
                                },
                            });
                            continue;
                        }
                    }
                }
                out.push(token.clone());
            }
            _ => out.push(token.clone()),
        }
    }
    out
}

fn scan_statement_invocation(line: &str) -> Option<(Option<String>, String, usize, usize)> {
    let mut cursor = Cursor::new(line);
    cursor.skip_ws();
    let at_col1 = cursor.pos() == 0;
    let first = cursor.peek()?;
    if first == b'.' || first == b';' || first == b'#' || first == b'*' {
        return None;
    }
    if !is_ident_start(first) {
        return None;
    }

    let mut label = None;
    if at_col1 {
        let name = cursor.take_ident()?;
        if cursor.peek() == Some(b':') {
            cursor.next();
        }
        label = Some(name);
        cursor.skip_ws();
        if cursor.peek().is_none() || !is_ident_start(cursor.peek()?) {
            return None;
        }
    }

    let mnemonic_col_start = cursor.pos() + 1;
    let mnemonic = cursor.take_ident()?;
    let mnemonic_end = cursor.pos();
    Some((label, mnemonic, mnemonic_end, mnemonic_col_start))
}

fn build_statement_args(statement_match: &crate::core::parser::StatementMatch) -> MacroArgs {
    let mut positional = Vec::new();
    let mut named = HashMap::new();
    for capture in &statement_match.captures {
        let text = capture
            .tokens
            .iter()
            .map(token_text_for_substitution)
            .collect::<String>();
        positional.push(text.clone());
        named.insert(to_upper(&capture.name), text);
    }
    let full_list = positional.join(", ");
    MacroArgs {
        positional,
        named,
        full_list,
    }
}

fn attach_label_to_expansion(label: &str, expanded: &mut Vec<String>) {
    if let Some(first) = expanded.first_mut() {
        let trimmed = first.trim_start();
        if trimmed.is_empty() {
            *first = label.to_string();
        } else {
            *first = format!("{label} {trimmed}");
        }
    } else {
        expanded.push(label.to_string());
    }
}
