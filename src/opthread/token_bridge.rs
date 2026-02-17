// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::sync::OnceLock;

use crate::core::parser::{LineAst, ParseError, Parser};
use crate::core::registry::ModuleRegistry;
use crate::core::text_utils::is_ident_start;
use crate::core::tokenizer::{register_checker_none, RegisterChecker, Span, Token, TokenKind};
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::opthread::builder::build_hierarchy_package_from_registry;
use crate::opthread::runtime::{HierarchyExecutionModel, PortableToken};
use crate::z80::module::Z80CpuModule;

// Use an authoritative rollout lane so bootstrap/macro token bridge paths
// exercise strict VM tokenizer entrypoints by default.
const DEFAULT_TOKENIZER_CPU_ID: &str = "m6502";

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
    let parser_contract = model
        .resolve_parser_contract(DEFAULT_TOKENIZER_CPU_ID, None)
        .map_err(|err| parse_error_at_end(line, line_num, err.to_string()))?;
    if parser_contract.is_none() {
        return Err(parse_error_at_end(
            line,
            line_num,
            "opThread parser contract is unavailable for the active CPU pipeline",
        ));
    }
    let register_checker = register_checker_none();
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        line,
        line_num,
        &register_checker,
    )?;
    let mut parser = Parser::from_tokens(tokens, end_span, end_token_text);
    parser.parse_line()
}

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
mod tests {
    use super::*;

    #[test]
    fn default_model_resolves_bridge_cpu_to_mos6502_family() {
        let model = default_runtime_model().expect("default runtime model should be available");
        let resolved = model
            .resolve_pipeline(DEFAULT_TOKENIZER_CPU_ID, None)
            .expect("default tokenizer cpu should resolve");
        assert_eq!(resolved.family_id.to_ascii_lowercase(), "mos6502");
        assert!(model
            .resolve_parser_contract(DEFAULT_TOKENIZER_CPU_ID, None)
            .expect("parser contract resolution")
            .is_some());
    }

    #[test]
    fn parse_line_with_default_model_smoke() {
        let line = parse_line_with_default_model("    LDA #$42", 1).expect("line should parse");
        match line {
            LineAst::Statement {
                mnemonic: Some(mnemonic),
                ..
            } => {
                assert_eq!(mnemonic.to_ascii_lowercase(), "lda");
            }
            other => panic!("expected instruction line ast, got {other:?}"),
        }
    }
}
