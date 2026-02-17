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
use crate::opthread::package::{ParserVmOpcode, PARSER_VM_OPCODE_VERSION_V1};
use crate::opthread::runtime::{
    HierarchyExecutionModel, PortableLineAst, PortableToken, RuntimeParserContract,
    RuntimeParserVmProgram,
};
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
    let register_checker = register_checker_none();
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        line,
        line_num,
        &register_checker,
    )?;
    let parser_contract = model
        .validate_parser_contract_for_assembler(DEFAULT_TOKENIZER_CPU_ID, None, tokens.len())
        .map_err(|err| parse_error_at_end(line, line_num, err.to_string()))?;
    let parser_vm_program = model
        .resolve_parser_vm_program(DEFAULT_TOKENIZER_CPU_ID, None)
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
    parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        line,
        line_num,
    )
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

fn parse_line_with_parser_vm(
    tokens: Vec<Token>,
    end_span: Span,
    end_token_text: Option<String>,
    parser_contract: &RuntimeParserContract,
    parser_vm_program: &RuntimeParserVmProgram,
    line: &str,
    line_num: u32,
) -> Result<LineAst, ParseError> {
    if parser_contract.opcode_version != PARSER_VM_OPCODE_VERSION_V1 {
        return Err(parse_error_at_end(
            line,
            line_num,
            format!(
                "{}: unsupported parser contract opcode version {}",
                parser_contract.diagnostics.invalid_statement, parser_contract.opcode_version
            ),
        ));
    }
    if parser_vm_program.opcode_version != PARSER_VM_OPCODE_VERSION_V1 {
        return Err(parse_error_at_end(
            line,
            line_num,
            format!(
                "{}: unsupported parser VM opcode version {}",
                parser_contract.diagnostics.invalid_statement, parser_vm_program.opcode_version
            ),
        ));
    }
    if parser_contract.opcode_version != parser_vm_program.opcode_version {
        return Err(parse_error_at_end(
            line,
            line_num,
            format!(
                "{}: parser contract/program opcode version mismatch ({} != {})",
                parser_contract.diagnostics.invalid_statement,
                parser_contract.opcode_version,
                parser_vm_program.opcode_version
            ),
        ));
    }

    let mut pc = 0usize;
    let mut parsed_line: Option<LineAst> = None;
    let mut token_buffer = Some(tokens);

    while pc < parser_vm_program.program.len() {
        let opcode_byte = parser_vm_program.program[pc];
        pc = pc.saturating_add(1);
        let Some(opcode) = ParserVmOpcode::from_u8(opcode_byte) else {
            return Err(parse_error_at_end(
                line,
                line_num,
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
                        line,
                        line_num,
                        format!(
                            "{}: parser VM ended without producing an AST",
                            parser_contract.diagnostics.invalid_statement
                        ),
                    )
                });
            }
            ParserVmOpcode::ParseStatementEnvelope => {
                let Some(core_tokens) = token_buffer.as_ref() else {
                    return Err(parse_error_at_end(
                        line,
                        line_num,
                        format!(
                            "{}: parser VM attempted ParseStatementEnvelope after tokens were consumed",
                            parser_contract.diagnostics.invalid_statement
                        ),
                    ));
                };
                let mut parser =
                    Parser::from_tokens(core_tokens.clone(), end_span, end_token_text.clone());
                let parsed = parser.parse_line()?;
                let envelope = PortableLineAst::from_core_line_ast(&parsed);
                parsed_line = Some(envelope.to_core_line_ast());
            }
            ParserVmOpcode::ParseCoreLine => {
                if parsed_line.is_some() {
                    continue;
                }
                let Some(core_tokens) = token_buffer.take() else {
                    return Err(parse_error_at_end(
                        line,
                        line_num,
                        format!(
                            "{}: parser VM attempted duplicate ParseCoreLine execution",
                            parser_contract.diagnostics.invalid_statement
                        ),
                    ));
                };
                let mut parser = Parser::from_tokens(core_tokens, end_span, end_token_text.clone());
                let parsed = parser.parse_line()?;
                parsed_line = Some(parsed);
            }
            ParserVmOpcode::EmitDiag => {
                let Some(slot) = parser_vm_program.program.get(pc).copied() else {
                    return Err(parse_error_at_end(
                        line,
                        line_num,
                        format!(
                            "{}: parser VM EmitDiag missing slot operand",
                            parser_contract.diagnostics.invalid_statement
                        ),
                    ));
                };
                let code = parser_diag_code_for_slot(&parser_contract.diagnostics, slot);
                return Err(parse_error_at_end(
                    line,
                    line_num,
                    format!("{code}: parser VM emitted diagnostic slot {slot}"),
                ));
            }
            ParserVmOpcode::Fail => {
                return Err(parse_error_at_end(
                    line,
                    line_num,
                    format!(
                        "{}: parser VM requested failure",
                        parser_contract.diagnostics.invalid_statement
                    ),
                ));
            }
        }
    }

    Err(parse_error_at_end(
        line,
        line_num,
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

    #[test]
    fn parse_line_with_parser_vm_supports_statement_envelope_opcode() {
        let model = default_runtime_model().expect("default runtime model should be available");
        let register_checker = register_checker_none();
        let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
            model,
            DEFAULT_TOKENIZER_CPU_ID,
            None,
            "    LDA ($10),Y",
            1,
            &register_checker,
        )
        .expect("tokenization should succeed");
        let parser_contract = model
            .validate_parser_contract_for_assembler(DEFAULT_TOKENIZER_CPU_ID, None, tokens.len())
            .expect("parser contract should validate");
        let parser_vm_program = RuntimeParserVmProgram {
            opcode_version: PARSER_VM_OPCODE_VERSION_V1,
            program: vec![
                ParserVmOpcode::ParseStatementEnvelope as u8,
                ParserVmOpcode::End as u8,
            ],
        };

        let line = parse_line_with_parser_vm(
            tokens,
            end_span,
            end_token_text,
            &parser_contract,
            &parser_vm_program,
            "    LDA ($10),Y",
            1,
        )
        .expect("parse should succeed");
        match line {
            LineAst::Statement {
                mnemonic: Some(mnemonic),
                ..
            } => assert_eq!(mnemonic.to_ascii_lowercase(), "lda"),
            other => panic!("expected statement line ast, got {other:?}"),
        }
    }

    #[test]
    fn parse_line_with_parser_vm_statement_envelope_supports_non_statement_ast() {
        let model = default_runtime_model().expect("default runtime model should be available");
        let register_checker = register_checker_none();
        let source = "    .if 1";
        let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
            model,
            DEFAULT_TOKENIZER_CPU_ID,
            None,
            source,
            1,
            &register_checker,
        )
        .expect("tokenization should succeed");
        let parser_contract = model
            .validate_parser_contract_for_assembler(DEFAULT_TOKENIZER_CPU_ID, None, tokens.len())
            .expect("parser contract should validate");
        let parser_vm_program = RuntimeParserVmProgram {
            opcode_version: PARSER_VM_OPCODE_VERSION_V1,
            program: vec![
                ParserVmOpcode::ParseStatementEnvelope as u8,
                ParserVmOpcode::End as u8,
            ],
        };

        let line = parse_line_with_parser_vm(
            tokens,
            end_span,
            end_token_text,
            &parser_contract,
            &parser_vm_program,
            source,
            1,
        )
        .expect("parse should succeed");
        assert!(
            matches!(line, LineAst::Conditional { .. }),
            "expected conditional line ast from statement envelope parse, got {line:?}"
        );
    }

    #[test]
    fn parse_line_with_parser_vm_keeps_legacy_parse_core_line_compatibility() {
        let model = default_runtime_model().expect("default runtime model should be available");
        let register_checker = register_checker_none();
        let source = "    LDA #$42";
        let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
            model,
            DEFAULT_TOKENIZER_CPU_ID,
            None,
            source,
            1,
            &register_checker,
        )
        .expect("tokenization should succeed");
        let parser_contract = model
            .validate_parser_contract_for_assembler(DEFAULT_TOKENIZER_CPU_ID, None, tokens.len())
            .expect("parser contract should validate");
        let parser_vm_program = RuntimeParserVmProgram {
            opcode_version: PARSER_VM_OPCODE_VERSION_V1,
            program: vec![
                ParserVmOpcode::ParseStatementEnvelope as u8,
                ParserVmOpcode::ParseCoreLine as u8,
                ParserVmOpcode::End as u8,
            ],
        };

        let line = parse_line_with_parser_vm(
            tokens,
            end_span,
            end_token_text,
            &parser_contract,
            &parser_vm_program,
            source,
            1,
        )
        .expect("parse should succeed");
        assert!(
            matches!(line, LineAst::Statement { .. }),
            "expected statement line ast for legacy program, got {line:?}"
        );
    }
}
