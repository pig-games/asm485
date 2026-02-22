use crate::core::parser::{LineAst, ParseError};
use crate::core::tokenizer::{Span, Token};
use crate::opthread::package::{ParserVmOpcode, PARSER_VM_OPCODE_VERSION_V1};
use crate::opthread::runtime::{
    RuntimeParserContract, RuntimeParserDiagnosticMap, RuntimeParserVmProgram,
};

use super::{
    parse_assignment_envelope_from_tokens, parse_dot_directive_envelope_from_tokens,
    parse_error_at_end, parse_instruction_envelope_from_tokens,
    parse_star_org_envelope_from_tokens, parse_statement_envelope_from_tokens, ParserVmExecContext,
};

pub(super) fn parse_line_with_parser_vm(
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

fn parser_diag_code_for_slot(diagnostics: &RuntimeParserDiagnosticMap, slot: u8) -> &str {
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
