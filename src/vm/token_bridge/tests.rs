use super::*;

#[derive(Debug, PartialEq, Eq)]
enum NormalizedExprDiag {
    None,
    ParseError { message: String, span: Span },
    ExprError { message: String, span: Span },
}

fn first_expr_error_from_ast(ast: &LineAst) -> Option<(String, Span)> {
    fn find_in_exprs(exprs: &[Expr]) -> Option<(String, Span)> {
        for expr in exprs {
            if let Expr::Error(message, span) = expr {
                return Some((message.clone(), *span));
            }
        }
        None
    }

    match ast {
        LineAst::Statement { operands, .. } => find_in_exprs(operands),
        LineAst::Assignment { expr, .. } => {
            if let Expr::Error(message, span) = expr {
                Some((message.clone(), *span))
            } else {
                None
            }
        }
        LineAst::Conditional { exprs, .. } => find_in_exprs(exprs),
        LineAst::Place { align, .. } => align.as_ref().and_then(|expr| {
            if let Expr::Error(message, span) = expr {
                Some((message.clone(), *span))
            } else {
                None
            }
        }),
        LineAst::Use { params, .. } => {
            for param in params {
                if let Expr::Error(message, span) = &param.value {
                    return Some((message.clone(), *span));
                }
            }
            None
        }
        _ => None,
    }
}

fn normalize_expr_diag(result: Result<LineAst, ParseError>) -> NormalizedExprDiag {
    match result {
        Ok(ast) => first_expr_error_from_ast(&ast).map_or(NormalizedExprDiag::None, |diag| {
            NormalizedExprDiag::ExprError {
                message: diag.0,
                span: diag.1,
            }
        }),
        Err(err) => NormalizedExprDiag::ParseError {
            message: err.message,
            span: err.span,
        },
    }
}

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
fn parse_line_with_default_model_parses_use_directive() {
    let line =
        parse_line_with_default_model("    .use math as m", 1).expect(".use line should parse");
    match line {
        LineAst::Use {
            module_id,
            alias,
            items,
            params,
            ..
        } => {
            assert_eq!(module_id, "math");
            assert_eq!(alias.as_deref(), Some("m"));
            assert!(items.is_empty());
            assert!(params.is_empty());
        }
        other => panic!("expected .use AST, got {other:?}"),
    }
}

#[test]
fn parse_line_with_default_model_parses_place_directive() {
    let line = parse_line_with_default_model("    .place code in ram, align=16", 1)
        .expect(".place line should parse");
    match line {
        LineAst::Place {
            section,
            region,
            align,
            ..
        } => {
            assert_eq!(section, "code");
            assert_eq!(region, "ram");
            assert!(align.is_some());
        }
        other => panic!("expected .place AST, got {other:?}"),
    }
}

#[test]
fn parse_line_with_default_model_parses_pack_directive() {
    let line = parse_line_with_default_model("    .pack in rom: code,data", 1)
        .expect(".pack line should parse");
    match line {
        LineAst::Pack {
            region, sections, ..
        } => {
            assert_eq!(region, "rom");
            assert_eq!(sections, vec!["code".to_string(), "data".to_string()]);
        }
        other => panic!("expected .pack AST, got {other:?}"),
    }
}

#[test]
fn parse_use_directive_from_tokens_parses_selective_alias_and_params() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    .use math(foo as f,bar) with(width=1+2, mask=$ff)";
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        source,
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let mut cursor = 2;
    let expr_parse_ctx = VmExprParseContext {
        model,
        cpu_id: DEFAULT_TOKENIZER_CPU_ID,
        dialect_override: None,
    };

    let parsed = parse_use_directive_from_tokens(
        &tokens,
        &mut cursor,
        tokens[1].span,
        end_span,
        end_token_text,
        &expr_parse_ctx,
    )
    .expect(".use directive parse should succeed");

    match parsed {
        LineAst::Use {
            module_id,
            alias,
            items,
            params,
            ..
        } => {
            assert_eq!(module_id, "math");
            assert_eq!(alias, None);
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].name, "foo");
            assert_eq!(items[0].alias.as_deref(), Some("f"));
            assert_eq!(items[1].name, "bar");
            assert_eq!(items[1].alias, None);
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "width");
            assert_eq!(params[1].name, "mask");
            assert!(!matches!(params[0].value, Expr::Error(_, _)));
            assert!(!matches!(params[1].value, Expr::Error(_, _)));
        }
        other => panic!("expected .use AST, got {other:?}"),
    }
}

#[test]
fn parse_use_directive_from_tokens_rejects_wildcard_alias() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    .use math(* as all)";
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        source,
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let mut cursor = 2;
    let expr_parse_ctx = VmExprParseContext {
        model,
        cpu_id: DEFAULT_TOKENIZER_CPU_ID,
        dialect_override: None,
    };

    let err = parse_use_directive_from_tokens(
        &tokens,
        &mut cursor,
        tokens[1].span,
        end_span,
        end_token_text,
        &expr_parse_ctx,
    )
    .expect_err("wildcard alias should be rejected");

    assert!(
        err.message.contains("Wildcard import cannot have an alias"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn parse_place_directive_from_tokens_rejects_unknown_option_key() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    .place code in ram, wrong=16";
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        source,
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let mut cursor = 2;
    let expr_parse_ctx = VmExprParseContext {
        model,
        cpu_id: DEFAULT_TOKENIZER_CPU_ID,
        dialect_override: None,
    };

    let err = parse_place_directive_from_tokens(
        &tokens,
        &mut cursor,
        tokens[1].span,
        end_span,
        end_token_text,
        &expr_parse_ctx,
    )
    .expect_err("unknown option should be rejected");

    assert!(
        err.message.contains("Unknown .place option key"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn parse_pack_directive_from_tokens_requires_at_least_one_section() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    .pack in rom:";
    let (tokens, end_span, _) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        source,
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let mut cursor = 2;

    let err = parse_pack_directive_from_tokens(&tokens, &mut cursor, tokens[1].span, end_span)
        .expect_err("missing section list should be rejected");

    assert!(
        err.message
            .contains("Expected at least one section in .pack directive"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn parse_statement_envelope_from_tokens_supports_statement_definition() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    .statement move.b char:dst \",\" char:src";
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        source,
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let expr_parse_ctx = VmExprParseContext {
        model,
        cpu_id: DEFAULT_TOKENIZER_CPU_ID,
        dialect_override: None,
    };

    let parsed =
        parse_statement_envelope_from_tokens(&tokens, end_span, end_token_text, &expr_parse_ctx)
            .expect("vm statement envelope parse should succeed")
            .to_core_line_ast();

    match parsed {
        LineAst::StatementDef {
            keyword, signature, ..
        } => {
            assert_eq!(keyword, "move.b");
            assert_eq!(signature.atoms.len(), 3);
        }
        other => panic!("expected statement definition AST, got {other:?}"),
    }
}

#[test]
fn parse_statement_envelope_from_tokens_handles_instruction_line() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "label: LDA ($10),Y",
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let expr_parse_ctx = VmExprParseContext {
        model,
        cpu_id: DEFAULT_TOKENIZER_CPU_ID,
        dialect_override: None,
    };

    let parsed =
        parse_statement_envelope_from_tokens(&tokens, end_span, end_token_text, &expr_parse_ctx)
            .expect("vm statement envelope parse should succeed")
            .to_core_line_ast();
    match parsed {
        LineAst::Statement {
            label: Some(label),
            mnemonic: Some(mnemonic),
            operands,
        } => {
            assert_eq!(label.name.to_ascii_lowercase(), "label");
            assert_eq!(mnemonic.to_ascii_lowercase(), "lda");
            assert_eq!(operands.len(), 2);
        }
        other => panic!("expected statement line ast, got {other:?}"),
    }
}

#[test]
fn parse_statement_envelope_from_tokens_parses_directive_line() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let (tokens, end_span, end_token_text) = tokenize_parser_tokens_with_model(
        model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "    .if 1",
        1,
        &register_checker,
    )
    .expect("tokenization should succeed");
    let expr_parse_ctx = VmExprParseContext {
        model,
        cpu_id: DEFAULT_TOKENIZER_CPU_ID,
        dialect_override: None,
    };

    let parsed =
        parse_statement_envelope_from_tokens(&tokens, end_span, end_token_text, &expr_parse_ctx)
            .expect("vm statement envelope parse should succeed")
            .to_core_line_ast();
    assert!(
        matches!(parsed, LineAst::Conditional { .. }),
        "directive line should parse as conditional, got {parsed:?}"
    );
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
        ParserVmExecContext {
            source_line: "    LDA ($10),Y",
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
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
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect("parse should succeed");
    assert!(
        matches!(line, LineAst::Conditional { .. }),
        "expected conditional line ast from statement envelope parse, got {line:?}"
    );
}

#[test]
fn parse_line_with_parser_vm_rejects_retired_parse_core_line_opcode() {
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
            0x01,
            ParserVmOpcode::End as u8,
        ],
    };

    let err = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect_err("retired opcode should fail");
    assert!(err.message.contains("invalid parser VM opcode 0x01"));
}

#[test]
fn parse_line_with_parser_vm_rejects_incompatible_contract_opcode_version() {
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
    let mut parser_contract = model
        .validate_parser_contract_for_assembler(DEFAULT_TOKENIZER_CPU_ID, None, tokens.len())
        .expect("parser contract should validate");
    parser_contract.opcode_version = PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
    let parser_vm_program = RuntimeParserVmProgram {
        opcode_version: parser_contract.opcode_version,
        program: vec![
            ParserVmOpcode::ParseInstructionEnvelope as u8,
            ParserVmOpcode::End as u8,
        ],
    };

    let err = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect_err("incompatible parser contract opcode version must fail");
    assert!(err
        .message
        .contains("unsupported parser contract opcode version"));
}

#[test]
fn parse_line_with_parser_vm_rejects_contract_program_opcode_version_mismatch() {
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
        opcode_version: PARSER_VM_OPCODE_VERSION_V1.saturating_add(1),
        program: vec![
            ParserVmOpcode::ParseInstructionEnvelope as u8,
            ParserVmOpcode::End as u8,
        ],
    };

    let err = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect_err("parser contract/program opcode version mismatch must fail");
    assert!(err
        .message
        .contains("parser contract/program opcode version mismatch"));
}

#[test]
fn parse_line_with_parser_vm_supports_dot_directive_primitive_opcode() {
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
            ParserVmOpcode::ParseDotDirectiveEnvelope as u8,
            ParserVmOpcode::ParseStarOrgEnvelope as u8,
            ParserVmOpcode::ParseAssignmentEnvelope as u8,
            ParserVmOpcode::ParseInstructionEnvelope as u8,
            ParserVmOpcode::EmitDiagIfNoAst as u8,
            0,
            ParserVmOpcode::End as u8,
        ],
    };

    let line = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect("parse should succeed");
    assert!(
        matches!(line, LineAst::Conditional { .. }),
        "expected conditional line ast from dot-directive primitive, got {line:?}"
    );
}

#[test]
fn parse_line_with_parser_vm_supports_assignment_envelope_opcode() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "var2 += 1";
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
            ParserVmOpcode::ParseAssignmentEnvelope as u8,
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
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect("parse should succeed");
    assert!(
        matches!(
            line,
            LineAst::Assignment {
                op: AssignOp::Add,
                ..
            }
        ),
        "expected add assignment from assignment primitive, got {line:?}"
    );
}

#[test]
fn parse_line_with_parser_vm_supports_star_org_envelope_opcode() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    * = $2000";
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
            ParserVmOpcode::ParseStarOrgEnvelope as u8,
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
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect("parse should succeed");
    assert!(
        matches!(
            line,
            LineAst::Statement {
                mnemonic: Some(ref m),
                ..
            } if m.eq_ignore_ascii_case(".org")
        ),
        "expected .org statement from star-org primitive, got {line:?}"
    );
}

#[test]
fn parse_line_with_parser_vm_supports_instruction_envelope_opcode() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "LBL LDA #$42";
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
            ParserVmOpcode::ParseInstructionEnvelope as u8,
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
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect("parse should succeed");
    assert!(
        matches!(
            line,
            LineAst::Statement {
                mnemonic: Some(_),
                ..
            }
        ),
        "expected instruction statement from instruction primitive, got {line:?}"
    );
}

#[test]
fn parse_line_with_parser_vm_dot_directive_primitive_skips_dot_assignment_ops() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "cat ..= $3456";
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
            ParserVmOpcode::ParseDotDirectiveEnvelope as u8,
            ParserVmOpcode::ParseStarOrgEnvelope as u8,
            ParserVmOpcode::ParseAssignmentEnvelope as u8,
            ParserVmOpcode::ParseInstructionEnvelope as u8,
            ParserVmOpcode::EmitDiagIfNoAst as u8,
            0,
            ParserVmOpcode::End as u8,
        ],
    };

    let line = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect("parse should succeed");
    assert!(
        matches!(
            line,
            LineAst::Assignment {
                op: AssignOp::Concat,
                ..
            }
        ),
        "expected concat assignment to be parsed by assignment primitive, got {line:?}"
    );
}

#[test]
fn parse_line_with_parser_vm_emit_diag_if_no_ast_reports_unexpected_token_slot() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    ?";
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
            ParserVmOpcode::ParseDotDirectiveEnvelope as u8,
            ParserVmOpcode::ParseStarOrgEnvelope as u8,
            ParserVmOpcode::ParseAssignmentEnvelope as u8,
            ParserVmOpcode::ParseInstructionEnvelope as u8,
            ParserVmOpcode::EmitDiagIfNoAst as u8,
            0,
            ParserVmOpcode::End as u8,
        ],
    };

    let err = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect_err("unmatched line should emit terminal parser VM diagnostic");
    assert_eq!(
        err.message,
        format!(
            "{}: parser VM emitted diagnostic slot 0",
            parser_contract.diagnostics.unexpected_token
        )
    );
}

#[test]
fn parse_line_with_parser_vm_emit_diag_if_no_ast_requires_slot_operand() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    NOP";
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
        program: vec![ParserVmOpcode::EmitDiagIfNoAst as u8],
    };

    let err = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect_err("missing EmitDiagIfNoAst slot must fail");
    assert!(err.message.contains("EmitDiagIfNoAst missing slot operand"));
}

#[test]
fn parse_line_with_parser_vm_emit_diag_requires_slot_operand() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let source = "    NOP";
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
        program: vec![ParserVmOpcode::EmitDiag as u8],
    };

    let err = parse_line_with_parser_vm(
        tokens,
        end_span,
        end_token_text,
        &parser_contract,
        &parser_vm_program,
        ParserVmExecContext {
            source_line: source,
            line_num: 1,
            expr_parse_ctx: VmExprParseContext {
                model,
                cpu_id: DEFAULT_TOKENIZER_CPU_ID,
                dialect_override: None,
            },
        },
    )
    .expect_err("missing EmitDiag slot must fail");
    assert!(err.message.contains("EmitDiag missing slot operand"));
}

#[test]
fn parse_line_with_model_preserves_expression_diagnostic_shape_and_span_parity() {
    let model = default_runtime_model().expect("default runtime model should be available");
    let register_checker = register_checker_none();
    let corpus = [
        "label = 1 +",
        "    LDA #(",
        "    .if 1 +",
        "    .place code in ram, align=1+",
        "    .use foo with(x=1+)",
    ];

    for (idx, line) in corpus.iter().enumerate() {
        let line_num = (idx + 1) as u32;
        let bridge = parse_line_with_model(
            model,
            DEFAULT_TOKENIZER_CPU_ID,
            None,
            line,
            line_num,
            &register_checker,
        )
        .map(|(ast, _, _)| ast);
        let host = crate::core::parser::Parser::from_line_with_registers(
            line,
            line_num,
            register_checker.clone(),
        )
        .and_then(|mut parser| parser.parse_line());
        let bridge_diag = normalize_expr_diag(bridge);
        let host_diag = normalize_expr_diag(host);
        assert_eq!(
            bridge_diag, host_diag,
            "expression diagnostic parity mismatch for line {:?}",
            line
        );
    }
}

#[test]
fn parse_line_with_model_requires_expression_contract_compatibility() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut chunks = crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
        .expect("hierarchy chunks build");
    for contract in &mut chunks.parser_contracts {
        if matches!(
            contract.owner,
            crate::vm::hierarchy::ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("mos6502")
        ) {
            contract.grammar_id = "opforge.line.v0".to_string();
        }
    }
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model should build");
    let register_checker = register_checker_none();
    let err = parse_line_with_model(
        &model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "    NOP",
        1,
        &register_checker,
    )
    .expect_err("incompatible parser contract should fail before AST parsing");
    let message = err.message;
    assert_eq!(
        message,
        "otp004: unsupported parser grammar id 'opforge.line.v0'"
    );
}

#[test]
fn parse_line_with_model_requires_parser_ast_schema_compatibility() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut chunks = crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
        .expect("hierarchy chunks build");
    for contract in &mut chunks.parser_contracts {
        if matches!(
            contract.owner,
            crate::vm::hierarchy::ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("mos6502")
        ) {
            contract.ast_schema_id = "opforge.ast.line.v0".to_string();
        }
    }
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model should build");
    let register_checker = register_checker_none();
    let err = parse_line_with_model(
        &model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "    NOP",
        1,
        &register_checker,
    )
    .expect_err("incompatible parser contract should fail before AST parsing");
    let message = err.message;
    assert_eq!(
        message,
        "otp004: unsupported parser AST schema id 'opforge.ast.line.v0'"
    );
}

#[test]
fn parse_line_with_model_enforces_parser_vm_program_byte_budget() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut chunks = crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
        .expect("hierarchy chunks build");
    for program in &mut chunks.parser_vm_programs {
        if matches!(
            program.owner,
            crate::vm::hierarchy::ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("mos6502")
        ) {
            program.program = vec![ParserVmOpcode::ParseInstructionEnvelope as u8; 100];
        }
    }
    let mut model =
        HierarchyExecutionModel::from_chunks(chunks).expect("execution model should build");
    model.set_runtime_budget_profile(crate::vm::runtime::RuntimeBudgetProfile::RetroConstrained);
    let register_checker = register_checker_none();
    let err = parse_line_with_model(
        &model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "    NOP",
        1,
        &register_checker,
    )
    .expect_err("oversized parser VM program should fail in retro profile");
    assert!(err
        .message
        .contains("parser VM program byte budget exceeded"));
}

#[test]
fn parse_line_with_model_parser_vm_budget_error_is_deterministic() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut chunks = crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
        .expect("hierarchy chunks build");
    for program in &mut chunks.parser_vm_programs {
        if matches!(
            program.owner,
            crate::vm::hierarchy::ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("mos6502")
        ) {
            program.program = vec![ParserVmOpcode::ParseInstructionEnvelope as u8; 100];
        }
    }
    let mut model =
        HierarchyExecutionModel::from_chunks(chunks).expect("execution model should build");
    model.set_runtime_budget_profile(crate::vm::runtime::RuntimeBudgetProfile::RetroConstrained);
    let register_checker = register_checker_none();
    let first = parse_line_with_model(
        &model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "    NOP",
        1,
        &register_checker,
    )
    .expect_err("oversized parser VM program should fail in retro profile");
    let second = parse_line_with_model(
        &model,
        DEFAULT_TOKENIZER_CPU_ID,
        None,
        "    NOP",
        1,
        &register_checker,
    )
    .expect_err("oversized parser VM program should fail in retro profile");
    assert_eq!(first.message, second.message);
    assert_eq!(first.span, second.span);
}

#[test]
fn parse_expr_with_vm_contract_rejects_slice_above_parser_token_budget() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut model = HierarchyExecutionModel::from_chunks(
        crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
            .expect("hierarchy chunks build"),
    )
    .expect("execution model should build");
    model.set_runtime_budget_profile(crate::vm::runtime::RuntimeBudgetProfile::RetroConstrained);
    let token_budget = model.runtime_budget_limits().max_parser_tokens_per_line;
    let span = Span {
        line: 1,
        col_start: 1,
        col_end: 2,
    };
    let tokens = vec![
        Token {
            kind: TokenKind::Identifier("A".to_string()),
            span,
        };
        token_budget.saturating_add(1)
    ];
    let err = parse_expr_with_vm_contract(
        &VmExprParseContext {
            model: &model,
            cpu_id: DEFAULT_TOKENIZER_CPU_ID,
            dialect_override: None,
        },
        tokens.as_slice(),
        span,
        None,
    )
    .expect_err("expression slice above parser token budget should fail");
    assert!(
        err.message
            .starts_with("otp004: parser token budget exceeded"),
        "unexpected parser token budget diagnostic: {}",
        err.message
    );
}

#[test]
fn parse_expr_program_ref_with_vm_contract_enforces_vm_contract_for_intel_family() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut chunks = crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
        .expect("hierarchy chunks build");
    for contract in &mut chunks.expr_parser_contracts {
        if matches!(
            contract.owner,
            crate::vm::hierarchy::ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("intel8080")
        ) {
            contract.opcode_version =
                crate::vm::package::EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
        }
    }
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model should build");

    let span = Span {
        line: 1,
        col_start: 1,
        col_end: 3,
    };
    let tokens = vec![Token {
        kind: TokenKind::Identifier("value".to_string()),
        span,
    }];

    let err = parse_expr_program_ref_with_vm_contract(
        &VmExprParseContext {
            model: &model,
            cpu_id: "8085",
            dialect_override: None,
        },
        tokens.as_slice(),
        span,
        None,
        None,
    )
    .expect_err("intel family should enforce expression parser VM contract compatibility");
    assert!(
        err.message
            .to_ascii_lowercase()
            .contains("unsupported expression parser contract opcode version"),
        "expected expression parser contract compatibility failure, got: {}",
        err.message
    );
}

#[test]
fn parse_expr_program_ref_with_vm_contract_uses_vm_path_for_enabled_family() {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    let mut chunks = crate::vm::builder::build_hierarchy_chunks_from_registry(&registry)
        .expect("hierarchy chunks build");
    for contract in &mut chunks.expr_parser_contracts {
        if matches!(
            contract.owner,
            crate::vm::hierarchy::ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("mos6502")
        ) {
            contract.opcode_version =
                crate::vm::package::EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
        }
    }
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model should build");

    let span = Span {
        line: 1,
        col_start: 1,
        col_end: 3,
    };
    let tokens = vec![Token {
        kind: TokenKind::Identifier("value".to_string()),
        span,
    }];

    let err = parse_expr_program_ref_with_vm_contract(
        &VmExprParseContext {
            model: &model,
            cpu_id: DEFAULT_TOKENIZER_CPU_ID,
            dialect_override: None,
        },
        tokens.as_slice(),
        span,
        None,
        None,
    )
    .expect_err("enabled family should enforce expression parser VM contract compatibility");
    assert!(
        err.message
            .contains("unsupported expression parser contract opcode version"),
        "expected VM-path expression parser contract compatibility error, got: {}",
        err.message
    );
}
