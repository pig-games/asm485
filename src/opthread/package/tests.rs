
use super::*;

fn sample_families() -> Vec<FamilyDescriptor> {
    vec![
        FamilyDescriptor {
            id: "mos6502".to_string(),
            canonical_dialect: "mos".to_string(),
        },
        FamilyDescriptor {
            id: "intel8080".to_string(),
            canonical_dialect: "intel".to_string(),
        },
    ]
}

fn sample_cpus() -> Vec<CpuDescriptor> {
    vec![
        CpuDescriptor {
            id: "z80".to_string(),
            family_id: "intel8080".to_string(),
            default_dialect: Some("zilog".to_string()),
        },
        CpuDescriptor {
            id: "8085".to_string(),
            family_id: "intel8080".to_string(),
            default_dialect: Some("intel".to_string()),
        },
        CpuDescriptor {
            id: "6502".to_string(),
            family_id: "mos6502".to_string(),
            default_dialect: Some("mos".to_string()),
        },
    ]
}

fn sample_dialects() -> Vec<DialectDescriptor> {
    vec![
        DialectDescriptor {
            id: "mos".to_string(),
            family_id: "mos6502".to_string(),
            cpu_allow_list: None,
        },
        DialectDescriptor {
            id: "intel".to_string(),
            family_id: "intel8080".to_string(),
            cpu_allow_list: None,
        },
        DialectDescriptor {
            id: "zilog".to_string(),
            family_id: "intel8080".to_string(),
            cpu_allow_list: Some(vec!["z80".to_string(), "Z80".to_string()]),
        },
    ]
}

fn sample_registers() -> Vec<ScopedRegisterDescriptor> {
    vec![
        ScopedRegisterDescriptor {
            owner: ScopedOwner::Family("intel8080".to_string()),
            id: "A".to_string(),
        },
        ScopedRegisterDescriptor {
            owner: ScopedOwner::Family("intel8080".to_string()),
            id: "HL".to_string(),
        },
        ScopedRegisterDescriptor {
            owner: ScopedOwner::Cpu("z80".to_string()),
            id: "IX".to_string(),
        },
        ScopedRegisterDescriptor {
            owner: ScopedOwner::Cpu("z80".to_string()),
            id: "ix".to_string(),
        },
    ]
}

fn sample_forms() -> Vec<ScopedFormDescriptor> {
    vec![
        ScopedFormDescriptor {
            owner: ScopedOwner::Family("intel8080".to_string()),
            mnemonic: "mov".to_string(),
        },
        ScopedFormDescriptor {
            owner: ScopedOwner::Family("intel8080".to_string()),
            mnemonic: "MOV".to_string(),
        },
        ScopedFormDescriptor {
            owner: ScopedOwner::Cpu("z80".to_string()),
            mnemonic: "djnz".to_string(),
        },
        ScopedFormDescriptor {
            owner: ScopedOwner::Dialect("zilog".to_string()),
            mnemonic: "ld".to_string(),
        },
    ]
}

fn sample_tables() -> Vec<VmProgramDescriptor> {
    vec![
        VmProgramDescriptor {
            owner: ScopedOwner::Cpu("m6502".to_string()),
            mnemonic: "lda".to_string(),
            mode_key: "immediate".to_string(),
            program: vec![0x01, 0xA9, 0x02, 0x00, 0xFF],
        },
        VmProgramDescriptor {
            owner: ScopedOwner::Cpu("m6502".to_string()),
            mnemonic: "LDA".to_string(),
            mode_key: "Immediate".to_string(),
            program: vec![0x01, 0xA9, 0x02, 0x00, 0xFF],
        },
    ]
}

fn token_policy_for_test(
    owner: ScopedOwner,
    case_rule: TokenCaseRule,
    identifier_start_class: u32,
    identifier_continue_class: u32,
    punctuation_chars: &str,
) -> TokenPolicyDescriptor {
    let defaults = default_token_policy_lexical_defaults();
    TokenPolicyDescriptor {
        owner,
        case_rule,
        identifier_start_class,
        identifier_continue_class,
        punctuation_chars: punctuation_chars.to_string(),
        comment_prefix: defaults.comment_prefix,
        quote_chars: defaults.quote_chars,
        escape_char: defaults.escape_char,
        number_prefix_chars: defaults.number_prefix_chars,
        number_suffix_binary: defaults.number_suffix_binary,
        number_suffix_octal: defaults.number_suffix_octal,
        number_suffix_decimal: defaults.number_suffix_decimal,
        number_suffix_hex: defaults.number_suffix_hex,
        operator_chars: defaults.operator_chars,
        multi_char_operators: defaults.multi_char_operators,
    }
}

fn sample_token_policies() -> Vec<TokenPolicyDescriptor> {
    vec![
        token_policy_for_test(
            ScopedOwner::Family("MOS6502".to_string()),
            TokenCaseRule::AsciiLower,
            token_identifier_class::ASCII_ALPHA | token_identifier_class::UNDERSCORE,
            token_identifier_class::ASCII_ALPHA
                | token_identifier_class::ASCII_DIGIT
                | token_identifier_class::UNDERSCORE,
            ")(,+-",
        ),
        token_policy_for_test(
            ScopedOwner::Family("mos6502".to_string()),
            TokenCaseRule::AsciiLower,
            token_identifier_class::ASCII_ALPHA | token_identifier_class::UNDERSCORE,
            token_identifier_class::ASCII_ALPHA
                | token_identifier_class::ASCII_DIGIT
                | token_identifier_class::UNDERSCORE,
            "-+(),",
        ),
        token_policy_for_test(
            ScopedOwner::Cpu("z80".to_string()),
            TokenCaseRule::Preserve,
            token_identifier_class::ASCII_ALPHA,
            token_identifier_class::ASCII_ALPHA | token_identifier_class::ASCII_DIGIT,
            "[]()",
        ),
    ]
}

fn tokenizer_vm_program_for_test(owner: ScopedOwner) -> TokenizerVmProgramDescriptor {
    TokenizerVmProgramDescriptor {
        owner,
        opcode_version: TOKENIZER_VM_OPCODE_VERSION_V1,
        start_state: 0,
        state_entry_offsets: vec![0],
        limits: TokenizerVmLimits {
            max_steps_per_line: 2048,
            max_tokens_per_line: 256,
            max_lexeme_bytes: 256,
            max_errors_per_line: 16,
        },
        diagnostics: TokenizerVmDiagnosticMap {
            invalid_char: DIAG_TOKENIZER_INVALID_CHAR.to_string(),
            unterminated_string: DIAG_TOKENIZER_UNTERMINATED_STRING.to_string(),
            step_limit_exceeded: DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED.to_string(),
            token_limit_exceeded: DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED.to_string(),
            lexeme_limit_exceeded: DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED.to_string(),
            error_limit_exceeded: DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED.to_string(),
        },
        program: vec![TokenizerVmOpcode::End as u8],
    }
}

fn sample_tokenizer_vm_programs() -> Vec<TokenizerVmProgramDescriptor> {
    vec![
        tokenizer_vm_program_for_test(ScopedOwner::Family("MOS6502".to_string())),
        tokenizer_vm_program_for_test(ScopedOwner::Family("mos6502".to_string())),
        tokenizer_vm_program_for_test(ScopedOwner::Cpu("z80".to_string())),
    ]
}

fn parser_contract_for_test(owner: ScopedOwner) -> ParserContractDescriptor {
    ParserContractDescriptor {
        owner,
        grammar_id: PARSER_GRAMMAR_ID_LINE_V1.to_string(),
        ast_schema_id: PARSER_AST_SCHEMA_ID_LINE_V1.to_string(),
        opcode_version: PARSER_VM_OPCODE_VERSION_V1,
        max_ast_nodes_per_line: 256,
        diagnostics: ParserDiagnosticMap {
            unexpected_token: DIAG_PARSER_UNEXPECTED_TOKEN.to_string(),
            expected_expression: DIAG_PARSER_EXPECTED_EXPRESSION.to_string(),
            expected_operand: DIAG_PARSER_EXPECTED_OPERAND.to_string(),
            invalid_statement: DIAG_PARSER_INVALID_STATEMENT.to_string(),
        },
    }
}

fn sample_parser_contracts() -> Vec<ParserContractDescriptor> {
    vec![
        parser_contract_for_test(ScopedOwner::Family("MOS6502".to_string())),
        parser_contract_for_test(ScopedOwner::Family("mos6502".to_string())),
        parser_contract_for_test(ScopedOwner::Cpu("z80".to_string())),
    ]
}

fn parser_vm_program_for_test(owner: ScopedOwner) -> ParserVmProgramDescriptor {
    ParserVmProgramDescriptor {
        owner,
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
    }
}

fn sample_parser_vm_programs() -> Vec<ParserVmProgramDescriptor> {
    vec![
        parser_vm_program_for_test(ScopedOwner::Family("MOS6502".to_string())),
        parser_vm_program_for_test(ScopedOwner::Family("mos6502".to_string())),
        parser_vm_program_for_test(ScopedOwner::Cpu("z80".to_string())),
    ]
}

fn expr_contract_for_test(owner: ScopedOwner) -> ExprContractDescriptor {
    ExprContractDescriptor {
        owner,
        opcode_version: EXPR_VM_OPCODE_VERSION_V1,
        max_program_bytes: 2048,
        max_stack_depth: 64,
        max_symbol_refs: 128,
        max_eval_steps: 2048,
        diagnostics: ExprDiagnosticMap {
            invalid_opcode: DIAG_EXPR_INVALID_OPCODE.to_string(),
            stack_underflow: DIAG_EXPR_STACK_UNDERFLOW.to_string(),
            stack_depth_exceeded: DIAG_EXPR_STACK_DEPTH_EXCEEDED.to_string(),
            unknown_symbol: DIAG_EXPR_UNKNOWN_SYMBOL.to_string(),
            eval_failure: DIAG_EXPR_EVAL_FAILURE.to_string(),
            unsupported_feature: DIAG_EXPR_UNSUPPORTED_FEATURE.to_string(),
            budget_exceeded: DIAG_EXPR_BUDGET_EXCEEDED.to_string(),
            invalid_program: DIAG_EXPR_INVALID_PROGRAM.to_string(),
        },
    }
}

fn sample_expr_contracts() -> Vec<ExprContractDescriptor> {
    vec![
        expr_contract_for_test(ScopedOwner::Family("MOS6502".to_string())),
        expr_contract_for_test(ScopedOwner::Family("mos6502".to_string())),
        expr_contract_for_test(ScopedOwner::Cpu("z80".to_string())),
    ]
}

fn expr_parser_contract_for_test(owner: ScopedOwner) -> ExprParserContractDescriptor {
    ExprParserContractDescriptor {
        owner,
        opcode_version: EXPR_PARSER_VM_OPCODE_VERSION_V1,
        diagnostics: ExprParserDiagnosticMap {
            invalid_expression_program: DIAG_PARSER_INVALID_STATEMENT.to_string(),
        },
    }
}

fn sample_expr_parser_contracts() -> Vec<ExprParserContractDescriptor> {
    vec![
        expr_parser_contract_for_test(ScopedOwner::Family("MOS6502".to_string())),
        expr_parser_contract_for_test(ScopedOwner::Family("mos6502".to_string())),
        expr_parser_contract_for_test(ScopedOwner::Cpu("z80".to_string())),
    ]
}

#[test]
fn encode_decode_round_trip_is_deterministic() {
    let bytes = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");
    let reencoded = encode_hierarchy_chunks(
        &decoded.families,
        &decoded.cpus,
        &decoded.dialects,
        &decoded.registers,
        &decoded.forms,
        &decoded.tables,
    )
    .expect("re-encode should succeed");
    assert_eq!(bytes, reencoded);
}

#[test]
fn load_hierarchy_package_validates_and_resolves() {
    let bytes = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("encode should succeed");
    let package = load_hierarchy_package(&bytes).expect("load should succeed");

    let resolved_8085 = package
        .resolve_pipeline("8085", None)
        .expect("8085 should resolve");
    assert_eq!(resolved_8085.dialect_id, "intel");

    let resolved_z80 = package
        .resolve_pipeline("z80", None)
        .expect("z80 should resolve");
    assert_eq!(resolved_z80.dialect_id, "zilog");
}

#[test]
fn encoding_is_stable_across_input_order() {
    let mut families = sample_families();
    families.reverse();
    let mut cpus = sample_cpus();
    cpus.reverse();
    let mut dialects = sample_dialects();
    dialects.reverse();
    let mut registers = sample_registers();
    registers.reverse();
    let mut forms = sample_forms();
    forms.reverse();
    let mut tables = sample_tables();
    tables.reverse();

    let a = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("ordered encode should succeed");
    let b = encode_hierarchy_chunks(&families, &cpus, &dialects, &registers, &forms, &tables)
        .expect("shuffled encode should succeed");
    assert_eq!(a, b);
}

#[test]
fn metadata_snapshot_is_stable() {
    let bytes = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");
    assert_eq!(decoded.metadata.package_id, "opforge.generated");
    assert_eq!(decoded.metadata.package_version, "0.1.0");
    assert_eq!(decoded.metadata.capability_flags, 0);
    assert!(decoded.strings.is_empty());
    assert!(decoded.diagnostics.is_empty());
    assert!(decoded.token_policies.is_empty());
    assert!(decoded.parser_contracts.is_empty());
    assert!(decoded.parser_vm_programs.is_empty());
    assert!(decoded.expr_contracts.is_empty());

    let family_snapshot: Vec<String> = decoded
        .families
        .iter()
        .map(|entry| format!("{}->{}", entry.id, entry.canonical_dialect))
        .collect();
    assert_eq!(family_snapshot, vec!["intel8080->intel", "mos6502->mos"]);

    let cpu_snapshot: Vec<String> = decoded
        .cpus
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}",
                entry.id,
                entry.family_id,
                entry.default_dialect.as_deref().unwrap_or("-")
            )
        })
        .collect();
    assert_eq!(
        cpu_snapshot,
        vec![
            "6502:mos6502:mos",
            "8085:intel8080:intel",
            "z80:intel8080:zilog"
        ]
    );

    let dialect_snapshot: Vec<String> = decoded
        .dialects
        .iter()
        .map(|entry| format!("{}:{}", entry.family_id, entry.id))
        .collect();
    assert_eq!(
        dialect_snapshot,
        vec!["intel8080:intel", "intel8080:zilog", "mos6502:mos"]
    );
}

#[test]
fn toc_snapshot_is_stable() {
    let bytes = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("encode should succeed");

    let toc_count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let mut toc_entries = Vec::new();
    for idx in 0..toc_count {
        let base = HEADER_SIZE + idx * TOC_ENTRY_SIZE;
        let chunk_id = String::from_utf8_lossy(&bytes[base..base + 4]).to_string();
        let offset = u32::from_le_bytes([
            bytes[base + 4],
            bytes[base + 5],
            bytes[base + 6],
            bytes[base + 7],
        ]);
        let length = u32::from_le_bytes([
            bytes[base + 8],
            bytes[base + 9],
            bytes[base + 10],
            bytes[base + 11],
        ]);
        toc_entries.push(format!("{}@{}+{}", chunk_id, offset, length));
    }

    assert_eq!(
        toc_entries,
        vec![
            "META@132+34",
            "STRS@166+4",
            "DIAG@170+4",
            "FAMS@174+44",
            "CPUS@218+92",
            "DIAL@310+80",
            "REGS@390+57",
            "FORM@447+57",
            "TABL@504+43",
            "MSEL@547+4"
        ]
    );
}

#[test]
fn ultimate64_abi_header_is_little_endian_v1() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: default_runtime_diagnostic_catalog(),
        token_policies: sample_token_policies(),
        tokenizer_vm_programs: sample_tokenizer_vm_programs(),
        parser_contracts: sample_parser_contracts(),
        parser_vm_programs: sample_parser_vm_programs(),
        expr_contracts: sample_expr_contracts(),
        expr_parser_contracts: sample_expr_parser_contracts(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");

    assert_eq!(&bytes[0..4], OPCPU_MAGIC.as_slice());
    assert_eq!(&bytes[4..6], OPCPU_VERSION_V1.to_le_bytes().as_slice());
    assert_eq!(&bytes[6..8], OPCPU_ENDIAN_MARKER.to_le_bytes().as_slice());
    assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), OPCPU_VERSION_V1);
    assert_eq!(
        u16::from_le_bytes([bytes[6], bytes[7]]),
        OPCPU_ENDIAN_MARKER
    );
}

#[test]
fn ultimate64_abi_toc_payload_layout_is_contiguous() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: default_runtime_diagnostic_catalog(),
        token_policies: sample_token_policies(),
        tokenizer_vm_programs: sample_tokenizer_vm_programs(),
        parser_contracts: sample_parser_contracts(),
        parser_vm_programs: sample_parser_vm_programs(),
        expr_contracts: sample_expr_contracts(),
        expr_parser_contracts: sample_expr_parser_contracts(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");
    let toc = parse_toc(&bytes).expect("TOC parse should succeed");
    let mut entries: Vec<TocEntry> = toc.values().copied().collect();
    entries.sort_by_key(|entry| entry.offset);
    assert!(!entries.is_empty(), "expected non-empty TOC entries");
    for idx in 1..entries.len() {
        let prev = entries[idx - 1];
        let current = entries[idx];
        assert_eq!(
            prev.offset.saturating_add(prev.length),
            current.offset,
            "expected contiguous payload layout for TOC entries"
        );
    }
    let last = entries.last().expect("entries not empty");
    let end = usize::try_from(last.offset.saturating_add(last.length))
        .expect("payload end must fit usize");
    assert_eq!(end, bytes.len());
}

#[test]
fn ultimate64_abi_default_diag_catalog_covers_parser_and_tokenizer_codes() {
    let diagnostics = default_runtime_diagnostic_catalog();
    let mut codes: Vec<String> = diagnostics.iter().map(|entry| entry.code.clone()).collect();
    codes.sort();
    assert!(codes.iter().any(|code| code == DIAG_TOKENIZER_INVALID_CHAR));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_TOKENIZER_UNTERMINATED_STRING));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_PARSER_UNEXPECTED_TOKEN));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_PARSER_EXPECTED_EXPRESSION));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_PARSER_EXPECTED_OPERAND));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_PARSER_INVALID_STATEMENT));
    assert!(codes.iter().any(|code| code == DIAG_EXPR_INVALID_OPCODE));
    assert!(codes.iter().any(|code| code == DIAG_EXPR_STACK_UNDERFLOW));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_EXPR_STACK_DEPTH_EXCEEDED));
    assert!(codes.iter().any(|code| code == DIAG_EXPR_UNKNOWN_SYMBOL));
    assert!(codes.iter().any(|code| code == DIAG_EXPR_EVAL_FAILURE));
    assert!(codes
        .iter()
        .any(|code| code == DIAG_EXPR_UNSUPPORTED_FEATURE));
    assert!(codes.iter().any(|code| code == DIAG_EXPR_BUDGET_EXCEEDED));
    assert!(codes.iter().any(|code| code == DIAG_EXPR_INVALID_PROGRAM));
}

#[test]
fn decode_rejects_missing_required_chunk() {
    let bytes = encode_container(&[]).expect("container encode should succeed");
    let err = decode_hierarchy_chunks(&bytes).expect_err("missing FAMS should fail");
    assert!(matches!(err, OpcpuCodecError::MissingRequiredChunk { .. }));
    assert_eq!(err.code(), "OPC006");
}

#[test]
fn decode_rejects_truncated_payload() {
    let mut bytes = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("encode should succeed");
    bytes.pop();
    let err = decode_hierarchy_chunks(&bytes).expect_err("truncated payload should fail");
    assert!(matches!(
        err,
        OpcpuCodecError::ChunkOutOfBounds { .. } | OpcpuCodecError::UnexpectedEof { .. }
    ));
}

#[test]
fn decode_rejects_invalid_endian_marker() {
    let mut bytes = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("encode should succeed");
    bytes[6] = 0x78;
    bytes[7] = 0x56;
    let err = decode_hierarchy_chunks(&bytes).expect_err("invalid marker should fail");
    assert!(matches!(
        err,
        OpcpuCodecError::InvalidEndiannessMarker { .. }
    ));
    assert_eq!(err.code(), "OPC003");
}

#[test]
fn load_rejects_cross_reference_errors() {
    let families = vec![FamilyDescriptor {
        id: "intel8080".to_string(),
        canonical_dialect: "intel".to_string(),
    }];
    let cpus = vec![CpuDescriptor {
        id: "8085".to_string(),
        family_id: "missing".to_string(),
        default_dialect: Some("intel".to_string()),
    }];
    let dials = vec![DialectDescriptor {
        id: "intel".to_string(),
        family_id: "intel8080".to_string(),
        cpu_allow_list: None,
    }];
    let chunks = vec![
        (CHUNK_FAMS, encode_fams_chunk(&families).expect("fams")),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus).expect("cpus")),
        (CHUNK_DIAL, encode_dial_chunk(&dials).expect("dial")),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");

    let err = load_hierarchy_package(&bytes).expect_err("cross-reference should fail");
    assert!(matches!(err, OpcpuCodecError::Hierarchy(_)));
    assert_eq!(err.code(), "OPC011");
}

#[test]
fn decode_legacy_container_defaults_meta_strs_diag() {
    let families = sample_families();
    let cpus = sample_cpus();
    let dials = sample_dialects();
    let chunks = vec![
        (CHUNK_FAMS, encode_fams_chunk(&families).expect("fams")),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus).expect("cpus")),
        (CHUNK_DIAL, encode_dial_chunk(&dials).expect("dial")),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode");
    assert_eq!(decoded.metadata, PackageMetaDescriptor::default());
    assert!(decoded.strings.is_empty());
    assert!(decoded.diagnostics.is_empty());
    assert!(decoded.token_policies.is_empty());
    assert!(decoded.parser_contracts.is_empty());
    assert!(decoded.parser_vm_programs.is_empty());
    assert!(decoded.expr_contracts.is_empty());
    assert!(decoded.expr_parser_contracts.is_empty());
}

#[test]
fn encode_decode_round_trip_preserves_toks_policy() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: sample_token_policies(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: Vec::new(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: Vec::new(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");

    assert_eq!(decoded.token_policies.len(), 2);
    assert!(matches!(
        &decoded.token_policies[0].owner,
        ScopedOwner::Family(owner) if owner == "mos6502"
    ));
    assert_eq!(
        decoded.token_policies[0].case_rule,
        TokenCaseRule::AsciiLower
    );
    assert_eq!(decoded.token_policies[0].punctuation_chars, "()+,-");
    assert_eq!(decoded.token_policies[0].comment_prefix, ";");
    assert_eq!(decoded.token_policies[0].quote_chars, "\"'");
    assert_eq!(decoded.token_policies[0].escape_char, Some('\\'));
    assert_eq!(decoded.token_policies[0].number_prefix_chars, "$%@");
    assert_eq!(
        decoded.token_policies[0].multi_char_operators,
        vec!["!=", "&&", "**", "<<", "<=", "<>", "==", ">=", ">>", "^^", "||"]
    );

    assert!(matches!(
        &decoded.token_policies[1].owner,
        ScopedOwner::Cpu(owner) if owner == "z80"
    ));
    assert_eq!(decoded.token_policies[1].case_rule, TokenCaseRule::Preserve);
    assert_eq!(decoded.token_policies[1].punctuation_chars, "()[]");
}

#[test]
fn encode_decode_round_trip_preserves_parser_contracts() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: sample_parser_contracts(),
        parser_vm_programs: Vec::new(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: Vec::new(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");

    assert_eq!(decoded.parser_contracts.len(), 2);
    assert!(matches!(
        &decoded.parser_contracts[0].owner,
        ScopedOwner::Family(owner) if owner == "mos6502"
    ));
    assert_eq!(
        decoded.parser_contracts[0].grammar_id,
        PARSER_GRAMMAR_ID_LINE_V1
    );
    assert_eq!(
        decoded.parser_contracts[0].ast_schema_id,
        PARSER_AST_SCHEMA_ID_LINE_V1
    );
    assert_eq!(
        decoded.parser_contracts[0].opcode_version,
        PARSER_VM_OPCODE_VERSION_V1
    );
    assert_eq!(decoded.parser_contracts[0].max_ast_nodes_per_line, 256);
    assert_eq!(
        decoded.parser_contracts[0].diagnostics.unexpected_token,
        "otp001"
    );

    assert!(matches!(
        &decoded.parser_contracts[1].owner,
        ScopedOwner::Cpu(owner) if owner == "z80"
    ));
}

#[test]
fn encode_decode_round_trip_preserves_parser_vm_programs() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: sample_parser_vm_programs(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: Vec::new(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");

    assert_eq!(decoded.parser_vm_programs.len(), 2);
    assert!(matches!(
        &decoded.parser_vm_programs[0].owner,
        ScopedOwner::Family(owner) if owner == "mos6502"
    ));
    assert_eq!(
        decoded.parser_vm_programs[0].opcode_version,
        PARSER_VM_OPCODE_VERSION_V1
    );
    assert_eq!(
        decoded.parser_vm_programs[0].program,
        vec![
            ParserVmOpcode::ParseDotDirectiveEnvelope as u8,
            ParserVmOpcode::ParseStarOrgEnvelope as u8,
            ParserVmOpcode::ParseAssignmentEnvelope as u8,
            ParserVmOpcode::ParseInstructionEnvelope as u8,
            ParserVmOpcode::EmitDiagIfNoAst as u8,
            0,
            ParserVmOpcode::End as u8
        ]
    );
    assert!(matches!(
        &decoded.parser_vm_programs[1].owner,
        ScopedOwner::Cpu(owner) if owner == "z80"
    ));
}

#[test]
fn encode_decode_round_trip_preserves_expr_contracts() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: Vec::new(),
        expr_contracts: sample_expr_contracts(),
        expr_parser_contracts: Vec::new(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");

    assert_eq!(decoded.expr_contracts.len(), 2);
    assert!(matches!(
        &decoded.expr_contracts[0].owner,
        ScopedOwner::Family(owner) if owner == "mos6502"
    ));
    assert_eq!(
        decoded.expr_contracts[0].opcode_version,
        EXPR_VM_OPCODE_VERSION_V1
    );
    assert_eq!(decoded.expr_contracts[0].max_program_bytes, 2048);
    assert_eq!(
        decoded.expr_contracts[0].diagnostics.invalid_opcode,
        "ope001"
    );
    assert!(matches!(
        &decoded.expr_contracts[1].owner,
        ScopedOwner::Cpu(owner) if owner == "z80"
    ));
}

#[test]
fn encode_decode_round_trip_preserves_expr_parser_contracts() {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: Vec::new(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: sample_expr_parser_contracts(),
        families: sample_families(),
        cpus: sample_cpus(),
        dialects: sample_dialects(),
        registers: sample_registers(),
        forms: sample_forms(),
        tables: sample_tables(),
        selectors: Vec::new(),
    };
    let bytes = encode_hierarchy_chunks_from_chunks(&chunks).expect("encode should succeed");
    let decoded = decode_hierarchy_chunks(&bytes).expect("decode should succeed");

    assert_eq!(decoded.expr_parser_contracts.len(), 2);
    assert!(matches!(
        &decoded.expr_parser_contracts[0].owner,
        ScopedOwner::Family(owner) if owner == "mos6502"
    ));
    assert_eq!(
        decoded.expr_parser_contracts[0].opcode_version,
        EXPR_PARSER_VM_OPCODE_VERSION_V1
    );
    assert_eq!(
        decoded.expr_parser_contracts[0]
            .diagnostics
            .invalid_expression_program,
        "otp004"
    );
    assert!(matches!(
        &decoded.expr_parser_contracts[1].owner,
        ScopedOwner::Cpu(owner) if owner == "z80"
    ));
}

#[test]
fn decode_rejects_invalid_toks_case_rule() {
    let families = sample_families();
    let cpus = sample_cpus();
    let dials = sample_dialects();
    let mut toks = Vec::new();
    write_u32(&mut toks, 1);
    toks.push(0);
    write_string(&mut toks, "TOKS", "mos6502").expect("owner");
    toks.push(9);
    write_u32(
        &mut toks,
        token_identifier_class::ASCII_ALPHA | token_identifier_class::UNDERSCORE,
    );
    write_u32(
        &mut toks,
        token_identifier_class::ASCII_ALPHA
            | token_identifier_class::ASCII_DIGIT
            | token_identifier_class::UNDERSCORE,
    );
    write_string(&mut toks, "TOKS", ",").expect("punctuation");
    let chunks = vec![
        (CHUNK_TOKS, toks),
        (CHUNK_FAMS, encode_fams_chunk(&families).expect("fams")),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus).expect("cpus")),
        (CHUNK_DIAL, encode_dial_chunk(&dials).expect("dial")),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");
    let err = decode_hierarchy_chunks(&bytes).expect_err("invalid case rule should fail");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert_eq!(err.code(), "OPC009");
}

#[test]
fn decode_rejects_bounded_count_overflow_before_allocation() {
    let mut fams = Vec::new();
    write_u32(&mut fams, u32::MAX);

    let err = decode_fams_chunk(&fams).expect_err("oversized count should be rejected");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert!(
        err.to_string().contains("family entry count") || err.to_string().contains("family entry")
    );
}

#[test]
fn decode_rejects_hard_limited_count_before_allocation() {
    let count = MAX_DECODE_ENTRY_COUNT + 1;
    let mut fams = Vec::new();
    write_u32(&mut fams, count as u32);
    fams.resize(4 + (count * 8), 0);

    let err = decode_fams_chunk(&fams).expect_err("hard-limited count should be rejected");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert!(err.to_string().contains("hard limit"));
}

#[test]
fn decode_rejects_invalid_msel_unstable_widen_flag() {
    let mut msel = Vec::new();
    write_u32(&mut msel, 1);
    msel.push(0);
    write_string(&mut msel, "MSEL", "mos6502").expect("owner");
    write_string(&mut msel, "MSEL", "lda").expect("mnemonic");
    write_string(&mut msel, "MSEL", "shape").expect("shape");
    write_string(&mut msel, "MSEL", "mode").expect("mode");
    write_string(&mut msel, "MSEL", "plan").expect("plan");
    msel.extend_from_slice(&0u16.to_le_bytes());
    msel.push(2);
    msel.push(0);

    let chunks = vec![
        (CHUNK_MSEL, msel),
        (
            CHUNK_FAMS,
            encode_fams_chunk(&sample_families()).expect("fams"),
        ),
        (CHUNK_CPUS, encode_cpus_chunk(&sample_cpus()).expect("cpus")),
        (
            CHUNK_DIAL,
            encode_dial_chunk(&sample_dialects()).expect("dial"),
        ),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");

    let err = decode_hierarchy_chunks(&bytes).expect_err("invalid unstable_widen should fail");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert!(err.to_string().contains("unstable_widen"));
}

#[test]
fn decode_rejects_truncated_msel_payload() {
    let mut msel = Vec::new();
    write_u32(&mut msel, 1);
    msel.push(0);
    write_string(&mut msel, "MSEL", "mos6502").expect("owner");

    let chunks = vec![
        (CHUNK_MSEL, msel),
        (
            CHUNK_FAMS,
            encode_fams_chunk(&sample_families()).expect("fams"),
        ),
        (CHUNK_CPUS, encode_cpus_chunk(&sample_cpus()).expect("cpus")),
        (
            CHUNK_DIAL,
            encode_dial_chunk(&sample_dialects()).expect("dial"),
        ),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");

    let err = decode_hierarchy_chunks(&bytes).expect_err("truncated MSEL should fail");
    assert!(matches!(
        err,
        OpcpuCodecError::InvalidChunkFormat { .. } | OpcpuCodecError::UnexpectedEof { .. }
    ));
    assert!(err.to_string().contains("MSEL"));
}

#[test]
fn decode_rejects_invalid_msel_owner_tag() {
    let mut msel = Vec::new();
    write_u32(&mut msel, 1);
    msel.push(9);
    write_string(&mut msel, "MSEL", "mos6502").expect("owner");
    write_string(&mut msel, "MSEL", "lda").expect("mnemonic");
    write_string(&mut msel, "MSEL", "shape").expect("shape");
    write_string(&mut msel, "MSEL", "mode").expect("mode");
    write_string(&mut msel, "MSEL", "plan").expect("plan");
    msel.extend_from_slice(&0u16.to_le_bytes());
    msel.push(0);
    msel.push(0);

    let chunks = vec![
        (CHUNK_MSEL, msel),
        (
            CHUNK_FAMS,
            encode_fams_chunk(&sample_families()).expect("fams"),
        ),
        (CHUNK_CPUS, encode_cpus_chunk(&sample_cpus()).expect("cpus")),
        (
            CHUNK_DIAL,
            encode_dial_chunk(&sample_dialects()).expect("dial"),
        ),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");

    let err = decode_hierarchy_chunks(&bytes).expect_err("invalid MSEL owner tag should fail");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert!(err.to_string().contains("owner tag"));
}

#[test]
fn decode_legacy_toks_entries_default_extended_fields() {
    let families = sample_families();
    let cpus = sample_cpus();
    let dials = sample_dialects();
    let mut toks = Vec::new();
    write_u32(&mut toks, 1);
    toks.push(0);
    write_string(&mut toks, "TOKS", "mos6502").expect("owner");
    toks.push(TokenCaseRule::AsciiLower as u8);
    write_u32(
        &mut toks,
        token_identifier_class::ASCII_ALPHA | token_identifier_class::UNDERSCORE,
    );
    write_u32(
        &mut toks,
        token_identifier_class::ASCII_ALPHA
            | token_identifier_class::ASCII_DIGIT
            | token_identifier_class::UNDERSCORE,
    );
    write_string(&mut toks, "TOKS", ",()").expect("punctuation");
    let chunks = vec![
        (CHUNK_TOKS, toks),
        (CHUNK_FAMS, encode_fams_chunk(&families).expect("fams")),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus).expect("cpus")),
        (CHUNK_DIAL, encode_dial_chunk(&dials).expect("dial")),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ];
    let bytes = encode_container(&chunks).expect("container");
    let decoded = decode_hierarchy_chunks(&bytes).expect("legacy TOKS decode should succeed");
    assert_eq!(decoded.token_policies.len(), 1);
    let policy = &decoded.token_policies[0];
    assert_eq!(policy.comment_prefix, ";");
    assert_eq!(policy.quote_chars, "\"'");
    assert_eq!(policy.escape_char, Some('\\'));
    assert_eq!(policy.number_prefix_chars, "$%@");
    assert_eq!(
        policy.multi_char_operators,
        vec!["**", "==", "!=", "&&", "||", "^^", "<<", ">>", "<=", ">=", "<>"]
    );
}

fn expr_chunk_with_single_contract(contract: &ExprContractDescriptor) -> Vec<u8> {
    encode_expr_chunk(std::slice::from_ref(contract)).expect("EXPR chunk encode")
}

fn base_required_chunks_with_expr(expr_chunk: Vec<u8>) -> Vec<([u8; 4], Vec<u8>)> {
    vec![
        (CHUNK_EXPR, expr_chunk),
        (
            CHUNK_FAMS,
            encode_fams_chunk(&sample_families()).expect("fams"),
        ),
        (CHUNK_CPUS, encode_cpus_chunk(&sample_cpus()).expect("cpus")),
        (
            CHUNK_DIAL,
            encode_dial_chunk(&sample_dialects()).expect("dial"),
        ),
        (CHUNK_REGS, encode_regs_chunk(&[]).expect("regs")),
        (CHUNK_FORM, encode_form_chunk(&[]).expect("form")),
        (CHUNK_TABL, encode_tabl_chunk(&[]).expect("tabl")),
    ]
}

#[test]
fn decode_rejects_expr_contract_with_unsupported_opcode_version() {
    let mut contract = expr_contract_for_test(ScopedOwner::Family("mos6502".to_string()));
    contract.opcode_version = EXPR_VM_OPCODE_VERSION_V1 + 1;

    let bytes = encode_container(&base_required_chunks_with_expr(
        expr_chunk_with_single_contract(&contract),
    ))
    .expect("container");

    let err = decode_hierarchy_chunks(&bytes)
        .expect_err("unsupported EXPR opcode version should fail decode");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert_eq!(err.code(), "OPC009");
    assert!(err.to_string().contains("unsupported opcode_version"));
}

#[test]
fn decode_rejects_expr_contract_with_zero_budget() {
    let mut contract = expr_contract_for_test(ScopedOwner::Family("mos6502".to_string()));
    contract.max_eval_steps = 0;

    let bytes = encode_container(&base_required_chunks_with_expr(
        expr_chunk_with_single_contract(&contract),
    ))
    .expect("container");

    let err = decode_hierarchy_chunks(&bytes).expect_err("zero EXPR budget should fail decode");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert_eq!(err.code(), "OPC009");
    assert!(err.to_string().contains("max_eval_steps must be > 0"));
}

#[test]
fn decode_rejects_expr_contract_with_missing_diag_mapping() {
    let mut contract = expr_contract_for_test(ScopedOwner::Family("mos6502".to_string()));
    contract.diagnostics.invalid_program.clear();

    let bytes = encode_container(&base_required_chunks_with_expr(
        expr_chunk_with_single_contract(&contract),
    ))
    .expect("container");

    let err = decode_hierarchy_chunks(&bytes)
        .expect_err("missing EXPR diagnostic mapping should fail decode");
    assert!(matches!(err, OpcpuCodecError::InvalidChunkFormat { .. }));
    assert_eq!(err.code(), "OPC009");
    assert!(err
        .to_string()
        .contains("missing diagnostics.invalid_program code"));
}

#[test]
fn expr_parser_vm_opcode_from_u8_round_trip_and_unknown_rejection() {
    assert_eq!(
        ExprParserVmOpcode::from_u8(ExprParserVmOpcode::End as u8),
        Some(ExprParserVmOpcode::End)
    );
    assert_eq!(
        ExprParserVmOpcode::from_u8(ExprParserVmOpcode::ParseExpression as u8),
        Some(ExprParserVmOpcode::ParseExpression)
    );
    assert_eq!(
        ExprParserVmOpcode::from_u8(ExprParserVmOpcode::EmitDiag as u8),
        Some(ExprParserVmOpcode::EmitDiag)
    );
    assert_eq!(
        ExprParserVmOpcode::from_u8(ExprParserVmOpcode::Fail as u8),
        Some(ExprParserVmOpcode::Fail)
    );
    assert_eq!(
        ExprParserVmOpcode::from_u8(ExprParserVmOpcode::DelegateCore as u8),
        Some(ExprParserVmOpcode::DelegateCore)
    );
    assert_eq!(ExprParserVmOpcode::from_u8(0xFF), None);
}

#[test]
fn decode_malformed_count_stress_never_panics_and_returns_errors() {
    let cpus = encode_cpus_chunk(&sample_cpus()).expect("cpus");
    let dials = encode_dial_chunk(&sample_dialects()).expect("dial");
    let regs = encode_regs_chunk(&[]).expect("regs");
    let forms = encode_form_chunk(&[]).expect("form");
    let tabl = encode_tabl_chunk(&[]).expect("tabl");

    let mut seed = 0xC0FF_EE01u32;
    for _ in 0..128 {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        let mut fams = Vec::new();
        write_u32(&mut fams, seed);

        let chunks = vec![
            (CHUNK_FAMS, fams),
            (CHUNK_CPUS, cpus.clone()),
            (CHUNK_DIAL, dials.clone()),
            (CHUNK_REGS, regs.clone()),
            (CHUNK_FORM, forms.clone()),
            (CHUNK_TABL, tabl.clone()),
        ];
        let bytes = encode_container(&chunks).expect("container");

        let result = decode_hierarchy_chunks(&bytes);
        assert!(result.is_err(), "seeded malformed count should fail decode");
        if let Err(error) = result {
            assert!(
                matches!(
                    error,
                    OpcpuCodecError::InvalidChunkFormat { .. }
                        | OpcpuCodecError::UnexpectedEof { .. }
                        | OpcpuCodecError::CountOutOfRange { .. }
                ),
                "unexpected decoder error variant: {error:?}"
            );
        }
    }
}

#[test]
fn decode_mutated_container_deterministic_fuzz_never_panics() {
    let baseline = encode_hierarchy_chunks(
        &sample_families(),
        &sample_cpus(),
        &sample_dialects(),
        &sample_registers(),
        &sample_forms(),
        &sample_tables(),
    )
    .expect("baseline encode should succeed");

    let mut seed = 0xD1CE_BA11u32;
    for _ in 0..256 {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        let mut mutated = baseline.clone();
        let index = (seed as usize) % mutated.len();

        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        let mask = ((seed as u8) | 1).wrapping_add(0x3d);
        mutated[index] ^= mask;

        if mutated.len() > 12 && (seed & 1) == 0 {
            let trim = (seed as usize % 8) + 1;
            mutated.truncate(mutated.len().saturating_sub(trim));
        }

        let first = decode_hierarchy_chunks(&mutated);
        let second = decode_hierarchy_chunks(&mutated);

        match (first, second) {
            (Ok(left), Ok(right)) => {
                assert_eq!(left.families.len(), right.families.len());
                assert_eq!(left.cpus.len(), right.cpus.len());
                assert_eq!(left.dialects.len(), right.dialects.len());
                assert_eq!(left.forms.len(), right.forms.len());
                assert_eq!(left.tables.len(), right.tables.len());
            }
            (Err(left), Err(right)) => {
                assert_eq!(left.code(), right.code());
            }
            (left, right) => {
                panic!("decode outcome changed for same bytes: first={left:?}, second={right:?}")
            }
        }
    }
}
