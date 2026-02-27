use super::*;
use crate::core::family::AssemblerContext;
use crate::core::parser::{
    AssignOp, Expr, Label, LineAst, SignatureAtom, StatementSignature, UseItem, UseParam,
};
use crate::core::registry::{ModuleRegistry, VmEncodeCandidate};
use crate::core::tokenizer::{ConditionalKind, Span, Token, TokenKind, Tokenizer};
use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::m6800::module::Motorola6800FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule, MOS6502Operands};
use crate::families::mos6502::Operand;
use crate::hd6309::module::HD6309CpuModule;
use crate::i8085::module::I8085CpuModule;
use crate::m45gs02::module::M45GS02CpuModule;
use crate::m65816::module::M65816CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::m6809::module::M6809CpuModule;
use crate::vm::builder::{
    build_hierarchy_chunks_from_registry, build_hierarchy_package_from_registry,
};
use crate::vm::hierarchy::{
    CpuDescriptor, DialectDescriptor, FamilyDescriptor, ResolvedHierarchy, ScopedOwner,
};
use crate::vm::package::{
    default_token_policy_lexical_defaults, token_identifier_class, DiagnosticDescriptor,
    ExprContractDescriptor, ExprDiagnosticMap, ExprParserContractDescriptor,
    ExprParserDiagnosticMap, HierarchyChunks, ParserContractDescriptor, ParserDiagnosticMap,
    ParserVmOpcode, ParserVmProgramDescriptor, TokenCaseRule, TokenPolicyDescriptor,
    TokenizerVmOpcode, TokenizerVmProgramDescriptor, VmProgramDescriptor,
    DIAG_EXPR_BUDGET_EXCEEDED, DIAG_EXPR_EVAL_FAILURE, DIAG_EXPR_INVALID_OPCODE,
    DIAG_EXPR_INVALID_PROGRAM, DIAG_EXPR_STACK_DEPTH_EXCEEDED, DIAG_EXPR_STACK_UNDERFLOW,
    DIAG_EXPR_UNKNOWN_SYMBOL, DIAG_EXPR_UNSUPPORTED_FEATURE, DIAG_OPTHREAD_MISSING_VM_PROGRAM,
    EXPR_PARSER_VM_OPCODE_VERSION_V1, EXPR_VM_OPCODE_VERSION_V1, PARSER_VM_OPCODE_VERSION_V1,
    TOKENIZER_VM_OPCODE_VERSION_V1,
};
use crate::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
use crate::z80::module::Z80CpuModule;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn tokenize_host_line(line: &str, line_num: u32) -> Result<Vec<PortableToken>, String> {
    let mut tokenizer = Tokenizer::new(line, line_num);
    let mut tokens = Vec::new();
    loop {
        let token = tokenizer.next_token().map_err(|err| err.message)?;
        if matches!(token.kind, TokenKind::End) {
            break;
        }
        if let Some(portable) = PortableToken::from_core_token(token) {
            tokens.push(portable);
        }
    }
    Ok(tokens)
}

fn tokenize_core_expr_tokens(expr: &str, line_num: u32) -> (Vec<Token>, Span) {
    let mut tokenizer = Tokenizer::new(expr, line_num);
    let mut tokens = Vec::new();
    let end_span = loop {
        let token = tokenizer.next_token().expect("expression tokenization");
        if matches!(token.kind, TokenKind::End) {
            break token.span;
        }
        tokens.push(token);
    };
    (tokens, end_span)
}

fn tokenize_host_line_with_policy(
    model: &HierarchyExecutionModel,
    cpu_id: &str,
    dialect_override: Option<&str>,
    line: &str,
    line_num: u32,
) -> Result<Vec<PortableToken>, String> {
    let policy = model
        .resolve_token_policy(cpu_id, dialect_override)
        .map_err(|err| err.to_string())?;
    Ok(tokenize_host_line(line, line_num)?
        .into_iter()
        .map(|token| apply_token_policy_to_token(token, &policy))
        .collect())
}

fn parity_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(Motorola6800FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    registry.register_cpu(Box::new(M45GS02CpuModule));
    registry.register_cpu(Box::new(M6809CpuModule));
    registry.register_cpu(Box::new(HD6309CpuModule));
    registry
}

fn mos6502_family_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    registry.register_cpu(Box::new(M45GS02CpuModule));
    registry
}

fn tokenize_with_mode(
    model: &mut HierarchyExecutionModel,
    mode: RuntimeTokenizerMode,
    cpu_id: &str,
    line: &str,
    line_num: u32,
) -> Result<Vec<PortableToken>, String> {
    model.set_tokenizer_mode(mode);
    model
        .tokenize_portable_statement(cpu_id, None, line, line_num)
        .map_err(|err| err.to_string())
}

fn tokenize_with_vm_program(
    model: &HierarchyExecutionModel,
    cpu_id: &str,
    line: &str,
    line_num: u32,
    vm_program: &RuntimeTokenizerVmProgram,
) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
    let resolved = model.resolve_pipeline(cpu_id, None)?;
    let request = PortableTokenizeRequest {
        family_id: resolved.family_id.as_str(),
        cpu_id: resolved.cpu_id.as_str(),
        dialect_id: resolved.dialect_id.as_str(),
        source_line: line,
        line_num,
        token_policy: model.token_policy_for_resolved(&resolved),
    };
    model.tokenize_with_vm_core(&request, vm_program)
}

fn tokenizer_edge_case_lines() -> Vec<String> {
    vec![
        "LDA #$42".to_string(),
        "label: .byte \"A\\n\"".to_string(),
        "A && B || C".to_string(),
        "BBR0 $12,$0005".to_string(),
        ".if 1".to_string(),
        "%1010 + $1f".to_string(),
        "DB \"unterminated".to_string(),
        "DB \"bad\\xZZ\"".to_string(),
        "MOV A,B ; trailing comment".to_string(),
        "  ".to_string(),
    ]
}

fn tokenizer_example_lines() -> Vec<String> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let examples_dir = repo_root.join("examples");
    let mut asm_files: Vec<PathBuf> = fs::read_dir(&examples_dir)
        .expect("read examples directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("asm"))
        .collect();
    asm_files.sort();

    let mut lines = Vec::new();
    for path in asm_files {
        let source = fs::read_to_string(&path).expect("read example source");
        lines.extend(source.lines().map(|line| line.to_string()));
    }
    lines
}

fn deterministic_fuzz_lines(seed: u64, count: usize, max_len: usize) -> Vec<String> {
    const ALPHABET: &str =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_,$#:+-*/()[]{}'\";<>|&^%!~.\\ \t";
    let alphabet = ALPHABET.as_bytes();
    let mut state = seed;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = ((state >> 24) as usize) % (max_len.saturating_add(1));
        let mut line = String::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = (state as usize) % alphabet.len();
            line.push(alphabet[idx] as char);
        }
        out.push(line);
    }
    out
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

fn tokenizer_vm_program_for_test(owner: ScopedOwner) -> TokenizerVmProgramDescriptor {
    TokenizerVmProgramDescriptor {
        owner,
        opcode_version: TOKENIZER_VM_OPCODE_VERSION_V1,
        start_state: 0,
        state_entry_offsets: vec![0],
        limits: TokenizerVmLimits {
            max_steps_per_line: 1024,
            max_tokens_per_line: 64,
            max_lexeme_bytes: 48,
            max_errors_per_line: 4,
        },
        diagnostics: TokenizerVmDiagnosticMap {
            invalid_char: "ott001".to_string(),
            unterminated_string: "ott002".to_string(),
            step_limit_exceeded: "ott003".to_string(),
            token_limit_exceeded: "ott004".to_string(),
            lexeme_limit_exceeded: "ott005".to_string(),
            error_limit_exceeded: "ott006".to_string(),
        },
        program: vec![TokenizerVmOpcode::End as u8],
    }
}

fn parser_contract_for_test(owner: ScopedOwner) -> ParserContractDescriptor {
    ParserContractDescriptor {
        owner,
        grammar_id: "opforge.line.v1".to_string(),
        ast_schema_id: "opforge.ast.line.v1".to_string(),
        opcode_version: 1,
        max_ast_nodes_per_line: 512,
        diagnostics: ParserDiagnosticMap {
            unexpected_token: "otp001".to_string(),
            expected_expression: "otp002".to_string(),
            expected_operand: "otp003".to_string(),
            invalid_statement: "otp004".to_string(),
        },
    }
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

fn expr_parser_contract_for_test(owner: ScopedOwner) -> ExprParserContractDescriptor {
    ExprParserContractDescriptor {
        owner,
        opcode_version: EXPR_PARSER_VM_OPCODE_VERSION_V1,
        diagnostics: ExprParserDiagnosticMap {
            invalid_expression_program: "otp004".to_string(),
        },
    }
}

fn runtime_vm_program_for_test(
    program: Vec<u8>,
    limits: TokenizerVmLimits,
) -> RuntimeTokenizerVmProgram {
    RuntimeTokenizerVmProgram {
        opcode_version: TOKENIZER_VM_OPCODE_VERSION_V1,
        start_state: 0,
        state_entry_offsets: vec![0],
        limits,
        diagnostics: tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()))
            .diagnostics,
        program,
    }
}

struct TestAssemblerContext {
    values: HashMap<String, i64>,
    finalized: HashMap<String, bool>,
    cpu_flags: HashMap<String, u32>,
    addr: u32,
    pass: u8,
    fail_eval_expr: bool,
}

impl TestAssemblerContext {
    fn new() -> Self {
        Self {
            values: HashMap::new(),
            finalized: HashMap::new(),
            cpu_flags: HashMap::new(),
            addr: 0,
            pass: 2,
            fail_eval_expr: false,
        }
    }
}

impl AssemblerContext for TestAssemblerContext {
    fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
        if self.fail_eval_expr {
            return Err("forced test eval failure".to_string());
        }
        match expr {
            Expr::Number(text, _) => text
                .parse::<i64>()
                .map_err(|_| format!("invalid test number '{}'", text)),
            Expr::Identifier(name, _) | Expr::Register(name, _) => {
                self.values.get(name).copied().map(Ok).unwrap_or_else(|| {
                    if self.pass == 1 {
                        Ok(0)
                    } else {
                        Err(format!("Label not found: {}", name))
                    }
                })
            }
            Expr::Immediate(inner, _) => self.eval_expr(inner),
            _ => Err("unsupported test expression".to_string()),
        }
    }

    fn symbols(&self) -> &crate::core::symbol_table::SymbolTable {
        panic!("symbols() is not used in runtime resolver tests")
    }

    fn has_symbol(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    fn symbol_is_finalized(&self, name: &str) -> Option<bool> {
        self.finalized.get(name).copied()
    }

    fn current_address(&self) -> u32 {
        self.addr
    }

    fn pass(&self) -> u8 {
        self.pass
    }

    fn cpu_state_flag(&self, key: &str) -> Option<u32> {
        self.cpu_flags.get(key).copied()
    }
}

fn sample_package() -> HierarchyPackage {
    HierarchyPackage::new(
        vec![
            FamilyDescriptor {
                id: "intel8080".to_string(),
                canonical_dialect: "intel".to_string(),
            },
            FamilyDescriptor {
                id: "mos6502".to_string(),
                canonical_dialect: "mos".to_string(),
            },
        ],
        vec![
            CpuDescriptor {
                id: "8085".to_string(),
                family_id: "intel8080".to_string(),
                default_dialect: Some("intel".to_string()),
            },
            CpuDescriptor {
                id: "z80".to_string(),
                family_id: "intel8080".to_string(),
                default_dialect: Some("zilog".to_string()),
            },
            CpuDescriptor {
                id: "6502".to_string(),
                family_id: "mos6502".to_string(),
                default_dialect: Some("mos".to_string()),
            },
        ],
        vec![
            DialectDescriptor {
                id: "intel".to_string(),
                family_id: "intel8080".to_string(),
                cpu_allow_list: None,
            },
            DialectDescriptor {
                id: "zilog".to_string(),
                family_id: "intel8080".to_string(),
                cpu_allow_list: Some(vec!["z80".to_string()]),
            },
            DialectDescriptor {
                id: "mos".to_string(),
                family_id: "mos6502".to_string(),
                cpu_allow_list: None,
            },
        ],
    )
    .expect("sample package should validate")
}

fn intel_only_chunks() -> HierarchyChunks {
    HierarchyChunks {
        metadata: crate::vm::package::PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: Vec::new(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: Vec::new(),
        families: vec![FamilyDescriptor {
            id: "intel8080".to_string(),
            canonical_dialect: "intel".to_string(),
        }],
        cpus: vec![CpuDescriptor {
            id: "8085".to_string(),
            family_id: "intel8080".to_string(),
            default_dialect: Some("intel".to_string()),
        }],
        dialects: vec![DialectDescriptor {
            id: "intel".to_string(),
            family_id: "intel8080".to_string(),
            cpu_allow_list: None,
        }],
        registers: Vec::new(),
        forms: Vec::new(),
        tables: vec![VmProgramDescriptor {
            owner: ScopedOwner::Family("intel8080".to_string()),
            mnemonic: "MVI".to_string(),
            mode_key: "immediate".to_string(),
            program: vec![OP_EMIT_U8, 0x3E, OP_EMIT_OPERAND, 0x00, OP_END],
        }],
        selectors: Vec::new(),
    }
}

fn intel_test_expr_resolver(
    _model: &HierarchyExecutionModel,
    _resolved: &ResolvedHierarchy,
    mnemonic: &str,
    operands: &[Expr],
    ctx: &dyn AssemblerContext,
) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
    if !mnemonic.eq_ignore_ascii_case("mvi") || operands.len() != 1 {
        return Ok(None);
    }
    let value = ctx
        .eval_expr(&operands[0])
        .map_err(RuntimeBridgeError::Resolve)?;
    if !(0..=255).contains(&value) {
        return Err(RuntimeBridgeError::Resolve(format!(
            "Immediate value {} out of range (0-255)",
            value
        )));
    }
    Ok(Some(vec![VmEncodeCandidate {
        mode_key: "immediate".to_string(),
        operand_bytes: vec![vec![value as u8]],
    }]))
}

#[derive(Debug)]
struct IntelDynResolver;

impl FamilyExprResolver for IntelDynResolver {
    fn family_id(&self) -> &str {
        "intel8080"
    }

    fn resolve_candidates(
        &self,
        _model: &HierarchyExecutionModel,
        _resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        if !mnemonic.eq_ignore_ascii_case("mvi") || operands.len() != 1 {
            return Ok(None);
        }
        let value = ctx
            .eval_expr(&operands[0])
            .map_err(RuntimeBridgeError::Resolve)?;
        if !(0..=255).contains(&value) {
            return Err(RuntimeBridgeError::Resolve(format!(
                "Immediate value {} out of range (0-255)",
                value
            )));
        }
        Ok(Some(vec![VmEncodeCandidate {
            mode_key: "immediate".to_string(),
            operand_bytes: vec![vec![value as u8]],
        }]))
    }
}

#[test]
fn active_cpu_selection_and_resolution_work() {
    let mut bridge = HierarchyRuntimeBridge::new(sample_package());

    assert!(matches!(
        bridge.resolve_active_pipeline(),
        Err(RuntimeBridgeError::ActiveCpuNotSet)
    ));

    bridge.set_active_cpu("z80").expect("set active cpu");
    let resolved = bridge
        .resolve_active_pipeline()
        .expect("active cpu should resolve");
    assert_eq!(resolved.family_id, "intel8080");
    assert_eq!(resolved.dialect_id, "zilog");
}

#[test]
fn explicit_resolve_pipeline_supports_override() {
    let bridge = HierarchyRuntimeBridge::new(sample_package());

    let resolved = bridge
        .resolve_pipeline("8085", Some("intel"))
        .expect("explicit resolve should succeed");
    assert_eq!(resolved.cpu_id, "8085");
    assert_eq!(resolved.dialect_id, "intel");
}

#[test]
fn override_validation_uses_active_cpu_context() {
    let mut bridge = HierarchyRuntimeBridge::new(sample_package());
    bridge.set_active_cpu("8085").expect("set active cpu");

    let err = bridge
        .set_dialect_override(Some("zilog"))
        .expect_err("zilog should be blocked for 8085");
    assert!(matches!(
        err,
        RuntimeBridgeError::Hierarchy(HierarchyError::CpuBlockedByDialectAllowList { .. })
    ));

    bridge
        .set_dialect_override(Some("intel"))
        .expect("intel override should pass");
    assert_eq!(bridge.dialect_override(), Some("intel"));
}

#[test]
fn execution_model_supports_family_and_cpu_forms() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    assert!(model
        .supports_mnemonic("m6502", None, "lda")
        .expect("resolve lda"));
    assert!(!model
        .supports_mnemonic("m6502", None, "bra")
        .expect("resolve bra"));
    assert!(model
        .supports_mnemonic("65c02", None, "bra")
        .expect("resolve bra for 65c02"));
}

#[test]
fn execution_model_defaults_to_host_budget_profile() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    assert_eq!(
        model.runtime_budget_profile(),
        RuntimeBudgetProfile::HostDefault
    );
    assert_eq!(
        model.runtime_budget_limits(),
        RuntimeBudgetProfile::HostDefault.limits()
    );
}

#[test]
fn execution_model_budget_profile_can_switch_to_retro_constrained() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    model.set_runtime_budget_profile(RuntimeBudgetProfile::RetroConstrained);
    assert_eq!(
        model.runtime_budget_profile(),
        RuntimeBudgetProfile::RetroConstrained
    );
    assert_eq!(
        model.runtime_budget_limits(),
        RuntimeBudgetProfile::RetroConstrained.limits()
    );
}

#[test]
fn execution_model_defaults_to_auto_tokenizer_rollout_mode() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    assert_eq!(model.tokenizer_mode(), RuntimeTokenizerMode::Auto);
}

#[test]
fn execution_model_budget_rejects_candidate_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_candidate_count = 1;
    model.set_runtime_budget_limits_for_tests(limits);

    let operands = MOS6502Operands(vec![Operand::ZeroPage(0x10, Span::default())]);
    let err = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect_err("candidate budget should reject promoted alternatives");
    assert!(err.to_string().contains("candidate_count"));
}

#[test]
fn execution_model_budget_rejects_operand_byte_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_operand_bytes_per_operand = 0;
    model.set_runtime_budget_limits_for_tests(limits);

    let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
    let err = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect_err("operand byte budget should reject immediate bytes");
    assert!(err.to_string().contains("operand_bytes_per_operand"));
}

#[test]
fn execution_model_budget_rejects_vm_program_byte_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_vm_program_bytes = 1;
    model.set_runtime_budget_limits_for_tests(limits);

    let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
    let err = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect_err("vm program size budget should reject oversized program");
    assert!(err.to_string().contains("vm_program_bytes"));
}

#[test]
fn execution_model_budget_rejects_selector_scan_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_selectors_scanned_per_instruction = 0;
    model.set_runtime_budget_limits_for_tests(limits);

    let span = Span::default();
    let operands = vec![Expr::Immediate(
        Box::new(Expr::Number("66".to_string(), span)),
        span,
    )];
    let ctx = TestAssemblerContext::new();
    let err = model
        .encode_instruction_from_exprs("m6502", None, "LDA", &operands, &ctx)
        .expect_err("selector scan budget should reject evaluation");
    assert!(err.to_string().contains("selector_scan_count"));
}

#[test]
fn execution_model_budget_rejects_parser_token_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_parser_tokens_per_line = 1;
    model.set_runtime_budget_limits_for_tests(limits);

    let (tokens, end_span) = tokenize_core_expr_tokens("1+2", 1);
    let err = model
        .parse_expression_for_assembler("m6502", None, tokens, end_span, None)
        .expect_err("parser token budget should reject oversized expression token stream");
    assert!(err.message.contains("parser token budget exceeded"));
}

#[test]
fn execution_model_budget_rejects_parser_ast_node_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_parser_ast_nodes_per_line = 1;
    model.set_runtime_budget_limits_for_tests(limits);

    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 2)
        .expect_err("runtime parser AST budget should cap estimated nodes");
    assert!(err.to_string().contains("parser AST node budget exceeded"));
}

#[test]
fn execution_model_budget_rejects_parser_vm_program_byte_overflow() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_parser_vm_program_bytes = 1;
    model.set_runtime_budget_limits_for_tests(limits);

    let contract = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect("parser contract should validate");
    let program = model
        .resolve_parser_vm_program("m6502", None)
        .expect("parser VM program resolution should succeed")
        .expect("parser VM program should exist");
    let err = model
        .enforce_parser_vm_program_budget_for_assembler(&contract, &program)
        .expect_err("runtime parser VM program budget should reject oversized program");
    assert!(err
        .to_string()
        .contains("parser VM program byte budget exceeded"));
}

#[test]
fn execution_model_parser_token_budget_overflow_is_deterministic() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_parser_tokens_per_line = 1;
    model.set_runtime_budget_limits_for_tests(limits);

    let (tokens_a, end_span_a) = tokenize_core_expr_tokens("1+2", 1);
    let first = model
        .parse_expression_for_assembler("m6502", None, tokens_a, end_span_a, None)
        .expect_err("parser token budget should reject oversized expression token stream");
    let (tokens_b, end_span_b) = tokenize_core_expr_tokens("1+2", 1);
    let second = model
        .parse_expression_for_assembler("m6502", None, tokens_b, end_span_b, None)
        .expect_err("parser token budget should reject oversized expression token stream");

    assert_eq!(first.message, second.message);
    assert_eq!(first.span, second.span);
}

#[test]
fn execution_model_encodes_base_6502_instruction_via_vm() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
    let bytes = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect("vm encode should succeed");
    assert_eq!(bytes, Some(vec![0xA9, 0x42]));
}

#[test]
fn execution_model_encodes_portable_request_via_vm() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let request = PortableInstructionRequest {
        cpu_id: "m6502".to_string(),
        dialect_override: None,
        mnemonic: "LDA".to_string(),
        candidates: vec![VmEncodeCandidate {
            mode_key: "immediate".to_string(),
            operand_bytes: vec![vec![0x42]],
        }],
    };
    let bytes = model
        .encode_portable_instruction(&request)
        .expect("portable request encode should succeed");
    assert_eq!(bytes, Some(vec![0xA9, 0x42]));
}

#[test]
fn execution_model_portable_request_respects_candidate_budget() {
    let registry = mos6502_family_registry();

    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mut limits = model.runtime_budget_limits();
    limits.max_candidate_count = 0;
    model.set_runtime_budget_limits_for_tests(limits);

    let request = PortableInstructionRequest {
        cpu_id: "m6502".to_string(),
        dialect_override: None,
        mnemonic: "LDA".to_string(),
        candidates: vec![VmEncodeCandidate {
            mode_key: "immediate".to_string(),
            operand_bytes: vec![vec![0x42]],
        }],
    };
    let err = model
        .encode_portable_instruction(&request)
        .expect_err("portable request should respect candidate budget");
    assert!(err.to_string().contains("candidate_count"));
}

#[test]
fn execution_model_tokenizer_vm_policy_parity_matches_host_tokens_mos6502() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let line = "lda #$42";
    let host_tokens = tokenize_host_line(line, 12).expect("host tokenization should succeed");
    let vm_tokens = model
        .tokenize_portable_statement("m6502", None, line, 12)
        .expect("portable tokenization should succeed");
    assert_eq!(vm_tokens, host_tokens);
}

#[test]
fn execution_model_tokenizer_vm_policy_parity_matches_host_tokens_with_cpu_override() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.token_policies.push(token_policy_for_test(
        ScopedOwner::Cpu("m6502".to_string()),
        TokenCaseRule::Preserve,
        token_identifier_class::ASCII_ALPHA | token_identifier_class::UNDERSCORE,
        token_identifier_class::ASCII_ALPHA
            | token_identifier_class::ASCII_DIGIT
            | token_identifier_class::UNDERSCORE,
        ",()[]{}+-*/#<>:=.&|^%!~;",
    ));

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let policy = model
        .resolve_token_policy("m6502", None)
        .expect("token policy resolution");
    assert_eq!(policy.case_rule, TokenCaseRule::Preserve);

    let line = "LDA #$42";
    let host_tokens = tokenize_host_line(line, 14).expect("host tokenization should succeed");
    let vm_tokens = model
        .tokenize_portable_statement("m6502", None, line, 14)
        .expect("portable tokenization should succeed");
    assert_eq!(vm_tokens, host_tokens);
}

#[test]
fn execution_model_tokenizer_applies_package_case_policy_hints() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let tokens = model
        .tokenize_portable_statement("m6502", None, "LDA #$42", 1)
        .expect("portable tokenization should succeed");
    assert!(matches!(
        &tokens[0].kind,
        PortableTokenKind::Identifier(name) if name == "lda"
    ));
}

#[test]
fn portable_token_contract_round_trips_core_token_model() {
    let mut tokenizer = Tokenizer::new("LDA #$42", 3);
    let mut core_tokens = Vec::new();
    loop {
        let token = tokenizer.next_token().expect("token");
        if matches!(token.kind, TokenKind::End) {
            break;
        }
        core_tokens.push(token);
    }
    let portable_tokens: Vec<PortableToken> = core_tokens
        .iter()
        .cloned()
        .filter_map(PortableToken::from_core_token)
        .collect();
    let round_trip: Vec<Token> = portable_tokens
        .iter()
        .map(PortableToken::to_core_token)
        .collect();
    assert_eq!(core_tokens, round_trip);
}

#[test]
fn portable_line_ast_contract_round_trips_core_line_model() {
    let span = Span {
        line: 7,
        col_start: 3,
        col_end: 9,
    };
    let num_expr = Expr::Number("42".to_string(), span);
    let id_expr = Expr::Identifier("value".to_string(), span);
    let unary_expr = Expr::Unary {
        op: super::UnaryOp::Minus,
        expr: Box::new(num_expr.clone()),
        span,
    };
    let binary_expr = Expr::Binary {
        op: super::BinaryOp::Add,
        left: Box::new(id_expr.clone()),
        right: Box::new(unary_expr.clone()),
        span,
    };
    let line_cases = vec![
        LineAst::Empty,
        LineAst::Conditional {
            kind: ConditionalKind::If,
            exprs: vec![binary_expr.clone()],
            span,
        },
        LineAst::Place {
            section: "code".to_string(),
            region: "rom".to_string(),
            align: Some(num_expr.clone()),
            span,
        },
        LineAst::Pack {
            region: "rom".to_string(),
            sections: vec!["code".to_string(), "data".to_string()],
            span,
        },
        LineAst::Use {
            module_id: "math".to_string(),
            alias: Some("m".to_string()),
            items: vec![UseItem {
                name: "add".to_string(),
                alias: Some("sum".to_string()),
                span,
            }],
            params: vec![UseParam {
                name: "width".to_string(),
                value: num_expr.clone(),
                span,
            }],
            span,
        },
        LineAst::StatementDef {
            keyword: "op".to_string(),
            signature: StatementSignature {
                atoms: vec![
                    SignatureAtom::Literal(b"op".to_vec(), span),
                    SignatureAtom::Capture {
                        type_name: "word".to_string(),
                        name: "arg".to_string(),
                        span,
                    },
                    SignatureAtom::Boundary {
                        atoms: vec![SignatureAtom::Literal(b",".to_vec(), span)],
                        span,
                    },
                ],
            },
            span,
        },
        LineAst::StatementEnd { span },
        LineAst::Assignment {
            label: Label {
                name: "foo".to_string(),
                span,
            },
            op: AssignOp::Add,
            expr: binary_expr.clone(),
            span,
        },
        LineAst::Statement {
            label: Some(Label {
                name: "start".to_string(),
                span,
            }),
            mnemonic: Some("lda".to_string()),
            operands: vec![
                Expr::Immediate(Box::new(num_expr.clone()), span),
                Expr::IndirectLong(Box::new(id_expr.clone()), span),
                Expr::Tuple(vec![id_expr, num_expr], span),
            ],
        },
    ];

    for (idx, line) in line_cases.iter().enumerate() {
        let portable = PortableLineAst::from_core_line_ast(line);
        let round_trip = portable.to_core_line_ast();
        assert_eq!(
            format!("{line:?}"),
            format!("{round_trip:?}"),
            "line ast round-trip mismatch at index {idx}"
        );
    }
}

#[test]
fn execution_model_token_policy_resolution_prefers_dialect_then_cpu_then_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.token_policies.push(token_policy_for_test(
        ScopedOwner::Family("mos6502".to_string()),
        TokenCaseRule::AsciiLower,
        token_identifier_class::ASCII_ALPHA,
        token_identifier_class::ASCII_ALPHA,
        ",",
    ));
    chunks.token_policies.push(token_policy_for_test(
        ScopedOwner::Cpu("m6502".to_string()),
        TokenCaseRule::Preserve,
        token_identifier_class::ASCII_ALPHA,
        token_identifier_class::ASCII_ALPHA,
        ",",
    ));
    chunks.token_policies.push(token_policy_for_test(
        ScopedOwner::Dialect("transparent".to_string()),
        TokenCaseRule::AsciiUpper,
        token_identifier_class::ASCII_ALPHA,
        token_identifier_class::ASCII_ALPHA,
        ",",
    ));
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");

    let policy = model
        .resolve_token_policy("m6502", None)
        .expect("policy should resolve");
    assert_eq!(policy.case_rule, TokenCaseRule::AsciiUpper);

    let tokens = model
        .tokenize_portable_statement("m6502", None, "lda", 1)
        .expect("tokenization should succeed");
    assert!(matches!(
        &tokens[0].kind,
        PortableTokenKind::Identifier(name) if name == "LDA"
    ));
}

#[test]
fn execution_model_tokenizer_vm_program_resolution_prefers_dialect_then_cpu_then_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks
        .tokenizer_vm_programs
        .push(tokenizer_vm_program_for_test(ScopedOwner::Family(
            "mos6502".to_string(),
        )));
    chunks
        .tokenizer_vm_programs
        .push(tokenizer_vm_program_for_test(ScopedOwner::Cpu(
            "m6502".to_string(),
        )));
    let mut dialect_program =
        tokenizer_vm_program_for_test(ScopedOwner::Dialect("transparent".to_string()));
    dialect_program.limits.max_tokens_per_line = 7;
    chunks.tokenizer_vm_programs.push(dialect_program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");

    let program = model
        .resolve_tokenizer_vm_program("m6502", None)
        .expect("tokenizer vm program resolution")
        .expect("tokenizer vm program should resolve");
    assert_eq!(program.limits.max_tokens_per_line, 7);
    assert!(program
        .diagnostics
        .invalid_char
        .eq_ignore_ascii_case("OTT001"));
}

#[test]
fn execution_model_tokenizer_vm_limits_default_when_program_missing() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let limits = model
        .resolve_tokenizer_vm_limits("m6502", None)
        .expect("tokenizer vm limits should resolve");
    assert_eq!(limits, TokenizerVmLimits::default());
}

#[test]
fn execution_model_parser_contract_resolution_prefers_dialect_then_cpu_then_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.parser_contracts.clear();
    chunks
        .parser_contracts
        .push(parser_contract_for_test(ScopedOwner::Family(
            "mos6502".to_string(),
        )));
    chunks
        .parser_contracts
        .push(parser_contract_for_test(ScopedOwner::Cpu(
            "m6502".to_string(),
        )));
    let mut dialect_contract =
        parser_contract_for_test(ScopedOwner::Dialect("transparent".to_string()));
    dialect_contract.max_ast_nodes_per_line = 42;
    chunks.parser_contracts.push(dialect_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let contract = model
        .resolve_parser_contract("m6502", None)
        .expect("parser contract resolution")
        .expect("parser contract should resolve");
    assert_eq!(contract.max_ast_nodes_per_line, 42);
    assert_eq!(contract.diagnostics.unexpected_token, "otp001");
}

#[test]
fn execution_model_from_registry_exposes_default_family_parser_contract() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let contract = model
        .resolve_parser_contract("m6502", None)
        .expect("parser contract resolution")
        .expect("parser contract should resolve");
    assert_eq!(contract.grammar_id, "opforge.line.v1");
    assert_eq!(contract.ast_schema_id, "opforge.ast.line.v1");
    assert_eq!(contract.opcode_version, 1);
}

#[test]
fn execution_model_expr_contract_resolution_prefers_dialect_then_cpu_then_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.expr_contracts.clear();
    chunks
        .expr_contracts
        .push(expr_contract_for_test(ScopedOwner::Family(
            "mos6502".to_string(),
        )));
    let mut cpu_contract = expr_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.max_program_bytes = 111;
    chunks.expr_contracts.push(cpu_contract);
    let mut dialect_contract =
        expr_contract_for_test(ScopedOwner::Dialect("transparent".to_string()));
    dialect_contract.max_program_bytes = 42;
    chunks.expr_contracts.push(dialect_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let contract = model
        .resolve_expr_contract("m6502", None)
        .expect("expr contract resolution")
        .expect("expr contract should resolve");
    assert_eq!(contract.max_program_bytes, 42);
    assert_eq!(contract.diagnostics.invalid_opcode, "ope001");
}

#[test]
fn execution_model_from_registry_exposes_default_family_expr_contract() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let contract = model
        .resolve_expr_contract("m6502", None)
        .expect("expr contract resolution")
        .expect("expr contract should resolve");
    assert_eq!(contract.opcode_version, EXPR_VM_OPCODE_VERSION_V1);
    assert_eq!(contract.max_program_bytes, 2048);

    let budgets = model
        .resolve_expr_budgets("m6502", None)
        .expect("expr budgets should resolve");
    assert_eq!(budgets.max_program_bytes, 2048);
    assert_eq!(budgets.max_stack_depth, 64);
}

#[test]
fn execution_model_expr_contract_budgets_apply_to_portable_eval() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.expr_contracts.clear();
    let mut contract = expr_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    contract.max_program_bytes = 1;
    chunks.expr_contracts.push(contract);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");

    let expr = Expr::Binary {
        op: BinaryOp::Add,
        left: Box::new(Expr::Number("1".to_string(), Span::default())),
        right: Box::new(Expr::Number("2".to_string(), Span::default())),
        span: Span::default(),
    };
    let program = compile_core_expr_to_portable_program(&expr).expect("compile should work");
    let ctx = TestAssemblerContext::new();

    let err = model
        .evaluate_portable_expression_program_with_contract_for_assembler(
            "m6502", None, &program, &ctx,
        )
        .expect_err("contract budget should reject eval");
    assert!(err.to_string().contains("ope007"));
}

#[test]
fn execution_model_expr_contract_unstable_check_uses_resolved_budgets() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let expr = Expr::Identifier("forward_label".to_string(), Span::default());
    let program = compile_core_expr_to_portable_program(&expr).expect("compile should work");
    let ctx = TestAssemblerContext::new();

    let unstable = model
        .portable_expression_has_unstable_symbols_with_contract_for_assembler(
            "m6502", None, &program, &ctx,
        )
        .expect("unstable-symbol scan should succeed");
    assert!(unstable);
}

#[test]
fn execution_model_parser_vm_program_resolution_prefers_dialect_then_cpu_then_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.parser_vm_programs.clear();
    chunks
        .parser_vm_programs
        .push(parser_vm_program_for_test(ScopedOwner::Family(
            "mos6502".to_string(),
        )));
    chunks
        .parser_vm_programs
        .push(parser_vm_program_for_test(ScopedOwner::Cpu(
            "m6502".to_string(),
        )));
    let mut dialect_program =
        parser_vm_program_for_test(ScopedOwner::Dialect("transparent".to_string()));
    dialect_program.program = vec![ParserVmOpcode::Fail as u8, ParserVmOpcode::End as u8];
    chunks.parser_vm_programs.push(dialect_program);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let program = model
        .resolve_parser_vm_program("m6502", None)
        .expect("parser vm program resolution")
        .expect("parser vm program should resolve");
    assert_eq!(
        program.program,
        vec![ParserVmOpcode::Fail as u8, ParserVmOpcode::End as u8]
    );
}

#[test]
fn execution_model_from_registry_exposes_default_family_parser_vm_program() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let program = model
        .resolve_parser_vm_program("m6502", None)
        .expect("parser vm program resolution")
        .expect("parser vm program should resolve");
    assert_eq!(program.opcode_version, PARSER_VM_OPCODE_VERSION_V1);
    assert_eq!(
        program.program,
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
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_enforces_budget() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.max_ast_nodes_per_line = 1;
    chunks.parser_contracts.push(cpu_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 2)
        .expect_err("parser budget should be enforced");
    match err {
        RuntimeBridgeError::Diagnostic(diag) => {
            assert_eq!(diag.code.to_ascii_lowercase(), "otp004");
            assert!(diag.message.contains("parser AST node budget exceeded"));
        }
        other => panic!("expected typed runtime diagnostic, got: {other:?}"),
    }
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_rejects_zero_ast_budget() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.max_ast_nodes_per_line = 0;
    chunks.parser_contracts.push(cpu_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("zero parser AST node budget should fail");
    assert!(err
        .to_string()
        .contains("parser contract max_ast_nodes_per_line must be > 0"));
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_rejects_missing_diag_mapping() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.diagnostics.expected_expression.clear();
    chunks.parser_contracts.push(cpu_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("missing parser diagnostic mapping should fail");
    assert!(err
        .to_string()
        .contains("missing parser contract diagnostic mapping for 'expected_expression'"));
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_rejects_unknown_diag_code() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.diagnostics.expected_operand = "otp999".to_string();
    chunks.parser_contracts.push(cpu_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("unknown parser diagnostic code should fail");
    assert!(err.to_string().contains(
        "parser contract diagnostic code 'otp999' is not declared in package DIAG catalog"
    ));
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_errors_when_missing() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.parser_contracts.clear();
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("missing parser contract should fail");
    assert!(
        err.to_string()
            .to_ascii_lowercase()
            .contains("missing vm parser contract"),
        "expected missing contract error, got: {err}"
    );
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_rejects_incompatible_grammar() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.grammar_id = "opforge.line.v0".to_string();
    chunks.parser_contracts.push(cpu_contract);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("incompatible parser grammar should fail");
    assert!(err.to_string().contains("unsupported parser grammar id"));
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_rejects_incompatible_ast_schema() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.ast_schema_id = "opforge.ast.line.v0".to_string();
    chunks.parser_contracts.push(cpu_contract);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("incompatible parser AST schema should fail");
    assert!(err.to_string().contains("unsupported parser AST schema id"));
}

#[test]
fn execution_model_validate_parser_contract_for_assembler_rejects_incompatible_opcode_version() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.opcode_version = PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
    chunks.parser_contracts.push(cpu_contract);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .validate_parser_contract_for_assembler("m6502", None, 0)
        .expect_err("incompatible parser opcode version should fail");
    assert!(err
        .to_string()
        .contains("unsupported parser contract opcode version"));
}

#[test]
fn execution_model_parse_expression_for_assembler_uses_contract_entrypoint() {
    let registry = mos6502_family_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    let (tokens, end_span) = tokenize_core_expr_tokens("1+2", 1);
    let expr = model
        .parse_expression_for_assembler("m6502", None, tokens, end_span, None)
        .expect("expression parsing should succeed through runtime entrypoint");
    assert!(matches!(
        expr,
        Expr::Binary {
            op: BinaryOp::Add,
            ..
        }
    ));
}

#[test]
fn execution_model_parse_expression_for_assembler_certified_path_bypasses_core_parser_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(false));
        }
    }

    let _reset = FailpointReset;
    CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(true));

    let registry = mos6502_family_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    let (tokens, end_span) = tokenize_core_expr_tokens("1+2", 1);
    let expr = model
        .parse_expression_for_assembler("m6502", None, tokens, end_span, None)
        .expect("certified parser path should bypass core parser failpoint");
    assert!(matches!(
        expr,
        Expr::Binary {
            op: BinaryOp::Add,
            ..
        }
    ));
}

#[test]
fn execution_model_compile_expression_program_vm_opt_in_bypasses_core_parser_failpoint() {
    struct FailpointReset;

    impl Drop for FailpointReset {
        fn drop(&mut self) {
            CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(false));
        }
    }

    let _reset = FailpointReset;
    CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(true));

    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let (tokens, end_span) = tokenize_core_expr_tokens("1+2*3", 1);
    let program = model
        .compile_expression_program_with_parser_vm_opt_in_for_assembler(
            "m6502",
            None,
            tokens,
            end_span,
            None,
            Some(EXPR_PARSER_VM_OPCODE_VERSION_V1),
        )
        .expect("vm opt-in compile should bypass core parser failpoint");
    assert!(!program.code.is_empty());
}

#[test]
fn execution_model_parse_expression_for_assembler_rejects_incompatible_contract() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    for contract in &mut chunks.parser_contracts {
        if matches!(
            contract.owner,
            ScopedOwner::Family(ref family_id)
                if family_id.eq_ignore_ascii_case("mos6502")
        ) {
            contract.grammar_id = "opforge.line.v0".to_string();
        }
    }
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let (tokens, end_span) = tokenize_core_expr_tokens("1", 1);
    let err = model
        .parse_expression_for_assembler("m6502", None, tokens, end_span, None)
        .expect_err("incompatible expression contract should fail");
    assert!(err.message.contains("unsupported parser grammar id"));
    assert!(
        err.message.to_ascii_lowercase().contains("otp004"),
        "expected parser invalid-statement diagnostic code, got: {}",
        err.message
    );
}

#[test]
fn execution_model_parse_expression_for_assembler_rejects_unclosed_parenthesis() {
    let registry = mos6502_family_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    let (tokens, end_span) = tokenize_core_expr_tokens("(1+2", 1);
    let err = model
        .parse_expression_for_assembler("m6502", None, tokens, end_span, None)
        .expect_err("unclosed parenthesis should fail");
    assert!(
        err.message.contains("Unexpected")
            || err.message.contains("expected ')'")
            || err.message.contains("Missing ')'"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn execution_model_parse_expression_for_assembler_rejects_trailing_operator() {
    let registry = mos6502_family_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    let (tokens, end_span) = tokenize_core_expr_tokens("1+", 1);
    let err = model
        .parse_expression_for_assembler("m6502", None, tokens, end_span, None)
        .expect_err("trailing operator should fail");
    assert!(
        err.message.contains("Unexpected end of expression")
            || err.message.contains("Expected expression"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn runtime_expression_parser_rejects_missing_ternary_colon_directly() {
    let (tokens, end_span) = tokenize_core_expr_tokens("1 ? 2", 1);
    let err = RuntimeExpressionParser::new(tokens, end_span, None)
        .parse_expr_from_tokens()
        .expect_err("missing ternary ':' should fail");
    assert!(
        err.message
            .contains("Missing ':' in conditional expression"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn runtime_expression_parser_rejects_unexpected_primary_token_directly() {
    let (tokens, end_span) = tokenize_core_expr_tokens(",1", 1);
    let err = RuntimeExpressionParser::new(tokens, end_span, None)
        .parse_expr_from_tokens()
        .expect_err("unexpected leading comma should fail");
    assert!(
        err.message.contains("Unexpected token in expression"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn runtime_expression_parser_honors_operator_precedence_directly() {
    let (tokens, end_span) = tokenize_core_expr_tokens("1+2*3", 1);
    let expr = RuntimeExpressionParser::new(tokens, end_span, None)
        .parse_expr_from_tokens()
        .expect("direct runtime parser should parse expression");

    match expr {
        Expr::Binary {
            op: BinaryOp::Add,
            left,
            right,
            ..
        } => {
            assert!(matches!(*left, Expr::Number(_, _)));
            assert!(matches!(
                *right,
                Expr::Binary {
                    op: BinaryOp::Multiply,
                    ..
                }
            ));
        }
        other => panic!("expected add-with-multiply-right AST, got {other:?}"),
    }
}

#[test]
fn execution_model_expr_parser_contract_resolution_prefers_dialect_then_cpu_then_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.expr_parser_contracts.clear();
    chunks
        .expr_parser_contracts
        .push(expr_parser_contract_for_test(ScopedOwner::Family(
            "mos6502".to_string(),
        )));
    let mut cpu_contract = expr_parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
    cpu_contract.opcode_version = EXPR_PARSER_VM_OPCODE_VERSION_V1;
    chunks.expr_parser_contracts.push(cpu_contract);
    let mut dialect_contract =
        expr_parser_contract_for_test(ScopedOwner::Dialect("transparent".to_string()));
    dialect_contract.diagnostics.invalid_expression_program = "otp003".to_string();
    chunks.expr_parser_contracts.push(dialect_contract);

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let contract = model
        .resolve_expr_parser_contract("m6502", None)
        .expect("expr parser contract resolution")
        .expect("expr parser contract should resolve");
    assert_eq!(contract.opcode_version, EXPR_PARSER_VM_OPCODE_VERSION_V1);
    assert_eq!(contract.diagnostics.invalid_expression_program, "otp003");
}

#[test]
fn execution_model_parse_expression_program_for_assembler_uses_expr_parser_contract() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.expr_parser_contracts.clear();
    let mut contract = expr_parser_contract_for_test(ScopedOwner::Family("mos6502".to_string()));
    contract.opcode_version = EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1);
    chunks.expr_parser_contracts.push(contract);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");

    let (tokens, end_span) = tokenize_core_expr_tokens("1+2", 1);
    let err = model
        .parse_expression_program_for_assembler("m6502", None, tokens, end_span, None)
        .expect_err("unsupported expr parser contract version should fail");
    assert!(err
        .message
        .contains("unsupported expression parser contract opcode version"));
}

#[test]
fn execution_model_compile_expression_program_parser_vm_opt_in_matches_host_semantics() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let (host_tokens, host_end_span) = tokenize_core_expr_tokens("1 ? $+1 : target", 1);
    let (opt_in_tokens, opt_in_end_span) = tokenize_core_expr_tokens("1 ? $+1 : target", 1);

    let host_program = model
        .compile_expression_program_for_assembler("m6502", None, host_tokens, host_end_span, None)
        .expect("host compile should succeed");
    let opt_in_program = model
        .compile_expression_program_with_parser_vm_opt_in_for_assembler(
            "m6502",
            None,
            opt_in_tokens,
            opt_in_end_span,
            None,
            Some(EXPR_PARSER_VM_OPCODE_VERSION_V1),
        )
        .expect("opt-in compile should succeed");

    assert_eq!(opt_in_program, host_program);

    let mut ctx = TestAssemblerContext::new();
    ctx.addr = 0x2000;
    ctx.values.insert("target".to_string(), 7);

    let host_eval = model
        .evaluate_portable_expression_program_with_contract_for_assembler(
            "m6502",
            None,
            &host_program,
            &ctx,
        )
        .expect("host eval should succeed");
    let opt_in_eval = model
        .evaluate_portable_expression_program_with_contract_for_assembler(
            "m6502",
            None,
            &opt_in_program,
            &ctx,
        )
        .expect("opt-in eval should succeed");

    assert_eq!(host_eval.value, 0x2001);
    assert_eq!(opt_in_eval, host_eval);
}

#[test]
fn execution_model_compile_expression_program_parser_vm_opt_in_matches_host_semantics_corpus() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let corpus = [
        "1+2*3",
        "$+1",
        "1 ? $2A : $55",
        "(<$1234) + (>$1234)",
        "target-1",
        "((1 << 3) | 2) & $ff",
    ];

    let mut ctx = TestAssemblerContext::new();
    ctx.addr = 0x2000;
    ctx.values.insert("target".to_string(), 7);

    for (index, expr) in corpus.iter().enumerate() {
        let line_num = (index as u32).saturating_add(1);
        let (host_tokens, host_end_span) = tokenize_core_expr_tokens(expr, line_num);
        let (opt_in_tokens, opt_in_end_span) = tokenize_core_expr_tokens(expr, line_num);

        let host_program = model
            .compile_expression_program_for_assembler(
                "m6502",
                None,
                host_tokens,
                host_end_span,
                None,
            )
            .expect("host compile should succeed");
        let opt_in_program = model
            .compile_expression_program_with_parser_vm_opt_in_for_assembler(
                "m6502",
                None,
                opt_in_tokens,
                opt_in_end_span,
                None,
                Some(EXPR_PARSER_VM_OPCODE_VERSION_V1),
            )
            .expect("opt-in compile should succeed");

        assert_eq!(
            opt_in_program, host_program,
            "program mismatch for expression {expr:?}"
        );

        let host_eval = model
            .evaluate_portable_expression_program_with_contract_for_assembler(
                "m6502",
                None,
                &host_program,
                &ctx,
            )
            .expect("host eval should succeed");
        let opt_in_eval = model
            .evaluate_portable_expression_program_with_contract_for_assembler(
                "m6502",
                None,
                &opt_in_program,
                &ctx,
            )
            .expect("opt-in eval should succeed");

        assert_eq!(
            opt_in_eval, host_eval,
            "evaluation mismatch for expression {expr:?}"
        );
    }
}

#[test]
fn execution_model_compile_expression_program_parser_vm_opt_in_rejects_unknown_opcode_version() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let (tokens, end_span) = tokenize_core_expr_tokens("1+2*3", 1);
    let err = model
        .compile_expression_program_with_parser_vm_opt_in_for_assembler(
            "m6502",
            None,
            tokens,
            end_span,
            None,
            Some(EXPR_PARSER_VM_OPCODE_VERSION_V1.saturating_add(1)),
        )
        .expect_err("unknown expression parser VM opcode version should fail");
    assert!(err
        .message
        .to_ascii_lowercase()
        .contains("unsupported vm expression parser vm opcode version"));
}

#[test]
fn execution_model_tokenizer_vm_parity_checklist_resolves_for_certified_families() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mos = model
        .resolve_tokenizer_vm_parity_checklist("m6502", None)
        .expect("mos6502 checklist resolution");
    let intel = model
        .resolve_tokenizer_vm_parity_checklist("z80", None)
        .expect("intel8080 checklist resolution");
    assert!(mos.is_some_and(|value| value.to_ascii_lowercase().contains("parity")));
    assert!(intel.is_some_and(|value| value.to_ascii_lowercase().contains("parity")));
}

#[test]
fn tokenizer_vm_certification_entries_require_parity_checklist_text() {
    assert!(
        TOKENIZER_VM_CERTIFICATIONS.iter().next().is_some(),
        "certified family list must be explicit"
    );
    for certification in TOKENIZER_VM_CERTIFICATIONS {
        assert!(
            !certification.parity_checklist.trim().is_empty(),
            "certified family {} must declare parity checklist text",
            certification.family_id
        );
        assert!(
            certification
                .parity_checklist
                .to_ascii_lowercase()
                .contains("parity"),
            "certified family {} checklist should reference parity gates",
            certification.family_id
        );
        assert_eq!(
            tokenizer_vm_parity_checklist_for_family(certification.family_id),
            Some(certification.parity_checklist)
        );
    }
    assert!(tokenizer_vm_parity_checklist_for_family("nonexistent").is_none());
}

#[test]
fn execution_model_expr_parser_vm_parity_checklist_resolves_for_certified_families() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let mos = model
        .resolve_expr_parser_vm_parity_checklist("m6502", None)
        .expect("mos6502 checklist resolution");
    let intel = model
        .resolve_expr_parser_vm_parity_checklist("z80", None)
        .expect("intel8080 checklist resolution");
    assert!(mos.is_some_and(|value| value.to_ascii_lowercase().contains("parity")));
    assert!(intel.is_some_and(|value| value.to_ascii_lowercase().contains("parity")));
}

#[test]
fn expr_parser_vm_certification_entries_require_parity_checklist_text() {
    assert!(
        EXPR_PARSER_VM_CERTIFICATIONS.iter().next().is_some(),
        "certified family list must be explicit"
    );
    for certification in EXPR_PARSER_VM_CERTIFICATIONS {
        assert!(
            !certification.parity_checklist.trim().is_empty(),
            "certified family {} must declare parity checklist text",
            certification.family_id
        );
        assert!(
            certification
                .parity_checklist
                .to_ascii_lowercase()
                .contains("parity"),
            "certified family {} checklist should reference parity gates",
            certification.family_id
        );
        assert_eq!(
            expr_parser_vm_parity_checklist_for_family(certification.family_id),
            Some(certification.parity_checklist)
        );
    }
    assert!(expr_parser_vm_parity_checklist_for_family("nonexistent").is_none());
}

#[test]
fn execution_model_parser_certification_checklists_return_expr_and_instruction_tracks() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let checklists = model
        .resolve_parser_certification_checklists("m6502", None)
        .expect("checklist resolution");
    assert_eq!(
        checklists.expression_parser_checklist,
        Some("phase8-mos6502-expr-parser-vm-authoritative")
    );
    assert_eq!(
        checklists.instruction_parse_encode_checklist,
        Some("phase6-mos6502-rollout-criteria")
    );
}

#[test]
fn execution_model_tokenizer_auto_mode_uses_vm_for_mos6502_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.program = vec![
        TokenizerVmOpcode::ReadChar as u8,
        TokenizerVmOpcode::StartLexeme as u8,
        TokenizerVmOpcode::PushChar as u8,
        TokenizerVmOpcode::EmitToken as u8,
        VM_TOKEN_KIND_IDENTIFIER,
        TokenizerVmOpcode::End as u8,
    ];
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");

    let tokens = model
        .tokenize_portable_statement("m6502", None, "A,B", 1)
        .expect("auto mode should route MOS6502 family to VM tokenizer");
    assert_eq!(tokens.len(), 1);
    assert!(matches!(
        &tokens[0].kind,
        PortableTokenKind::Identifier(name) if name == "a"
    ));
}

#[test]
fn execution_model_tokenizer_auto_mode_uses_vm_for_intel8080_family() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let tokens = model
        .tokenize_portable_statement("z80", None, "LD A,B", 1)
        .expect("intel8080 family should route through VM tokenizer authority");
    assert!(matches!(
        &tokens[0].kind,
        PortableTokenKind::Identifier(name) if name == "ld"
    ));
}

#[test]
fn execution_model_tokenizer_vm_covers_all_supported_cpu_ids() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    let cpu_cases = [
        ("m6502", "LDA #$42", "lda"),
        ("65c02", "LDA #$42", "lda"),
        ("65816", "LDA #$42", "lda"),
        ("8085", "MVI A,1", "mvi"),
        ("z80", "LD A,B", "ld"),
    ];

    for (cpu_id, source_line, mnemonic) in cpu_cases {
        let program = model
            .resolve_tokenizer_vm_program(cpu_id, None)
            .expect("tokenizer vm program resolution should succeed");
        let program = program.expect("supported cpu should resolve a tokenizer vm program");
        assert!(
            program
                .program
                .contains(&(TokenizerVmOpcode::ScanCoreToken as u8)),
            "{cpu_id} should resolve a tokenizer VM program containing ScanCoreToken"
        );

        let tokens = model
            .tokenize_portable_statement_for_assembler(cpu_id, None, source_line, 1)
            .expect("assembler tokenization should remain strict VM for supported cpu");
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == mnemonic
        ));
    }
}

#[test]
fn execution_model_tokenizer_mode_auto_matches_vm_mode() {
    let registry = mos6502_family_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    model.set_tokenizer_mode(RuntimeTokenizerMode::Auto);
    let auto_tokens = model
        .tokenize_portable_statement("m6502", None, "LDA #$42", 1)
        .expect("auto tokenizer mode should execute VM path");
    model.set_tokenizer_mode(RuntimeTokenizerMode::Vm);
    let vm_tokens = model
        .tokenize_portable_statement("m6502", None, "LDA #$42", 1)
        .expect("vm tokenizer mode should execute VM path");
    assert_eq!(auto_tokens, vm_tokens);
}

#[test]
fn execution_model_tokenizer_mode_vm_is_strict_for_empty_non_comment_output() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.program = vec![TokenizerVmOpcode::End as u8];
    chunks.tokenizer_vm_programs.push(program);
    let mut model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    model.set_tokenizer_mode(RuntimeTokenizerMode::Vm);
    let err = model
        .tokenize_portable_statement("m6502", None, "LDA #$42", 1)
        .expect_err("vm mode should stay strict and reject empty token output");
    assert!(err
        .to_string()
        .to_ascii_lowercase()
        .contains("produced no tokens"));
}

#[test]
fn execution_model_tokenizer_vm_authoritative_mode_requires_program() {
    let registry = mos6502_family_registry();
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.tokenizer_vm_programs.clear();
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative vm tokenization should require a vm program");
    assert!(err
        .to_string()
        .to_ascii_lowercase()
        .contains("missing tokenizer vm program"));
}

#[test]
fn execution_model_tokenizer_vm_authoritative_mode_rejects_incompatible_opcode_version() {
    let registry = mos6502_family_registry();
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.opcode_version = TOKENIZER_VM_OPCODE_VERSION_V1.saturating_add(1);
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative vm tokenization should reject incompatible opcode version");
    assert!(
        err.to_string()
            .to_ascii_lowercase()
            .contains("unsupported tokenizer vm opcode version"),
        "expected tokenizer opcode version error, got: {err}"
    );
}

#[test]
fn execution_model_tokenizer_vm_authoritative_mode_rejects_missing_diag_mapping() {
    let registry = mos6502_family_registry();
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.diagnostics.lexeme_limit_exceeded.clear();
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative vm tokenization should reject missing diag mapping");
    assert!(err
        .to_string()
        .contains("missing tokenizer VM diagnostic mapping for 'lexeme_limit_exceeded'"));
}

#[test]
fn execution_model_tokenizer_vm_authoritative_mode_rejects_unknown_diag_code() {
    let registry = mos6502_family_registry();
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.diagnostics.token_limit_exceeded = "ott999".to_string();
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative vm tokenization should reject unknown diag mapping");
    assert!(err
        .to_string()
        .contains("tokenizer VM diagnostic code 'ott999' is not declared in package DIAG catalog"));
}

#[test]
fn execution_model_tokenizer_vm_authoritative_mode_rejects_empty_tokens() {
    let registry = mos6502_family_registry();
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.program = vec![TokenizerVmOpcode::End as u8];
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative vm tokenization should reject empty non-comment output");
    assert!(err
        .to_string()
        .to_ascii_lowercase()
        .contains("produced no tokens"));
}

#[test]
fn execution_model_tokenizer_vm_authoritative_mode_rejects_delegate_opcode() {
    let registry = mos6502_family_registry();
    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.program = vec![
        TokenizerVmOpcode::DelegateCore as u8,
        TokenizerVmOpcode::End as u8,
    ];
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let err = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative vm tokenization should reject DelegateCore");
    assert!(err
        .to_string()
        .to_ascii_lowercase()
        .contains("delegatecore opcode is forbidden"));
}

#[test]
fn execution_model_tokenizer_mode_vm_executes_program_from_package() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.program = vec![
        TokenizerVmOpcode::ReadChar as u8,
        TokenizerVmOpcode::StartLexeme as u8,
        TokenizerVmOpcode::PushChar as u8,
        TokenizerVmOpcode::EmitToken as u8,
        VM_TOKEN_KIND_IDENTIFIER,
        TokenizerVmOpcode::End as u8,
    ];
    chunks.tokenizer_vm_programs.push(program);
    let mut model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    model.set_tokenizer_mode(RuntimeTokenizerMode::Vm);

    let tokens = model
        .tokenize_portable_statement("m6502", None, "A,B", 1)
        .expect("vm mode should execute tokenizer VM program");
    assert_eq!(tokens.len(), 1);
    assert!(matches!(
        &tokens[0].kind,
        PortableTokenKind::Identifier(name) if name == "a"
    ));
}

#[test]
fn execution_model_assembler_tokenization_path_is_strict_for_authoritative_family() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
    program.program = vec![TokenizerVmOpcode::End as u8];
    chunks.tokenizer_vm_programs.push(program);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");

    let err = model
        .tokenize_portable_statement_for_assembler("m6502", None, "LDA #$42", 1)
        .expect_err("authoritative assembler path should not fall back");
    assert!(err
        .to_string()
        .to_ascii_lowercase()
        .contains("produced no tokens"));
}

#[test]
fn execution_model_assembler_tokenization_path_uses_vm_for_intel8080_family() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    let tokens = model
        .tokenize_portable_statement_for_assembler("z80", None, "LD A,B", 1)
        .expect("intel8080 family assembler tokenization should route through VM");
    assert!(matches!(
        &tokens[0].kind,
        PortableTokenKind::Identifier(name) if name == "ld"
    ));
}

#[test]
fn execution_model_tokenizer_vm_retro_profile_enforces_step_budget() {
    let registry = mos6502_family_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    model.set_runtime_budget_profile(RuntimeBudgetProfile::RetroConstrained);

    let vm_program = runtime_vm_program_for_test(
        vec![TokenizerVmOpcode::Jump as u8, 0, 0, 0, 0],
        TokenizerVmLimits {
            max_steps_per_line: 4096,
            max_tokens_per_line: 1024,
            max_lexeme_bytes: 512,
            max_errors_per_line: 16,
        },
    );
    let err = tokenize_with_vm_program(&model, "m6502", "LDA #$42", 1, &vm_program)
        .expect_err("retro step budget should cap VM execution");
    assert!(err.to_string().contains("step budget exceeded"));
    assert!(err.to_string().contains("/512)"));
}

#[test]
fn execution_model_tokenizer_vm_retro_profile_enforces_lexeme_budget() {
    let registry = mos6502_family_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    model.set_runtime_budget_profile(RuntimeBudgetProfile::RetroConstrained);

    let vm_program = runtime_vm_program_for_test(
        vec![
            TokenizerVmOpcode::StartLexeme as u8,
            TokenizerVmOpcode::ReadChar as u8,
            TokenizerVmOpcode::JumpIfEol as u8,
            14,
            0,
            0,
            0,
            TokenizerVmOpcode::PushChar as u8,
            TokenizerVmOpcode::Advance as u8,
            TokenizerVmOpcode::Jump as u8,
            1,
            0,
            0,
            0,
            TokenizerVmOpcode::EmitToken as u8,
            VM_TOKEN_KIND_IDENTIFIER,
            TokenizerVmOpcode::End as u8,
        ],
        TokenizerVmLimits {
            max_steps_per_line: 4096,
            max_tokens_per_line: 1024,
            max_lexeme_bytes: 512,
            max_errors_per_line: 16,
        },
    );
    let long_identifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD";
    let err = tokenize_with_vm_program(&model, "m6502", long_identifier, 1, &vm_program)
        .expect_err("retro lexeme budget should cap VM lexeme growth");
    assert!(err.to_string().contains("lexeme budget exceeded"));
    assert!(err.to_string().contains("/32)"));
}

#[test]
fn execution_model_tokenizer_vm_retro_profile_enforces_token_budget() {
    let registry = mos6502_family_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    model.set_runtime_budget_profile(RuntimeBudgetProfile::RetroConstrained);

    let vm_program = runtime_vm_program_for_test(
        vec![
            TokenizerVmOpcode::ReadChar as u8,
            TokenizerVmOpcode::JumpIfEol as u8,
            16,
            0,
            0,
            0,
            TokenizerVmOpcode::StartLexeme as u8,
            TokenizerVmOpcode::PushChar as u8,
            TokenizerVmOpcode::EmitToken as u8,
            VM_TOKEN_KIND_IDENTIFIER,
            TokenizerVmOpcode::Advance as u8,
            TokenizerVmOpcode::Jump as u8,
            0,
            0,
            0,
            0,
            TokenizerVmOpcode::End as u8,
        ],
        TokenizerVmLimits {
            max_steps_per_line: 4096,
            max_tokens_per_line: 1024,
            max_lexeme_bytes: 512,
            max_errors_per_line: 16,
        },
    );
    let dense = "A".repeat(70);
    let err = tokenize_with_vm_program(&model, "m6502", dense.as_str(), 1, &vm_program)
        .expect_err("retro token budget should cap token emission");
    assert!(err.to_string().contains("token budget exceeded"));
    assert!(err.to_string().contains("/64)"));
}

#[test]
fn execution_model_tokenizer_parity_corpus_examples_and_edge_cases_core_vs_vm() {
    let mut corpus = tokenizer_example_lines();
    corpus.extend(tokenizer_edge_case_lines());
    assert!(
        !corpus.is_empty(),
        "tokenizer parity corpus should not be empty"
    );

    let registry = parity_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    for cpu_id in ["m6502", "z80"] {
        for (index, line) in corpus.iter().enumerate() {
            let line_num = (index + 1) as u32;
            let host = tokenize_host_line_with_policy(&model, cpu_id, None, line, line_num);
            let vm =
                tokenize_with_mode(&mut model, RuntimeTokenizerMode::Vm, cpu_id, line, line_num);
            assert_eq!(
                vm, host,
                "tokenizer parity mismatch for cpu {} at corpus index {} line {:?}",
                cpu_id, index, line
            );
        }
    }
}

#[test]
fn execution_model_tokenizer_parity_deterministic_fuzz_core_vs_vm() {
    let corpus = deterministic_fuzz_lines(0x50_45_45_44, 512, 48);
    let registry = parity_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    for (index, line) in corpus.iter().enumerate() {
        let line_num = (index + 1) as u32;
        let host = tokenize_host_line_with_policy(&model, "m6502", None, line, line_num);
        let vm = tokenize_with_mode(
            &mut model,
            RuntimeTokenizerMode::Vm,
            "m6502",
            line,
            line_num,
        );
        assert_eq!(
            vm, host,
            "deterministic fuzz parity mismatch at index {} line {:?}",
            index, line
        );
    }
}

#[test]
fn execution_model_tokenizer_vm_mode_is_deterministic_for_same_input() {
    let corpus = deterministic_fuzz_lines(0x44_45_54, 256, 40);
    let registry = parity_registry();
    let mut model =
        HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    for (index, line) in corpus.iter().enumerate() {
        let line_num = (index + 1) as u32;
        let first = tokenize_with_mode(
            &mut model,
            RuntimeTokenizerMode::Vm,
            "m6502",
            line,
            line_num,
        );
        let second = tokenize_with_mode(
            &mut model,
            RuntimeTokenizerMode::Vm,
            "m6502",
            line,
            line_num,
        );
        assert_eq!(
            second, first,
            "vm tokenizer determinism mismatch at index {} line {:?}",
            index, line
        );
    }
}

#[test]
fn execution_model_vm_encode_supports_m65c02_cpu_tables() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let operands = MOS6502Operands(vec![Operand::Relative(2, Span::default())]);
    let bytes = model
        .encode_instruction("65c02", None, "BRA", &operands)
        .expect("vm encode should resolve");
    assert_eq!(bytes, Some(vec![0x80, 0x02]));
}

#[test]
fn execution_model_encodes_m6502_instruction_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Immediate(
        Box::new(Expr::Number("66".to_string(), span)),
        span,
    )];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("m6502", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xA9, 0x42]));
}

#[test]
fn execution_model_encodes_m65c02_instruction_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Number("4".to_string(), span)];
    let mut ctx = TestAssemblerContext::new();
    ctx.addr = 0;
    let bytes = model
        .encode_instruction_from_exprs("65c02", None, "BRA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0x80, 0x02]));
}

#[test]
fn execution_model_encodes_m65816_block_move_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Number("1".to_string(), span),
        Expr::Number("2".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "MVN", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0x54, 0x01, 0x02]));
}

#[test]
fn execution_model_encodes_45gs02_plain_table_form_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("45gs02", None, "MAP", &[], &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0x5C]));
}

#[test]
fn execution_model_encodes_45gs02_q_prefix_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Immediate(
        Box::new(Expr::Number("1".to_string(), span)),
        span,
    )];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("45gs02", None, "ADCQ", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0x42, 0x42, 0x69, 0x01]));
}

#[test]
fn execution_model_encodes_45gs02_flat_memory_form_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Indirect(Box::new(Expr::Number("32".to_string(), span)), span),
        Expr::Register("Z".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("45gs02", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xEA, 0xB1, 0x20]));
}

#[test]
fn execution_model_encodes_45gs02_bsr_pass1_placeholder_and_pass2_error() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Number("50000".to_string(), span)];

    let mut pass1_ctx = TestAssemblerContext::new();
    pass1_ctx.pass = 1;
    pass1_ctx.addr = 0;
    let pass1 = model
        .encode_instruction_from_exprs("45gs02", None, "BSR", &operands, &pass1_ctx)
        .expect("pass1 vm expr encode should succeed");
    assert_eq!(pass1, Some(vec![0x63, 0x00, 0x00]));

    let mut pass2_ctx = TestAssemblerContext::new();
    pass2_ctx.pass = 2;
    pass2_ctx.addr = 0;
    let err = model
        .encode_instruction_from_exprs("45gs02", None, "BSR", &operands, &pass2_ctx)
        .expect_err("pass2 vm expr encode should reject out-of-range relfar");
    assert!(err.to_string().contains("Long branch target out of range"));
}

#[test]
fn execution_model_reports_expr_resolver_support_by_family() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    assert!(model.supports_expr_resolution_for_family("mos6502"));
    assert!(model.supports_expr_resolution_for_family("MOS6502"));
    assert!(model.supports_expr_resolution_for_family("intel8080"));
}

#[test]
fn execution_model_expr_encode_returns_none_for_unsupported_intel_shape() {
    let model =
        HierarchyExecutionModel::from_chunks(intel_only_chunks()).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Number("66".to_string(), span)];
    let ctx = TestAssemblerContext::new();

    let bytes = model
        .encode_instruction_from_exprs("8085", None, "MVI", &operands, &ctx)
        .expect("unsupported shape should continue to resolve as None");
    assert!(bytes.is_none());
    assert!(model.expr_resolution_is_strict_for_family("intel8080"));
}

#[test]
fn execution_model_intel_expr_resolver_encodes_matching_mvi_program() {
    let mut chunks = intel_only_chunks();
    let mvi_a = crate::families::intel8080::table::lookup_instruction("MVI", Some("A"), None)
        .expect("MVI A should exist");
    chunks.tables[0].mode_key = mode_key_for_instruction_entry(mvi_a);
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Identifier("A".to_string(), span),
        Expr::Number("66".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("8085", None, "MVI", &operands, &ctx)
        .expect("intel expr resolver should encode MVI");
    assert_eq!(bytes, Some(vec![0x3E, 0x42]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_jp_ix_iy() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ix_operands = vec![Expr::Indirect(
        Box::new(Expr::Identifier("IX".to_string(), span)),
        span,
    )];
    let iy_operands = vec![Expr::Indirect(
        Box::new(Expr::Identifier("IY".to_string(), span)),
        span,
    )];
    let ctx = TestAssemblerContext::new();

    let ix_bytes = model
        .encode_instruction_from_exprs("z80", None, "JP", &ix_operands, &ctx)
        .expect("JP (IX) should resolve via intel expr resolver");
    let iy_bytes = model
        .encode_instruction_from_exprs("z80", None, "JP", &iy_operands, &ctx)
        .expect("JP (IY) should resolve via intel expr resolver");

    assert_eq!(ix_bytes, Some(vec![0xDD, 0xE9]));
    assert_eq!(iy_bytes, Some(vec![0xFD, 0xE9]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_im_modes() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();

    let im0 = model
        .encode_instruction_from_exprs("z80", None, "IM", &[Expr::Number("0".into(), span)], &ctx)
        .expect("IM 0 should resolve");
    let im1 = model
        .encode_instruction_from_exprs("z80", None, "IM", &[Expr::Number("1".into(), span)], &ctx)
        .expect("IM 1 should resolve");
    let im2 = model
        .encode_instruction_from_exprs("z80", None, "IM", &[Expr::Number("2".into(), span)], &ctx)
        .expect("IM 2 should resolve");

    assert_eq!(im0, Some(vec![0xED, 0x46]));
    assert_eq!(im1, Some(vec![0xED, 0x56]));
    assert_eq!(im2, Some(vec![0xED, 0x5E]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_half_index_forms() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();

    let ld_rr = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "LD",
            &[
                Expr::Register("IXH".to_string(), span),
                Expr::Register("B".to_string(), span),
            ],
            &ctx,
        )
        .expect("LD IXH,B should resolve");
    let ld_imm = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "LD",
            &[
                Expr::Register("IYL".to_string(), span),
                Expr::Number("18".to_string(), span),
            ],
            &ctx,
        )
        .expect("LD IYL,18 should resolve");
    let inc = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "INC",
            &[Expr::Register("IYH".to_string(), span)],
            &ctx,
        )
        .expect("INC IYH should resolve");
    let sub = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "SUB",
            &[Expr::Register("IXL".to_string(), span)],
            &ctx,
        )
        .expect("SUB IXL should resolve");
    let xor = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "XOR",
            &[
                Expr::Register("A".to_string(), span),
                Expr::Register("IYH".to_string(), span),
            ],
            &ctx,
        )
        .expect("XOR A,IYH should resolve");

    assert_eq!(ld_rr, Some(vec![0xDD, 0x60]));
    assert_eq!(ld_imm, Some(vec![0xFD, 0x2E, 0x12]));
    assert_eq!(inc, Some(vec![0xFD, 0x24]));
    assert_eq!(sub, Some(vec![0xDD, 0x95]));
    assert_eq!(xor, Some(vec![0xFD, 0xAC]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_indexed_cb_rotate() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();
    let operands = [Expr::Indirect(
        Box::new(Expr::Identifier("IX".to_string(), span)),
        span,
    )];

    let bytes = model
        .encode_instruction_from_exprs("z80", None, "RLC", &operands, &ctx)
        .expect("RLC (IX) should resolve");

    assert_eq!(bytes, Some(vec![0xDD, 0xCB, 0x00, 0x06]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_indexed_cb_bit() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();
    let operands = [
        Expr::Number("2".to_string(), span),
        Expr::Indirect(Box::new(Expr::Identifier("IY".to_string(), span)), span),
    ];

    let bytes = model
        .encode_instruction_from_exprs("z80", None, "BIT", &operands, &ctx)
        .expect("BIT 2,(IY) should resolve");

    assert_eq!(bytes, Some(vec![0xFD, 0xCB, 0x00, 0x56]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_nonindexed_cb_bit_forms() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();

    let bit = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "BIT",
            &[
                Expr::Number("2".to_string(), span),
                Expr::Register("A".to_string(), span),
            ],
            &ctx,
        )
        .expect("BIT 2,A should resolve");
    let res = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "RES",
            &[
                Expr::Number("6".to_string(), span),
                Expr::Indirect(Box::new(Expr::Identifier("HL".to_string(), span)), span),
            ],
            &ctx,
        )
        .expect("RES 6,(HL) should resolve");
    let set = model
        .encode_instruction_from_exprs(
            "z80",
            None,
            "SET",
            &[
                Expr::Number("4".to_string(), span),
                Expr::Register("E".to_string(), span),
            ],
            &ctx,
        )
        .expect("SET 4,E should resolve");

    assert_eq!(bit, Some(vec![0xCB, 0x57]));
    assert_eq!(res, Some(vec![0xCB, 0xB6]));
    assert_eq!(set, Some(vec![0xCB, 0xE3]));
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_indexed_memory_ld_forms() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();
    let load_from_idx = [
        Expr::Identifier("A".to_string(), span),
        Expr::Indirect(Box::new(Expr::Identifier("IX".to_string(), span)), span),
    ];
    let store_imm_idx = [
        Expr::Indirect(Box::new(Expr::Identifier("IY".to_string(), span)), span),
        Expr::Number("66".to_string(), span),
    ];

    let load_bytes = model
        .encode_instruction_from_exprs("z80", None, "LD", &load_from_idx, &ctx)
        .expect("LD A,(IX) should resolve");
    let store_bytes = model
        .encode_instruction_from_exprs("z80", None, "LD", &store_imm_idx, &ctx)
        .expect("LD (IY),n should resolve");

    assert_eq!(load_bytes, Some(vec![0xDD, 0x7E, 0x00]));
    assert_eq!(store_bytes, Some(vec![0xFD, 0x36, 0x00, 0x42]));
}

#[test]
fn execution_model_intel_expr_candidate_supports_z80_ld_indirect_forms() {
    let span = Span::default();
    let load_candidate = intel8080_ld_indirect_candidate(
        "LD",
        "z80",
        &[
            IntelOperand::Register("BC".to_string(), span),
            IntelOperand::IndirectAddress16(0x4000, span),
        ],
    )
    .expect("LD BC,(nn) should yield a VM candidate");
    let store_candidate = intel8080_ld_indirect_candidate(
        "LD",
        "z80",
        &[
            IntelOperand::IndirectAddress16(0x5000, span),
            IntelOperand::Register("IY".to_string(), span),
        ],
    )
    .expect("LD (nn),IY should yield a VM candidate");

    assert_eq!(
        load_candidate.mode_key,
        mode_key_for_z80_ld_indirect("BC", false).expect("valid mode key")
    );
    assert_eq!(load_candidate.operand_bytes, vec![vec![0x00, 0x40]]);
    assert_eq!(
        store_candidate.mode_key,
        mode_key_for_z80_ld_indirect("IY", true).expect("valid mode key")
    );
    assert_eq!(store_candidate.operand_bytes, vec![vec![0x00, 0x50]]);
}

#[test]
fn execution_model_intel_expr_candidate_supports_rst_vector_forms() {
    let span = Span::default();
    let candidate = intel8080_candidate_from_resolved(
        "RST",
        "8085",
        &[IntelOperand::RstVector(3, span)],
        &TestAssemblerContext::new(),
    )
    .expect("RST 3 should yield a VM candidate");
    let entry = crate::families::intel8080::table::lookup_instruction("RST", Some("3"), None)
        .expect("RST 3 table entry should exist");
    assert_eq!(candidate.mode_key, mode_key_for_instruction_entry(entry));
    assert!(candidate.operand_bytes.is_empty());
}

#[test]
fn execution_model_intel_expr_encode_supports_z80_indexed_memory_alu_forms() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();
    let and_idx = [Expr::Indirect(
        Box::new(Expr::Identifier("IX".to_string(), span)),
        span,
    )];
    let sub_a_idx = [
        Expr::Identifier("A".to_string(), span),
        Expr::Indirect(Box::new(Expr::Identifier("IY".to_string(), span)), span),
    ];

    let and_bytes = model
        .encode_instruction_from_exprs("z80", None, "AND", &and_idx, &ctx)
        .expect("AND (IX) should resolve");
    let sub_bytes = model
        .encode_instruction_from_exprs("z80", None, "SUB", &sub_a_idx, &ctx)
        .expect("SUB A,(IY) should resolve");

    assert_eq!(and_bytes, Some(vec![0xDD, 0xA6, 0x00]));
    assert_eq!(sub_bytes, Some(vec![0xFD, 0x96, 0x00]));
}

#[test]
fn execution_model_allows_registering_fn_family_expr_resolver() {
    let mut model =
        HierarchyExecutionModel::from_chunks(intel_only_chunks()).expect("execution model build");
    let replaced = model.register_expr_resolver_for_family("intel8080", intel_test_expr_resolver);
    assert!(replaced.is_some());
    assert!(model.supports_expr_resolution_for_family("intel8080"));
    assert!(model.expr_resolution_is_strict_for_family("intel8080"));

    let span = Span::default();
    let operands = vec![Expr::Number("66".to_string(), span)];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("8085", None, "MVI", &operands, &ctx)
        .expect("expr encode should succeed through registered resolver");
    assert_eq!(bytes, Some(vec![0x3E, 0x42]));
}

#[test]
fn execution_model_allows_registering_trait_family_expr_resolver() {
    let mut model =
        HierarchyExecutionModel::from_chunks(intel_only_chunks()).expect("execution model build");
    let replaced = model.register_family_expr_resolver(Box::new(IntelDynResolver));
    assert!(replaced.is_some());
    assert!(model.supports_expr_resolution_for_family("intel8080"));
    assert!(model.expr_resolution_is_strict_for_family("intel8080"));

    let span = Span::default();
    let operands = vec![Expr::Number("66".to_string(), span)];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("8085", None, "MVI", &operands, &ctx)
        .expect("expr encode should succeed through trait resolver");
    assert_eq!(bytes, Some(vec![0x3E, 0x42]));
}

#[test]
fn execution_model_intel_expr_resolver_is_strict() {
    let model =
        HierarchyExecutionModel::from_chunks(intel_only_chunks()).expect("execution model build");
    assert!(model.supports_expr_resolution_for_family("intel8080"));
    assert!(model.expr_resolution_is_strict_for_family("intel8080"));
}

#[test]
fn execution_model_defer_native_diagnostics_uses_resolver_capability() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    assert!(model.defer_native_diagnostics_on_expr_none("intel8080"));
    assert!(!model.defer_native_diagnostics_on_expr_none("mos6502"));
    assert!(!model.defer_native_diagnostics_on_expr_none("motorola6800"));
    assert!(!model.defer_native_diagnostics_on_expr_none("unknown"));
}

#[test]
fn execution_model_m6800_expr_resolver_is_strict() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    assert!(model.supports_expr_resolution_for_family("motorola6800"));
    assert!(model.expr_resolution_is_strict_for_family("motorola6800"));
}

#[test]
fn execution_model_m6800_expr_encode_supports_m6809_and_hd6309_paths() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let ctx = TestAssemblerContext::new();

    let m6809_immediate = [Expr::Immediate(
        Box::new(Expr::Number("66".to_string(), span)),
        span,
    )];
    let m6809_indexed = [
        Expr::Number("0".to_string(), span),
        Expr::Identifier("X".to_string(), span),
    ];

    let lda_imm = model
        .encode_instruction_from_exprs("m6809", None, "LDA", &m6809_immediate, &ctx)
        .expect("m6809 immediate should resolve");
    let lda_indexed = model
        .encode_instruction_from_exprs("m6809", None, "LDA", &m6809_indexed, &ctx)
        .expect("m6809 indexed should resolve");
    let sexw = model
        .encode_instruction_from_exprs("hd6309", None, "SEXW", &[], &ctx)
        .expect("hd6309 extension should resolve");

    assert_eq!(lda_imm, Some(vec![0x86, 0x42]));
    assert_eq!(lda_indexed, Some(vec![0xA6, 0x00]));
    assert_eq!(sexw, Some(vec![0x14]));
}

#[test]
fn execution_model_selector_gate_only_uses_cpu_capability() {
    let registry = parity_registry();
    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

    assert!(model.selector_gate_only_expr_runtime_for_cpu("65816"));
    assert!(!model.selector_gate_only_expr_runtime_for_cpu("6502"));
}

#[test]
fn execution_model_encodes_m65816_forced_long_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Number("1193046".to_string(), span),
        Expr::Register("l".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAF, 0x56, 0x34, 0x12]));
}

#[test]
fn execution_model_encodes_m65816_forced_data_bank_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Number("4660".to_string(), span),
        Expr::Register("b".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAD, 0x34, 0x12]));
}

#[test]
fn execution_model_encodes_m65816_forced_program_bank_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Number("4660".to_string(), span),
        Expr::Register("k".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "JMP", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0x4C, 0x34, 0x12]));
}

#[test]
fn execution_model_encodes_m65816_forced_direct_page_from_expr_operands() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Identifier("target".to_string(), span),
        Expr::Register("d".to_string(), span),
    ];
    let mut ctx = TestAssemblerContext::new();
    ctx.values.insert("target".to_string(), 0x20F0);
    ctx.cpu_flags
        .insert(crate::m65816::state::DIRECT_PAGE_KEY.to_string(), 0x2000);
    ctx.cpu_flags
        .insert(crate::m65816::state::DIRECT_PAGE_KNOWN_KEY.to_string(), 1);
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xA5, 0xF0]));
}

#[test]
fn execution_model_encodes_m65816_forced_long_unresolved_symbol_on_pass1() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Identifier("target".to_string(), span),
        Expr::Register("l".to_string(), span),
    ];
    let mut ctx = TestAssemblerContext::new();
    ctx.pass = 1;
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAF, 0x00, 0x00, 0x00]));
}

#[test]
fn execution_model_encodes_m65816_unresolved_symbol_as_absolute_when_bank_is_stable() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Identifier("target".to_string(), span)];
    let mut ctx = TestAssemblerContext::new();
    ctx.pass = 1;
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAD, 0x00, 0x00]));
}

#[test]
fn execution_model_encodes_m65816_unresolved_symbol_as_long_when_bank_unknown() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Identifier("target".to_string(), span)];
    let mut ctx = TestAssemblerContext::new();
    ctx.pass = 1;
    ctx.cpu_flags
        .insert(crate::m65816::state::DATA_BANK_KNOWN_KEY.to_string(), 0);
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAF, 0x00, 0x00, 0x00]));
}

#[test]
fn execution_model_folds_m65816_high_bank_literal_to_absolute_when_bank_matches() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Number("1193046".to_string(), span)];
    let mut ctx = TestAssemblerContext::new();
    ctx.cpu_flags
        .insert(crate::m65816::state::DATA_BANK_KEY.to_string(), 0x12);
    ctx.cpu_flags
        .insert(crate::m65816::state::DATA_BANK_EXPLICIT_KEY.to_string(), 1);
    ctx.cpu_flags
        .insert(crate::m65816::state::DATA_BANK_KNOWN_KEY.to_string(), 1);
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAD, 0x56, 0x34]));
}

#[test]
fn execution_model_keeps_m65816_high_bank_literal_long_when_bank_mismatches() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Number("1193046".to_string(), span)];
    let ctx = TestAssemblerContext::new();
    let bytes = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect("vm expr encode should succeed");
    assert_eq!(bytes, Some(vec![0xAF, 0x56, 0x34, 0x12]));
}

#[test]
fn execution_model_reports_m65816_invalid_force_override_without_fallback() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Number("1193046".to_string(), span),
        Expr::Register("k".to_string(), span),
    ];
    let ctx = TestAssemblerContext::new();
    let err = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect_err("vm runtime should reject invalid force override");
    assert_eq!(
        err.to_string(),
        "Explicit addressing override ',k' is not valid for LDA"
    );
}

#[test]
fn execution_model_reports_m65816_force_data_bank_unknown() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let span = Span::default();
    let operands = vec![
        Expr::Number("1193046".to_string(), span),
        Expr::Register("b".to_string(), span),
    ];
    let mut ctx = TestAssemblerContext::new();
    ctx.cpu_flags
        .insert(crate::m65816::state::DATA_BANK_KNOWN_KEY.to_string(), 0);
    let err = model
        .encode_instruction_from_exprs("65816", None, "LDA", &operands, &ctx)
        .expect_err("vm runtime should require known data bank");
    assert!(err.to_string().contains(".assume dbr"));
    assert!(err.to_string().contains("forced with ',l'"));
}

#[test]
fn m6502_expr_candidates_prefer_absolute_for_unstable_symbols() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let resolved = model
        .resolve_pipeline("m6502", None)
        .expect("resolve m6502 pipeline");

    let span = Span::default();
    let expr = Expr::Identifier("target".to_string(), span);
    let mut ctx = TestAssemblerContext::new();
    ctx.values.insert("target".to_string(), 0x10);
    ctx.finalized.insert("target".to_string(), false);
    let candidates = model
        .select_candidates_from_exprs_mos6502(&resolved, "LDA", &[expr], &ctx)
        .expect("m6502 selector candidates")
        .expect("m6502 candidates should exist");
    assert_eq!(candidates[0].mode_key, "absolute");
    assert!(candidates
        .iter()
        .all(|candidate| candidate.mode_key != "zeropage"));
}

#[test]
fn m6502_expr_candidates_use_portable_eval_under_rollout_gate() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let resolved = model
        .resolve_pipeline("m6502", None)
        .expect("resolve m6502 pipeline");

    let span = Span::default();
    let expr = Expr::Number("66".to_string(), span);
    let mut ctx = TestAssemblerContext::new();
    ctx.fail_eval_expr = true;

    let candidates = model
        .select_candidates_from_exprs_mos6502(&resolved, "LDA", &[expr], &ctx)
        .expect("m6502 selector candidates")
        .expect("m6502 candidates should exist");

    assert_eq!(candidates[0].operand_bytes, vec![vec![66]]);
}

#[test]
fn execution_model_vm_encode_supports_m65c02_bit_branch_tables() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let operands = MOS6502Operands(vec![
        Operand::ZeroPage(0x12, Span::default()),
        Operand::Relative(0x05, Span::default()),
    ]);
    let bytes = model
        .encode_instruction("65c02", None, "BBR0", &operands)
        .expect("vm encode should resolve");
    assert_eq!(bytes, Some(vec![0x0F, 0x12, 0x05]));
}

#[test]
fn execution_model_uses_package_tabl_programs_for_vm_encode() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    let mut patched = false;
    for program in &mut chunks.tables {
        let is_mos6502_family_owner = matches!(&program.owner, ScopedOwner::Family(owner) if owner.eq_ignore_ascii_case("mos6502"));
        if is_mos6502_family_owner
            && program.mnemonic.eq_ignore_ascii_case("lda")
            && program.mode_key.eq_ignore_ascii_case("immediate")
        {
            program.program = vec![OP_EMIT_U8, 0xEA, OP_EMIT_OPERAND, 0x00, OP_END];
            patched = true;
            break;
        }
    }
    assert!(
        patched,
        "expected to patch LDA immediate VM program in TABL"
    );

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
    let bytes = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect("vm encode should succeed")
        .expect("m6502 vm program should be available");
    assert_eq!(bytes, vec![0xEA, 0x42]);
}

#[test]
fn execution_model_loads_from_encoded_package_bytes() {
    let registry = mos6502_family_registry();

    let package_bytes =
        build_hierarchy_package_from_registry(&registry).expect("package bytes build");
    let model = HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice())
        .expect("execution model build from package bytes");
    let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
    let bytes = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect("vm encode should succeed")
        .expect("m6502 vm program should be available");
    assert_eq!(bytes, vec![0xA9, 0x42]);
}

#[test]
fn ultimate64_abi_runtime_model_owns_package_bytes_after_load() {
    let registry = mos6502_family_registry();

    let mut package_bytes =
        build_hierarchy_package_from_registry(&registry).expect("package bytes build");
    let model = HierarchyExecutionModel::from_package_bytes(package_bytes.as_slice())
        .expect("execution model build from package bytes");
    package_bytes.fill(0);

    let tokens = model
        .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
        .expect("runtime model should not borrow package buffer after load");
    assert!(
        !tokens.is_empty(),
        "expected tokens after package buffer reuse"
    );
}

#[test]
fn native6502_abi_control_block_v1_layout_is_stable() {
    assert_eq!(NATIVE_6502_ABI_MAGIC_V1, *b"OT65");
    assert_eq!(NATIVE_6502_ABI_VERSION_V1, 0x0001);
    assert_eq!(NATIVE_6502_CONTROL_BLOCK_SIZE_V1, 32);

    assert_eq!(NATIVE_6502_CB_MAGIC_OFFSET, 0);
    assert_eq!(NATIVE_6502_CB_ABI_VERSION_OFFSET, 4);
    assert_eq!(NATIVE_6502_CB_STRUCT_SIZE_OFFSET, 6);
    assert_eq!(NATIVE_6502_CB_CAPABILITY_FLAGS_OFFSET, 8);
    assert_eq!(NATIVE_6502_CB_STATUS_CODE_OFFSET, 10);
    assert_eq!(NATIVE_6502_CB_REQUEST_ID_OFFSET, 12);
    assert_eq!(NATIVE_6502_CB_RESERVED0_OFFSET, 14);
    assert_eq!(NATIVE_6502_CB_INPUT_PTR_OFFSET, 16);
    assert_eq!(NATIVE_6502_CB_INPUT_LEN_OFFSET, 18);
    assert_eq!(NATIVE_6502_CB_OUTPUT_PTR_OFFSET, 20);
    assert_eq!(NATIVE_6502_CB_OUTPUT_LEN_OFFSET, 22);
    assert_eq!(NATIVE_6502_CB_EXTENSION_PTR_OFFSET, 24);
    assert_eq!(NATIVE_6502_CB_EXTENSION_LEN_OFFSET, 26);
    assert_eq!(NATIVE_6502_CB_LAST_ERROR_PTR_OFFSET, 28);
    assert_eq!(NATIVE_6502_CB_LAST_ERROR_LEN_OFFSET, 30);
    assert_eq!(
        NATIVE_6502_CB_LAST_ERROR_LEN_OFFSET + std::mem::size_of::<u16>(),
        NATIVE_6502_CONTROL_BLOCK_SIZE_V1 as usize
    );

    assert_eq!(NATIVE_6502_CAPABILITY_EXT_TLV_V1, 1 << 0);
    assert_eq!(NATIVE_6502_CAPABILITY_STRUCT_LAYOUTS_V1, 1 << 1);
    assert_eq!(NATIVE_6502_CAPABILITY_ENUM_TABLES_V1, 1 << 2);

    let mut control_block = [0u8; NATIVE_6502_CONTROL_BLOCK_SIZE_V1 as usize];
    control_block[NATIVE_6502_CB_MAGIC_OFFSET..NATIVE_6502_CB_MAGIC_OFFSET + 4]
        .copy_from_slice(&NATIVE_6502_ABI_MAGIC_V1);
    control_block[NATIVE_6502_CB_ABI_VERSION_OFFSET..NATIVE_6502_CB_ABI_VERSION_OFFSET + 2]
        .copy_from_slice(&NATIVE_6502_ABI_VERSION_V1.to_le_bytes());
    control_block[NATIVE_6502_CB_STRUCT_SIZE_OFFSET..NATIVE_6502_CB_STRUCT_SIZE_OFFSET + 2]
        .copy_from_slice(&NATIVE_6502_CONTROL_BLOCK_SIZE_V1.to_le_bytes());
    control_block
        [NATIVE_6502_CB_CAPABILITY_FLAGS_OFFSET..NATIVE_6502_CB_CAPABILITY_FLAGS_OFFSET + 2]
        .copy_from_slice(
            &(NATIVE_6502_CAPABILITY_EXT_TLV_V1
                | NATIVE_6502_CAPABILITY_STRUCT_LAYOUTS_V1
                | NATIVE_6502_CAPABILITY_ENUM_TABLES_V1)
                .to_le_bytes(),
        );

    assert_eq!(
        &control_block[NATIVE_6502_CB_MAGIC_OFFSET..NATIVE_6502_CB_MAGIC_OFFSET + 4],
        b"OT65"
    );
    assert_eq!(
        u16::from_le_bytes([
            control_block[NATIVE_6502_CB_ABI_VERSION_OFFSET],
            control_block[NATIVE_6502_CB_ABI_VERSION_OFFSET + 1],
        ]),
        NATIVE_6502_ABI_VERSION_V1
    );
    assert_eq!(
        u16::from_le_bytes([
            control_block[NATIVE_6502_CB_STRUCT_SIZE_OFFSET],
            control_block[NATIVE_6502_CB_STRUCT_SIZE_OFFSET + 1],
        ]),
        NATIVE_6502_CONTROL_BLOCK_SIZE_V1
    );
    assert_eq!(
        u16::from_le_bytes([
            control_block[NATIVE_6502_CB_CAPABILITY_FLAGS_OFFSET],
            control_block[NATIVE_6502_CB_CAPABILITY_FLAGS_OFFSET + 1],
        ]),
        NATIVE_6502_CAPABILITY_EXT_TLV_V1
            | NATIVE_6502_CAPABILITY_STRUCT_LAYOUTS_V1
            | NATIVE_6502_CAPABILITY_ENUM_TABLES_V1
    );
}

#[test]
fn native6502_abi_entrypoint_ordinals_are_stable() {
    assert_eq!(NATIVE_6502_ENTRYPOINT_INIT_V1, 0);
    assert_eq!(NATIVE_6502_ENTRYPOINT_LOAD_PACKAGE_V1, 1);
    assert_eq!(NATIVE_6502_ENTRYPOINT_SET_PIPELINE_V1, 2);
    assert_eq!(NATIVE_6502_ENTRYPOINT_TOKENIZE_LINE_V1, 3);
    assert_eq!(NATIVE_6502_ENTRYPOINT_PARSE_LINE_V1, 4);
    assert_eq!(NATIVE_6502_ENTRYPOINT_ENCODE_INSTRUCTION_V1, 5);
    assert_eq!(NATIVE_6502_ENTRYPOINT_LAST_ERROR_V1, 6);
    assert_eq!(NATIVE_6502_ENTRYPOINT_COUNT_V1, 7);

    let ordinals = [
        NATIVE_6502_ENTRYPOINT_INIT_V1,
        NATIVE_6502_ENTRYPOINT_LOAD_PACKAGE_V1,
        NATIVE_6502_ENTRYPOINT_SET_PIPELINE_V1,
        NATIVE_6502_ENTRYPOINT_TOKENIZE_LINE_V1,
        NATIVE_6502_ENTRYPOINT_PARSE_LINE_V1,
        NATIVE_6502_ENTRYPOINT_ENCODE_INSTRUCTION_V1,
        NATIVE_6502_ENTRYPOINT_LAST_ERROR_V1,
    ];
    for (expected, ordinal) in ordinals.into_iter().enumerate() {
        assert_eq!(ordinal as usize, expected);
    }
}

#[test]
fn execution_model_rejects_invalid_package_bytes() {
    let err = HierarchyExecutionModel::from_package_bytes(b"not-an-opcpu")
        .expect_err("invalid package bytes should be rejected");
    assert!(matches!(err, RuntimeBridgeError::Package(_)));
}

#[test]
fn execution_model_returns_none_when_target_has_no_tabl_programs() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.tables.clear();

    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
    let bytes = model
        .encode_instruction("m6502", None, "LDA", &operands)
        .expect("vm encode should resolve");
    assert!(bytes.is_none());
}

#[test]
fn execution_model_uses_package_diag_template_for_missing_vm_program() {
    let registry = mos6502_family_registry();

    let mut chunks =
        build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
    chunks.tables.clear();
    chunks.diagnostics = vec![DiagnosticDescriptor {
        code: DIAG_OPTHREAD_MISSING_VM_PROGRAM.to_string(),
        message_template: "no vm program for {mnemonic}".to_string(),
    }];
    let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
    let span = Span::default();
    let operands = vec![Expr::Immediate(
        Box::new(Expr::Number("66".to_string(), span)),
        span,
    )];
    let ctx = TestAssemblerContext::new();
    let err = model
        .encode_instruction_from_exprs("m6502", None, "LDA", &operands, &ctx)
        .expect_err("missing VM program should produce a resolve error");
    assert_eq!(err.to_string(), "no vm program for LDA");
}

#[test]
fn execution_model_vm_encode_supports_m65816_cpu_tables() {
    let registry = mos6502_family_registry();

    let model = HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
    let operands = MOS6502Operands(vec![Operand::AbsoluteLong(0x001234, Span::default())]);
    let bytes = model
        .encode_instruction("65816", None, "JSL", &operands)
        .expect("vm encode should resolve");
    assert_eq!(bytes, Some(vec![0x22, 0x34, 0x12, 0x00]));
}
