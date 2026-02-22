// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Host/runtime bridge helpers for hierarchy-aware target selection.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use crate::core::expr_vm::{
    compile_core_expr_to_portable_program, eval_portable_expr_program,
    expr_program_has_unstable_symbols, PortableExprBudgets, PortableExprEvalContext,
    PortableExprEvaluation, PortableExprProgram,
};
use crate::core::family::AssemblerContext;
use crate::core::parser::{
    AssignOp, BinaryOp, Expr, Label, LineAst, ParseError, Parser, SignatureAtom,
    StatementSignature, UnaryOp, UseItem, UseParam,
};
use crate::core::registry::{ModuleRegistry, OperandSet, VmEncodeCandidate};
use crate::core::tokenizer::{
    register_checker_none, ConditionalKind, NumberLiteral, OperatorKind, Span, StringLiteral,
    Token, TokenKind, Tokenizer,
};
use crate::families::mos6502::OperandForce;
use crate::opthread::builder::{build_hierarchy_package_from_registry, HierarchyBuildError};
use crate::opthread::hierarchy::{
    HierarchyError, HierarchyPackage, ResolvedHierarchy, ResolvedHierarchyContext, ScopedOwner,
};
use crate::opthread::package::{
    decode_hierarchy_chunks, default_token_policy_lexical_defaults, HierarchyChunks,
    ModeSelectorDescriptor, OpcpuCodecError, TokenCaseRule, TokenizerVmDiagnosticMap,
    TokenizerVmLimits, TokenizerVmOpcode, DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502,
    DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02, DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE,
    DIAG_OPTHREAD_MISSING_VM_PROGRAM, EXPR_PARSER_VM_OPCODE_VERSION_V1, EXPR_VM_OPCODE_VERSION_V1,
    PARSER_AST_SCHEMA_ID_LINE_V1, PARSER_GRAMMAR_ID_LINE_V1, PARSER_VM_OPCODE_VERSION_V1,
    TOKENIZER_VM_OPCODE_VERSION_V1,
};
use crate::opthread::rollout::{
    family_expr_parser_rollout_policy, portable_expr_parser_runtime_enabled_for_family,
};
use crate::opthread::vm::{execute_program, VmError};

mod contract_bridge;
mod encoding_bridge;
mod expression_bridge;
mod model_core_helpers;
mod portable_contract;
mod runtime_expr_parser;
mod selector_bridge;
mod selector_encoding;
mod tokenizer_bridge;
pub use portable_contract::*;
use runtime_expr_parser::RuntimeExpressionParser;

#[cfg(test)]
use crate::families::intel8080::Operand as IntelOperand;
#[cfg(test)]
use crate::opthread::intel8080_vm::{mode_key_for_instruction_entry, mode_key_for_z80_ld_indirect};
#[cfg(test)]
use selector_bridge::{intel8080_candidate_from_resolved, intel8080_ld_indirect_candidate};
#[cfg(test)]
use tokenizer_bridge::apply_token_policy_to_token;

#[cfg(test)]
thread_local! {
    static CORE_EXPR_PARSER_FAILPOINT: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_core_expr_parser_failpoint_for_tests(enabled: bool) {
    CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(enabled));
}

/// Family-keyed operand parse/resolve adapter used by expr-based runtime encode.
///
/// Contract:
/// - Dispatch is keyed by resolved family id.
/// - Returning `Ok(None)` means "unsupported shape/path, fall back to host/native flow".
/// - Returning `Err(...)` means deterministic family-level resolution failure.
pub type ExprResolverFn = fn(
    &HierarchyExecutionModel,
    &ResolvedHierarchy,
    &str,
    &[Expr],
    &dyn AssemblerContext,
) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError>;

/// Generic family adapter contract for expr-based parse/resolve candidate generation.
pub trait FamilyExprResolver: std::fmt::Debug + Send + Sync {
    fn family_id(&self) -> &str;
    fn resolve_candidates(
        &self,
        model: &HierarchyExecutionModel,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError>;
}

#[derive(Debug)]
struct FnFamilyExprResolver {
    family_id: String,
    resolver: ExprResolverFn,
}

impl FamilyExprResolver for FnFamilyExprResolver {
    fn family_id(&self) -> &str {
        self.family_id.as_str()
    }

    fn resolve_candidates(
        &self,
        model: &HierarchyExecutionModel,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        (self.resolver)(model, resolved, mnemonic, operands, ctx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeTokenizerMode {
    Auto,
    Vm,
}

#[derive(Debug)]
struct ExprResolverEntry {
    resolver: Box<dyn FamilyExprResolver>,
    strict: bool,
    defer_native_diagnostics_on_none: bool,
}

fn register_fn_resolver(
    map: &mut HashMap<String, ExprResolverEntry>,
    family_id: &str,
    resolver: ExprResolverFn,
    strict: bool,
    defer_native_diagnostics_on_none: bool,
) {
    let key = family_id.to_ascii_lowercase();
    map.insert(
        key.clone(),
        ExprResolverEntry {
            resolver: Box::new(FnFamilyExprResolver {
                family_id: key,
                resolver,
            }),
            strict,
            defer_native_diagnostics_on_none,
        },
    );
}

/// Errors emitted by the opThread host/runtime bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeBridgeError {
    ActiveCpuNotSet,
    Build(HierarchyBuildError),
    Package(OpcpuCodecError),
    Hierarchy(HierarchyError),
    Resolve(String),
    Vm(VmError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBudgetProfile {
    HostDefault,
    RetroConstrained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeBudgetLimits {
    pub max_candidate_count: usize,
    pub max_operand_count_per_candidate: usize,
    pub max_operand_bytes_per_operand: usize,
    pub max_vm_program_bytes: usize,
    pub max_selectors_scanned_per_instruction: usize,
    pub max_parser_tokens_per_line: usize,
    pub max_parser_ast_nodes_per_line: usize,
    pub max_parser_vm_program_bytes: usize,
    pub max_tokenizer_steps_per_line: u32,
    pub max_tokenizer_tokens_per_line: u32,
    pub max_tokenizer_lexeme_bytes: u32,
    pub max_tokenizer_errors_per_line: u32,
}

type VmProgramKey = (u8, u32, u32, u32);
type ModeSelectorKey = (u8, u32, u32, u32);
type TokenPolicyKey = (u8, u32);
type ParserContractKey = (u8, u32);
type ParserVmProgramKey = (u8, u32);
type ExprContractKey = (u8, u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTokenizerVmProgram {
    pub opcode_version: u16,
    pub start_state: u16,
    pub state_entry_offsets: Vec<u32>,
    pub limits: TokenizerVmLimits,
    pub diagnostics: TokenizerVmDiagnosticMap,
    pub program: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeParserDiagnosticMap {
    pub unexpected_token: String,
    pub expected_expression: String,
    pub expected_operand: String,
    pub invalid_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeParserContract {
    pub grammar_id: String,
    pub ast_schema_id: String,
    pub opcode_version: u16,
    pub max_ast_nodes_per_line: u32,
    pub diagnostics: RuntimeParserDiagnosticMap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeParserVmProgram {
    pub opcode_version: u16,
    pub program: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeExprDiagnosticMap {
    pub invalid_opcode: String,
    pub stack_underflow: String,
    pub stack_depth_exceeded: String,
    pub unknown_symbol: String,
    pub eval_failure: String,
    pub unsupported_feature: String,
    pub budget_exceeded: String,
    pub invalid_program: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExprContract {
    pub opcode_version: u16,
    pub max_program_bytes: u32,
    pub max_stack_depth: u32,
    pub max_symbol_refs: u32,
    pub max_eval_steps: u32,
    pub diagnostics: RuntimeExprDiagnosticMap,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeExprParserDiagnosticMap {
    pub invalid_expression_program: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExprParserContract {
    pub opcode_version: u16,
    pub diagnostics: RuntimeExprParserDiagnosticMap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeParserCertificationChecklists {
    pub expression_parser_checklist: Option<&'static str>,
    pub instruction_parse_encode_checklist: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTokenPolicy {
    pub case_rule: TokenCaseRule,
    pub identifier_start_class: u32,
    pub identifier_continue_class: u32,
    pub punctuation_chars: String,
    pub comment_prefix: String,
    pub quote_chars: String,
    pub escape_char: Option<char>,
    pub number_prefix_chars: String,
    pub number_suffix_binary: String,
    pub number_suffix_octal: String,
    pub number_suffix_decimal: String,
    pub number_suffix_hex: String,
    pub operator_chars: String,
    pub multi_char_operators: Vec<String>,
}

impl Default for RuntimeTokenPolicy {
    fn default() -> Self {
        let defaults = default_token_policy_lexical_defaults();
        Self {
            case_rule: TokenCaseRule::Preserve,
            identifier_start_class: 0,
            identifier_continue_class: 0,
            punctuation_chars: String::new(),
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
}

#[derive(Debug, Default)]
struct LowercaseIdInterner {
    ids: HashMap<String, u32>,
}

impl LowercaseIdInterner {
    fn intern(&mut self, value: &str) -> u32 {
        let key = value.to_ascii_lowercase();
        if let Some(id) = self.ids.get(&key) {
            return *id;
        }
        let next = self.ids.len();
        let id = u32::try_from(next).expect("interner id overflow");
        self.ids.insert(key, id);
        id
    }

    fn into_ids(self) -> HashMap<String, u32> {
        self.ids
    }
}

impl RuntimeBudgetProfile {
    fn limits(self) -> RuntimeBudgetLimits {
        match self {
            Self::HostDefault => RuntimeBudgetLimits {
                max_candidate_count: 64,
                max_operand_count_per_candidate: 8,
                max_operand_bytes_per_operand: 8,
                max_vm_program_bytes: 128,
                max_selectors_scanned_per_instruction: 512,
                max_parser_tokens_per_line: 512,
                max_parser_ast_nodes_per_line: 1024,
                max_parser_vm_program_bytes: 256,
                max_tokenizer_steps_per_line: 4096,
                max_tokenizer_tokens_per_line: 256,
                max_tokenizer_lexeme_bytes: 256,
                max_tokenizer_errors_per_line: 16,
            },
            Self::RetroConstrained => RuntimeBudgetLimits {
                max_candidate_count: 16,
                max_operand_count_per_candidate: 4,
                max_operand_bytes_per_operand: 4,
                max_vm_program_bytes: 48,
                max_selectors_scanned_per_instruction: 128,
                max_parser_tokens_per_line: 128,
                max_parser_ast_nodes_per_line: 128,
                max_parser_vm_program_bytes: 96,
                max_tokenizer_steps_per_line: 512,
                max_tokenizer_tokens_per_line: 64,
                max_tokenizer_lexeme_bytes: 32,
                max_tokenizer_errors_per_line: 4,
            },
        }
    }
}

impl std::fmt::Display for RuntimeBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActiveCpuNotSet => write!(f, "active cpu is not set"),
            Self::Build(err) => write!(f, "runtime model build error: {}", err),
            Self::Package(err) => write!(f, "runtime package error: {}", err),
            Self::Hierarchy(err) => write!(f, "hierarchy resolution error: {}", err),
            Self::Resolve(err) => write!(f, "{}", err),
            Self::Vm(err) => write!(f, "VM encode error: {}", err),
        }
    }
}

impl std::error::Error for RuntimeBridgeError {}

impl From<HierarchyError> for RuntimeBridgeError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

impl From<HierarchyBuildError> for RuntimeBridgeError {
    fn from(value: HierarchyBuildError) -> Self {
        Self::Build(value)
    }
}

impl From<OpcpuCodecError> for RuntimeBridgeError {
    fn from(value: OpcpuCodecError) -> Self {
        Self::Package(value)
    }
}

impl From<VmError> for RuntimeBridgeError {
    fn from(value: VmError) -> Self {
        Self::Vm(value)
    }
}

/// Small bridge state that mirrors host-side active target selection APIs.
#[derive(Debug)]
pub struct HierarchyRuntimeBridge {
    package: HierarchyPackage,
    active_cpu: Option<String>,
    dialect_override: Option<String>,
}

impl HierarchyRuntimeBridge {
    pub fn new(package: HierarchyPackage) -> Self {
        Self {
            package,
            active_cpu: None,
            dialect_override: None,
        }
    }

    pub fn active_cpu(&self) -> Option<&str> {
        self.active_cpu.as_deref()
    }

    pub fn dialect_override(&self) -> Option<&str> {
        self.dialect_override.as_deref()
    }

    pub fn set_active_cpu(&mut self, cpu_id: &str) -> Result<(), RuntimeBridgeError> {
        self.package
            .resolve_pipeline(cpu_id, self.dialect_override.as_deref())?;
        self.active_cpu = Some(cpu_id.to_string());
        Ok(())
    }

    pub fn set_dialect_override(
        &mut self,
        dialect_override: Option<&str>,
    ) -> Result<(), RuntimeBridgeError> {
        if let Some(cpu_id) = self.active_cpu.as_deref() {
            self.package.resolve_pipeline(cpu_id, dialect_override)?;
        }
        self.dialect_override = dialect_override.map(ToString::to_string);
        Ok(())
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        self.package
            .resolve_pipeline(cpu_id, dialect_override)
            .map_err(Into::into)
    }

    pub fn resolve_active_pipeline(&self) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        let cpu_id = self
            .active_cpu
            .as_deref()
            .ok_or(RuntimeBridgeError::ActiveCpuNotSet)?;
        self.resolve_pipeline(cpu_id, self.dialect_override.as_deref())
    }

    pub fn resolve_active_pipeline_context(
        &self,
    ) -> Result<ResolvedHierarchyContext<'_>, RuntimeBridgeError> {
        let cpu_id = self
            .active_cpu
            .as_deref()
            .ok_or(RuntimeBridgeError::ActiveCpuNotSet)?;
        self.package
            .resolve_pipeline_context(cpu_id, self.dialect_override.as_deref())
            .map_err(Into::into)
    }
}

pub mod native6502_abi {
    /// opThread v1 native host ABI marker for 6502-class integrations.
    pub const NATIVE_6502_ABI_MAGIC_V1: [u8; 4] = *b"OT65";
    pub const NATIVE_6502_ABI_VERSION_V1: u16 = 0x0001;

    /// Fixed control-block size for the 6502-native host ABI v1 envelope.
    pub const NATIVE_6502_CONTROL_BLOCK_SIZE_V1: u16 = 32;

    pub const NATIVE_6502_CB_MAGIC_OFFSET: usize = 0;
    pub const NATIVE_6502_CB_ABI_VERSION_OFFSET: usize = 4;
    pub const NATIVE_6502_CB_STRUCT_SIZE_OFFSET: usize = 6;
    pub const NATIVE_6502_CB_CAPABILITY_FLAGS_OFFSET: usize = 8;
    pub const NATIVE_6502_CB_STATUS_CODE_OFFSET: usize = 10;
    pub const NATIVE_6502_CB_REQUEST_ID_OFFSET: usize = 12;
    pub const NATIVE_6502_CB_RESERVED0_OFFSET: usize = 14;
    pub const NATIVE_6502_CB_INPUT_PTR_OFFSET: usize = 16;
    pub const NATIVE_6502_CB_INPUT_LEN_OFFSET: usize = 18;
    pub const NATIVE_6502_CB_OUTPUT_PTR_OFFSET: usize = 20;
    pub const NATIVE_6502_CB_OUTPUT_LEN_OFFSET: usize = 22;
    pub const NATIVE_6502_CB_EXTENSION_PTR_OFFSET: usize = 24;
    pub const NATIVE_6502_CB_EXTENSION_LEN_OFFSET: usize = 26;
    pub const NATIVE_6502_CB_LAST_ERROR_PTR_OFFSET: usize = 28;
    pub const NATIVE_6502_CB_LAST_ERROR_LEN_OFFSET: usize = 30;

    /// Capability bits for forward-compatible native ABI growth.
    pub const NATIVE_6502_CAPABILITY_EXT_TLV_V1: u16 = 1 << 0;
    pub const NATIVE_6502_CAPABILITY_STRUCT_LAYOUTS_V1: u16 = 1 << 1;
    pub const NATIVE_6502_CAPABILITY_ENUM_TABLES_V1: u16 = 1 << 2;

    /// Stable jump-table ordinals for 6502-native host runtimes.
    pub const NATIVE_6502_ENTRYPOINT_INIT_V1: u8 = 0;
    pub const NATIVE_6502_ENTRYPOINT_LOAD_PACKAGE_V1: u8 = 1;
    pub const NATIVE_6502_ENTRYPOINT_SET_PIPELINE_V1: u8 = 2;
    pub const NATIVE_6502_ENTRYPOINT_TOKENIZE_LINE_V1: u8 = 3;
    pub const NATIVE_6502_ENTRYPOINT_PARSE_LINE_V1: u8 = 4;
    pub const NATIVE_6502_ENTRYPOINT_ENCODE_INSTRUCTION_V1: u8 = 5;
    pub const NATIVE_6502_ENTRYPOINT_LAST_ERROR_V1: u8 = 6;
    pub const NATIVE_6502_ENTRYPOINT_COUNT_V1: u8 = 7;
}

pub use native6502_abi::*;

/// Minimal host-to-runtime ABI for portable/native targets.
///
/// Hosts provide resolved VM candidates plus active hierarchy ids; runtime lookup
/// and bytecode execution stays generic and package-driven.
pub trait PortableInstructionAdapter: std::fmt::Debug {
    fn cpu_id(&self) -> &str;
    fn dialect_override(&self) -> Option<&str> {
        None
    }
    fn mnemonic(&self) -> &str;
    fn vm_encode_candidates(&self) -> &[VmEncodeCandidate];
}

/// Portable tokenization request envelope for runtime VM integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableTokenizeRequest<'a> {
    pub family_id: &'a str,
    pub cpu_id: &'a str,
    pub dialect_id: &'a str,
    pub source_line: &'a str,
    pub line_num: u32,
    pub token_policy: RuntimeTokenPolicy,
}

/// Default portable request container for host adapter integration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortableInstructionRequest {
    pub cpu_id: String,
    pub dialect_override: Option<String>,
    pub mnemonic: String,
    pub candidates: Vec<VmEncodeCandidate>,
}

impl PortableInstructionAdapter for PortableInstructionRequest {
    fn cpu_id(&self) -> &str {
        self.cpu_id.as_str()
    }

    fn dialect_override(&self) -> Option<&str> {
        self.dialect_override.as_deref()
    }

    fn mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }

    fn vm_encode_candidates(&self) -> &[VmEncodeCandidate] {
        self.candidates.as_slice()
    }
}

#[derive(Debug)]
struct OperandSetInstructionAdapter<'a> {
    cpu_id: &'a str,
    dialect_override: Option<&'a str>,
    mnemonic: &'a str,
    candidates: &'a [VmEncodeCandidate],
}

impl PortableInstructionAdapter for OperandSetInstructionAdapter<'_> {
    fn cpu_id(&self) -> &str {
        self.cpu_id
    }

    fn dialect_override(&self) -> Option<&str> {
        self.dialect_override
    }

    fn mnemonic(&self) -> &str {
        self.mnemonic
    }

    fn vm_encode_candidates(&self) -> &[VmEncodeCandidate] {
        self.candidates
    }
}

/// Runtime view with resolved hierarchy bridge and scoped FORM ownership sets.
#[derive(Debug)]
pub struct HierarchyExecutionModel {
    bridge: HierarchyRuntimeBridge,
    family_forms: HashMap<String, HashSet<String>>,
    cpu_forms: HashMap<String, HashSet<String>>,
    dialect_forms: HashMap<String, HashSet<String>>,
    vm_programs: HashMap<VmProgramKey, Vec<u8>>,
    mode_selectors: HashMap<ModeSelectorKey, Vec<ModeSelectorDescriptor>>,
    token_policies: HashMap<TokenPolicyKey, RuntimeTokenPolicy>,
    tokenizer_vm_programs: HashMap<TokenPolicyKey, RuntimeTokenizerVmProgram>,
    parser_contracts: HashMap<ParserContractKey, RuntimeParserContract>,
    parser_vm_programs: HashMap<ParserVmProgramKey, RuntimeParserVmProgram>,
    expr_contracts: HashMap<ExprContractKey, RuntimeExprContract>,
    expr_parser_contracts: HashMap<ParserContractKey, RuntimeExprParserContract>,
    interned_ids: HashMap<String, u32>,
    expr_resolvers: HashMap<String, ExprResolverEntry>,
    selector_gate_only_expr_runtime_cpus: HashSet<String>,
    diag_templates: HashMap<String, String>,
    tokenizer_mode: RuntimeTokenizerMode,
    budget_profile: RuntimeBudgetProfile,
    budget_limits: RuntimeBudgetLimits,
}

impl HierarchyExecutionModel {
    pub fn from_registry(registry: &ModuleRegistry) -> Result<Self, RuntimeBridgeError> {
        let package_bytes = build_hierarchy_package_from_registry(registry)?;
        Self::from_package_bytes(package_bytes.as_slice())
    }

    pub fn from_package_bytes(bytes: &[u8]) -> Result<Self, RuntimeBridgeError> {
        let chunks = decode_hierarchy_chunks(bytes)?;
        Self::from_chunks(chunks)
    }

    pub fn from_chunks(chunks: HierarchyChunks) -> Result<Self, RuntimeBridgeError> {
        let HierarchyChunks {
            metadata: _,
            strings: _,
            diagnostics,
            token_policies,
            tokenizer_vm_programs,
            parser_contracts,
            parser_vm_programs,
            expr_contracts,
            expr_parser_contracts,
            families,
            cpus,
            dialects,
            registers: _,
            forms,
            tables,
            selectors,
        } = chunks;
        let package = HierarchyPackage::new(families, cpus, dialects)?;
        let mut interner = LowercaseIdInterner::default();
        let mut vm_programs = HashMap::new();
        for entry in tables {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            let mnemonic_id = interner.intern(entry.mnemonic.as_str());
            let mode_id = interner.intern(entry.mode_key.as_str());
            vm_programs.insert((owner_tag, owner_id, mnemonic_id, mode_id), entry.program);
        }
        let mut mode_selectors: HashMap<ModeSelectorKey, Vec<ModeSelectorDescriptor>> =
            HashMap::new();
        let mut selector_gate_only_expr_runtime_cpus: HashSet<String> = HashSet::new();
        for entry in selectors {
            if matches!(entry.owner, ScopedOwner::Cpu(_)) && entry.shape_key.contains("force_") {
                let (_, owner_id) = owner_key_parts(&entry.owner);
                selector_gate_only_expr_runtime_cpus.insert(owner_id.to_ascii_lowercase());
            }
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            let mnemonic_id = interner.intern(entry.mnemonic.as_str());
            let shape_id = interner.intern(entry.shape_key.as_str());
            mode_selectors
                .entry((owner_tag, owner_id, mnemonic_id, shape_id))
                .or_default()
                .push(entry);
        }
        for entries in mode_selectors.values_mut() {
            entries.sort_by_key(|entry| (entry.priority, entry.width_rank, entry.mode_key.clone()));
        }
        let mut scoped_token_policies: HashMap<TokenPolicyKey, RuntimeTokenPolicy> = HashMap::new();
        for entry in token_policies {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            scoped_token_policies.insert(
                (owner_tag, owner_id),
                RuntimeTokenPolicy {
                    case_rule: entry.case_rule,
                    identifier_start_class: entry.identifier_start_class,
                    identifier_continue_class: entry.identifier_continue_class,
                    punctuation_chars: entry.punctuation_chars,
                    comment_prefix: entry.comment_prefix,
                    quote_chars: entry.quote_chars,
                    escape_char: entry.escape_char,
                    number_prefix_chars: entry.number_prefix_chars,
                    number_suffix_binary: entry.number_suffix_binary,
                    number_suffix_octal: entry.number_suffix_octal,
                    number_suffix_decimal: entry.number_suffix_decimal,
                    number_suffix_hex: entry.number_suffix_hex,
                    operator_chars: entry.operator_chars,
                    multi_char_operators: entry.multi_char_operators,
                },
            );
        }
        let mut scoped_tokenizer_vm_programs: HashMap<TokenPolicyKey, RuntimeTokenizerVmProgram> =
            HashMap::new();
        for entry in tokenizer_vm_programs {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            scoped_tokenizer_vm_programs.insert(
                (owner_tag, owner_id),
                RuntimeTokenizerVmProgram {
                    opcode_version: entry.opcode_version,
                    start_state: entry.start_state,
                    state_entry_offsets: entry.state_entry_offsets,
                    limits: entry.limits,
                    diagnostics: entry.diagnostics,
                    program: entry.program,
                },
            );
        }
        let mut scoped_parser_contracts: HashMap<ParserContractKey, RuntimeParserContract> =
            HashMap::new();
        for entry in parser_contracts {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            scoped_parser_contracts.insert(
                (owner_tag, owner_id),
                RuntimeParserContract {
                    grammar_id: entry.grammar_id,
                    ast_schema_id: entry.ast_schema_id,
                    opcode_version: entry.opcode_version,
                    max_ast_nodes_per_line: entry.max_ast_nodes_per_line,
                    diagnostics: RuntimeParserDiagnosticMap {
                        unexpected_token: entry.diagnostics.unexpected_token,
                        expected_expression: entry.diagnostics.expected_expression,
                        expected_operand: entry.diagnostics.expected_operand,
                        invalid_statement: entry.diagnostics.invalid_statement,
                    },
                },
            );
        }
        let mut scoped_parser_vm_programs: HashMap<ParserVmProgramKey, RuntimeParserVmProgram> =
            HashMap::new();
        for entry in parser_vm_programs {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            scoped_parser_vm_programs.insert(
                (owner_tag, owner_id),
                RuntimeParserVmProgram {
                    opcode_version: entry.opcode_version,
                    program: entry.program,
                },
            );
        }
        let mut scoped_expr_contracts: HashMap<ExprContractKey, RuntimeExprContract> =
            HashMap::new();
        for entry in expr_contracts {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            scoped_expr_contracts.insert(
                (owner_tag, owner_id),
                RuntimeExprContract {
                    opcode_version: entry.opcode_version,
                    max_program_bytes: entry.max_program_bytes,
                    max_stack_depth: entry.max_stack_depth,
                    max_symbol_refs: entry.max_symbol_refs,
                    max_eval_steps: entry.max_eval_steps,
                    diagnostics: RuntimeExprDiagnosticMap {
                        invalid_opcode: entry.diagnostics.invalid_opcode,
                        stack_underflow: entry.diagnostics.stack_underflow,
                        stack_depth_exceeded: entry.diagnostics.stack_depth_exceeded,
                        unknown_symbol: entry.diagnostics.unknown_symbol,
                        eval_failure: entry.diagnostics.eval_failure,
                        unsupported_feature: entry.diagnostics.unsupported_feature,
                        budget_exceeded: entry.diagnostics.budget_exceeded,
                        invalid_program: entry.diagnostics.invalid_program,
                    },
                },
            );
        }
        let mut scoped_expr_parser_contracts: HashMap<
            ParserContractKey,
            RuntimeExprParserContract,
        > = HashMap::new();
        for entry in expr_parser_contracts {
            let (owner_tag, owner_id) = owner_key_parts(&entry.owner);
            let owner_id = interner.intern(owner_id.as_str());
            scoped_expr_parser_contracts.insert(
                (owner_tag, owner_id),
                RuntimeExprParserContract {
                    opcode_version: entry.opcode_version,
                    diagnostics: RuntimeExprParserDiagnosticMap {
                        invalid_expression_program: entry.diagnostics.invalid_expression_program,
                    },
                },
            );
        }
        let mut family_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cpu_forms: HashMap<String, HashSet<String>> = HashMap::new();
        let mut dialect_forms: HashMap<String, HashSet<String>> = HashMap::new();
        for form in forms {
            let mnemonic = form.mnemonic.to_ascii_lowercase();
            match form.owner {
                ScopedOwner::Family(owner) => {
                    family_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
                ScopedOwner::Cpu(owner) => {
                    cpu_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
                ScopedOwner::Dialect(owner) => {
                    dialect_forms
                        .entry(owner.to_ascii_lowercase())
                        .or_default()
                        .insert(mnemonic);
                }
            }
        }
        let mut expr_resolvers: HashMap<String, ExprResolverEntry> = HashMap::new();
        register_fn_resolver(
            &mut expr_resolvers,
            "mos6502",
            HierarchyExecutionModel::select_candidates_from_exprs_mos6502,
            true,
            false,
        );
        register_fn_resolver(
            &mut expr_resolvers,
            "intel8080",
            HierarchyExecutionModel::select_candidates_from_exprs_intel8080,
            true,
            true,
        );
        let mut diag_templates = HashMap::new();
        for entry in diagnostics {
            diag_templates.insert(
                entry.code.to_ascii_lowercase(),
                entry.message_template.to_string(),
            );
        }

        Ok(Self {
            bridge: HierarchyRuntimeBridge::new(package),
            family_forms,
            cpu_forms,
            dialect_forms,
            vm_programs,
            mode_selectors,
            token_policies: scoped_token_policies,
            tokenizer_vm_programs: scoped_tokenizer_vm_programs,
            parser_contracts: scoped_parser_contracts,
            parser_vm_programs: scoped_parser_vm_programs,
            expr_contracts: scoped_expr_contracts,
            expr_parser_contracts: scoped_expr_parser_contracts,
            interned_ids: interner.into_ids(),
            expr_resolvers,
            selector_gate_only_expr_runtime_cpus,
            diag_templates,
            tokenizer_mode: RuntimeTokenizerMode::Auto,
            budget_profile: RuntimeBudgetProfile::HostDefault,
            budget_limits: RuntimeBudgetProfile::HostDefault.limits(),
        })
    }

    pub fn runtime_budget_profile(&self) -> RuntimeBudgetProfile {
        self.budget_profile
    }

    pub fn runtime_budget_limits(&self) -> RuntimeBudgetLimits {
        self.budget_limits
    }

    pub fn set_runtime_budget_profile(&mut self, profile: RuntimeBudgetProfile) {
        self.budget_profile = profile;
        self.budget_limits = profile.limits();
    }

    pub fn tokenizer_mode(&self) -> RuntimeTokenizerMode {
        self.tokenizer_mode
    }

    pub fn set_tokenizer_mode(&mut self, mode: RuntimeTokenizerMode) {
        self.tokenizer_mode = mode;
    }

    #[cfg(test)]
    fn set_runtime_budget_limits_for_tests(&mut self, limits: RuntimeBudgetLimits) {
        self.budget_limits = limits;
    }

    pub fn set_active_cpu(&mut self, cpu_id: &str) -> Result<(), RuntimeBridgeError> {
        self.bridge.set_active_cpu(cpu_id)
    }

    pub fn resolve_pipeline(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<ResolvedHierarchy, RuntimeBridgeError> {
        self.bridge.resolve_pipeline(cpu_id, dialect_override)
    }

    pub fn supports_mnemonic(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
    ) -> Result<bool, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let needle = mnemonic.to_ascii_lowercase();

        if contains_form(&self.dialect_forms, &resolved.dialect_id, &needle) {
            return Ok(true);
        }
        if contains_form(&self.cpu_forms, &resolved.cpu_id, &needle) {
            return Ok(true);
        }
        Ok(contains_form(
            &self.family_forms,
            &resolved.family_id,
            &needle,
        ))
    }

    pub fn resolve_token_policy(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<RuntimeTokenPolicy, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.token_policy_for_resolved(&resolved))
    }

    pub(crate) fn resolve_parser_contract(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeParserContract>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.parser_contract_for_resolved(&resolved).cloned())
    }

    pub(crate) fn validate_parser_contract_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        estimated_ast_nodes: usize,
    ) -> Result<RuntimeParserContract, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let contract = self
            .parser_contract_for_resolved(&resolved)
            .ok_or_else(|| {
                RuntimeBridgeError::Resolve(format!(
                    "missing opThread parser contract for family '{}'",
                    resolved.family_id
                ))
            })?;
        self.ensure_parser_contract_compatible_for_assembler(contract)?;
        let error_code = parser_contract_error_code(contract);
        let parser_token_budget = self.budget_limits.max_parser_tokens_per_line;
        if estimated_ast_nodes > parser_token_budget {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: parser token budget exceeded ({} > {})",
                error_code, estimated_ast_nodes, parser_token_budget
            )));
        }
        let max_nodes = (contract.max_ast_nodes_per_line as usize)
            .min(self.budget_limits.max_parser_ast_nodes_per_line);
        if estimated_ast_nodes > max_nodes {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: parser AST node budget exceeded ({} > {})",
                error_code, estimated_ast_nodes, max_nodes
            )));
        }
        Ok(contract.clone())
    }

    pub(crate) fn resolve_parser_vm_program(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeParserVmProgram>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.parser_vm_program_for_resolved(&resolved).cloned())
    }

    pub fn resolve_expr_contract(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeExprContract>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.expr_contract_for_resolved(&resolved).cloned())
    }

    pub(crate) fn resolve_expr_parser_contract(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeExprParserContract>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.expr_parser_contract_for_resolved(&resolved).cloned())
    }

    pub(crate) fn resolve_expr_budgets(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<PortableExprBudgets, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let Some(contract) = self.expr_contract_for_resolved(&resolved) else {
            return Ok(PortableExprBudgets::default());
        };
        if contract.opcode_version != EXPR_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "unsupported opThread expression contract opcode version {}",
                contract.opcode_version
            )));
        }
        Ok(PortableExprBudgets {
            max_program_bytes: contract.max_program_bytes as usize,
            max_stack_depth: contract.max_stack_depth as usize,
            max_symbol_refs: contract.max_symbol_refs as usize,
            max_eval_steps: contract.max_eval_steps as usize,
        })
    }

    pub(crate) fn enforce_parser_vm_program_budget_for_assembler(
        &self,
        parser_contract: &RuntimeParserContract,
        parser_vm_program: &RuntimeParserVmProgram,
    ) -> Result<(), RuntimeBridgeError> {
        let max_bytes = self.budget_limits.max_parser_vm_program_bytes;
        let actual = parser_vm_program.program.len();
        if actual > max_bytes {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: parser VM program byte budget exceeded ({} > {})",
                parser_contract_error_code(parser_contract),
                actual,
                max_bytes
            )));
        }
        Ok(())
    }

    pub(crate) fn parse_portable_line_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        line: &str,
        line_num: u32,
    ) -> Result<PortableLineAst, ParseError> {
        let register_checker = register_checker_none();
        let (line_ast, _, _) = crate::opthread::token_bridge::parse_line_with_model(
            self,
            cpu_id,
            dialect_override,
            line,
            line_num,
            &register_checker,
        )?;
        Ok(PortableLineAst::from_core_line_ast(&line_ast))
    }

    pub fn resolve_tokenizer_vm_parity_checklist(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<&'static str>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(tokenizer_vm_parity_checklist_for_family(
            resolved.family_id.as_str(),
        ))
    }

    pub fn resolve_expr_parser_vm_parity_checklist(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<&'static str>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        if family_expr_parser_rollout_policy(resolved.family_id.as_str()).is_none() {
            return Ok(None);
        }
        Ok(expr_parser_vm_parity_checklist_for_family(
            resolved.family_id.as_str(),
        ))
    }

    pub fn resolve_parser_certification_checklists(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<RuntimeParserCertificationChecklists, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let checklists = crate::opthread::rollout::parser_certification_checklists_for_family(
            resolved.family_id.as_str(),
        );
        Ok(RuntimeParserCertificationChecklists {
            expression_parser_checklist: checklists.expression_parser_checklist,
            instruction_parse_encode_checklist: checklists.instruction_parse_encode_checklist,
        })
    }

    fn diag_message(&self, code: &str, fallback: &str, args: &[(&str, &str)]) -> String {
        let Some(template) = self.diag_templates.get(&code.to_ascii_lowercase()) else {
            return fallback.to_string();
        };
        render_diag_template(template, args)
    }
}

impl HierarchyExecutionModel {
    fn mode_exists_for_owner(
        &self,
        selector: &ModeSelectorDescriptor,
        owner_tag: u8,
        owner_id: u32,
        mnemonic_id: u32,
    ) -> bool {
        let mode_key = selector.mode_key.to_ascii_lowercase();
        let Some(mode_id) = self.interned_id(&mode_key) else {
            return false;
        };
        let key = (owner_tag, owner_id, mnemonic_id, mode_id);
        self.vm_programs.contains_key(&key)
    }

    fn invalid_force_error(&self, force: OperandForce, context: &str) -> String {
        let force_token = force_suffix(force);
        let fallback = format!(
            "Explicit addressing override ',{}' is not valid for {}",
            force_token, context
        );
        self.diag_message(
            DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE,
            fallback.as_str(),
            &[("force", force_token), ("context", context)],
        )
    }

    fn non_m65816_force_error(&self, cpu_id: &str) -> String {
        if cpu_id.eq_ignore_ascii_case("65c02") {
            let fallback = "65816-only addressing mode not supported on 65C02";
            self.diag_message(DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02, fallback, &[])
        } else {
            let fallback = "65816-only addressing mode not supported on base 6502";
            self.diag_message(DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502, fallback, &[])
        }
    }
}

fn force_suffix(force: OperandForce) -> &'static str {
    match force {
        OperandForce::DirectPage => "d",
        OperandForce::DataBank => "b",
        OperandForce::ProgramBank => "k",
        OperandForce::Long => "l",
    }
}

const VM_TOKEN_KIND_IDENTIFIER: u8 = 0;
const VM_TOKEN_KIND_REGISTER: u8 = 1;
const VM_TOKEN_KIND_NUMBER: u8 = 2;
const VM_TOKEN_KIND_STRING: u8 = 3;
const VM_TOKEN_KIND_COMMA: u8 = 4;
const VM_TOKEN_KIND_COLON: u8 = 5;
const VM_TOKEN_KIND_DOLLAR: u8 = 6;
const VM_TOKEN_KIND_DOT: u8 = 7;
const VM_TOKEN_KIND_HASH: u8 = 8;
const VM_TOKEN_KIND_QUESTION: u8 = 9;
const VM_TOKEN_KIND_OPEN_BRACKET: u8 = 10;
const VM_TOKEN_KIND_CLOSE_BRACKET: u8 = 11;
const VM_TOKEN_KIND_OPEN_BRACE: u8 = 12;
const VM_TOKEN_KIND_CLOSE_BRACE: u8 = 13;
const VM_TOKEN_KIND_OPEN_PAREN: u8 = 14;
const VM_TOKEN_KIND_CLOSE_PAREN: u8 = 15;

const VM_CHAR_CLASS_WHITESPACE: u8 = 1;
const VM_CHAR_CLASS_IDENTIFIER_START: u8 = 2;
const VM_CHAR_CLASS_IDENTIFIER_CONTINUE: u8 = 3;
const VM_CHAR_CLASS_DIGIT: u8 = 4;
const VM_CHAR_CLASS_QUOTE: u8 = 5;
const VM_CHAR_CLASS_PUNCTUATION: u8 = 6;
const VM_CHAR_CLASS_OPERATOR: u8 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TokenizerVmCertification {
    family_id: &'static str,
    parity_checklist: &'static str,
}

const TOKENIZER_VM_CERTIFICATIONS: &[TokenizerVmCertification] = &[
    TokenizerVmCertification {
        family_id: "mos6502",
        parity_checklist: "Phase 5 tokenizer parity corpus and deterministic fuzz gates",
    },
    TokenizerVmCertification {
        family_id: "intel8080",
        parity_checklist: "Phase 5 tokenizer parity corpus and deterministic fuzz gates",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExprParserVmCertification {
    family_id: &'static str,
    parity_checklist: &'static str,
}

const EXPR_PARSER_VM_CERTIFICATIONS: &[ExprParserVmCertification] = &[
    ExprParserVmCertification {
        family_id: "mos6502",
        parity_checklist: "Phase 8 expression parser VM parity corpus and deterministic diff gates",
    },
    ExprParserVmCertification {
        family_id: "intel8080",
        parity_checklist: "Phase 8 expression parser VM parity corpus and deterministic diff gates",
    },
];

fn tokenizer_vm_certification_for_family(
    family_id: &str,
) -> Option<&'static TokenizerVmCertification> {
    TOKENIZER_VM_CERTIFICATIONS
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}

fn tokenizer_vm_parity_checklist_for_family(family_id: &str) -> Option<&'static str> {
    tokenizer_vm_certification_for_family(family_id).map(|entry| entry.parity_checklist)
}

fn expr_parser_vm_certification_for_family(
    family_id: &str,
) -> Option<&'static ExprParserVmCertification> {
    EXPR_PARSER_VM_CERTIFICATIONS
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}

fn expr_parser_vm_parity_checklist_for_family(family_id: &str) -> Option<&'static str> {
    expr_parser_vm_certification_for_family(family_id).map(|entry| entry.parity_checklist)
}

fn parser_contract_error_code(contract: &RuntimeParserContract) -> &str {
    let code = contract.diagnostics.invalid_statement.trim();
    if code.is_empty() {
        "opthread-runtime"
    } else {
        code
    }
}

fn render_diag_template(template: &str, args: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (key, value) in args {
        rendered = rendered.replace(&format!("{{{}}}", key), value);
    }
    rendered
}

fn owner_key_parts(owner: &ScopedOwner) -> (u8, String) {
    owner.key_parts_lowercase()
}

fn contains_form(map: &HashMap<String, HashSet<String>>, owner_id: &str, mnemonic: &str) -> bool {
    map.get(&owner_id.to_ascii_lowercase())
        .is_some_and(|forms| forms.contains(mnemonic))
}

#[cfg(test)]
mod tests;
