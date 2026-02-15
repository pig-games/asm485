// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Host/runtime bridge helpers for hierarchy-aware target selection.

use std::collections::{HashMap, HashSet};

#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::core::family::CpuHandler;
use crate::core::family::{expr_has_unstable_symbols, AssemblerContext, FamilyHandler};
use crate::core::parser::Expr;
use crate::core::registry::{ModuleRegistry, OperandSet, VmEncodeCandidate};
use crate::core::tokenizer::{
    NumberLiteral, OperatorKind, Span, StringLiteral, Token, TokenKind, Tokenizer,
};
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::families::intel8080::table::{
    lookup_instruction, ArgType as IntelArgType, InstructionEntry as IntelInstructionEntry,
};
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::families::intel8080::{Intel8080FamilyHandler, Operand as IntelOperand};
use crate::families::mos6502::{AddressMode, FamilyOperand, MOS6502FamilyHandler, OperandForce};
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::i8085::extensions::lookup_extension as lookup_i8085_extension;
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::i8085::handler::I8085CpuHandler;
use crate::m65816::state;
use crate::opthread::builder::{build_hierarchy_package_from_registry, HierarchyBuildError};
use crate::opthread::hierarchy::{
    HierarchyError, HierarchyPackage, ResolvedHierarchy, ResolvedHierarchyContext, ScopedOwner,
};
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::opthread::intel8080_vm::{mode_key_for_instruction_entry, prefix_len};
use crate::opthread::package::{
    decode_hierarchy_chunks, default_token_policy_lexical_defaults, HierarchyChunks,
    ModeSelectorDescriptor, OpcpuCodecError, TokenCaseRule, TokenizerVmDiagnosticMap,
    TokenizerVmLimits, TokenizerVmOpcode, DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502,
    DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02, DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE,
    DIAG_OPTHREAD_MISSING_VM_PROGRAM, TOKENIZER_VM_OPCODE_VERSION_V1,
};
use crate::opthread::vm::{execute_program, VmError};
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::z80::extensions::lookup_extension as lookup_z80_extension;
#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
use crate::z80::handler::Z80CpuHandler;

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
    Host,
    DelegatedCore,
    Vm,
}

#[derive(Debug)]
struct ExprResolverEntry {
    resolver: Box<dyn FamilyExprResolver>,
    strict: bool,
}

fn register_fn_resolver(
    map: &mut HashMap<String, ExprResolverEntry>,
    family_id: &str,
    resolver: ExprResolverFn,
    strict: bool,
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
    pub max_tokenizer_steps_per_line: u32,
    pub max_tokenizer_tokens_per_line: u32,
    pub max_tokenizer_lexeme_bytes: u32,
    pub max_tokenizer_errors_per_line: u32,
}

type VmProgramKey = (u8, u32, u32, u32);
type ModeSelectorKey = (u8, u32, u32, u32);
type TokenPolicyKey = (u8, u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTokenizerVmProgram {
    pub opcode_version: u16,
    pub start_state: u16,
    pub state_entry_offsets: Vec<u32>,
    pub limits: TokenizerVmLimits,
    pub diagnostics: TokenizerVmDiagnosticMap,
    pub program: Vec<u8>,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortableSpan {
    pub line: u32,
    pub col_start: usize,
    pub col_end: usize,
}

impl From<Span> for PortableSpan {
    fn from(value: Span) -> Self {
        Self {
            line: value.line,
            col_start: value.col_start,
            col_end: value.col_end,
        }
    }
}

impl From<PortableSpan> for Span {
    fn from(value: PortableSpan) -> Self {
        Self {
            line: value.line,
            col_start: value.col_start,
            col_end: value.col_end,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableOperatorKind {
    Plus,
    Minus,
    Multiply,
    Power,
    Divide,
    Mod,
    Shl,
    Shr,
    BitNot,
    LogicNot,
    BitAnd,
    BitOr,
    BitXor,
    LogicAnd,
    LogicOr,
    LogicXor,
    Eq,
    Ne,
    Ge,
    Gt,
    Le,
    Lt,
}

impl From<OperatorKind> for PortableOperatorKind {
    fn from(value: OperatorKind) -> Self {
        match value {
            OperatorKind::Plus => Self::Plus,
            OperatorKind::Minus => Self::Minus,
            OperatorKind::Multiply => Self::Multiply,
            OperatorKind::Power => Self::Power,
            OperatorKind::Divide => Self::Divide,
            OperatorKind::Mod => Self::Mod,
            OperatorKind::Shl => Self::Shl,
            OperatorKind::Shr => Self::Shr,
            OperatorKind::BitNot => Self::BitNot,
            OperatorKind::LogicNot => Self::LogicNot,
            OperatorKind::BitAnd => Self::BitAnd,
            OperatorKind::BitOr => Self::BitOr,
            OperatorKind::BitXor => Self::BitXor,
            OperatorKind::LogicAnd => Self::LogicAnd,
            OperatorKind::LogicOr => Self::LogicOr,
            OperatorKind::LogicXor => Self::LogicXor,
            OperatorKind::Eq => Self::Eq,
            OperatorKind::Ne => Self::Ne,
            OperatorKind::Ge => Self::Ge,
            OperatorKind::Gt => Self::Gt,
            OperatorKind::Le => Self::Le,
            OperatorKind::Lt => Self::Lt,
        }
    }
}

impl From<PortableOperatorKind> for OperatorKind {
    fn from(value: PortableOperatorKind) -> Self {
        match value {
            PortableOperatorKind::Plus => Self::Plus,
            PortableOperatorKind::Minus => Self::Minus,
            PortableOperatorKind::Multiply => Self::Multiply,
            PortableOperatorKind::Power => Self::Power,
            PortableOperatorKind::Divide => Self::Divide,
            PortableOperatorKind::Mod => Self::Mod,
            PortableOperatorKind::Shl => Self::Shl,
            PortableOperatorKind::Shr => Self::Shr,
            PortableOperatorKind::BitNot => Self::BitNot,
            PortableOperatorKind::LogicNot => Self::LogicNot,
            PortableOperatorKind::BitAnd => Self::BitAnd,
            PortableOperatorKind::BitOr => Self::BitOr,
            PortableOperatorKind::BitXor => Self::BitXor,
            PortableOperatorKind::LogicAnd => Self::LogicAnd,
            PortableOperatorKind::LogicOr => Self::LogicOr,
            PortableOperatorKind::LogicXor => Self::LogicXor,
            PortableOperatorKind::Eq => Self::Eq,
            PortableOperatorKind::Ne => Self::Ne,
            PortableOperatorKind::Ge => Self::Ge,
            PortableOperatorKind::Gt => Self::Gt,
            PortableOperatorKind::Le => Self::Le,
            PortableOperatorKind::Lt => Self::Lt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableTokenKind {
    Identifier(String),
    Register(String),
    Number { text: String, base: u32 },
    String { raw: String, bytes: Vec<u8> },
    Comma,
    Colon,
    Dollar,
    Dot,
    Hash,
    Question,
    OpenBracket,
    CloseBracket,
    OpenBrace,
    CloseBrace,
    OpenParen,
    CloseParen,
    Operator(PortableOperatorKind),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableToken {
    pub kind: PortableTokenKind,
    pub span: PortableSpan,
}

impl PortableToken {
    fn from_core_token(value: Token) -> Self {
        let kind = match value.kind {
            TokenKind::Identifier(name) => PortableTokenKind::Identifier(name),
            TokenKind::Register(name) => PortableTokenKind::Register(name),
            TokenKind::Number(NumberLiteral { text, base }) => {
                PortableTokenKind::Number { text, base }
            }
            TokenKind::String(StringLiteral { raw, bytes }) => {
                PortableTokenKind::String { raw, bytes }
            }
            TokenKind::Comma => PortableTokenKind::Comma,
            TokenKind::Colon => PortableTokenKind::Colon,
            TokenKind::Dollar => PortableTokenKind::Dollar,
            TokenKind::Dot => PortableTokenKind::Dot,
            TokenKind::Hash => PortableTokenKind::Hash,
            TokenKind::Question => PortableTokenKind::Question,
            TokenKind::OpenBracket => PortableTokenKind::OpenBracket,
            TokenKind::CloseBracket => PortableTokenKind::CloseBracket,
            TokenKind::OpenBrace => PortableTokenKind::OpenBrace,
            TokenKind::CloseBrace => PortableTokenKind::CloseBrace,
            TokenKind::OpenParen => PortableTokenKind::OpenParen,
            TokenKind::CloseParen => PortableTokenKind::CloseParen,
            TokenKind::Operator(op) => PortableTokenKind::Operator(op.into()),
            TokenKind::End => unreachable!("end token is not representable as portable token"),
        };
        Self {
            kind,
            span: value.span.into(),
        }
    }

    #[cfg(any(test, feature = "opthread-runtime"))]
    pub(crate) fn to_core_token(&self) -> Token {
        let kind = match &self.kind {
            PortableTokenKind::Identifier(name) => TokenKind::Identifier(name.clone()),
            PortableTokenKind::Register(name) => TokenKind::Register(name.clone()),
            PortableTokenKind::Number { text, base } => TokenKind::Number(NumberLiteral {
                text: text.clone(),
                base: *base,
            }),
            PortableTokenKind::String { raw, bytes } => TokenKind::String(StringLiteral {
                raw: raw.clone(),
                bytes: bytes.clone(),
            }),
            PortableTokenKind::Comma => TokenKind::Comma,
            PortableTokenKind::Colon => TokenKind::Colon,
            PortableTokenKind::Dollar => TokenKind::Dollar,
            PortableTokenKind::Dot => TokenKind::Dot,
            PortableTokenKind::Hash => TokenKind::Hash,
            PortableTokenKind::Question => TokenKind::Question,
            PortableTokenKind::OpenBracket => TokenKind::OpenBracket,
            PortableTokenKind::CloseBracket => TokenKind::CloseBracket,
            PortableTokenKind::OpenBrace => TokenKind::OpenBrace,
            PortableTokenKind::CloseBrace => TokenKind::CloseBrace,
            PortableTokenKind::OpenParen => TokenKind::OpenParen,
            PortableTokenKind::CloseParen => TokenKind::CloseParen,
            PortableTokenKind::Operator(op) => TokenKind::Operator((*op).into()),
        };
        Token {
            kind,
            span: self.span.into(),
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

/// Minimal host-to-runtime tokenization ABI for portable/native targets.
///
/// Host tokenizers can keep ownership of token production while accepting package-driven
/// token policy hints selected by hierarchy ownership (dialect -> cpu -> family).
pub trait PortableTokenizerAdapter: std::fmt::Debug {
    fn tokenize_statement(
        &self,
        request: &PortableTokenizeRequest<'_>,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError>;
}

/// Portable tokenization request envelope for host adapter integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableTokenizeRequest<'a> {
    pub family_id: &'a str,
    pub cpu_id: &'a str,
    pub dialect_id: &'a str,
    pub source_line: &'a str,
    pub line_num: u32,
    pub token_policy: RuntimeTokenPolicy,
}

/// Default tokenizer adapter that uses the core host tokenizer and applies
/// package-driven case-folding hints to identifier/register tokens.
#[derive(Clone, Copy, Debug, Default)]
pub struct CoreTokenizerAdapter;

impl PortableTokenizerAdapter for CoreTokenizerAdapter {
    fn tokenize_statement(
        &self,
        request: &PortableTokenizeRequest<'_>,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        let mut tokenizer = Tokenizer::new(request.source_line, request.line_num);
        let mut tokens = Vec::new();
        loop {
            let token = tokenizer
                .next_token()
                .map_err(|err| RuntimeBridgeError::Resolve(err.message))?;
            if matches!(token.kind, TokenKind::End) {
                break;
            }
            let portable = PortableToken::from_core_token(token);
            tokens.push(apply_token_policy_to_token(portable, &request.token_policy));
        }
        Ok(tokens)
    }
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
    interned_ids: HashMap<String, u32>,
    expr_resolvers: HashMap<String, ExprResolverEntry>,
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
        for entry in selectors {
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
        );
        #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
        register_fn_resolver(
            &mut expr_resolvers,
            "intel8080",
            HierarchyExecutionModel::select_candidates_from_exprs_intel8080_scaffold,
            false,
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
            interned_ids: interner.into_ids(),
            expr_resolvers,
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

    pub fn tokenize_portable_statement(
        &self,
        adapter: &dyn PortableTokenizerAdapter,
        cpu_id: &str,
        dialect_override: Option<&str>,
        source_line: &str,
        line_num: u32,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let request = PortableTokenizeRequest {
            family_id: resolved.family_id.as_str(),
            cpu_id: resolved.cpu_id.as_str(),
            dialect_id: resolved.dialect_id.as_str(),
            source_line,
            line_num,
            token_policy: self.token_policy_for_resolved(&resolved),
        };
        match self.effective_tokenizer_mode_for_resolved(&resolved) {
            RuntimeTokenizerMode::Host => Self::tokenize_with_host_core(&request),
            RuntimeTokenizerMode::DelegatedCore => adapter.tokenize_statement(&request),
            RuntimeTokenizerMode::Vm => {
                let vm_result = self
                    .tokenizer_vm_program_for_resolved(&resolved)
                    .map(|program| self.tokenize_with_vm_core(&request, &program))
                    .transpose();
                match vm_result {
                    Ok(Some(tokens)) if !tokens.is_empty() || source_line.trim().is_empty() => {
                        Ok(tokens)
                    }
                    _ => Self::tokenize_with_host_core(&request),
                }
            }
            RuntimeTokenizerMode::Auto => unreachable!("auto mode is resolved before dispatch"),
        }
    }

    pub fn resolve_tokenizer_vm_program(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeTokenizerVmProgram>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.tokenizer_vm_program_for_resolved(&resolved))
    }

    pub fn resolve_tokenizer_vm_limits(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<TokenizerVmLimits, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self
            .tokenizer_vm_program_for_resolved(&resolved)
            .map(|entry| entry.limits)
            .unwrap_or_default())
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

    pub fn encode_instruction(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
        operands: &dyn OperandSet,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let candidates = operands.vm_encode_candidates();
        let adapter = OperandSetInstructionAdapter {
            cpu_id,
            dialect_override,
            mnemonic,
            candidates: candidates.as_slice(),
        };
        self.encode_portable_instruction(&adapter)
    }

    pub fn encode_portable_instruction(
        &self,
        request: &dyn PortableInstructionAdapter,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let resolved = self
            .bridge
            .resolve_pipeline(request.cpu_id(), request.dialect_override())?;
        let candidates = request.vm_encode_candidates();
        if candidates.is_empty() {
            return Ok(None);
        }
        self.enforce_candidate_budget(candidates)?;
        self.encode_candidates(&resolved, request.mnemonic(), candidates)
    }

    pub fn encode_instruction_from_exprs(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        let Some(resolver) = self
            .expr_resolvers
            .get(&resolved.family_id.to_ascii_lowercase())
        else {
            return Ok(None);
        };
        let Some(candidates) = resolver
            .resolver
            .resolve_candidates(self, &resolved, mnemonic, operands, ctx)?
        else {
            return Ok(None);
        };
        self.enforce_candidate_budget(&candidates)?;
        match self.encode_candidates(&resolved, mnemonic, &candidates)? {
            Some(bytes) => Ok(Some(bytes)),
            None => {
                let upper = mnemonic.to_ascii_uppercase();
                let fallback = format!("missing opThread VM program for {}", upper);
                let message = self.diag_message(
                    DIAG_OPTHREAD_MISSING_VM_PROGRAM,
                    fallback.as_str(),
                    &[("mnemonic", upper.as_str())],
                );
                Err(RuntimeBridgeError::Resolve(message))
            }
        }
    }

    /// Returns `true` when this model has an expr parse/resolve adapter for the family.
    pub fn supports_expr_resolution_for_family(&self, family_id: &str) -> bool {
        self.expr_resolvers
            .contains_key(&family_id.to_ascii_lowercase())
    }

    /// Returns `true` when expr parse/resolve is strict for this family.
    ///
    /// Strict means `encode_instruction_from_exprs(..)` returning `Ok(None)` should
    /// be treated by callers as a hard runtime parse/resolve failure, not a fallback signal.
    pub fn expr_resolution_is_strict_for_family(&self, family_id: &str) -> bool {
        self.expr_resolvers
            .get(&family_id.to_ascii_lowercase())
            .map(|entry| entry.strict)
            .unwrap_or(false)
    }

    /// Registers or replaces an expr parse/resolve adapter for a family id.
    ///
    /// This is the extension seam used to onboard non-MOS family adapters without
    /// changing runtime encode core dispatch.
    pub fn register_expr_resolver_for_family(
        &mut self,
        family_id: &str,
        resolver: ExprResolverFn,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        self.register_expr_resolver_for_family_with_strict_mode(family_id, resolver, true)
    }

    /// Registers a trait-based family adapter as strict parse/resolve behavior.
    pub fn register_family_expr_resolver(
        &mut self,
        resolver: Box<dyn FamilyExprResolver>,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        self.register_family_expr_resolver_with_strict_mode(resolver, true)
    }

    fn register_expr_resolver_for_family_with_strict_mode(
        &mut self,
        family_id: &str,
        resolver: ExprResolverFn,
        strict: bool,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        let key = family_id.to_ascii_lowercase();
        self.expr_resolvers
            .insert(
                key.clone(),
                ExprResolverEntry {
                    resolver: Box::new(FnFamilyExprResolver {
                        family_id: key,
                        resolver,
                    }),
                    strict,
                },
            )
            .map(|entry| entry.resolver)
    }

    fn register_family_expr_resolver_with_strict_mode(
        &mut self,
        resolver: Box<dyn FamilyExprResolver>,
        strict: bool,
    ) -> Option<Box<dyn FamilyExprResolver>> {
        let key = resolver.family_id().to_ascii_lowercase();
        self.expr_resolvers
            .insert(key, ExprResolverEntry { resolver, strict })
            .map(|entry| entry.resolver)
    }

    fn diag_message(&self, code: &str, fallback: &str, args: &[(&str, &str)]) -> String {
        let Some(template) = self.diag_templates.get(&code.to_ascii_lowercase()) else {
            return fallback.to_string();
        };
        render_diag_template(template, args)
    }

    fn token_policy_for_resolved(&self, resolved: &ResolvedHierarchy) -> RuntimeTokenPolicy {
        let dialect_id = resolved.dialect_id.to_ascii_lowercase();
        let cpu_id = resolved.cpu_id.to_ascii_lowercase();
        let family_id = resolved.family_id.to_ascii_lowercase();
        let owner_order = [
            (2u8, self.interned_id(dialect_id.as_str())),
            (1u8, self.interned_id(cpu_id.as_str())),
            (0u8, self.interned_id(family_id.as_str())),
        ];
        for (owner_tag, owner_id) in owner_order {
            let Some(owner_id) = owner_id else {
                continue;
            };
            if let Some(policy) = self.token_policies.get(&(owner_tag, owner_id)) {
                return policy.clone();
            }
        }
        RuntimeTokenPolicy::default()
    }

    fn effective_tokenizer_mode_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> RuntimeTokenizerMode {
        match self.tokenizer_mode {
            RuntimeTokenizerMode::Auto => {
                if tokenizer_vm_authoritative_for_family(resolved.family_id.as_str()) {
                    RuntimeTokenizerMode::Vm
                } else {
                    RuntimeTokenizerMode::DelegatedCore
                }
            }
            mode => mode,
        }
    }

    fn tokenizer_vm_program_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<RuntimeTokenizerVmProgram> {
        let dialect_id = resolved.dialect_id.to_ascii_lowercase();
        let cpu_id = resolved.cpu_id.to_ascii_lowercase();
        let family_id = resolved.family_id.to_ascii_lowercase();
        let owner_order = [
            (2u8, self.interned_id(dialect_id.as_str())),
            (1u8, self.interned_id(cpu_id.as_str())),
            (0u8, self.interned_id(family_id.as_str())),
        ];
        for (owner_tag, owner_id) in owner_order {
            let Some(owner_id) = owner_id else {
                continue;
            };
            if let Some(program) = self.tokenizer_vm_programs.get(&(owner_tag, owner_id)) {
                return Some(program.clone());
            }
        }
        None
    }

    fn tokenize_with_host_core(
        request: &PortableTokenizeRequest<'_>,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        CoreTokenizerAdapter.tokenize_statement(request)
    }

    fn tokenize_with_vm_core(
        &self,
        request: &PortableTokenizeRequest<'_>,
        vm_program: &RuntimeTokenizerVmProgram,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        if vm_program.opcode_version != TOKENIZER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported tokenizer VM opcode version {}",
                vm_program.diagnostics.invalid_char, vm_program.opcode_version
            )));
        }
        if vm_program.state_entry_offsets.is_empty() {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: tokenizer VM state table is empty",
                vm_program.diagnostics.invalid_char
            )));
        }
        let start_state = usize::from(vm_program.start_state);
        let Some(start_offset) = vm_program.state_entry_offsets.get(start_state).copied() else {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: tokenizer VM start state {} out of range",
                vm_program.diagnostics.invalid_char, vm_program.start_state
            )));
        };

        let bytes = request.source_line.as_bytes();
        let max_steps_per_line = vm_program
            .limits
            .max_steps_per_line
            .min(self.budget_limits.max_tokenizer_steps_per_line);
        let max_tokens_per_line = vm_program
            .limits
            .max_tokens_per_line
            .min(self.budget_limits.max_tokenizer_tokens_per_line);
        let max_lexeme_bytes = vm_program
            .limits
            .max_lexeme_bytes
            .min(self.budget_limits.max_tokenizer_lexeme_bytes);
        let max_errors_per_line = vm_program
            .limits
            .max_errors_per_line
            .min(self.budget_limits.max_tokenizer_errors_per_line);
        let max_lexeme_bytes_usize = usize::try_from(max_lexeme_bytes).unwrap_or(usize::MAX);
        let max_tokens_per_line_usize = usize::try_from(max_tokens_per_line).unwrap_or(usize::MAX);
        let lexeme_capacity = max_lexeme_bytes_usize.min(bytes.len());
        let token_capacity = max_tokens_per_line_usize.min(bytes.len().saturating_add(1));
        let mut pc = vm_offset_to_pc(
            vm_program.program.as_slice(),
            start_offset,
            vm_program.diagnostics.invalid_char.as_str(),
            "start state offset",
        )?;
        let mut cursor = 0usize;
        let mut current_byte: Option<u8> = None;
        let mut lexeme = Vec::with_capacity(lexeme_capacity);
        let mut lexeme_start = 0usize;
        let mut lexeme_end = 0usize;
        let mut tokens = Vec::with_capacity(token_capacity);
        let mut emitted_errors = 0u32;
        let mut step_count = 0u32;

        loop {
            step_count = step_count.saturating_add(1);
            if step_count > max_steps_per_line {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: tokenizer VM step budget exceeded ({}/{})",
                    vm_program.diagnostics.step_limit_exceeded, step_count, max_steps_per_line
                )));
            }

            let opcode_byte = vm_read_u8(
                vm_program.program.as_slice(),
                &mut pc,
                vm_program.diagnostics.invalid_char.as_str(),
                "opcode",
            )?;
            let Some(opcode) = TokenizerVmOpcode::from_u8(opcode_byte) else {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: unknown tokenizer VM opcode 0x{:02X}",
                    vm_program.diagnostics.invalid_char, opcode_byte
                )));
            };

            match opcode {
                TokenizerVmOpcode::End => break,
                TokenizerVmOpcode::ReadChar => {
                    current_byte = bytes.get(cursor).copied();
                }
                TokenizerVmOpcode::Advance => {
                    if cursor < bytes.len() {
                        cursor += 1;
                    }
                }
                TokenizerVmOpcode::StartLexeme => {
                    lexeme.clear();
                    lexeme_start = cursor;
                    lexeme_end = cursor;
                }
                TokenizerVmOpcode::PushChar => {
                    let Some(byte) = current_byte else {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: PushChar requires ReadChar at non-EOL",
                            vm_program.diagnostics.invalid_char
                        )));
                    };
                    if lexeme.len() >= max_lexeme_bytes_usize {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: tokenizer VM lexeme budget exceeded ({}/{})",
                            vm_program.diagnostics.lexeme_limit_exceeded,
                            lexeme.len().saturating_add(1),
                            max_lexeme_bytes
                        )));
                    }
                    lexeme.push(byte);
                    lexeme_end = cursor.saturating_add(1);
                }
                TokenizerVmOpcode::EmitToken => {
                    let token_kind = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "emit token kind",
                    )?;
                    if tokens.len() >= max_tokens_per_line_usize {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: tokenizer VM token budget exceeded ({}/{})",
                            vm_program.diagnostics.token_limit_exceeded,
                            tokens.len().saturating_add(1),
                            max_tokens_per_line
                        )));
                    }
                    let token = vm_build_token(
                        token_kind,
                        lexeme.as_slice(),
                        request.line_num,
                        lexeme_start,
                        lexeme_end,
                        cursor,
                    )?;
                    tokens.push(apply_token_policy_to_token(token, &request.token_policy));
                }
                TokenizerVmOpcode::SetState => {
                    let state = usize::from(vm_read_u16(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "state index",
                    )?);
                    let Some(offset) = vm_program.state_entry_offsets.get(state).copied() else {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: state index {} out of range",
                            vm_program.diagnostics.invalid_char, state
                        )));
                    };
                    pc = vm_offset_to_pc(
                        vm_program.program.as_slice(),
                        offset,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "state entry offset",
                    )?;
                }
                TokenizerVmOpcode::Jump => {
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "jump target",
                    )?;
                    pc = vm_offset_to_pc(
                        vm_program.program.as_slice(),
                        target,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "jump target",
                    )?;
                }
                TokenizerVmOpcode::JumpIfEol => {
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "conditional jump target",
                    )?;
                    if cursor >= bytes.len() {
                        pc = vm_offset_to_pc(
                            vm_program.program.as_slice(),
                            target,
                            vm_program.diagnostics.invalid_char.as_str(),
                            "conditional jump target",
                        )?;
                    }
                }
                TokenizerVmOpcode::JumpIfByteEq => {
                    let expected = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "expected byte",
                    )?;
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "conditional jump target",
                    )?;
                    if current_byte.is_some_and(|byte| byte == expected) {
                        pc = vm_offset_to_pc(
                            vm_program.program.as_slice(),
                            target,
                            vm_program.diagnostics.invalid_char.as_str(),
                            "conditional jump target",
                        )?;
                    }
                }
                TokenizerVmOpcode::JumpIfClass => {
                    let class = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "character class",
                    )?;
                    let target = vm_read_u32(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "conditional jump target",
                    )?;
                    if vm_char_class_matches(current_byte, class, &request.token_policy) {
                        pc = vm_offset_to_pc(
                            vm_program.program.as_slice(),
                            target,
                            vm_program.diagnostics.invalid_char.as_str(),
                            "conditional jump target",
                        )?;
                    }
                }
                TokenizerVmOpcode::Fail => {
                    let reason = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "failure reason",
                    )?;
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM failure reason {}",
                        vm_program.diagnostics.invalid_char, reason
                    )));
                }
                TokenizerVmOpcode::EmitDiag => {
                    let slot = vm_read_u8(
                        vm_program.program.as_slice(),
                        &mut pc,
                        vm_program.diagnostics.invalid_char.as_str(),
                        "diagnostic slot",
                    )?;
                    emitted_errors = emitted_errors.saturating_add(1);
                    if emitted_errors > max_errors_per_line {
                        return Err(RuntimeBridgeError::Resolve(format!(
                            "{}: tokenizer VM diagnostic budget exceeded ({}/{})",
                            vm_program.diagnostics.error_limit_exceeded,
                            emitted_errors,
                            max_errors_per_line
                        )));
                    }
                    let code = vm_diag_code_for_slot(&vm_program.diagnostics, slot);
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM emitted diagnostic slot {}",
                        code, slot
                    )));
                }
            }
        }

        Ok(tokens)
    }

    fn interned_id(&self, value_lower: &str) -> Option<u32> {
        self.interned_ids.get(value_lower).copied()
    }

    fn encode_candidates(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        candidates: &[VmEncodeCandidate],
    ) -> Result<Option<Vec<u8>>, RuntimeBridgeError> {
        let normalized_mnemonic = mnemonic.to_ascii_lowercase();
        let Some(mnemonic_id) = self.interned_id(&normalized_mnemonic) else {
            return Ok(None);
        };
        let dialect_id = resolved.dialect_id.to_ascii_lowercase();
        let cpu_id = resolved.cpu_id.to_ascii_lowercase();
        let family_id = resolved.family_id.to_ascii_lowercase();
        let owner_order = [
            (2u8, self.interned_id(&dialect_id)),
            (1u8, self.interned_id(&cpu_id)),
            (0u8, self.interned_id(&family_id)),
        ];

        for candidate in candidates {
            let mode_key = candidate.mode_key.to_ascii_lowercase();
            let Some(mode_id) = self.interned_id(&mode_key) else {
                continue;
            };
            let operand_views: Vec<&[u8]> =
                candidate.operand_bytes.iter().map(Vec::as_slice).collect();
            for (owner_tag, owner_id) in owner_order {
                let Some(owner_id) = owner_id else {
                    continue;
                };
                let key = (owner_tag, owner_id, mnemonic_id, mode_id);
                if let Some(program) = self.vm_programs.get(&key) {
                    self.enforce_vm_program_budget(program.len())?;
                    return execute_program(program, operand_views.as_slice())
                        .map(Some)
                        .map_err(Into::into);
                }
            }
        }
        Ok(None)
    }

    fn enforce_candidate_budget(
        &self,
        candidates: &[VmEncodeCandidate],
    ) -> Result<(), RuntimeBridgeError> {
        if candidates.len() > self.budget_limits.max_candidate_count {
            return Err(Self::budget_error(
                "candidate_count",
                self.budget_limits.max_candidate_count,
                candidates.len(),
            ));
        }
        for candidate in candidates {
            if candidate.operand_bytes.len() > self.budget_limits.max_operand_count_per_candidate {
                return Err(Self::budget_error(
                    "operand_count_per_candidate",
                    self.budget_limits.max_operand_count_per_candidate,
                    candidate.operand_bytes.len(),
                ));
            }
            for operand_bytes in &candidate.operand_bytes {
                if operand_bytes.len() > self.budget_limits.max_operand_bytes_per_operand {
                    return Err(Self::budget_error(
                        "operand_bytes_per_operand",
                        self.budget_limits.max_operand_bytes_per_operand,
                        operand_bytes.len(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn enforce_vm_program_budget(&self, program_len: usize) -> Result<(), RuntimeBridgeError> {
        if program_len > self.budget_limits.max_vm_program_bytes {
            return Err(Self::budget_error(
                "vm_program_bytes",
                self.budget_limits.max_vm_program_bytes,
                program_len,
            ));
        }
        Ok(())
    }

    fn budget_error(name: &str, limit: usize, observed: usize) -> RuntimeBridgeError {
        RuntimeBridgeError::Resolve(format!(
            "opThread runtime budget exceeded ({name}): observed {observed}, limit {limit}"
        ))
    }
}

#[derive(Clone, Debug)]
struct SelectorInput<'a> {
    shape_key: String,
    expr0: Option<&'a Expr>,
    expr1: Option<&'a Expr>,
    force: Option<OperandForce>,
}

impl HierarchyExecutionModel {
    fn select_candidates_from_exprs_mos6502(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        let family = MOS6502FamilyHandler::new();
        let parsed = family.parse_operands(mnemonic, operands).ok();
        let Some(input) = parsed
            .as_ref()
            .and_then(|operands| selector_input_from_family_operands(operands))
        else {
            return Ok(None);
        };

        let upper_mnemonic = mnemonic.to_ascii_uppercase();
        let lower_mnemonic = mnemonic.to_ascii_lowercase();
        let Some(mnemonic_id) = self.interned_id(&lower_mnemonic) else {
            return Ok(None);
        };
        let shape_key = input.shape_key.to_ascii_lowercase();
        let Some(shape_id) = self.interned_id(&shape_key) else {
            return Ok(None);
        };
        if !resolved.cpu_id.eq_ignore_ascii_case("65816")
            && input_shape_requires_m65816(&input.shape_key)
        {
            return Err(RuntimeBridgeError::Resolve(
                self.non_m65816_force_error(&resolved.cpu_id),
            ));
        }
        let owner_order = [
            (2u8, resolved.dialect_id.as_str()),
            (1u8, resolved.cpu_id.as_str()),
            (0u8, resolved.family_id.as_str()),
        ];

        let unstable_expr = input
            .expr0
            .is_some_and(|expr| expr_has_unstable_symbols(expr, ctx));
        let mut candidates = Vec::new();
        let mut candidate_error: Option<String> = None;
        let mut saw_selector = false;
        let mut selectors_scanned = 0usize;

        for (owner_tag, owner_id) in owner_order {
            let owner_id = owner_id.to_ascii_lowercase();
            let Some(owner_id) = self.interned_id(&owner_id) else {
                continue;
            };
            let key = (owner_tag, owner_id, mnemonic_id, shape_id);
            let Some(selectors) = self.mode_selectors.get(&key) else {
                continue;
            };
            saw_selector = true;

            let has_wider = selectors.iter().any(|entry| {
                entry.width_rank > 1
                    && self.mode_exists_for_owner(entry, owner_tag, owner_id, mnemonic_id)
            });

            for selector in selectors {
                selectors_scanned += 1;
                if selectors_scanned > self.budget_limits.max_selectors_scanned_per_instruction {
                    return Err(Self::budget_error(
                        "selector_scan_count",
                        self.budget_limits.max_selectors_scanned_per_instruction,
                        selectors_scanned,
                    ));
                }
                if unstable_expr && selector.unstable_widen && has_wider {
                    continue;
                }
                match selector_to_candidate(selector, &input, &upper_mnemonic, ctx) {
                    Ok(Some(candidate)) => {
                        candidates.push(candidate);
                        if candidates.len() > self.budget_limits.max_candidate_count {
                            return Err(Self::budget_error(
                                "candidate_count",
                                self.budget_limits.max_candidate_count,
                                candidates.len(),
                            ));
                        }
                    }
                    Ok(None) => {}
                    Err(message) => {
                        if candidate_error.is_none() {
                            candidate_error = Some(message);
                        }
                    }
                }
            }
        }

        if !candidates.is_empty() {
            return Ok(Some(candidates));
        }

        if let Some(force) = input.force {
            if !resolved.cpu_id.eq_ignore_ascii_case("65816") {
                return Err(RuntimeBridgeError::Resolve(
                    self.non_m65816_force_error(&resolved.cpu_id),
                ));
            }
            if let Some(message) = candidate_error {
                return Err(RuntimeBridgeError::Resolve(message));
            }
            if !saw_selector {
                return Err(RuntimeBridgeError::Resolve(
                    self.invalid_force_error(force, &upper_mnemonic),
                ));
            }
        }

        if let Some(message) = candidate_error {
            return Err(RuntimeBridgeError::Resolve(message));
        }

        Ok(None)
    }

    #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
    fn select_candidates_from_exprs_intel8080_scaffold(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        let family = Intel8080FamilyHandler;
        let parsed = match family.parse_operands(mnemonic, operands) {
            Ok(parsed) => parsed,
            Err(_) => return Ok(None),
        };

        let resolved_operands = if resolved.cpu_id.eq_ignore_ascii_case("z80") {
            Z80CpuHandler::new().resolve_operands(mnemonic, &parsed, ctx)
        } else if resolved.cpu_id.eq_ignore_ascii_case("8085") {
            I8085CpuHandler::new().resolve_operands(mnemonic, &parsed, ctx)
        } else {
            return Ok(None);
        };
        let resolved_operands = match resolved_operands {
            Ok(ops) => ops,
            Err(_) => return Ok(None),
        };

        let Some(entry) = intel8080_lookup_instruction_entry(
            mnemonic,
            resolved.cpu_id.as_str(),
            &resolved_operands,
        ) else {
            return Ok(None);
        };
        let Some(operand_bytes) = intel8080_operand_bytes_for_entry(entry, &resolved_operands, ctx)
        else {
            return Ok(None);
        };

        Ok(Some(vec![VmEncodeCandidate {
            mode_key: mode_key_for_instruction_entry(entry),
            operand_bytes,
        }]))
    }

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

#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
fn intel8080_lookup_instruction_entry(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<&'static IntelInstructionEntry> {
    let reg1 = operands.first().and_then(intel8080_lookup_key);
    let reg2 = operands.get(1).and_then(intel8080_lookup_key);

    if let Some(entry) = lookup_instruction(mnemonic, reg1.as_deref(), reg2.as_deref()) {
        return Some(entry);
    }
    if cpu_id.eq_ignore_ascii_case("8085") {
        return lookup_i8085_extension(mnemonic, reg1.as_deref(), reg2.as_deref());
    }
    if cpu_id.eq_ignore_ascii_case("z80") {
        return lookup_z80_extension(mnemonic, reg1.as_deref(), reg2.as_deref());
    }
    None
}

#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
fn intel8080_lookup_key(operand: &IntelOperand) -> Option<String> {
    match operand {
        IntelOperand::Register(name, _) => Some(name.to_string()),
        IntelOperand::Indirect(name, _) if name.eq_ignore_ascii_case("hl") => Some("M".to_string()),
        IntelOperand::Indirect(name, _) => Some(name.to_string()),
        IntelOperand::Condition(name, _) => Some(name.to_string()),
        _ => None,
    }
}

#[cfg(feature = "opthread-runtime-intel8080-scaffold")]
fn intel8080_operand_bytes_for_entry(
    entry: &IntelInstructionEntry,
    operands: &[IntelOperand],
    ctx: &dyn AssemblerContext,
) -> Option<Vec<Vec<u8>>> {
    let imm_index = entry.num_regs as usize;
    match entry.arg_type {
        IntelArgType::None => Some(Vec::new()),
        IntelArgType::Byte => {
            let value = match operands.get(imm_index)? {
                IntelOperand::Immediate8(value, _)
                | IntelOperand::Port(value, _)
                | IntelOperand::RstVector(value, _)
                | IntelOperand::InterruptMode(value, _)
                | IntelOperand::BitNumber(value, _) => *value,
                _ => return None,
            };
            Some(vec![vec![value]])
        }
        IntelArgType::Word => {
            let value = match operands.get(imm_index)? {
                IntelOperand::Immediate16(value, _) | IntelOperand::IndirectAddress16(value, _) => {
                    *value
                }
                _ => return None,
            };
            Some(vec![vec![value as u8, (value >> 8) as u8]])
        }
        IntelArgType::Relative => {
            let value = match operands.get(imm_index)? {
                IntelOperand::Immediate8(value, _) => *value,
                IntelOperand::Immediate16(target, _) => {
                    let next_pc =
                        ctx.current_address() as i64 + prefix_len(entry.prefix) as i64 + 2;
                    let delta = *target as i64 - next_pc;
                    if !(-128..=127).contains(&delta) {
                        return None;
                    }
                    delta as i8 as u8
                }
                _ => return None,
            };
            Some(vec![vec![value]])
        }
        IntelArgType::Im => None,
    }
}

fn selector_input_from_family_operands(operands: &[FamilyOperand]) -> Option<SelectorInput<'_>> {
    match operands {
        [] => Some(SelectorInput {
            shape_key: "implied".to_string(),
            expr0: None,
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Accumulator(_)] => Some(SelectorInput {
            shape_key: "accumulator".to_string(),
            expr0: None,
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Immediate(expr)] => Some(SelectorInput {
            shape_key: "immediate".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Direct(expr)] => Some(SelectorInput {
            shape_key: "direct".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::DirectX(expr)] => Some(SelectorInput {
            shape_key: "direct_x".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::DirectY(expr)] => Some(SelectorInput {
            shape_key: "direct_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndexedIndirectX(expr) | FamilyOperand::IndirectX(expr)] => {
            Some(SelectorInput {
                shape_key: "indexed_indirect_x".to_string(),
                expr0: Some(expr),
                expr1: None,
                force: None,
            })
        }
        [FamilyOperand::IndirectIndexedY(expr)] => Some(SelectorInput {
            shape_key: "indirect_indexed_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::Indirect(expr)] => Some(SelectorInput {
            shape_key: "indirect".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLong(expr)] => Some(SelectorInput {
            shape_key: "indirect_long".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::IndirectLongY(expr)] => Some(SelectorInput {
            shape_key: "indirect_long_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::StackRelative(expr)] => Some(SelectorInput {
            shape_key: "stack_relative".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::StackRelativeIndirectIndexedY(expr)] => Some(SelectorInput {
            shape_key: "stack_relative_indirect_y".to_string(),
            expr0: Some(expr),
            expr1: None,
            force: None,
        }),
        [FamilyOperand::BlockMove { src, dst, .. }] => Some(SelectorInput {
            shape_key: "pair_direct".to_string(),
            expr0: Some(src),
            expr1: Some(dst),
            force: None,
        }),
        [FamilyOperand::Forced { inner, force, .. }] => {
            let nested = selector_input_from_family_operands(std::slice::from_ref(inner.as_ref()))?;
            Some(SelectorInput {
                shape_key: format!("{}:force_{}", nested.shape_key, force_suffix(*force)),
                force: Some(*force),
                ..nested
            })
        }
        [FamilyOperand::Direct(first), FamilyOperand::Direct(second)] => Some(SelectorInput {
            shape_key: "pair_direct".to_string(),
            expr0: Some(first),
            expr1: Some(second),
            force: None,
        }),
        _ => None,
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

fn tokenizer_vm_certification_for_family(
    family_id: &str,
) -> Option<&'static TokenizerVmCertification> {
    TOKENIZER_VM_CERTIFICATIONS
        .iter()
        .find(|entry| entry.family_id.eq_ignore_ascii_case(family_id))
}
fn tokenizer_vm_authoritative_for_family(family_id: &str) -> bool {
    tokenizer_vm_certification_for_family(family_id).is_some()
}

fn tokenizer_vm_parity_checklist_for_family(family_id: &str) -> Option<&'static str> {
    tokenizer_vm_certification_for_family(family_id).map(|entry| entry.parity_checklist)
}

fn vm_read_u8(
    program: &[u8],
    pc: &mut usize,
    diag_code: &str,
    context: &str,
) -> Result<u8, RuntimeBridgeError> {
    let Some(value) = program.get(*pc).copied() else {
        return Err(RuntimeBridgeError::Resolve(format!(
            "{}: tokenizer VM truncated while reading {}",
            diag_code, context
        )));
    };
    *pc += 1;
    Ok(value)
}

fn vm_read_u16(
    program: &[u8],
    pc: &mut usize,
    diag_code: &str,
    context: &str,
) -> Result<u16, RuntimeBridgeError> {
    let lo = vm_read_u8(program, pc, diag_code, context)?;
    let hi = vm_read_u8(program, pc, diag_code, context)?;
    Ok(u16::from_le_bytes([lo, hi]))
}

fn vm_read_u32(
    program: &[u8],
    pc: &mut usize,
    diag_code: &str,
    context: &str,
) -> Result<u32, RuntimeBridgeError> {
    let b0 = vm_read_u8(program, pc, diag_code, context)?;
    let b1 = vm_read_u8(program, pc, diag_code, context)?;
    let b2 = vm_read_u8(program, pc, diag_code, context)?;
    let b3 = vm_read_u8(program, pc, diag_code, context)?;
    Ok(u32::from_le_bytes([b0, b1, b2, b3]))
}

fn vm_offset_to_pc(
    program: &[u8],
    offset: u32,
    diag_code: &str,
    context: &str,
) -> Result<usize, RuntimeBridgeError> {
    let offset = usize::try_from(offset).map_err(|_| {
        RuntimeBridgeError::Resolve(format!(
            "{}: tokenizer VM {} exceeds host address range",
            diag_code, context
        ))
    })?;
    if offset > program.len() {
        return Err(RuntimeBridgeError::Resolve(format!(
            "{}: tokenizer VM {} {} exceeds program length {}",
            diag_code,
            context,
            offset,
            program.len()
        )));
    }
    Ok(offset)
}

fn vm_diag_code_for_slot(diagnostics: &TokenizerVmDiagnosticMap, slot: u8) -> &str {
    match slot {
        0 => diagnostics.invalid_char.as_str(),
        1 => diagnostics.unterminated_string.as_str(),
        2 => diagnostics.step_limit_exceeded.as_str(),
        3 => diagnostics.token_limit_exceeded.as_str(),
        4 => diagnostics.lexeme_limit_exceeded.as_str(),
        5 => diagnostics.error_limit_exceeded.as_str(),
        _ => diagnostics.invalid_char.as_str(),
    }
}

fn vm_char_class_matches(byte: Option<u8>, class: u8, policy: &RuntimeTokenPolicy) -> bool {
    let Some(byte) = byte else {
        return false;
    };
    let ch = byte as char;
    match class {
        VM_CHAR_CLASS_WHITESPACE => ch.is_ascii_whitespace(),
        VM_CHAR_CLASS_IDENTIFIER_START => {
            vm_matches_identifier_start_class(byte, policy.identifier_start_class)
        }
        VM_CHAR_CLASS_IDENTIFIER_CONTINUE => {
            vm_matches_identifier_continue_class(byte, policy.identifier_continue_class)
        }
        VM_CHAR_CLASS_DIGIT => ch.is_ascii_digit(),
        VM_CHAR_CLASS_QUOTE => policy.quote_chars.as_bytes().contains(&byte),
        VM_CHAR_CLASS_PUNCTUATION => policy.punctuation_chars.as_bytes().contains(&byte),
        VM_CHAR_CLASS_OPERATOR => policy.operator_chars.as_bytes().contains(&byte),
        _ => false,
    }
}

fn vm_matches_identifier_start_class(byte: u8, class_mask: u32) -> bool {
    let is_alpha = (class_mask & crate::opthread::package::token_identifier_class::ASCII_ALPHA)
        != 0
        && (byte as char).is_ascii_alphabetic();
    let is_underscore = (class_mask & crate::opthread::package::token_identifier_class::UNDERSCORE)
        != 0
        && byte == b'_';
    let is_dot =
        (class_mask & crate::opthread::package::token_identifier_class::DOT) != 0 && byte == b'.';
    is_alpha || is_underscore || is_dot
}

fn vm_matches_identifier_continue_class(byte: u8, class_mask: u32) -> bool {
    let ch = byte as char;
    let is_alpha = (class_mask & crate::opthread::package::token_identifier_class::ASCII_ALPHA)
        != 0
        && ch.is_ascii_alphabetic();
    let is_digit = (class_mask & crate::opthread::package::token_identifier_class::ASCII_DIGIT)
        != 0
        && ch.is_ascii_digit();
    let is_underscore = (class_mask & crate::opthread::package::token_identifier_class::UNDERSCORE)
        != 0
        && byte == b'_';
    let is_dollar = (class_mask & crate::opthread::package::token_identifier_class::DOLLAR) != 0
        && byte == b'$';
    let is_at = (class_mask & crate::opthread::package::token_identifier_class::AT_SIGN) != 0
        && byte == b'@';
    let is_dot =
        (class_mask & crate::opthread::package::token_identifier_class::DOT) != 0 && byte == b'.';
    is_alpha || is_digit || is_underscore || is_dollar || is_at || is_dot
}

fn vm_build_token(
    kind_code: u8,
    lexeme: &[u8],
    line_num: u32,
    lexeme_start: usize,
    lexeme_end: usize,
    cursor: usize,
) -> Result<PortableToken, RuntimeBridgeError> {
    let span_start = if lexeme_end > lexeme_start {
        lexeme_start
    } else {
        cursor
    };
    let span_end = if lexeme_end > lexeme_start {
        lexeme_end
    } else {
        cursor.saturating_add(1)
    };
    let span = PortableSpan {
        line: line_num,
        col_start: span_start.saturating_add(1),
        col_end: span_end.saturating_add(1),
    };
    let kind = match kind_code {
        VM_TOKEN_KIND_IDENTIFIER => {
            PortableTokenKind::Identifier(String::from_utf8_lossy(lexeme).to_string())
        }
        VM_TOKEN_KIND_REGISTER => {
            PortableTokenKind::Register(String::from_utf8_lossy(lexeme).to_string())
        }
        VM_TOKEN_KIND_NUMBER => {
            let upper = String::from_utf8_lossy(lexeme).to_ascii_uppercase();
            let base = if upper.starts_with('$') {
                16
            } else if upper.starts_with('%') {
                2
            } else if upper.ends_with('H') {
                16
            } else if upper.ends_with('B') {
                2
            } else if upper.ends_with('O') || upper.ends_with('Q') {
                8
            } else {
                10
            };
            PortableTokenKind::Number { text: upper, base }
        }
        VM_TOKEN_KIND_STRING => PortableTokenKind::String {
            raw: String::from_utf8_lossy(lexeme).to_string(),
            bytes: lexeme.to_vec(),
        },
        VM_TOKEN_KIND_COMMA => PortableTokenKind::Comma,
        VM_TOKEN_KIND_COLON => PortableTokenKind::Colon,
        VM_TOKEN_KIND_DOLLAR => PortableTokenKind::Dollar,
        VM_TOKEN_KIND_DOT => PortableTokenKind::Dot,
        VM_TOKEN_KIND_HASH => PortableTokenKind::Hash,
        VM_TOKEN_KIND_QUESTION => PortableTokenKind::Question,
        VM_TOKEN_KIND_OPEN_BRACKET => PortableTokenKind::OpenBracket,
        VM_TOKEN_KIND_CLOSE_BRACKET => PortableTokenKind::CloseBracket,
        VM_TOKEN_KIND_OPEN_BRACE => PortableTokenKind::OpenBrace,
        VM_TOKEN_KIND_CLOSE_BRACE => PortableTokenKind::CloseBrace,
        VM_TOKEN_KIND_OPEN_PAREN => PortableTokenKind::OpenParen,
        VM_TOKEN_KIND_CLOSE_PAREN => PortableTokenKind::CloseParen,
        _ => {
            return Err(RuntimeBridgeError::Resolve(format!(
                "unknown tokenizer VM token kind {}",
                kind_code
            )))
        }
    };
    Ok(PortableToken { kind, span })
}

fn apply_token_policy_to_token(token: PortableToken, policy: &RuntimeTokenPolicy) -> PortableToken {
    let kind = match token.kind {
        PortableTokenKind::Identifier(name) => {
            PortableTokenKind::Identifier(apply_identifier_case_rule(name, policy.case_rule))
        }
        PortableTokenKind::Register(name) => {
            PortableTokenKind::Register(apply_identifier_case_rule(name, policy.case_rule))
        }
        other => other,
    };
    PortableToken {
        kind,
        span: token.span,
    }
}

fn apply_identifier_case_rule(name: String, rule: TokenCaseRule) -> String {
    match rule {
        TokenCaseRule::Preserve => name,
        TokenCaseRule::AsciiLower => name.to_ascii_lowercase(),
        TokenCaseRule::AsciiUpper => name.to_ascii_uppercase(),
    }
}

fn render_diag_template(template: &str, args: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (key, value) in args {
        rendered = rendered.replace(&format!("{{{}}}", key), value);
    }
    rendered
}

fn input_shape_requires_m65816(shape_key: &str) -> bool {
    matches!(
        shape_key.to_ascii_lowercase().as_str(),
        "stack_relative" | "stack_relative_indirect_y" | "indirect_long" | "indirect_long_y"
    )
}

fn bank_mismatch_error(
    address: u32,
    actual_bank: u8,
    assumed_bank: u8,
    assumed_bank_key: &str,
) -> String {
    format!(
        "Address ${address:06X} is in bank ${actual_bank:02X}, but .assume {assumed_bank_key}=${assumed_bank:02X}"
    )
}

fn bank_unknown_error(assumed_bank_key: &str, upper_mnemonic: &str) -> String {
    let mut message = format!(
        "Unable to resolve 24-bit bank because .assume {assumed_bank_key}=... is unknown; set .assume {assumed_bank_key}=$00..$FF or {assumed_bank_key}=auto"
    );
    message.push_str(
        ". If this source relied on removed stack-sequence inference, update .assume near this site",
    );
    let has_long = matches!(
        upper_mnemonic,
        "ORA" | "AND" | "EOR" | "ADC" | "STA" | "LDA" | "CMP" | "SBC" | "JML" | "JSL"
    );
    if has_long {
        message.push_str("; long-capable operands can be forced with ',l'");
    }
    message.push('.');
    message
}

fn selector_to_candidate(
    selector: &ModeSelectorDescriptor,
    input: &SelectorInput<'_>,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<Option<VmEncodeCandidate>, String> {
    let Some(mode) = parse_mode_key(&selector.mode_key) else {
        return Ok(None);
    };
    let operand_bytes = match selector.operand_plan.as_str() {
        "none" => Vec::new(),
        "u8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u8(expr0, ctx)?]
        }
        "u16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u16(expr0, ctx)?]
        }
        "u24" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u24(expr0, ctx)?]
        }
        "force_l_u24" => vec![encode_expr_force_u24(
            input
                .expr0
                .ok_or_else(|| "missing force-l operand".to_string())?,
            ctx,
        )?],
        "m65816_long_pref_u24" => {
            let expr0 = input
                .expr0
                .ok_or_else(|| "missing unresolved-long operand".to_string())?;
            if !prefer_long_for_expr(expr0, upper_mnemonic, ctx)? {
                return Ok(None);
            }
            vec![encode_expr_force_u24(expr0, ctx)?]
        }
        "m65816_abs16_bank_fold_dbr" => {
            let expr0 = input
                .expr0
                .ok_or_else(|| "missing bank-fold operand".to_string())?;
            if should_defer_abs16_to_other_candidates(expr0, upper_mnemonic, ctx)? {
                return Ok(None);
            }
            vec![encode_expr_abs16_bank_fold(expr0, upper_mnemonic, ctx)?]
        }
        "rel8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel8(expr0, ctx, 2)?]
        }
        "rel16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel16(expr0, ctx, 3)?]
        }
        "pair_u8_rel8" => vec![
            encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                ctx,
            )?,
            encode_expr_rel8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                ctx,
                3,
            )?,
        ],
        "u8u8_packed" => vec![{
            let mut packed = encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                ctx,
            )?;
            packed.extend(encode_expr_u8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                ctx,
            )?);
            packed
        }],
        "force_d_u8" => vec![encode_expr_force_d_u8(
            input
                .expr0
                .ok_or_else(|| "missing force-d operand".to_string())?,
            ctx,
        )?],
        "force_b_abs16_dbr" => {
            if matches!(upper_mnemonic, "JMP" | "JSR") {
                return Ok(None);
            }
            vec![encode_expr_force_abs16(
                input
                    .expr0
                    .ok_or_else(|| "missing force-b operand".to_string())?,
                false,
                OperandForce::DataBank,
                upper_mnemonic,
                ctx,
            )?]
        }
        "force_k_abs16_pbr" => {
            if !matches!(upper_mnemonic, "JMP" | "JSR") {
                return Ok(None);
            }
            vec![encode_expr_force_abs16(
                input
                    .expr0
                    .ok_or_else(|| "missing force-k operand".to_string())?,
                true,
                OperandForce::ProgramBank,
                upper_mnemonic,
                ctx,
            )?]
        }
        "imm_mx" => vec![encode_expr_m65816_immediate(
            input
                .expr0
                .ok_or_else(|| "missing immediate operand".to_string())?,
            upper_mnemonic,
            ctx,
        )?],
        _ => return Ok(None),
    };

    // Ensure mode-width matches generated bytes before candidate emission.
    if mode.operand_size() == 0 && !operand_bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(VmEncodeCandidate {
        mode_key: selector.mode_key.to_ascii_lowercase(),
        operand_bytes,
    }))
}

fn parse_mode_key(mode_key: &str) -> Option<AddressMode> {
    match mode_key.to_ascii_lowercase().as_str() {
        "implied" => Some(AddressMode::Implied),
        "accumulator" => Some(AddressMode::Accumulator),
        "immediate" => Some(AddressMode::Immediate),
        "zeropage" => Some(AddressMode::ZeroPage),
        "zeropagex" => Some(AddressMode::ZeroPageX),
        "zeropagey" => Some(AddressMode::ZeroPageY),
        "absolute" => Some(AddressMode::Absolute),
        "absolutex" => Some(AddressMode::AbsoluteX),
        "absolutey" => Some(AddressMode::AbsoluteY),
        "indirect" => Some(AddressMode::Indirect),
        "indexedindirectx" => Some(AddressMode::IndexedIndirectX),
        "indirectindexedy" => Some(AddressMode::IndirectIndexedY),
        "relative" => Some(AddressMode::Relative),
        "relativelong" => Some(AddressMode::RelativeLong),
        "zeropageindirect" => Some(AddressMode::ZeroPageIndirect),
        "absoluteindexedindirect" => Some(AddressMode::AbsoluteIndexedIndirect),
        "stackrelative" => Some(AddressMode::StackRelative),
        "stackrelativeindirectindexedy" => Some(AddressMode::StackRelativeIndirectIndexedY),
        "absolutelong" => Some(AddressMode::AbsoluteLong),
        "absolutelongx" => Some(AddressMode::AbsoluteLongX),
        "indirectlong" => Some(AddressMode::IndirectLong),
        "directpageindirectlong" => Some(AddressMode::DirectPageIndirectLong),
        "directpageindirectlongy" => Some(AddressMode::DirectPageIndirectLongY),
        "blockmove" => Some(AddressMode::BlockMove),
        _ => None,
    }
}

fn encode_expr_u8(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    if (0..=255).contains(&value) {
        Ok(vec![value as u8])
    } else {
        Err("invalid u8 operand".to_string())
    }
}

fn encode_expr_u16(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    if (0..=65535).contains(&value) {
        Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ])
    } else {
        Err("invalid u16 operand".to_string())
    }
}

fn encode_expr_u24(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    if (0..=0xFF_FFFF).contains(&value) {
        Ok(vec![
            (value as u32 & 0xFF) as u8,
            ((value as u32 >> 8) & 0xFF) as u8,
            ((value as u32 >> 16) & 0xFF) as u8,
        ])
    } else {
        Err("invalid u24 operand".to_string())
    }
}

fn encode_expr_force_d_u8(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(vec![0]);
    }
    let value = ctx.eval_expr(expr)?;
    if (0..=255).contains(&value) {
        return Ok(vec![value as u8]);
    }
    if !(0..=0xFFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 16-bit range for explicit ',d'",
            value
        ));
    }
    let absolute_value = value as u16;
    let Some(dp_offset) = direct_page_offset_for_absolute_address(absolute_value, ctx) else {
        return Err(format!(
            "Address ${absolute_value:04X} is outside the direct-page window for explicit ',d'"
        ));
    };
    Ok(vec![dp_offset])
}

fn encode_expr_force_u24(expr: &Expr, ctx: &dyn AssemblerContext) -> Result<Vec<u8>, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(vec![0, 0, 0]);
    }
    let value = ctx.eval_expr(expr)?;
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 24-bit range for explicit ',l'",
            value
        ));
    }
    Ok(vec![
        (value as u32 & 0xFF) as u8,
        ((value as u32 >> 8) & 0xFF) as u8,
        ((value as u32 >> 16) & 0xFF) as u8,
    ])
}

fn prefer_long_for_expr(
    expr: &Expr,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<bool, String> {
    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, ctx);
    let symbol_based = expr_has_symbol_references(expr);

    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(ctx.current_address() > 0xFFFF || !assumed_known || assumed_bank != 0);
    }

    let value = ctx.eval_expr(expr)?;
    if symbol_based && (0..=0xFFFF).contains(&value) && (!assumed_known || assumed_bank != 0) {
        return Ok(true);
    }
    if (0x1_0000..=0xFF_FFFF).contains(&value) {
        let absolute_bank = ((value as u32) >> 16) as u8;
        if !assumed_known || absolute_bank != assumed_bank {
            return Ok(true);
        }
    }
    Ok(false)
}

fn should_defer_abs16_to_other_candidates(
    expr: &Expr,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<bool, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(true);
    }
    let value = ctx.eval_expr(expr)?;
    if value <= 0xFFFF {
        return Ok(true);
    }
    if value > 0xFF_FFFF {
        return Ok(false);
    }
    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, ctx);
    let absolute_bank = ((value as u32) >> 16) as u8;
    Ok(!assumed_known || absolute_bank != assumed_bank)
}

fn encode_expr_abs16_bank_fold(
    expr: &Expr,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!("Address {} out of 24-bit range", value));
    }
    if value <= 0xFFFF {
        let absolute = value as u16;
        return Ok(vec![
            (absolute & 0xFF) as u8,
            ((absolute >> 8) & 0xFF) as u8,
        ]);
    }

    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, ctx);
    let assumed_key = if matches!(upper_mnemonic, "JMP" | "JSR") {
        "pbr"
    } else {
        "dbr"
    };
    if !assumed_known {
        return Err(bank_unknown_error(assumed_key, upper_mnemonic));
    }
    let absolute_bank = ((value as u32) >> 16) as u8;
    if absolute_bank != assumed_bank {
        return Err(bank_mismatch_error(
            value as u32,
            absolute_bank,
            assumed_bank,
            assumed_key,
        ));
    }
    let absolute = (value as u32 & 0xFFFF) as u16;
    Ok(vec![
        (absolute & 0xFF) as u8,
        ((absolute >> 8) & 0xFF) as u8,
    ])
}

fn assumed_bank_state(upper_mnemonic: &str, ctx: &dyn AssemblerContext) -> (u8, bool) {
    if matches!(upper_mnemonic, "JMP" | "JSR") {
        (state::program_bank(ctx), state::program_bank_known(ctx))
    } else {
        (state::data_bank(ctx), state::data_bank_known(ctx))
    }
}

fn expr_has_symbol_references(expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(_, _) | Expr::Register(_, _) => true,
        Expr::Indirect(inner, _) | Expr::Immediate(inner, _) | Expr::IndirectLong(inner, _) => {
            expr_has_symbol_references(inner)
        }
        Expr::Tuple(items, _) => items.iter().any(expr_has_symbol_references),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            expr_has_symbol_references(cond)
                || expr_has_symbol_references(then_expr)
                || expr_has_symbol_references(else_expr)
        }
        Expr::Unary { expr, .. } => expr_has_symbol_references(expr),
        Expr::Binary { left, right, .. } => {
            expr_has_symbol_references(left) || expr_has_symbol_references(right)
        }
        Expr::Number(_, _) | Expr::Dollar(_) | Expr::String(_, _) | Expr::Error(_, _) => false,
    }
}

fn encode_expr_force_abs16(
    expr: &Expr,
    use_program_bank: bool,
    force: OperandForce,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<Vec<u8>, String> {
    if ctx.pass() == 1 && expr_has_unstable_symbols(expr, ctx) {
        return Ok(vec![0, 0]);
    }
    let value = ctx.eval_expr(expr)?;
    if (0..=65535).contains(&value) {
        return Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ]);
    }
    if !(0..=0xFF_FFFF).contains(&value) {
        return Err(format!(
            "Address {} out of 24-bit range for explicit ',{}'",
            value,
            force_suffix(force)
        ));
    }
    let assumed_bank_key = if use_program_bank { "pbr" } else { "dbr" };
    let assumed_known = if use_program_bank {
        state::program_bank_known(ctx)
    } else {
        state::data_bank_known(ctx)
    };
    if !assumed_known {
        return Err(bank_unknown_error(assumed_bank_key, upper_mnemonic));
    }
    let assumed_bank = if use_program_bank {
        state::program_bank(ctx)
    } else {
        state::data_bank(ctx)
    };
    let absolute_bank = ((value as u32) >> 16) as u8;
    if absolute_bank != assumed_bank {
        return Err(bank_mismatch_error(
            value as u32,
            absolute_bank,
            assumed_bank,
            assumed_bank_key,
        ));
    }
    let absolute = (value as u32 & 0xFFFF) as u16;
    Ok(vec![
        (absolute & 0xFF) as u8,
        ((absolute >> 8) & 0xFF) as u8,
    ])
}

fn direct_page_offset_for_absolute_address(address: u16, ctx: &dyn AssemblerContext) -> Option<u8> {
    if !state::direct_page_known(ctx) || address <= 0x00FF {
        return None;
    }
    let dp = state::direct_page(ctx);
    let offset = address.wrapping_sub(dp);
    (offset <= 0x00FF).then_some(offset as u8)
}

fn encode_expr_rel8(
    expr: &Expr,
    ctx: &dyn AssemblerContext,
    instr_len: i64,
) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    let current = ctx.current_address() as i64 + instr_len;
    let offset = value - current;
    if !(-128..=127).contains(&offset) {
        if ctx.pass() > 1 {
            return Err(format!("Branch target out of range: offset {}", offset));
        }
        return Ok(vec![0]);
    }
    Ok(vec![offset as i8 as u8])
}

fn encode_expr_rel16(
    expr: &Expr,
    ctx: &dyn AssemblerContext,
    instr_len: i64,
) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    let current = ctx.current_address() as i64 + instr_len;
    let offset = value - current;
    if !(-32768..=32767).contains(&offset) {
        if ctx.pass() > 1 {
            return Err(format!(
                "Long branch target out of range: offset {}",
                offset
            ));
        }
        return Ok(vec![0, 0]);
    }
    let rel = offset as i16;
    Ok(vec![
        (rel as u16 & 0xFF) as u8,
        ((rel as u16 >> 8) & 0xFF) as u8,
    ])
}

fn encode_expr_m65816_immediate(
    expr: &Expr,
    upper_mnemonic: &str,
    ctx: &dyn AssemblerContext,
) -> Result<Vec<u8>, String> {
    let value = ctx.eval_expr(expr)?;
    let acc_imm = matches!(
        upper_mnemonic,
        "ADC" | "AND" | "BIT" | "CMP" | "EOR" | "LDA" | "ORA" | "SBC"
    );
    let idx_imm = matches!(upper_mnemonic, "CPX" | "CPY" | "LDX" | "LDY");
    if acc_imm {
        if state::accumulator_is_8bit(ctx) {
            if !(0..=255).contains(&value) {
                return Err(format!(
                    "Accumulator immediate value {} out of range (0-255) in 8-bit mode",
                    value
                ));
            }
            return Ok(vec![value as u8]);
        }
        if !(0..=65535).contains(&value) {
            return Err(format!(
                "Accumulator immediate value {} out of range (0-65535) in 16-bit mode",
                value
            ));
        }
        return Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ]);
    }
    if idx_imm {
        if state::index_is_8bit(ctx) {
            if !(0..=255).contains(&value) {
                return Err(format!(
                    "Index immediate value {} out of range (0-255) in 8-bit mode",
                    value
                ));
            }
            return Ok(vec![value as u8]);
        }
        if !(0..=65535).contains(&value) {
            return Err(format!(
                "Index immediate value {} out of range (0-65535) in 16-bit mode",
                value
            ));
        }
        return Ok(vec![
            (value as u16 & 0xFF) as u8,
            ((value as u16 >> 8) & 0xFF) as u8,
        ]);
    }
    if !(0..=255).contains(&value) {
        return Err(format!("Immediate value {} out of range (0-255)", value));
    }
    Ok(vec![value as u8])
}

fn owner_key_parts(owner: &ScopedOwner) -> (u8, String) {
    match owner {
        ScopedOwner::Family(id) => (0u8, id.to_ascii_lowercase()),
        ScopedOwner::Cpu(id) => (1u8, id.to_ascii_lowercase()),
        ScopedOwner::Dialect(id) => (2u8, id.to_ascii_lowercase()),
    }
}

fn contains_form(map: &HashMap<String, HashSet<String>>, owner_id: &str, mnemonic: &str) -> bool {
    map.get(&owner_id.to_ascii_lowercase())
        .is_some_and(|forms| forms.contains(mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::family::AssemblerContext;
    use crate::core::parser::Expr;
    use crate::core::registry::{ModuleRegistry, VmEncodeCandidate};
    use crate::core::tokenizer::{Span, Token, TokenKind, Tokenizer};
    use crate::families::intel8080::module::Intel8080FamilyModule;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule, MOS6502Operands};
    use crate::families::mos6502::Operand;
    use crate::i8085::module::I8085CpuModule;
    use crate::m65816::module::M65816CpuModule;
    use crate::m65c02::module::M65C02CpuModule;
    use crate::opthread::builder::{
        build_hierarchy_chunks_from_registry, build_hierarchy_package_from_registry,
    };
    use crate::opthread::hierarchy::{
        CpuDescriptor, DialectDescriptor, FamilyDescriptor, ResolvedHierarchy, ScopedOwner,
    };
    use crate::opthread::package::{
        default_token_policy_lexical_defaults, token_identifier_class, DiagnosticDescriptor,
        HierarchyChunks, TokenCaseRule, TokenPolicyDescriptor, TokenizerVmOpcode,
        TokenizerVmProgramDescriptor, VmProgramDescriptor, DIAG_OPTHREAD_MISSING_VM_PROGRAM,
        TOKENIZER_VM_OPCODE_VERSION_V1,
    };
    use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
    use crate::z80::module::Z80CpuModule;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    fn tokenize_host_line(line: &str, line_num: u32) -> Vec<PortableToken> {
        let mut tokenizer = Tokenizer::new(line, line_num);
        let mut tokens = Vec::new();
        loop {
            let token = tokenizer.next_token().expect("tokenize line");
            if matches!(token.kind, TokenKind::End) {
                break;
            }
            tokens.push(PortableToken::from_core_token(token));
        }
        tokens
    }

    fn parity_registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(Intel8080FamilyModule));
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(I8085CpuModule));
        registry.register_cpu(Box::new(Z80CpuModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
            .tokenize_portable_statement(&CoreTokenizerAdapter, cpu_id, None, line, line_num)
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

    #[derive(Debug)]
    struct FailingTokenizerAdapter;

    impl PortableTokenizerAdapter for FailingTokenizerAdapter {
        fn tokenize_statement(
            &self,
            _request: &PortableTokenizeRequest<'_>,
        ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
            Err(RuntimeBridgeError::Resolve(
                "failing delegated adapter".to_string(),
            ))
        }
    }

    #[derive(Debug)]
    struct FixedTokenizerAdapter;

    impl PortableTokenizerAdapter for FixedTokenizerAdapter {
        fn tokenize_statement(
            &self,
            request: &PortableTokenizeRequest<'_>,
        ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
            Ok(vec![PortableToken {
                kind: PortableTokenKind::Identifier("adapter".to_string()),
                span: PortableSpan {
                    line: request.line_num,
                    col_start: 1,
                    col_end: 8,
                },
            }])
        }
    }

    struct TestAssemblerContext {
        values: HashMap<String, i64>,
        finalized: HashMap<String, bool>,
        cpu_flags: HashMap<String, u32>,
        addr: u32,
        pass: u8,
    }

    impl TestAssemblerContext {
        fn new() -> Self {
            Self {
                values: HashMap::new(),
                finalized: HashMap::new(),
                cpu_flags: HashMap::new(),
                addr: 0,
                pass: 2,
            }
        }
    }

    impl AssemblerContext for TestAssemblerContext {
        fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
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
            metadata: crate::opthread::package::PackageMetaDescriptor::default(),
            strings: Vec::new(),
            diagnostics: Vec::new(),
            token_policies: Vec::new(),
            tokenizer_vm_programs: Vec::new(),
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        assert_eq!(model.tokenizer_mode(), RuntimeTokenizerMode::Auto);
    }

    #[test]
    fn execution_model_budget_rejects_candidate_overflow() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
    fn execution_model_encodes_base_6502_instruction_via_vm() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::Immediate(0x42, Span::default())]);
        let bytes = model
            .encode_instruction("m6502", None, "LDA", &operands)
            .expect("vm encode should succeed");
        assert_eq!(bytes, Some(vec![0xA9, 0x42]));
    }

    #[test]
    fn execution_model_encodes_portable_request_via_vm() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let line = "lda #$42";
        let host_tokens = tokenize_host_line(line, 12);
        let vm_tokens = model
            .tokenize_portable_statement(&CoreTokenizerAdapter, "m6502", None, line, 12)
            .expect("portable tokenization should succeed");
        assert_eq!(vm_tokens, host_tokens);
    }

    #[test]
    fn execution_model_tokenizer_vm_policy_parity_matches_host_tokens_with_cpu_override() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let host_tokens = tokenize_host_line(line, 14);
        let vm_tokens = model
            .tokenize_portable_statement(&CoreTokenizerAdapter, "m6502", None, line, 14)
            .expect("portable tokenization should succeed");
        assert_eq!(vm_tokens, host_tokens);
    }

    #[test]
    fn execution_model_tokenizer_applies_package_case_policy_hints() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let tokens = model
            .tokenize_portable_statement(&CoreTokenizerAdapter, "m6502", None, "LDA #$42", 1)
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
            .map(PortableToken::from_core_token)
            .collect();
        let round_trip: Vec<Token> = portable_tokens
            .iter()
            .map(PortableToken::to_core_token)
            .collect();
        assert_eq!(core_tokens, round_trip);
    }

    #[test]
    fn execution_model_token_policy_resolution_prefers_dialect_then_cpu_then_family() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
            .tokenize_portable_statement(&CoreTokenizerAdapter, "m6502", None, "lda", 1)
            .expect("tokenization should succeed");
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == "LDA"
        ));
    }

    #[test]
    fn execution_model_tokenizer_vm_program_resolution_prefers_dialect_then_cpu_then_family() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let limits = model
            .resolve_tokenizer_vm_limits("m6502", None)
            .expect("tokenizer vm limits should resolve");
        assert_eq!(limits, TokenizerVmLimits::default());
    }

    #[test]
    fn execution_model_tokenizer_vm_parity_checklist_resolves_for_certified_families() {
        let registry = parity_registry();
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
            !TOKENIZER_VM_CERTIFICATIONS.is_empty(),
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
    fn execution_model_tokenizer_auto_mode_uses_vm_for_mos6502_family() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
            .tokenize_portable_statement(&FailingTokenizerAdapter, "m6502", None, "A,B", 1)
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
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let tokens = model
            .tokenize_portable_statement(&FailingTokenizerAdapter, "z80", None, "LD A,B", 1)
            .expect("auto mode should route certified intel8080 family to VM tokenizer");
        assert!(!tokens.is_empty());
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == "ld"
        ));
    }

    #[test]
    fn execution_model_tokenizer_mode_host_uses_core_path() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        let mut model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        model.set_tokenizer_mode(RuntimeTokenizerMode::Host);
        let tokens = model
            .tokenize_portable_statement(&FailingTokenizerAdapter, "m6502", None, "LDA #$42", 1)
            .expect("host tokenizer mode should not use delegated adapter");
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == "lda"
        ));
    }

    #[test]
    fn execution_model_tokenizer_mode_delegated_core_uses_adapter() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        model.set_tokenizer_mode(RuntimeTokenizerMode::DelegatedCore);
        let tokens = model
            .tokenize_portable_statement(&FixedTokenizerAdapter, "m6502", None, "LDA #$42", 1)
            .expect("delegated-core tokenizer mode should use delegated adapter");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == "adapter"
        ));
    }

    #[test]
    fn execution_model_tokenizer_mode_vm_falls_back_to_host() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        model.set_tokenizer_mode(RuntimeTokenizerMode::Vm);
        let tokens = model
            .tokenize_portable_statement(&FailingTokenizerAdapter, "m6502", None, "LDA #$42", 1)
            .expect("vm mode should fall back to host path");
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == "lda"
        ));
    }

    #[test]
    fn execution_model_tokenizer_mode_vm_executes_program_from_package() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut model =
            HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
        model.set_tokenizer_mode(RuntimeTokenizerMode::Vm);

        let tokens = model
            .tokenize_portable_statement(&FailingTokenizerAdapter, "m6502", None, "A,B", 1)
            .expect("vm mode should execute tokenizer VM program");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(
            &tokens[0].kind,
            PortableTokenKind::Identifier(name) if name == "a"
        ));
    }

    #[test]
    fn execution_model_tokenizer_vm_retro_profile_enforces_step_budget() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
    fn execution_model_tokenizer_parity_corpus_examples_and_edge_cases_host_vs_vm() {
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
                let host = tokenize_with_mode(
                    &mut model,
                    RuntimeTokenizerMode::Host,
                    cpu_id,
                    line,
                    line_num,
                );
                let vm = tokenize_with_mode(
                    &mut model,
                    RuntimeTokenizerMode::Vm,
                    cpu_id,
                    line,
                    line_num,
                );
                assert_eq!(
                    vm, host,
                    "tokenizer parity mismatch for cpu {} at corpus index {} line {:?}",
                    cpu_id, index, line
                );
            }
        }
    }

    #[test]
    fn execution_model_tokenizer_parity_deterministic_fuzz_host_vs_vm() {
        let corpus = deterministic_fuzz_lines(0x50_45_45_44, 512, 48);
        let registry = parity_registry();
        let mut model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        for (index, line) in corpus.iter().enumerate() {
            let line_num = (index + 1) as u32;
            let host = tokenize_with_mode(
                &mut model,
                RuntimeTokenizerMode::Host,
                "m6502",
                line,
                line_num,
            );
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::Relative(2, Span::default())]);
        let bytes = model
            .encode_instruction("65c02", None, "BRA", &operands)
            .expect("vm encode should resolve");
        assert_eq!(bytes, Some(vec![0x80, 0x02]));
    }

    #[test]
    fn execution_model_encodes_m6502_instruction_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
    fn execution_model_reports_expr_resolver_support_by_family() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        assert!(model.supports_expr_resolution_for_family("mos6502"));
        assert!(model.supports_expr_resolution_for_family("MOS6502"));
        #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
        assert!(model.supports_expr_resolution_for_family("intel8080"));
        #[cfg(not(feature = "opthread-runtime-intel8080-scaffold"))]
        assert!(!model.supports_expr_resolution_for_family("intel8080"));
    }

    #[test]
    fn execution_model_expr_encode_returns_none_for_unimplemented_intel_resolver() {
        let model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
        let span = Span::default();
        let operands = vec![Expr::Number("66".to_string(), span)];
        let ctx = TestAssemblerContext::new();

        let bytes = model
            .encode_instruction_from_exprs("8085", None, "MVI", &operands, &ctx)
            .expect("expr encode should not error when family resolver is absent");
        assert!(bytes.is_none());
        assert!(!model.expr_resolution_is_strict_for_family("intel8080"));
    }

    #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
    #[test]
    fn execution_model_intel_scaffold_encodes_matching_mvi_program() {
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
            .expect("intel scaffold should encode MVI");
        assert_eq!(bytes, Some(vec![0x3E, 0x42]));
    }

    #[test]
    fn execution_model_allows_registering_fn_family_expr_resolver() {
        let mut model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
        let replaced =
            model.register_expr_resolver_for_family("intel8080", intel_test_expr_resolver);
        #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
        assert!(replaced.is_some());
        #[cfg(not(feature = "opthread-runtime-intel8080-scaffold"))]
        assert!(replaced.is_none());
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
        let mut model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
        let replaced = model.register_family_expr_resolver(Box::new(IntelDynResolver));
        #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
        assert!(replaced.is_some());
        #[cfg(not(feature = "opthread-runtime-intel8080-scaffold"))]
        assert!(replaced.is_none());
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

    #[cfg(feature = "opthread-runtime-intel8080-scaffold")]
    #[test]
    fn execution_model_intel_scaffold_is_non_strict() {
        let model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
        assert!(model.supports_expr_resolution_for_family("intel8080"));
        assert!(!model.expr_resolution_is_strict_for_family("intel8080"));
    }

    #[test]
    fn execution_model_encodes_m65816_forced_long_from_expr_operands() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
    fn execution_model_vm_encode_supports_m65c02_bit_branch_tables() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
    fn execution_model_rejects_invalid_package_bytes() {
        let err = HierarchyExecutionModel::from_package_bytes(b"not-an-opcpu")
            .expect_err("invalid package bytes should be rejected");
        assert!(matches!(err, RuntimeBridgeError::Package(_)));
    }

    #[test]
    fn execution_model_returns_none_when_target_has_no_tabl_programs() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let operands = MOS6502Operands(vec![Operand::AbsoluteLong(0x001234, Span::default())]);
        let bytes = model
            .encode_instruction("65816", None, "JSL", &operands)
            .expect("vm encode should resolve");
        assert_eq!(bytes, Some(vec![0x22, 0x34, 0x12, 0x00]));
    }
}
