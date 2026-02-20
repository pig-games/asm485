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
use crate::core::family::CpuHandler;
use crate::core::family::{expr_has_unstable_symbols, AssemblerContext, FamilyHandler};
use crate::core::parser::{
    AssignOp, BinaryOp, Expr, Label, LineAst, ParseError, Parser, SignatureAtom,
    StatementSignature, UnaryOp, UseItem, UseParam,
};
use crate::core::registry::{ModuleRegistry, OperandSet, VmEncodeCandidate};
use crate::core::tokenizer::{
    register_checker_none, ConditionalKind, NumberLiteral, OperatorKind, Span, StringLiteral,
    Token, TokenKind, Tokenizer,
};
use crate::families::intel8080::handler::resolve_operands as resolve_intel8080_operands;
use crate::families::intel8080::table::{
    lookup_instruction, ArgType as IntelArgType, InstructionEntry as IntelInstructionEntry,
};
use crate::families::intel8080::{Intel8080FamilyHandler, Operand as IntelOperand};
use crate::families::mos6502::{AddressMode, FamilyOperand, MOS6502FamilyHandler, OperandForce};
use crate::i8085::extensions::lookup_extension as lookup_i8085_extension;
use crate::i8085::handler::I8085CpuHandler;
use crate::m65816::state;
use crate::opthread::builder::{build_hierarchy_package_from_registry, HierarchyBuildError};
use crate::opthread::hierarchy::{
    HierarchyError, HierarchyPackage, ResolvedHierarchy, ResolvedHierarchyContext, ScopedOwner,
};
use crate::opthread::intel8080_vm::{
    mode_key_for_instruction_entry, mode_key_for_z80_cb_register, mode_key_for_z80_half_index,
    mode_key_for_z80_indexed_cb, mode_key_for_z80_indexed_memory, mode_key_for_z80_interrupt_mode,
    mode_key_for_z80_ld_indirect, prefix_len,
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
use crate::z80::extensions::lookup_extension as lookup_z80_extension;
use crate::z80::handler::Z80CpuHandler;

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
    fn from_core_token(value: Token) -> Option<Self> {
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
            TokenKind::End => return None,
        };
        Some(Self {
            kind,
            span: value.span.into(),
        })
    }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstLabel {
    pub name: String,
    pub span: PortableSpan,
}

impl PortableAstLabel {
    fn from_core_label(label: &Label) -> Self {
        Self {
            name: label.name.clone(),
            span: label.span.into(),
        }
    }

    fn to_core_label(&self) -> Label {
        Label {
            name: self.name.clone(),
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableAstUnaryOp {
    Plus,
    Minus,
    BitNot,
    LogicNot,
    High,
    Low,
}

impl From<UnaryOp> for PortableAstUnaryOp {
    fn from(value: UnaryOp) -> Self {
        match value {
            UnaryOp::Plus => Self::Plus,
            UnaryOp::Minus => Self::Minus,
            UnaryOp::BitNot => Self::BitNot,
            UnaryOp::LogicNot => Self::LogicNot,
            UnaryOp::High => Self::High,
            UnaryOp::Low => Self::Low,
        }
    }
}

impl From<PortableAstUnaryOp> for UnaryOp {
    fn from(value: PortableAstUnaryOp) -> Self {
        match value {
            PortableAstUnaryOp::Plus => Self::Plus,
            PortableAstUnaryOp::Minus => Self::Minus,
            PortableAstUnaryOp::BitNot => Self::BitNot,
            PortableAstUnaryOp::LogicNot => Self::LogicNot,
            PortableAstUnaryOp::High => Self::High,
            PortableAstUnaryOp::Low => Self::Low,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableAstBinaryOp {
    Multiply,
    Divide,
    Mod,
    Power,
    Shl,
    Shr,
    Add,
    Subtract,
    Eq,
    Ne,
    Ge,
    Gt,
    Le,
    Lt,
    BitAnd,
    BitOr,
    BitXor,
    LogicAnd,
    LogicOr,
    LogicXor,
}

impl From<BinaryOp> for PortableAstBinaryOp {
    fn from(value: BinaryOp) -> Self {
        match value {
            BinaryOp::Multiply => Self::Multiply,
            BinaryOp::Divide => Self::Divide,
            BinaryOp::Mod => Self::Mod,
            BinaryOp::Power => Self::Power,
            BinaryOp::Shl => Self::Shl,
            BinaryOp::Shr => Self::Shr,
            BinaryOp::Add => Self::Add,
            BinaryOp::Subtract => Self::Subtract,
            BinaryOp::Eq => Self::Eq,
            BinaryOp::Ne => Self::Ne,
            BinaryOp::Ge => Self::Ge,
            BinaryOp::Gt => Self::Gt,
            BinaryOp::Le => Self::Le,
            BinaryOp::Lt => Self::Lt,
            BinaryOp::BitAnd => Self::BitAnd,
            BinaryOp::BitOr => Self::BitOr,
            BinaryOp::BitXor => Self::BitXor,
            BinaryOp::LogicAnd => Self::LogicAnd,
            BinaryOp::LogicOr => Self::LogicOr,
            BinaryOp::LogicXor => Self::LogicXor,
        }
    }
}

impl From<PortableAstBinaryOp> for BinaryOp {
    fn from(value: PortableAstBinaryOp) -> Self {
        match value {
            PortableAstBinaryOp::Multiply => Self::Multiply,
            PortableAstBinaryOp::Divide => Self::Divide,
            PortableAstBinaryOp::Mod => Self::Mod,
            PortableAstBinaryOp::Power => Self::Power,
            PortableAstBinaryOp::Shl => Self::Shl,
            PortableAstBinaryOp::Shr => Self::Shr,
            PortableAstBinaryOp::Add => Self::Add,
            PortableAstBinaryOp::Subtract => Self::Subtract,
            PortableAstBinaryOp::Eq => Self::Eq,
            PortableAstBinaryOp::Ne => Self::Ne,
            PortableAstBinaryOp::Ge => Self::Ge,
            PortableAstBinaryOp::Gt => Self::Gt,
            PortableAstBinaryOp::Le => Self::Le,
            PortableAstBinaryOp::Lt => Self::Lt,
            PortableAstBinaryOp::BitAnd => Self::BitAnd,
            PortableAstBinaryOp::BitOr => Self::BitOr,
            PortableAstBinaryOp::BitXor => Self::BitXor,
            PortableAstBinaryOp::LogicAnd => Self::LogicAnd,
            PortableAstBinaryOp::LogicOr => Self::LogicOr,
            PortableAstBinaryOp::LogicXor => Self::LogicXor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableAstExpr {
    Number(String, PortableSpan),
    Identifier(String, PortableSpan),
    Register(String, PortableSpan),
    Indirect(Box<PortableAstExpr>, PortableSpan),
    Dollar(PortableSpan),
    String(Vec<u8>, PortableSpan),
    Immediate(Box<PortableAstExpr>, PortableSpan),
    IndirectLong(Box<PortableAstExpr>, PortableSpan),
    Tuple(Vec<PortableAstExpr>, PortableSpan),
    Error(String, PortableSpan),
    Ternary {
        cond: Box<PortableAstExpr>,
        then_expr: Box<PortableAstExpr>,
        else_expr: Box<PortableAstExpr>,
        span: PortableSpan,
    },
    Unary {
        op: PortableAstUnaryOp,
        expr: Box<PortableAstExpr>,
        span: PortableSpan,
    },
    Binary {
        op: PortableAstBinaryOp,
        left: Box<PortableAstExpr>,
        right: Box<PortableAstExpr>,
        span: PortableSpan,
    },
}

impl PortableAstExpr {
    fn to_core_expr(&self) -> Expr {
        match self {
            Self::Number(text, span) => Expr::Number(text.clone(), (*span).into()),
            Self::Identifier(name, span) => Expr::Identifier(name.clone(), (*span).into()),
            Self::Register(name, span) => Expr::Register(name.clone(), (*span).into()),
            Self::Indirect(inner, span) => {
                Expr::Indirect(Box::new(inner.to_core_expr()), (*span).into())
            }
            Self::Dollar(span) => Expr::Dollar((*span).into()),
            Self::String(bytes, span) => Expr::String(bytes.clone(), (*span).into()),
            Self::Immediate(inner, span) => {
                Expr::Immediate(Box::new(inner.to_core_expr()), (*span).into())
            }
            Self::IndirectLong(inner, span) => {
                Expr::IndirectLong(Box::new(inner.to_core_expr()), (*span).into())
            }
            Self::Tuple(items, span) => Expr::Tuple(
                items.iter().map(PortableAstExpr::to_core_expr).collect(),
                (*span).into(),
            ),
            Self::Error(message, span) => Expr::Error(message.clone(), (*span).into()),
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
                span,
            } => Expr::Ternary {
                cond: Box::new(cond.to_core_expr()),
                then_expr: Box::new(then_expr.to_core_expr()),
                else_expr: Box::new(else_expr.to_core_expr()),
                span: (*span).into(),
            },
            Self::Unary { op, expr, span } => Expr::Unary {
                op: (*op).into(),
                expr: Box::new(expr.to_core_expr()),
                span: (*span).into(),
            },
            Self::Binary {
                op,
                left,
                right,
                span,
            } => Expr::Binary {
                op: (*op).into(),
                left: Box::new(left.to_core_expr()),
                right: Box::new(right.to_core_expr()),
                span: (*span).into(),
            },
        }
    }

    fn from_core_expr(value: &Expr) -> Self {
        match value {
            Expr::Number(text, span) => Self::Number(text.clone(), (*span).into()),
            Expr::Identifier(name, span) => Self::Identifier(name.clone(), (*span).into()),
            Expr::Register(name, span) => Self::Register(name.clone(), (*span).into()),
            Expr::Indirect(inner, span) => {
                Self::Indirect(Box::new(Self::from_core_expr(inner)), (*span).into())
            }
            Expr::Immediate(inner, span) => {
                Self::Immediate(Box::new(Self::from_core_expr(inner)), (*span).into())
            }
            Expr::IndirectLong(inner, span) => {
                Self::IndirectLong(Box::new(Self::from_core_expr(inner)), (*span).into())
            }
            Expr::Tuple(items, span) => Self::Tuple(
                items.iter().map(Self::from_core_expr).collect(),
                (*span).into(),
            ),
            Expr::Dollar(span) => Self::Dollar((*span).into()),
            Expr::String(bytes, span) => Self::String(bytes.clone(), (*span).into()),
            Expr::Error(message, span) => Self::Error(message.clone(), (*span).into()),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                span,
            } => Self::Ternary {
                cond: Box::new(Self::from_core_expr(cond)),
                then_expr: Box::new(Self::from_core_expr(then_expr)),
                else_expr: Box::new(Self::from_core_expr(else_expr)),
                span: (*span).into(),
            },
            Expr::Unary { op, expr, span } => Self::Unary {
                op: (*op).into(),
                expr: Box::new(Self::from_core_expr(expr)),
                span: (*span).into(),
            },
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => Self::Binary {
                op: (*op).into(),
                left: Box::new(Self::from_core_expr(left)),
                right: Box::new(Self::from_core_expr(right)),
                span: (*span).into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstUseItem {
    pub name: String,
    pub alias: Option<String>,
    pub span: PortableSpan,
}

impl PortableAstUseItem {
    fn from_core_item(item: &UseItem) -> Self {
        Self {
            name: item.name.clone(),
            alias: item.alias.clone(),
            span: item.span.into(),
        }
    }

    fn to_core_item(&self) -> UseItem {
        UseItem {
            name: self.name.clone(),
            alias: self.alias.clone(),
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstUseParam {
    pub name: String,
    pub value: PortableAstExpr,
    pub span: PortableSpan,
}

impl PortableAstUseParam {
    fn from_core_param(param: &UseParam) -> Self {
        Self {
            name: param.name.clone(),
            value: PortableAstExpr::from_core_expr(&param.value),
            span: param.span.into(),
        }
    }

    fn to_core_param(&self) -> UseParam {
        UseParam {
            name: self.name.clone(),
            value: self.value.to_core_expr(),
            span: self.span.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableAstSignatureAtom {
    Literal(Vec<u8>, PortableSpan),
    Capture {
        type_name: String,
        name: String,
        span: PortableSpan,
    },
    Boundary {
        atoms: Vec<PortableAstSignatureAtom>,
        span: PortableSpan,
    },
}

impl PortableAstSignatureAtom {
    fn from_core_atom(atom: &SignatureAtom) -> Self {
        match atom {
            SignatureAtom::Literal(bytes, span) => Self::Literal(bytes.clone(), (*span).into()),
            SignatureAtom::Capture {
                type_name,
                name,
                span,
            } => Self::Capture {
                type_name: type_name.clone(),
                name: name.clone(),
                span: (*span).into(),
            },
            SignatureAtom::Boundary { atoms, span } => Self::Boundary {
                atoms: atoms.iter().map(Self::from_core_atom).collect(),
                span: (*span).into(),
            },
        }
    }

    fn to_core_atom(&self) -> SignatureAtom {
        match self {
            Self::Literal(bytes, span) => SignatureAtom::Literal(bytes.clone(), (*span).into()),
            Self::Capture {
                type_name,
                name,
                span,
            } => SignatureAtom::Capture {
                type_name: type_name.clone(),
                name: name.clone(),
                span: (*span).into(),
            },
            Self::Boundary { atoms, span } => SignatureAtom::Boundary {
                atoms: atoms
                    .iter()
                    .map(PortableAstSignatureAtom::to_core_atom)
                    .collect(),
                span: (*span).into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableAstStatementSignature {
    pub atoms: Vec<PortableAstSignatureAtom>,
}

impl PortableAstStatementSignature {
    fn from_core_signature(signature: &StatementSignature) -> Self {
        Self {
            atoms: signature
                .atoms
                .iter()
                .map(PortableAstSignatureAtom::from_core_atom)
                .collect(),
        }
    }

    fn to_core_signature(&self) -> StatementSignature {
        StatementSignature {
            atoms: self
                .atoms
                .iter()
                .map(PortableAstSignatureAtom::to_core_atom)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableLineAst {
    Empty,
    Conditional {
        kind: ConditionalKind,
        exprs: Vec<PortableAstExpr>,
        span: PortableSpan,
    },
    Place {
        section: String,
        region: String,
        align: Option<PortableAstExpr>,
        span: PortableSpan,
    },
    Pack {
        region: String,
        sections: Vec<String>,
        span: PortableSpan,
    },
    Use {
        module_id: String,
        alias: Option<String>,
        items: Vec<PortableAstUseItem>,
        params: Vec<PortableAstUseParam>,
        span: PortableSpan,
    },
    StatementDef {
        keyword: String,
        signature: PortableAstStatementSignature,
        span: PortableSpan,
    },
    StatementEnd {
        span: PortableSpan,
    },
    Assignment {
        label: PortableAstLabel,
        op: AssignOp,
        expr: PortableAstExpr,
        span: PortableSpan,
    },
    Statement {
        label: Option<PortableAstLabel>,
        mnemonic: Option<String>,
        operands: Vec<PortableAstExpr>,
    },
}

impl PortableLineAst {
    pub fn from_core_line_ast(value: &LineAst) -> Self {
        match value {
            LineAst::Empty => Self::Empty,
            LineAst::Conditional { kind, exprs, span } => Self::Conditional {
                kind: *kind,
                exprs: exprs.iter().map(PortableAstExpr::from_core_expr).collect(),
                span: (*span).into(),
            },
            LineAst::Place {
                section,
                region,
                align,
                span,
            } => Self::Place {
                section: section.clone(),
                region: region.clone(),
                align: align.as_ref().map(PortableAstExpr::from_core_expr),
                span: (*span).into(),
            },
            LineAst::Pack {
                region,
                sections,
                span,
            } => Self::Pack {
                region: region.clone(),
                sections: sections.clone(),
                span: (*span).into(),
            },
            LineAst::Use {
                module_id,
                alias,
                items,
                params,
                span,
            } => Self::Use {
                module_id: module_id.clone(),
                alias: alias.clone(),
                items: items
                    .iter()
                    .map(PortableAstUseItem::from_core_item)
                    .collect(),
                params: params
                    .iter()
                    .map(PortableAstUseParam::from_core_param)
                    .collect(),
                span: (*span).into(),
            },
            LineAst::StatementDef {
                keyword,
                signature,
                span,
            } => Self::StatementDef {
                keyword: keyword.clone(),
                signature: PortableAstStatementSignature::from_core_signature(signature),
                span: (*span).into(),
            },
            LineAst::StatementEnd { span } => Self::StatementEnd {
                span: (*span).into(),
            },
            LineAst::Assignment {
                label,
                op,
                expr,
                span,
            } => Self::Assignment {
                label: PortableAstLabel::from_core_label(label),
                op: *op,
                expr: PortableAstExpr::from_core_expr(expr),
                span: (*span).into(),
            },
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => Self::Statement {
                label: label.as_ref().map(PortableAstLabel::from_core_label),
                mnemonic: mnemonic.clone(),
                operands: operands
                    .iter()
                    .map(PortableAstExpr::from_core_expr)
                    .collect(),
            },
        }
    }

    pub fn to_core_line_ast(&self) -> LineAst {
        match self {
            Self::Empty => LineAst::Empty,
            Self::Conditional { kind, exprs, span } => LineAst::Conditional {
                kind: *kind,
                exprs: exprs.iter().map(PortableAstExpr::to_core_expr).collect(),
                span: (*span).into(),
            },
            Self::Place {
                section,
                region,
                align,
                span,
            } => LineAst::Place {
                section: section.clone(),
                region: region.clone(),
                align: align.as_ref().map(PortableAstExpr::to_core_expr),
                span: (*span).into(),
            },
            Self::Pack {
                region,
                sections,
                span,
            } => LineAst::Pack {
                region: region.clone(),
                sections: sections.clone(),
                span: (*span).into(),
            },
            Self::Use {
                module_id,
                alias,
                items,
                params,
                span,
            } => LineAst::Use {
                module_id: module_id.clone(),
                alias: alias.clone(),
                items: items.iter().map(PortableAstUseItem::to_core_item).collect(),
                params: params
                    .iter()
                    .map(PortableAstUseParam::to_core_param)
                    .collect(),
                span: (*span).into(),
            },
            Self::StatementDef {
                keyword,
                signature,
                span,
            } => LineAst::StatementDef {
                keyword: keyword.clone(),
                signature: signature.to_core_signature(),
                span: (*span).into(),
            },
            Self::StatementEnd { span } => LineAst::StatementEnd {
                span: (*span).into(),
            },
            Self::Assignment {
                label,
                op,
                expr,
                span,
            } => LineAst::Assignment {
                label: label.to_core_label(),
                op: *op,
                expr: expr.to_core_expr(),
                span: (*span).into(),
            },
            Self::Statement {
                label,
                mnemonic,
                operands,
            } => LineAst::Statement {
                label: label.as_ref().map(PortableAstLabel::to_core_label),
                mnemonic: mnemonic.clone(),
                operands: operands.iter().map(PortableAstExpr::to_core_expr).collect(),
            },
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

struct RuntimePortableExprEvalContext<'a> {
    assembler_ctx: &'a dyn AssemblerContext,
}

impl PortableExprEvalContext for RuntimePortableExprEvalContext<'_> {
    fn lookup_symbol(&self, name: &str) -> Option<i64> {
        if !self.assembler_ctx.has_symbol(name) {
            return None;
        }
        self.assembler_ctx
            .eval_expr(&Expr::Identifier(name.to_string(), Span::default()))
            .ok()
    }

    fn current_address(&self) -> Option<i64> {
        Some(self.assembler_ctx.current_address() as i64)
    }

    fn pass(&self) -> u8 {
        self.assembler_ctx.pass()
    }

    fn symbol_is_finalized(&self, name: &str) -> Option<bool> {
        self.assembler_ctx.symbol_is_finalized(name)
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
        );
        register_fn_resolver(
            &mut expr_resolvers,
            "intel8080",
            HierarchyExecutionModel::select_candidates_from_exprs_intel8080,
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
        match self.effective_tokenizer_mode() {
            RuntimeTokenizerMode::Auto | RuntimeTokenizerMode::Vm => {
                let vm_program = self
                    .tokenizer_vm_program_for_resolved(&resolved)
                    .ok_or_else(|| {
                        RuntimeBridgeError::Resolve(format!(
                            "missing opThread tokenizer VM program for family '{}'",
                            resolved.family_id
                        ))
                    })?;
                let tokens = self.tokenize_with_vm_core(&request, &vm_program)?;
                if tokens.is_empty()
                    && !source_line_can_tokenize_to_empty(source_line, &request.token_policy)
                {
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM produced no tokens for non-empty source line",
                        vm_program.diagnostics.invalid_char
                    )));
                }
                Ok(tokens)
            }
        }
    }

    pub fn tokenize_portable_statement_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        source_line: &str,
        line_num: u32,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        self.tokenize_portable_statement_vm_authoritative(
            cpu_id,
            dialect_override,
            source_line,
            line_num,
        )
    }

    pub fn tokenize_portable_statement_vm_authoritative(
        &self,
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
        let vm_program = self
            .tokenizer_vm_program_for_resolved(&resolved)
            .ok_or_else(|| {
                RuntimeBridgeError::Resolve(format!(
                    "missing opThread tokenizer VM program for family '{}'",
                    resolved.family_id
                ))
            })?;
        let tokens = self.tokenize_with_vm_core(&request, &vm_program)?;
        if tokens.is_empty()
            && !source_line_can_tokenize_to_empty(source_line, &request.token_policy)
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: tokenizer VM produced no tokens for non-empty source line",
                vm_program.diagnostics.invalid_char
            )));
        }
        Ok(tokens)
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

    pub fn resolve_parser_contract(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeParserContract>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.parser_contract_for_resolved(&resolved))
    }

    pub fn validate_parser_contract_for_assembler(
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
        self.ensure_parser_contract_compatible_for_assembler(&contract)?;
        let error_code = parser_contract_error_code(&contract);
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
        Ok(contract)
    }

    pub fn resolve_parser_vm_program(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeParserVmProgram>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.parser_vm_program_for_resolved(&resolved))
    }

    pub fn resolve_expr_contract(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeExprContract>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.expr_contract_for_resolved(&resolved))
    }

    pub fn resolve_expr_parser_contract(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<Option<RuntimeExprParserContract>, RuntimeBridgeError> {
        let resolved = self.bridge.resolve_pipeline(cpu_id, dialect_override)?;
        Ok(self.expr_parser_contract_for_resolved(&resolved))
    }

    pub fn resolve_expr_budgets(
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

    pub fn enforce_parser_vm_program_budget_for_assembler(
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

    pub fn parse_expression_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
    ) -> Result<Expr, ParseError> {
        let use_vm_parser = self.resolve_expr_parser_vm_rollout_for_assembler(
            cpu_id,
            dialect_override,
            false,
            end_span,
        )?;

        self.parse_expression_with_mode_for_assembler(
            cpu_id,
            dialect_override,
            tokens,
            end_span,
            end_token_text,
            use_vm_parser,
        )
    }

    fn parse_expression_with_mode_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
        use_vm_parser: bool,
    ) -> Result<Expr, ParseError> {
        self.validate_parser_contract_for_assembler(cpu_id, dialect_override, tokens.len())
            .map_err(|err| ParseError {
                message: err.to_string(),
                span: end_span,
            })?;

        if use_vm_parser {
            return RuntimeExpressionParser::new(tokens, end_span, end_token_text)
                .parse_expr_from_tokens();
        }

        #[cfg(test)]
        if CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.get()) {
            return Err(ParseError {
                message: "core expression parser failpoint".to_string(),
                span: end_span,
            });
        }

        Parser::parse_expr_from_tokens(tokens, end_span, end_token_text)
    }

    fn resolve_expr_parser_vm_rollout_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        force_vm_parser: bool,
        end_span: Span,
    ) -> Result<bool, ParseError> {
        if force_vm_parser {
            return Ok(true);
        }

        let resolved = self
            .resolve_pipeline(cpu_id, dialect_override)
            .map_err(|err| ParseError {
                message: err.to_string(),
                span: end_span,
            })?;

        Ok(portable_expr_parser_runtime_enabled_for_family(
            resolved.family_id.as_str(),
            &[],
            &[],
        ))
    }

    fn compile_parsed_expression_for_assembler(
        expr: &Expr,
        end_span: Span,
    ) -> Result<PortableExprProgram, ParseError> {
        compile_core_expr_to_portable_program(expr).map_err(|err| ParseError {
            message: err.to_string(),
            span: err.span.unwrap_or(end_span),
        })
    }

    pub fn compile_expression_program_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
    ) -> Result<PortableExprProgram, ParseError> {
        let expr = self.parse_expression_for_assembler(
            cpu_id,
            dialect_override,
            tokens,
            end_span,
            end_token_text,
        )?;
        Self::compile_parsed_expression_for_assembler(&expr, end_span)
    }

    pub fn parse_expression_program_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
    ) -> Result<PortableExprProgram, ParseError> {
        self.compile_expression_program_with_parser_vm_opt_in_for_assembler(
            cpu_id,
            dialect_override,
            tokens,
            end_span,
            end_token_text,
            None,
        )
    }

    pub fn validate_expression_parser_contract_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
    ) -> Result<(), RuntimeBridgeError> {
        let resolved = self.resolve_pipeline(cpu_id, dialect_override)?;
        let use_expr_parser_vm =
            portable_expr_parser_runtime_enabled_for_family(resolved.family_id.as_str(), &[], &[]);
        if !use_expr_parser_vm {
            return Ok(());
        }

        let contract = self.resolve_expr_parser_contract(cpu_id, dialect_override)?;
        if let Some(contract) = contract.as_ref() {
            self.ensure_expr_parser_contract_compatible_for_assembler(contract)?;
        }
        Ok(())
    }

    pub fn compile_expression_program_with_parser_vm_opt_in_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        tokens: Vec<Token>,
        end_span: Span,
        end_token_text: Option<String>,
        parser_vm_opcode_version: Option<u16>,
    ) -> Result<PortableExprProgram, ParseError> {
        let use_expr_parser_vm = self.resolve_expr_parser_vm_rollout_for_assembler(
            cpu_id,
            dialect_override,
            parser_vm_opcode_version.is_some(),
            end_span,
        )?;
        if !use_expr_parser_vm {
            let expr = self.parse_expression_with_mode_for_assembler(
                cpu_id,
                dialect_override,
                tokens,
                end_span,
                end_token_text,
                false,
            );
            return expr
                .and_then(|expr| Self::compile_parsed_expression_for_assembler(&expr, end_span));
        }

        let contract = self
            .resolve_expr_parser_contract(cpu_id, dialect_override)
            .map_err(|err| ParseError {
                message: err.to_string(),
                span: end_span,
            })?;

        if let Some(contract) = contract.as_ref() {
            self.ensure_expr_parser_contract_compatible_for_assembler(contract)
                .map_err(|err| ParseError {
                    message: err.to_string(),
                    span: end_span,
                })?;
        }

        let opcode_version = parser_vm_opcode_version
            .or_else(|| contract.as_ref().map(|entry| entry.opcode_version))
            .unwrap_or(EXPR_PARSER_VM_OPCODE_VERSION_V1);
        if opcode_version != EXPR_PARSER_VM_OPCODE_VERSION_V1 {
            return Err(ParseError {
                message: format!(
                    "unsupported opThread expression parser VM opcode version {}",
                    opcode_version
                ),
                span: end_span,
            });
        }

        let expr = self.parse_expression_with_mode_for_assembler(
            cpu_id,
            dialect_override,
            tokens,
            end_span,
            end_token_text,
            true,
        )?;
        Self::compile_parsed_expression_for_assembler(&expr, end_span)
    }

    pub fn evaluate_portable_expression_program_for_assembler(
        &self,
        program: &PortableExprProgram,
        budgets: PortableExprBudgets,
        ctx: &dyn AssemblerContext,
    ) -> Result<PortableExprEvaluation, RuntimeBridgeError> {
        let adapter = RuntimePortableExprEvalContext { assembler_ctx: ctx };
        eval_portable_expr_program(program, &adapter, budgets)
            .map_err(|err| RuntimeBridgeError::Resolve(err.to_string()))
    }

    pub fn evaluate_portable_expression_program_with_contract_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        program: &PortableExprProgram,
        ctx: &dyn AssemblerContext,
    ) -> Result<PortableExprEvaluation, RuntimeBridgeError> {
        let budgets = self.resolve_expr_budgets(cpu_id, dialect_override)?;
        self.evaluate_portable_expression_program_for_assembler(program, budgets, ctx)
    }

    pub fn portable_expression_has_unstable_symbols_for_assembler(
        &self,
        program: &PortableExprProgram,
        budgets: PortableExprBudgets,
        ctx: &dyn AssemblerContext,
    ) -> Result<bool, RuntimeBridgeError> {
        let adapter = RuntimePortableExprEvalContext { assembler_ctx: ctx };
        expr_program_has_unstable_symbols(program, &adapter, budgets)
            .map_err(|err| RuntimeBridgeError::Resolve(err.to_string()))
    }

    pub fn portable_expression_has_unstable_symbols_with_contract_for_assembler(
        &self,
        cpu_id: &str,
        dialect_override: Option<&str>,
        program: &PortableExprProgram,
        ctx: &dyn AssemblerContext,
    ) -> Result<bool, RuntimeBridgeError> {
        let budgets = self.resolve_expr_budgets(cpu_id, dialect_override)?;
        self.portable_expression_has_unstable_symbols_for_assembler(program, budgets, ctx)
    }

    pub fn parse_portable_line_for_assembler(
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

    pub fn defer_native_diagnostics_on_expr_none(&self, family_id: &str) -> bool {
        family_id.eq_ignore_ascii_case(crate::families::intel8080::module::FAMILY_ID.as_str())
    }

    pub fn selector_gate_only_expr_runtime_for_cpu(&self, cpu_id: &str) -> bool {
        cpu_id.eq_ignore_ascii_case(crate::m65816::module::CPU_ID.as_str())
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

    fn effective_tokenizer_mode(&self) -> RuntimeTokenizerMode {
        match self.tokenizer_mode {
            RuntimeTokenizerMode::Auto => RuntimeTokenizerMode::Vm,
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

    fn parser_contract_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<RuntimeParserContract> {
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
            if let Some(contract) = self.parser_contracts.get(&(owner_tag, owner_id)) {
                return Some(contract.clone());
            }
        }
        None
    }

    fn parser_vm_program_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<RuntimeParserVmProgram> {
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
            if let Some(program) = self.parser_vm_programs.get(&(owner_tag, owner_id)) {
                return Some(program.clone());
            }
        }
        None
    }

    fn expr_contract_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<RuntimeExprContract> {
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
            if let Some(contract) = self.expr_contracts.get(&(owner_tag, owner_id)) {
                return Some(contract.clone());
            }
        }
        None
    }

    fn expr_parser_contract_for_resolved(
        &self,
        resolved: &ResolvedHierarchy,
    ) -> Option<RuntimeExprParserContract> {
        let dialect_id = resolved.dialect_id.to_ascii_lowercase();
        let cpu_id = resolved.cpu_id.to_ascii_lowercase();
        let family_id = resolved.family_id.to_ascii_lowercase();
        let owner_order = [
            (2u8, self.interned_id(&dialect_id)),
            (1u8, self.interned_id(&cpu_id)),
            (0u8, self.interned_id(&family_id)),
        ];
        for (owner_tag, owner_id) in owner_order {
            let Some(owner_id) = owner_id else {
                continue;
            };
            if let Some(contract) = self.expr_parser_contracts.get(&(owner_tag, owner_id)) {
                return Some(contract.clone());
            }
        }
        None
    }

    fn ensure_parser_contract_compatible_for_assembler(
        &self,
        contract: &RuntimeParserContract,
    ) -> Result<(), RuntimeBridgeError> {
        self.ensure_parser_diagnostic_map_compatible_for_assembler(contract)?;
        let error_code = parser_contract_error_code(contract);
        if contract.max_ast_nodes_per_line == 0 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: parser contract max_ast_nodes_per_line must be > 0",
                error_code
            )));
        }
        if contract.opcode_version != PARSER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported parser contract opcode version {}",
                error_code, contract.opcode_version
            )));
        }
        if !contract
            .grammar_id
            .eq_ignore_ascii_case(PARSER_GRAMMAR_ID_LINE_V1)
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported parser grammar id '{}'",
                error_code, contract.grammar_id
            )));
        }
        if !contract
            .ast_schema_id
            .eq_ignore_ascii_case(PARSER_AST_SCHEMA_ID_LINE_V1)
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported parser AST schema id '{}'",
                error_code, contract.ast_schema_id
            )));
        }
        Ok(())
    }

    fn ensure_parser_diagnostic_map_compatible_for_assembler(
        &self,
        contract: &RuntimeParserContract,
    ) -> Result<(), RuntimeBridgeError> {
        let error_code = parser_contract_error_code(contract);
        for (field_name, value) in [
            (
                "unexpected_token",
                contract.diagnostics.unexpected_token.as_str(),
            ),
            (
                "expected_expression",
                contract.diagnostics.expected_expression.as_str(),
            ),
            (
                "expected_operand",
                contract.diagnostics.expected_operand.as_str(),
            ),
            (
                "invalid_statement",
                contract.diagnostics.invalid_statement.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: missing parser contract diagnostic mapping for '{}'",
                    error_code, field_name
                )));
            }
            self.ensure_diag_code_declared_in_package_catalog(
                error_code,
                "parser contract",
                value,
            )?;
        }
        Ok(())
    }

    fn ensure_expr_parser_contract_compatible_for_assembler(
        &self,
        contract: &RuntimeExprParserContract,
    ) -> Result<(), RuntimeBridgeError> {
        let error_code = if contract
            .diagnostics
            .invalid_expression_program
            .trim()
            .is_empty()
        {
            "opthread-runtime"
        } else {
            contract.diagnostics.invalid_expression_program.as_str()
        };

        if contract.opcode_version != EXPR_PARSER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported expression parser contract opcode version {}",
                error_code, contract.opcode_version
            )));
        }

        if contract
            .diagnostics
            .invalid_expression_program
            .trim()
            .is_empty()
        {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: missing diagnostics.invalid_expression_program code",
                error_code
            )));
        }

        self.ensure_diag_code_declared_in_package_catalog(
            error_code,
            "expression parser contract diagnostics.invalid_expression_program",
            contract.diagnostics.invalid_expression_program.as_str(),
        )
    }

    fn ensure_tokenizer_vm_program_compatible_for_assembler(
        &self,
        vm_program: &RuntimeTokenizerVmProgram,
    ) -> Result<(), RuntimeBridgeError> {
        let error_code = tokenizer_vm_error_code(vm_program);
        if vm_program.opcode_version != TOKENIZER_VM_OPCODE_VERSION_V1 {
            return Err(RuntimeBridgeError::Resolve(format!(
                "{}: unsupported tokenizer VM opcode version {}",
                error_code, vm_program.opcode_version
            )));
        }
        for (field_name, value) in [
            ("invalid_char", vm_program.diagnostics.invalid_char.as_str()),
            (
                "unterminated_string",
                vm_program.diagnostics.unterminated_string.as_str(),
            ),
            (
                "step_limit_exceeded",
                vm_program.diagnostics.step_limit_exceeded.as_str(),
            ),
            (
                "token_limit_exceeded",
                vm_program.diagnostics.token_limit_exceeded.as_str(),
            ),
            (
                "lexeme_limit_exceeded",
                vm_program.diagnostics.lexeme_limit_exceeded.as_str(),
            ),
            (
                "error_limit_exceeded",
                vm_program.diagnostics.error_limit_exceeded.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(RuntimeBridgeError::Resolve(format!(
                    "{}: missing tokenizer VM diagnostic mapping for '{}'",
                    error_code, field_name
                )));
            }
            self.ensure_diag_code_declared_in_package_catalog(error_code, "tokenizer VM", value)?;
        }
        Ok(())
    }

    fn ensure_diag_code_declared_in_package_catalog(
        &self,
        error_code: &str,
        context: &str,
        code: &str,
    ) -> Result<(), RuntimeBridgeError> {
        if self.diag_templates.contains_key(&code.to_ascii_lowercase()) {
            return Ok(());
        }
        Err(RuntimeBridgeError::Resolve(format!(
            "{}: {} diagnostic code '{}' is not declared in package DIAG catalog",
            error_code, context, code
        )))
    }

    fn tokenize_with_vm_core(
        &self,
        request: &PortableTokenizeRequest<'_>,
        vm_program: &RuntimeTokenizerVmProgram,
    ) -> Result<Vec<PortableToken>, RuntimeBridgeError> {
        self.ensure_tokenizer_vm_program_compatible_for_assembler(vm_program)?;
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
        let mut core_tokenizer: Option<Tokenizer<'_>> = None;

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
                TokenizerVmOpcode::DelegateCore => {
                    return Err(RuntimeBridgeError::Resolve(format!(
                        "{}: tokenizer VM DelegateCore opcode is forbidden in VM tokenizer execution mode",
                        vm_program.diagnostics.invalid_char
                    )));
                }
                TokenizerVmOpcode::ScanCoreToken => {
                    match vm_scan_next_core_token(request, cursor, &mut core_tokenizer)? {
                        Some((portable, next_cursor)) => {
                            if tokens.len() >= max_tokens_per_line_usize {
                                return Err(RuntimeBridgeError::Resolve(format!(
                                    "{}: tokenizer VM token budget exceeded ({}/{})",
                                    vm_program.diagnostics.token_limit_exceeded,
                                    tokens.len().saturating_add(1),
                                    max_tokens_per_line
                                )));
                            }
                            let lexeme_len = vm_token_lexeme_len(&portable);
                            if lexeme_len > max_lexeme_bytes_usize {
                                return Err(RuntimeBridgeError::Resolve(format!(
                                    "{}: tokenizer VM lexeme budget exceeded ({}/{})",
                                    vm_program.diagnostics.lexeme_limit_exceeded,
                                    lexeme_len,
                                    max_lexeme_bytes
                                )));
                            }
                            tokens
                                .push(apply_token_policy_to_token(portable, &request.token_policy));
                            cursor = next_cursor;
                            current_byte = bytes.get(cursor).copied();
                        }
                        None => {
                            cursor = bytes.len();
                            current_byte = None;
                        }
                    }
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

struct RuntimeExpressionParser {
    tokens: Vec<Token>,
    index: usize,
    end_span: Span,
    end_token_text: Option<String>,
}

impl RuntimeExpressionParser {
    fn new(tokens: Vec<Token>, end_span: Span, end_token_text: Option<String>) -> Self {
        Self {
            tokens,
            index: 0,
            end_span,
            end_token_text,
        }
    }

    fn parse_expr_from_tokens(mut self) -> Result<Expr, ParseError> {
        let expr = self.parse_expr()?;
        if self.index < self.tokens.len() {
            return Err(ParseError {
                message: "Unexpected trailing tokens".to_string(),
                span: self.tokens[self.index].span,
            });
        }
        Ok(expr)
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        match self.peek_operator_kind() {
            Some(OperatorKind::Lt) => {
                self.index += 1;
                let span = self.prev_span();
                let expr = self.parse_expr()?;
                return Ok(Expr::Unary {
                    op: UnaryOp::Low,
                    expr: Box::new(expr),
                    span,
                });
            }
            Some(OperatorKind::Gt) => {
                self.index += 1;
                let span = self.prev_span();
                let expr = self.parse_expr()?;
                return Ok(Expr::Unary {
                    op: UnaryOp::High,
                    expr: Box::new(expr),
                    span,
                });
            }
            _ => {}
        }

        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_logical_or()?;
        if let Some(token) = self.peek() {
            if token.kind == TokenKind::Question {
                let span = token.span;
                self.index += 1;
                let then_expr = self.parse_expr()?;
                if !self.consume_kind(TokenKind::Colon) {
                    return Err(ParseError {
                        message: "Missing ':' in conditional expression".to_string(),
                        span: self.current_span(),
                    });
                }
                let else_expr = self.parse_expr()?;
                node = Expr::Ternary {
                    cond: Box::new(node),
                    then_expr: Box::new(then_expr),
                    else_expr: Box::new(else_expr),
                    span,
                };
            }
        }
        Ok(node)
    }

    fn parse_logical_or(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_logical_and()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::LogicOr) => BinaryOp::LogicOr,
                Some(OperatorKind::LogicXor) => BinaryOp::LogicXor,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_logical_and()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_logical_and(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_bit_or()?;
        while self.match_operator(OperatorKind::LogicAnd) {
            let op_span = self.prev_span();
            let right = self.parse_bit_or()?;
            node = Expr::Binary {
                op: BinaryOp::LogicAnd,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_bit_or(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_bit_xor()?;
        while self.match_operator(OperatorKind::BitOr) {
            let op_span = self.prev_span();
            let right = self.parse_bit_xor()?;
            node = Expr::Binary {
                op: BinaryOp::BitOr,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_bit_xor(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_bit_and()?;
        while self.match_operator(OperatorKind::BitXor) {
            let op_span = self.prev_span();
            let right = self.parse_bit_and()?;
            node = Expr::Binary {
                op: BinaryOp::BitXor,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_bit_and(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_compare()?;
        while self.match_operator(OperatorKind::BitAnd) {
            let op_span = self.prev_span();
            let right = self.parse_compare()?;
            node = Expr::Binary {
                op: BinaryOp::BitAnd,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_compare(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_shift()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Eq) => BinaryOp::Eq,
                Some(OperatorKind::Ne) => BinaryOp::Ne,
                Some(OperatorKind::Ge) => BinaryOp::Ge,
                Some(OperatorKind::Gt) => BinaryOp::Gt,
                Some(OperatorKind::Le) => BinaryOp::Le,
                Some(OperatorKind::Lt) => BinaryOp::Lt,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_shift()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_shift(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_sum()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Shl) => BinaryOp::Shl,
                Some(OperatorKind::Shr) => BinaryOp::Shr,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_sum()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_sum(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_term()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Plus) => BinaryOp::Add,
                Some(OperatorKind::Minus) => BinaryOp::Subtract,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_term()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_term(&mut self) -> Result<Expr, ParseError> {
        let mut node = self.parse_power()?;
        loop {
            let op = match self.peek_operator_kind() {
                Some(OperatorKind::Multiply) => BinaryOp::Multiply,
                Some(OperatorKind::Divide) => BinaryOp::Divide,
                Some(OperatorKind::Mod) => BinaryOp::Mod,
                _ => break,
            };
            self.index += 1;
            let op_span = self.prev_span();
            let right = self.parse_power()?;
            node = Expr::Binary {
                op,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            };
        }
        Ok(node)
    }

    fn parse_power(&mut self) -> Result<Expr, ParseError> {
        let node = self.parse_unary()?;
        if self.match_operator(OperatorKind::Power) {
            let op_span = self.prev_span();
            let right = self.parse_power()?;
            return Ok(Expr::Binary {
                op: BinaryOp::Power,
                left: Box::new(node),
                right: Box::new(right),
                span: op_span,
            });
        }
        Ok(node)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if let Some(op) = match self.peek_operator_kind() {
            Some(OperatorKind::Plus) => Some(UnaryOp::Plus),
            Some(OperatorKind::Minus) => Some(UnaryOp::Minus),
            Some(OperatorKind::BitNot) => Some(UnaryOp::BitNot),
            Some(OperatorKind::LogicNot) => Some(UnaryOp::LogicNot),
            _ => None,
        } {
            self.index += 1;
            let span = self.prev_span();
            let expr = self.parse_unary()?;
            return Ok(Expr::Unary {
                op,
                expr: Box::new(expr),
                span,
            });
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.next() {
            Some(Token {
                kind: TokenKind::Hash,
                span: hash_span,
            }) => {
                let expr = self.parse_expr()?;
                let end_span = self.prev_span();
                let span = Span {
                    line: hash_span.line,
                    col_start: hash_span.col_start,
                    col_end: end_span.col_end,
                };
                Ok(Expr::Immediate(Box::new(expr), span))
            }
            Some(Token {
                kind: TokenKind::Number(num),
                span,
            }) => Ok(Expr::Number(num.text, span)),
            Some(Token {
                kind: TokenKind::Identifier(name),
                span,
            }) => Ok(Expr::Identifier(name, span)),
            Some(Token {
                kind: TokenKind::Register(name),
                span,
            }) => Ok(Expr::Register(name, span)),
            Some(Token {
                kind: TokenKind::Dollar,
                span,
            }) => Ok(Expr::Dollar(span)),
            Some(Token {
                kind: TokenKind::String(lit),
                span,
            }) => Ok(Expr::String(lit.bytes, span)),
            Some(Token {
                kind: TokenKind::OpenParen,
                span: open_span,
            }) => {
                let expr = self.parse_expr()?;

                if self.consume_comma() {
                    let mut elements = vec![expr];
                    elements.push(self.parse_expr()?);
                    while self.consume_comma() {
                        elements.push(self.parse_expr()?);
                    }

                    let close_span = self.current_span();
                    if !self.consume_kind(TokenKind::CloseParen) {
                        return Err(ParseError {
                            message: "Missing ')' in tuple".to_string(),
                            span: self.current_span(),
                        });
                    }
                    let span = Span {
                        line: open_span.line,
                        col_start: open_span.col_start,
                        col_end: close_span.col_end,
                    };
                    Ok(Expr::Indirect(Box::new(Expr::Tuple(elements, span)), span))
                } else {
                    let close_span = self.current_span();
                    if !self.consume_kind(TokenKind::CloseParen) {
                        return Err(ParseError {
                            message: "Missing ')'".to_string(),
                            span: self.current_span(),
                        });
                    }
                    Ok(Expr::Indirect(
                        Box::new(expr),
                        Span {
                            line: open_span.line,
                            col_start: open_span.col_start,
                            col_end: close_span.col_end,
                        },
                    ))
                }
            }
            Some(Token {
                kind: TokenKind::OpenBracket,
                span: open_span,
            }) => {
                let expr = self.parse_expr()?;
                let close_span = self.current_span();
                if !self.consume_kind(TokenKind::CloseBracket) {
                    return Err(ParseError {
                        message: "Missing ']'".to_string(),
                        span: self.current_span(),
                    });
                }
                Ok(Expr::IndirectLong(
                    Box::new(expr),
                    Span {
                        line: open_span.line,
                        col_start: open_span.col_start,
                        col_end: close_span.col_end,
                    },
                ))
            }
            Some(token) => Err(ParseError {
                message: "Unexpected token in expression".to_string(),
                span: token.span,
            }),
            None => Err(ParseError {
                message: match self.end_token_text.as_deref() {
                    Some(token) => format!("Expected label or numeric constant, found: {token}"),
                    None => "Unexpected end of expression".to_string(),
                },
                span: self.end_span,
            }),
        }
    }

    fn consume_comma(&mut self) -> bool {
        self.consume_kind(TokenKind::Comma)
    }

    fn consume_kind(&mut self, kind: TokenKind) -> bool {
        if let Some(token) = self.peek() {
            if token.kind == kind {
                self.index += 1;
                return true;
            }
        }
        false
    }

    fn match_operator(&mut self, op: OperatorKind) -> bool {
        if let Some(token) = self.peek() {
            if token.kind == TokenKind::Operator(op) {
                self.index += 1;
                return true;
            }
        }
        false
    }

    fn peek_operator_kind(&self) -> Option<OperatorKind> {
        if let Some(token) = self.peek() {
            if let TokenKind::Operator(op) = token.kind {
                return Some(op);
            }
        }
        None
    }

    fn next(&mut self) -> Option<Token> {
        if self.index >= self.tokens.len() {
            None
        } else {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            Some(token)
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn prev_span(&self) -> Span {
        if self.index == 0 {
            Span {
                line: 0,
                col_start: 0,
                col_end: 0,
            }
        } else {
            self.tokens[self.index - 1].span
        }
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.index)
            .map(|token| token.span)
            .unwrap_or(self.end_span)
    }
}

#[derive(Clone, Debug)]
struct SelectorInput<'a> {
    shape_key: String,
    expr0: Option<&'a Expr>,
    expr1: Option<&'a Expr>,
    force: Option<OperandForce>,
}

struct SelectorExprContext<'a> {
    model: &'a HierarchyExecutionModel,
    resolved: &'a ResolvedHierarchy,
    assembler_ctx: &'a dyn AssemblerContext,
    use_portable_eval: bool,
}

impl<'a> SelectorExprContext<'a> {
    fn is_unknown_symbol_error(message: &str) -> bool {
        let trimmed = message.trim_start();
        trimmed == "ope004" || trimmed.starts_with("ope004:")
    }

    /// Compatibility fallback allowlist for selector expression resolution.
    ///
    /// Host-eval fallback is intentionally restricted to the unresolved-symbol
    /// diagnostic (`ope004`) so legacy pass-sensitive sizing/selection behavior
    /// remains stable while expression VM rollout completes.
    ///
    /// Any other VM evaluation error must remain a hard runtime error and must
    /// not silently fall back to host evaluation.
    fn allows_host_eval_compat_fallback(message: &str) -> bool {
        Self::is_unknown_symbol_error(message)
    }

    fn new(
        model: &'a HierarchyExecutionModel,
        resolved: &'a ResolvedHierarchy,
        assembler_ctx: &'a dyn AssemblerContext,
    ) -> Self {
        let use_portable_eval =
            crate::opthread::rollout::package_runtime_default_enabled_for_family(
                resolved.family_id.as_str(),
            );
        Self {
            model,
            resolved,
            assembler_ctx,
            use_portable_eval,
        }
    }

    fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
        if !self.use_portable_eval {
            return self.assembler_ctx.eval_expr(expr);
        }
        let program = compile_core_expr_to_portable_program(expr).map_err(|err| err.to_string())?;
        match self
            .model
            .evaluate_portable_expression_program_with_contract_for_assembler(
                self.resolved.cpu_id.as_str(),
                Some(self.resolved.dialect_id.as_str()),
                &program,
                self.assembler_ctx,
            ) {
            Ok(evaluation) => Ok(evaluation.value),
            Err(err) => {
                let message = err.to_string();
                if Self::allows_host_eval_compat_fallback(message.as_str()) {
                    return self.assembler_ctx.eval_expr(expr);
                }
                Err(message)
            }
        }
    }

    fn has_unstable_symbols(&self, expr: &Expr) -> Result<bool, String> {
        if !self.use_portable_eval {
            return Ok(expr_has_unstable_symbols(expr, self.assembler_ctx));
        }
        let program = compile_core_expr_to_portable_program(expr).map_err(|err| err.to_string())?;
        match self
            .model
            .portable_expression_has_unstable_symbols_with_contract_for_assembler(
                self.resolved.cpu_id.as_str(),
                Some(self.resolved.dialect_id.as_str()),
                &program,
                self.assembler_ctx,
            ) {
            Ok(value) => Ok(value),
            Err(err) => {
                let message = err.to_string();
                if Self::allows_host_eval_compat_fallback(message.as_str()) {
                    return Ok(expr_has_unstable_symbols(expr, self.assembler_ctx));
                }
                Err(message)
            }
        }
    }
}

impl HierarchyExecutionModel {
    fn select_candidates_from_exprs_mos6502(
        &self,
        resolved: &ResolvedHierarchy,
        mnemonic: &str,
        operands: &[Expr],
        ctx: &dyn AssemblerContext,
    ) -> Result<Option<Vec<VmEncodeCandidate>>, RuntimeBridgeError> {
        let expr_ctx = SelectorExprContext::new(self, resolved, ctx);
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

        let unstable_expr = match input.expr0 {
            Some(expr) => expr_ctx
                .has_unstable_symbols(expr)
                .map_err(RuntimeBridgeError::Resolve)?,
            None => false,
        };
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
                match selector_to_candidate(selector, &input, &upper_mnemonic, &expr_ctx) {
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

    fn select_candidates_from_exprs_intel8080(
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

        let mut resolved_candidates: Vec<Vec<IntelOperand>> = Vec::new();

        if resolved.cpu_id.eq_ignore_ascii_case("z80") {
            if let Ok(ops) = Z80CpuHandler::new().resolve_operands(mnemonic, &parsed, ctx) {
                resolved_candidates.push(ops);
            }
            if let Ok(ops) =
                resolve_intel8080_operands(mnemonic, &parsed, ctx).map_err(|err| err.message)
            {
                resolved_candidates.push(ops);
            }
        } else if resolved.cpu_id.eq_ignore_ascii_case("8085") {
            if let Ok(ops) = I8085CpuHandler::new().resolve_operands(mnemonic, &parsed, ctx) {
                resolved_candidates.push(ops);
            }
        } else if let Ok(ops) =
            resolve_intel8080_operands(mnemonic, &parsed, ctx).map_err(|err| err.message)
        {
            resolved_candidates.push(ops);
        }

        for resolved_operands in resolved_candidates.iter() {
            if let Some(candidate) = intel8080_candidate_from_resolved(
                mnemonic,
                resolved.cpu_id.as_str(),
                resolved_operands,
                ctx,
            ) {
                return Ok(Some(vec![candidate]));
            }
        }

        Ok(None)
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

fn intel8080_candidate_from_resolved(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
    ctx: &dyn AssemblerContext,
) -> Option<VmEncodeCandidate> {
    let normalized_operands;
    let operands =
        if let Some(stripped) = intel8080_strip_redundant_condition_operand(mnemonic, operands) {
            normalized_operands = stripped;
            normalized_operands.as_slice()
        } else {
            operands
        };

    if let Some(candidate) = intel8080_ld_indirect_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_half_index_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_cb_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_indexed_memory_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }
    if let Some(candidate) = intel8080_indexed_cb_candidate(mnemonic, cpu_id, operands) {
        return Some(candidate);
    }

    let entry = intel8080_lookup_instruction_entry(mnemonic, cpu_id, operands)?;
    if matches!(entry.arg_type, IntelArgType::Im) {
        let mode = intel8080_interrupt_mode_for_entry(entry, operands)?;
        let mode_key = mode_key_for_z80_interrupt_mode(mode)?;
        return Some(VmEncodeCandidate {
            mode_key,
            operand_bytes: Vec::new(),
        });
    }
    let operand_bytes = intel8080_operand_bytes_for_entry(entry, operands, ctx)?;
    Some(VmEncodeCandidate {
        mode_key: mode_key_for_instruction_entry(entry),
        operand_bytes,
    })
}

fn intel8080_strip_redundant_condition_operand(
    mnemonic: &str,
    operands: &[IntelOperand],
) -> Option<Vec<IntelOperand>> {
    let suffix = intel8080_condition_suffix_for_mnemonic(mnemonic)?;
    let first = operands.first()?;
    let condition = match first {
        IntelOperand::Condition(name, _) | IntelOperand::Register(name, _) => name.as_str(),
        _ => return None,
    };
    if !condition.eq_ignore_ascii_case(suffix) {
        return None;
    }
    Some(operands[1..].to_vec())
}

fn intel8080_condition_suffix_for_mnemonic(mnemonic: &str) -> Option<&'static str> {
    match mnemonic.to_ascii_uppercase().as_str() {
        "JNZ" | "CNZ" | "RNZ" => Some("NZ"),
        "JZ" | "CZ" | "RZ" => Some("Z"),
        "JNC" | "CNC" | "RNC" => Some("NC"),
        "JC" | "CC" | "RC" => Some("C"),
        "JPO" | "CPO" | "RPO" => Some("PO"),
        "JPE" | "CPE" | "RPE" => Some("PE"),
        "JP" | "CP" | "RP" => Some("P"),
        "JM" | "CM" | "RM" => Some("M"),
        _ => None,
    }
}

fn intel8080_lookup_key(operand: &IntelOperand) -> Option<String> {
    match operand {
        IntelOperand::Register(name, _) => Some(name.to_string()),
        IntelOperand::Indirect(name, _) if name.eq_ignore_ascii_case("hl") => Some("M".to_string()),
        IntelOperand::Indirect(name, _) => Some(name.to_string()),
        IntelOperand::Indexed { base, offset, .. } if *offset == 0 => Some(base.to_string()),
        IntelOperand::Condition(name, _) => Some(name.to_string()),
        IntelOperand::RstVector(value, _)
        | IntelOperand::InterruptMode(value, _)
        | IntelOperand::BitNumber(value, _) => Some(value.to_string()),
        _ => None,
    }
}

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

fn intel8080_interrupt_mode_for_entry(
    entry: &IntelInstructionEntry,
    operands: &[IntelOperand],
) -> Option<u8> {
    if !matches!(entry.arg_type, IntelArgType::Im) {
        return None;
    }
    let imm_index = entry.num_regs as usize;
    let mode = match operands.get(imm_index)? {
        IntelOperand::InterruptMode(value, _) | IntelOperand::Immediate8(value, _) => *value,
        IntelOperand::Immediate16(value, _) => (*value).try_into().ok()?,
        _ => return None,
    };
    if mode <= 2 {
        Some(mode)
    } else {
        None
    }
}

fn intel8080_ld_indirect_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80")
        || !mnemonic.eq_ignore_ascii_case("ld")
        || operands.len() != 2
    {
        return None;
    }

    let (mode_key, addr) = match (&operands[0], &operands[1]) {
        (IntelOperand::Register(dst, _), IntelOperand::IndirectAddress16(addr, _)) => {
            (mode_key_for_z80_ld_indirect(dst.as_str(), false)?, *addr)
        }
        (IntelOperand::IndirectAddress16(addr, _), IntelOperand::Register(src, _)) => {
            (mode_key_for_z80_ld_indirect(src.as_str(), true)?, *addr)
        }
        _ => return None,
    };

    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes: vec![vec![addr as u8, (addr >> 8) as u8]],
    })
}

fn intel8080_half_index_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let mut prefix: Option<&str> = None;
    for operand in operands {
        let IntelOperand::Register(name, _) = operand else {
            continue;
        };
        let Some((current_prefix, _)) = intel8080_half_index_parts(name) else {
            continue;
        };
        match prefix {
            None => prefix = Some(current_prefix),
            Some(existing) if existing.eq_ignore_ascii_case(current_prefix) => {}
            Some(_) => return None,
        }
    }
    let prefix = prefix?;
    let upper = mnemonic.to_ascii_uppercase();

    let (_opcode, operand_bytes, form) = match upper.as_str() {
        "LD" => {
            if operands.len() != 2 {
                return None;
            }
            match (&operands[0], &operands[1]) {
                (IntelOperand::Register(dst, _), IntelOperand::Register(src, _)) => {
                    let dst_code = intel8080_half_index_reg_code(prefix, dst)?;
                    let src_code = intel8080_half_index_reg_code(prefix, src)?;
                    (
                        0x40 | (dst_code << 3) | src_code,
                        Vec::new(),
                        format!("rr:{dst_code}:{src_code}"),
                    )
                }
                (IntelOperand::Register(dst, _), IntelOperand::Immediate8(value, _)) => {
                    let (dst_prefix, dst_code) = intel8080_half_index_parts(dst)?;
                    if !dst_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    (
                        0x06 | (dst_code << 3),
                        vec![vec![*value]],
                        format!("ri:{dst_code}"),
                    )
                }
                (IntelOperand::Register(dst, _), IntelOperand::Immediate16(value, _))
                    if *value <= 0xFF =>
                {
                    let (dst_prefix, dst_code) = intel8080_half_index_parts(dst)?;
                    if !dst_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    (
                        0x06 | (dst_code << 3),
                        vec![vec![*value as u8]],
                        format!("ri:{dst_code}"),
                    )
                }
                _ => return None,
            }
        }
        "INC" | "DEC" => {
            if operands.len() != 1 {
                return None;
            }
            let code = match &operands[0] {
                IntelOperand::Register(name, _) => {
                    let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
                    if !reg_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    reg_code
                }
                _ => return None,
            };
            let base = if upper == "INC" { 0x04 } else { 0x05 };
            (base | (code << 3), Vec::new(), format!("r:{code}"))
        }
        "ADD" | "ADC" | "SBC" => {
            if operands.len() != 2 || !intel8080_is_register_a(&operands[0]) {
                return None;
            }
            let code = match &operands[1] {
                IntelOperand::Register(name, _) => {
                    let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
                    if !reg_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    reg_code
                }
                _ => return None,
            };
            let base = match upper.as_str() {
                "ADD" => 0x80,
                "ADC" => 0x88,
                "SBC" => 0x98,
                _ => return None,
            };
            (base | code, Vec::new(), format!("r:{code}"))
        }
        "SUB" | "AND" | "XOR" | "OR" | "CP" => {
            let src = match operands {
                [src] => src,
                [dst, src] if intel8080_is_register_a(dst) => src,
                _ => return None,
            };
            let code = match src {
                IntelOperand::Register(name, _) => {
                    let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
                    if !reg_prefix.eq_ignore_ascii_case(prefix) {
                        return None;
                    }
                    reg_code
                }
                _ => return None,
            };
            let base = match upper.as_str() {
                "SUB" => 0x90,
                "AND" => 0xA0,
                "XOR" => 0xA8,
                "OR" => 0xB0,
                "CP" => 0xB8,
                _ => return None,
            };
            (base | code, Vec::new(), format!("r:{code}"))
        }
        _ => return None,
    };

    let mode_key = mode_key_for_z80_half_index(prefix, mnemonic, form.as_str())?;
    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes,
    })
}

fn intel8080_half_index_parts(name: &str) -> Option<(&'static str, u8)> {
    match name.to_ascii_uppercase().as_str() {
        "IXH" => Some(("IX", 4)),
        "IXL" => Some(("IX", 5)),
        "IYH" => Some(("IY", 4)),
        "IYL" => Some(("IY", 5)),
        _ => None,
    }
}

fn intel8080_half_index_reg_code(prefix: &str, name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "B" => Some(0),
        "C" => Some(1),
        "D" => Some(2),
        "E" => Some(3),
        "A" => Some(7),
        _ => {
            let (reg_prefix, reg_code) = intel8080_half_index_parts(name)?;
            if reg_prefix.eq_ignore_ascii_case(prefix) {
                Some(reg_code)
            } else {
                None
            }
        }
    }
}

fn intel8080_cb_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let upper = mnemonic.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SLL" | "SRL"
    ) {
        if operands.len() != 1 {
            return None;
        }
        let reg = intel8080_cb_register_name(&operands[0])?;
        let mode_key = mode_key_for_z80_cb_register(&upper, None, reg)?;
        return Some(VmEncodeCandidate {
            mode_key,
            operand_bytes: Vec::new(),
        });
    }

    if matches!(upper.as_str(), "BIT" | "RES" | "SET") {
        if operands.len() != 2 || intel8080_indexed_base_disp(&operands[1]).is_some() {
            return None;
        }
        let bit = intel8080_bit_value(&operands[0])?;
        let reg = intel8080_cb_register_name(&operands[1])?;
        let mode_key = mode_key_for_z80_cb_register(&upper, Some(bit), reg)?;
        return Some(VmEncodeCandidate {
            mode_key,
            operand_bytes: Vec::new(),
        });
    }

    None
}

fn intel8080_indexed_memory_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let (indexed_pos, base, displacement) = intel8080_single_indexed_operand(operands)?;
    let upper = mnemonic.to_ascii_uppercase();

    let (form, operand_bytes) = match upper.as_str() {
        "LD" => {
            if operands.len() != 2 {
                return None;
            }
            match (&operands[0], &operands[1], indexed_pos) {
                (IntelOperand::Register(dst, _), IntelOperand::Indexed { .. }, 1) => {
                    let _ = intel8080_z80_indexed_reg_code(dst)?;
                    (
                        format!("ld_r_from_idx_{}", dst.to_ascii_lowercase()),
                        vec![vec![displacement]],
                    )
                }
                (IntelOperand::Indexed { .. }, IntelOperand::Register(src, _), 0) => {
                    let _ = intel8080_z80_indexed_reg_code(src)?;
                    (
                        format!("ld_idx_from_r_{}", src.to_ascii_lowercase()),
                        vec![vec![displacement]],
                    )
                }
                (IntelOperand::Indexed { .. }, IntelOperand::Immediate8(value, _), 0) => (
                    "ld_idx_imm".to_string(),
                    vec![vec![displacement], vec![*value]],
                ),
                _ => return None,
            }
        }
        "INC" | "DEC" if operands.len() == 1 && indexed_pos == 0 => (
            if upper == "INC" {
                "inc_idx".to_string()
            } else {
                "dec_idx".to_string()
            },
            vec![vec![displacement]],
        ),
        "ADD" | "ADC" | "SBC"
            if operands.len() == 2 && indexed_pos == 1 && intel8080_is_register_a(&operands[0]) =>
        {
            let form = match upper.as_str() {
                "ADD" => "add_a_idx",
                "ADC" => "adc_a_idx",
                "SBC" => "sbc_a_idx",
                _ => return None,
            };
            (form.to_string(), vec![vec![displacement]])
        }
        "SUB"
            if (indexed_pos == 0 && operands.len() == 1)
                || (indexed_pos == 1
                    && operands.len() == 2
                    && intel8080_is_register_a(&operands[0])) =>
        {
            ("sub_idx".to_string(), vec![vec![displacement]])
        }
        "AND" | "XOR" | "OR" | "CP"
            if (indexed_pos == 0 && operands.len() == 1)
                || (indexed_pos == 1
                    && operands.len() == 2
                    && intel8080_is_register_a(&operands[0])) =>
        {
            let form = match upper.as_str() {
                "AND" => "and_idx",
                "XOR" => "xor_idx",
                "OR" => "or_idx",
                "CP" => "cp_idx",
                _ => return None,
            };
            (form.to_string(), vec![vec![displacement]])
        }
        _ => return None,
    };

    let mode_key = mode_key_for_z80_indexed_memory(base, form.as_str())?;
    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes,
    })
}

fn intel8080_single_indexed_operand(operands: &[IntelOperand]) -> Option<(usize, &str, u8)> {
    let mut found = None;
    for (idx, operand) in operands.iter().enumerate() {
        let Some((base, displacement)) = intel8080_indexed_base_disp(operand) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some((idx, base, displacement));
    }
    found
}

fn intel8080_z80_indexed_reg_code(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "B" => Some(0),
        "C" => Some(1),
        "D" => Some(2),
        "E" => Some(3),
        "H" => Some(4),
        "L" => Some(5),
        "A" => Some(7),
        _ => None,
    }
}

fn intel8080_is_register_a(operand: &IntelOperand) -> bool {
    matches!(operand, IntelOperand::Register(name, _) if name.eq_ignore_ascii_case("a"))
}

fn intel8080_indexed_cb_candidate(
    mnemonic: &str,
    cpu_id: &str,
    operands: &[IntelOperand],
) -> Option<VmEncodeCandidate> {
    if !cpu_id.eq_ignore_ascii_case("z80") {
        return None;
    }

    let upper = mnemonic.to_ascii_uppercase();
    let (base, displacement) = match upper.as_str() {
        "BIT" | "RES" | "SET" => {
            if operands.len() != 2 {
                return None;
            }
            let bit = intel8080_bit_value(&operands[0])?;
            let (base, displacement) = intel8080_indexed_base_disp(&operands[1])?;
            let mode_key = mode_key_for_z80_indexed_cb(base, &upper, Some(bit))?;
            return Some(VmEncodeCandidate {
                mode_key,
                operand_bytes: vec![vec![displacement]],
            });
        }
        "RLC" | "RRC" | "RL" | "RR" | "SLA" | "SRA" | "SLL" | "SRL" => {
            if operands.len() != 1 {
                return None;
            }
            intel8080_indexed_base_disp(&operands[0])?
        }
        _ => return None,
    };

    let mode_key = mode_key_for_z80_indexed_cb(base, &upper, None)?;
    Some(VmEncodeCandidate {
        mode_key,
        operand_bytes: vec![vec![displacement]],
    })
}

fn intel8080_indexed_base_disp(operand: &IntelOperand) -> Option<(&str, u8)> {
    match operand {
        IntelOperand::Indexed { base, offset, .. }
            if base.eq_ignore_ascii_case("ix") || base.eq_ignore_ascii_case("iy") =>
        {
            Some((base.as_str(), *offset as u8))
        }
        _ => None,
    }
}

fn intel8080_bit_value(operand: &IntelOperand) -> Option<u8> {
    let bit = match operand {
        IntelOperand::BitNumber(value, _) | IntelOperand::Immediate8(value, _) => *value,
        IntelOperand::Immediate16(value, _) => (*value).try_into().ok()?,
        _ => return None,
    };
    if bit <= 7 {
        Some(bit)
    } else {
        None
    }
}

fn intel8080_cb_register_name(operand: &IntelOperand) -> Option<&str> {
    match operand {
        IntelOperand::Register(name, _) => Some(name.as_str()),
        IntelOperand::Indirect(name, _) if name.eq_ignore_ascii_case("hl") => Some("M"),
        _ => None,
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

fn parser_contract_error_code(contract: &RuntimeParserContract) -> &str {
    let code = contract.diagnostics.invalid_statement.trim();
    if code.is_empty() {
        "opthread-runtime"
    } else {
        code
    }
}

fn tokenizer_vm_error_code(program: &RuntimeTokenizerVmProgram) -> &str {
    let code = program.diagnostics.invalid_char.trim();
    if code.is_empty() {
        "opthread-runtime"
    } else {
        code
    }
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

fn source_line_can_tokenize_to_empty(source_line: &str, policy: &RuntimeTokenPolicy) -> bool {
    let trimmed = source_line.trim_start();
    trimmed.is_empty()
        || (!policy.comment_prefix.is_empty()
            && trimmed.starts_with(policy.comment_prefix.as_str()))
}

fn vm_scan_next_core_token<'a>(
    request: &PortableTokenizeRequest<'a>,
    cursor: usize,
    tokenizer: &mut Option<Tokenizer<'a>>,
) -> Result<Option<(PortableToken, usize)>, RuntimeBridgeError> {
    if cursor >= request.source_line.len() {
        return Ok(None);
    }

    if tokenizer.is_none() {
        *tokenizer = Some(Tokenizer::new(request.source_line, request.line_num));
    }
    let Some(tokenizer) = tokenizer.as_mut() else {
        return Ok(None);
    };
    loop {
        let token = tokenizer
            .next_token()
            .map_err(|err| RuntimeBridgeError::Resolve(err.message))?;
        let token_end = token.span.col_end.saturating_sub(1);
        if token_end <= cursor {
            if matches!(token.kind, TokenKind::End) {
                return Ok(None);
            }
            continue;
        }
        if matches!(token.kind, TokenKind::End) {
            return Ok(None);
        }
        if let Some(portable) = PortableToken::from_core_token(token) {
            return Ok(Some((portable, token_end)));
        }
        return Ok(None);
    }
}

fn vm_token_lexeme_len(token: &PortableToken) -> usize {
    match &token.kind {
        PortableTokenKind::Identifier(name) | PortableTokenKind::Register(name) => name.len(),
        PortableTokenKind::Number { text, .. } => text.len(),
        // Budget string lexemes by encoded payload bytes; raw includes delimiters.
        PortableTokenKind::String { bytes, .. } => bytes.len(),
        PortableTokenKind::Comma
        | PortableTokenKind::Colon
        | PortableTokenKind::Dollar
        | PortableTokenKind::Dot
        | PortableTokenKind::Hash
        | PortableTokenKind::Question
        | PortableTokenKind::OpenBracket
        | PortableTokenKind::CloseBracket
        | PortableTokenKind::OpenBrace
        | PortableTokenKind::CloseBrace
        | PortableTokenKind::OpenParen
        | PortableTokenKind::CloseParen => 1,
        PortableTokenKind::Operator(op) => match op {
            PortableOperatorKind::Power
            | PortableOperatorKind::Shl
            | PortableOperatorKind::Shr
            | PortableOperatorKind::LogicAnd
            | PortableOperatorKind::LogicOr
            | PortableOperatorKind::LogicXor
            | PortableOperatorKind::Eq
            | PortableOperatorKind::Ne
            | PortableOperatorKind::Ge
            | PortableOperatorKind::Le => 2,
            _ => 1,
        },
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
    expr_ctx: &SelectorExprContext<'_>,
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
            vec![encode_expr_u8(expr0, expr_ctx)?]
        }
        "u16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u16(expr0, expr_ctx)?]
        }
        "u24" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_u24(expr0, expr_ctx)?]
        }
        "force_l_u24" => vec![encode_expr_force_u24(
            input
                .expr0
                .ok_or_else(|| "missing force-l operand".to_string())?,
            expr_ctx,
        )?],
        "m65816_long_pref_u24" => {
            let expr0 = input
                .expr0
                .ok_or_else(|| "missing unresolved-long operand".to_string())?;
            if !prefer_long_for_expr(expr0, upper_mnemonic, expr_ctx)? {
                return Ok(None);
            }
            vec![encode_expr_force_u24(expr0, expr_ctx)?]
        }
        "m65816_abs16_bank_fold_dbr" => {
            let expr0 = input
                .expr0
                .ok_or_else(|| "missing bank-fold operand".to_string())?;
            if should_defer_abs16_to_other_candidates(expr0, upper_mnemonic, expr_ctx)? {
                return Ok(None);
            }
            vec![encode_expr_abs16_bank_fold(
                expr0,
                upper_mnemonic,
                expr_ctx,
            )?]
        }
        "rel8" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel8(expr0, expr_ctx, 2)?]
        }
        "rel16" => {
            let Some(expr0) = input.expr0 else {
                return Ok(None);
            };
            vec![encode_expr_rel16(expr0, expr_ctx, 3)?]
        }
        "pair_u8_rel8" => vec![
            encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                expr_ctx,
            )?,
            encode_expr_rel8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                expr_ctx,
                3,
            )?,
        ],
        "u8u8_packed" => vec![{
            let mut packed = encode_expr_u8(
                input
                    .expr0
                    .ok_or_else(|| "missing first operand".to_string())?,
                expr_ctx,
            )?;
            packed.extend(encode_expr_u8(
                input
                    .expr1
                    .ok_or_else(|| "missing second operand".to_string())?,
                expr_ctx,
            )?);
            packed
        }],
        "force_d_u8" => vec![encode_expr_force_d_u8(
            input
                .expr0
                .ok_or_else(|| "missing force-d operand".to_string())?,
            expr_ctx,
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
                expr_ctx,
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
                expr_ctx,
            )?]
        }
        "imm_mx" => vec![encode_expr_m65816_immediate(
            input
                .expr0
                .ok_or_else(|| "missing immediate operand".to_string())?,
            upper_mnemonic,
            expr_ctx,
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

fn encode_expr_u8(expr: &Expr, expr_ctx: &SelectorExprContext<'_>) -> Result<Vec<u8>, String> {
    encode_expr_fixed_width(expr, expr_ctx, 1, 0xFF, "invalid u8 operand")
}

fn encode_expr_u16(expr: &Expr, expr_ctx: &SelectorExprContext<'_>) -> Result<Vec<u8>, String> {
    encode_expr_fixed_width(expr, expr_ctx, 2, 0xFFFF, "invalid u16 operand")
}

fn encode_expr_u24(expr: &Expr, expr_ctx: &SelectorExprContext<'_>) -> Result<Vec<u8>, String> {
    encode_expr_fixed_width(expr, expr_ctx, 3, 0xFF_FFFF, "invalid u24 operand")
}

fn encode_expr_fixed_width(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    byte_count: usize,
    max_value: i64,
    error_message: &str,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    if !(0..=max_value).contains(&value) {
        return Err(error_message.to_string());
    }

    let mut bytes = Vec::with_capacity(byte_count);
    let mut remaining = value as u32;
    for _ in 0..byte_count {
        bytes.push((remaining & 0xFF) as u8);
        remaining >>= 8;
    }
    Ok(bytes)
}

fn encode_expr_force_d_u8(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(vec![0]);
    }
    let value = expr_ctx.eval_expr(expr)?;
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
    let Some(dp_offset) =
        direct_page_offset_for_absolute_address(absolute_value, expr_ctx.assembler_ctx)
    else {
        return Err(format!(
            "Address ${absolute_value:04X} is outside the direct-page window for explicit ',d'"
        ));
    };
    Ok(vec![dp_offset])
}

fn encode_expr_force_u24(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(vec![0, 0, 0]);
    }
    let value = expr_ctx.eval_expr(expr)?;
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
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<bool, String> {
    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, expr_ctx.assembler_ctx);
    let symbol_based = expr_has_symbol_references(expr);

    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(expr_ctx.assembler_ctx.current_address() > 0xFFFF
            || !assumed_known
            || assumed_bank != 0);
    }

    let value = expr_ctx.eval_expr(expr)?;
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
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<bool, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(true);
    }
    let value = expr_ctx.eval_expr(expr)?;
    if value <= 0xFFFF {
        return Ok(true);
    }
    if value > 0xFF_FFFF {
        return Ok(false);
    }
    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, expr_ctx.assembler_ctx);
    let absolute_bank = ((value as u32) >> 16) as u8;
    Ok(!assumed_known || absolute_bank != assumed_bank)
}

fn encode_expr_abs16_bank_fold(
    expr: &Expr,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
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

    let (assumed_bank, assumed_known) = assumed_bank_state(upper_mnemonic, expr_ctx.assembler_ctx);
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
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    if expr_ctx.assembler_ctx.pass() == 1 && expr_ctx.has_unstable_symbols(expr)? {
        return Ok(vec![0, 0]);
    }
    let value = expr_ctx.eval_expr(expr)?;
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
        state::program_bank_known(expr_ctx.assembler_ctx)
    } else {
        state::data_bank_known(expr_ctx.assembler_ctx)
    };
    if !assumed_known {
        return Err(bank_unknown_error(assumed_bank_key, upper_mnemonic));
    }
    let assumed_bank = if use_program_bank {
        state::program_bank(expr_ctx.assembler_ctx)
    } else {
        state::data_bank(expr_ctx.assembler_ctx)
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
    expr_ctx: &SelectorExprContext<'_>,
    instr_len: i64,
) -> Result<Vec<u8>, String> {
    encode_expr_relative(
        expr,
        expr_ctx,
        instr_len,
        -128,
        127,
        1,
        "Branch target out of range",
    )
}

fn encode_expr_rel16(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    instr_len: i64,
) -> Result<Vec<u8>, String> {
    encode_expr_relative(
        expr,
        expr_ctx,
        instr_len,
        -32768,
        32767,
        2,
        "Long branch target out of range",
    )
}

fn encode_expr_relative(
    expr: &Expr,
    expr_ctx: &SelectorExprContext<'_>,
    instr_len: i64,
    min_offset: i64,
    max_offset: i64,
    byte_count: usize,
    error_label: &str,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    let current = expr_ctx.assembler_ctx.current_address() as i64 + instr_len;
    let offset = value - current;
    if !(min_offset..=max_offset).contains(&offset) {
        if expr_ctx.assembler_ctx.pass() > 1 {
            return Err(format!("{}: offset {}", error_label, offset));
        }
        return Ok(vec![0; byte_count]);
    }
    let mut bytes = Vec::with_capacity(byte_count);
    let mut remaining = offset as i32 as u32;
    for _ in 0..byte_count {
        bytes.push((remaining & 0xFF) as u8);
        remaining >>= 8;
    }
    Ok(bytes)
}

fn encode_expr_m65816_immediate(
    expr: &Expr,
    upper_mnemonic: &str,
    expr_ctx: &SelectorExprContext<'_>,
) -> Result<Vec<u8>, String> {
    let value = expr_ctx.eval_expr(expr)?;
    let acc_imm = matches!(
        upper_mnemonic,
        "ADC" | "AND" | "BIT" | "CMP" | "EOR" | "LDA" | "ORA" | "SBC"
    );
    let idx_imm = matches!(upper_mnemonic, "CPX" | "CPY" | "LDX" | "LDY");
    if acc_imm {
        if state::accumulator_is_8bit(expr_ctx.assembler_ctx) {
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
        if state::index_is_8bit(expr_ctx.assembler_ctx) {
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
    use crate::core::parser::{
        AssignOp, Expr, Label, LineAst, SignatureAtom, StatementSignature, UseItem, UseParam,
    };
    use crate::core::registry::{ModuleRegistry, VmEncodeCandidate};
    use crate::core::tokenizer::{ConditionalKind, Span, Token, TokenKind, Tokenizer};
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
    use crate::opthread::vm::{OP_EMIT_OPERAND, OP_EMIT_U8, OP_END};
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
            metadata: crate::opthread::package::PackageMetaDescriptor::default(),
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
    fn execution_model_budget_rejects_parser_token_overflow() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let host_tokens = tokenize_host_line(line, 12).expect("host tokenization should succeed");
        let vm_tokens = model
            .tokenize_portable_statement("m6502", None, line, 12)
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
        let host_tokens = tokenize_host_line(line, 14).expect("host tokenization should succeed");
        let vm_tokens = model
            .tokenize_portable_statement("m6502", None, line, 14)
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
            .tokenize_portable_statement("m6502", None, "lda", 1)
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
    fn execution_model_parser_contract_resolution_prefers_dialect_then_cpu_then_family() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
        let mut cpu_contract = parser_contract_for_test(ScopedOwner::Cpu("m6502".to_string()));
        cpu_contract.max_ast_nodes_per_line = 1;
        chunks.parser_contracts.push(cpu_contract);

        let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
        let err = model
            .validate_parser_contract_for_assembler("m6502", None, 2)
            .expect_err("parser budget should be enforced");
        assert!(
            err.to_string().to_ascii_lowercase().contains("otp004"),
            "expected diagnostic code in error, got: {err}"
        );
    }

    #[test]
    fn execution_model_validate_parser_contract_for_assembler_rejects_zero_ast_budget() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
                .contains("missing opthread parser contract"),
            "expected missing contract error, got: {err}"
        );
    }

    #[test]
    fn execution_model_validate_parser_contract_for_assembler_rejects_incompatible_grammar() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
    fn execution_model_validate_parser_contract_for_assembler_rejects_incompatible_opcode_version()
    {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

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
    fn execution_model_parse_expression_for_assembler_certified_path_bypasses_core_parser_failpoint(
    ) {
        struct FailpointReset;

        impl Drop for FailpointReset {
            fn drop(&mut self) {
                CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(false));
            }
        }

        let _reset = FailpointReset;
        CORE_EXPR_PARSER_FAILPOINT.with(|flag| flag.set(true));

        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

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

        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

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
    fn execution_model_expr_parser_contract_resolution_prefers_dialect_then_cpu_then_family() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
        chunks.expr_parser_contracts.clear();
        let mut contract =
            expr_parser_contract_for_test(ScopedOwner::Family("mos6502".to_string()));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
        let (host_tokens, host_end_span) = tokenize_core_expr_tokens("1 ? $+1 : target", 1);
        let (opt_in_tokens, opt_in_end_span) = tokenize_core_expr_tokens("1 ? $+1 : target", 1);

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
    fn execution_model_compile_expression_program_parser_vm_opt_in_rejects_unknown_opcode_version()
    {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
            .contains("unsupported opThread expression parser VM opcode version"));
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
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");
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
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        let mut chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
        let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
        program.program = vec![TokenizerVmOpcode::End as u8];
        chunks.tokenizer_vm_programs.push(program);
        let mut model =
            HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
            .contains("missing opthread tokenizer vm program"));
    }

    #[test]
    fn execution_model_tokenizer_vm_authoritative_mode_rejects_incompatible_opcode_version() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
        let mut chunks =
            build_hierarchy_chunks_from_registry(&registry).expect("hierarchy chunks build");
        let mut program = tokenizer_vm_program_for_test(ScopedOwner::Cpu("m6502".to_string()));
        program.diagnostics.token_limit_exceeded = "ott999".to_string();
        chunks.tokenizer_vm_programs.push(program);
        let model = HierarchyExecutionModel::from_chunks(chunks).expect("execution model build");
        let err = model
            .tokenize_portable_statement_vm_authoritative("m6502", None, "LDA #$42", 1)
            .expect_err("authoritative vm tokenization should reject unknown diag mapping");
        assert!(err.to_string().contains(
            "tokenizer VM diagnostic code 'ott999' is not declared in package DIAG catalog"
        ));
    }

    #[test]
    fn execution_model_tokenizer_vm_authoritative_mode_rejects_empty_tokens() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));
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
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
        let model =
            HierarchyExecutionModel::from_registry(&registry).expect("execution model build");

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
        assert!(model.supports_expr_resolution_for_family("intel8080"));
    }

    #[test]
    fn execution_model_expr_encode_returns_none_for_unsupported_intel_shape() {
        let model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
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
            .encode_instruction_from_exprs(
                "z80",
                None,
                "IM",
                &[Expr::Number("0".into(), span)],
                &ctx,
            )
            .expect("IM 0 should resolve");
        let im1 = model
            .encode_instruction_from_exprs(
                "z80",
                None,
                "IM",
                &[Expr::Number("1".into(), span)],
                &ctx,
            )
            .expect("IM 1 should resolve");
        let im2 = model
            .encode_instruction_from_exprs(
                "z80",
                None,
                "IM",
                &[Expr::Number("2".into(), span)],
                &ctx,
            )
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
        let mut model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
        let replaced =
            model.register_expr_resolver_for_family("intel8080", intel_test_expr_resolver);
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
        let mut model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
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
        let model = HierarchyExecutionModel::from_chunks(intel_only_chunks())
            .expect("execution model build");
        assert!(model.supports_expr_resolution_for_family("intel8080"));
        assert!(model.expr_resolution_is_strict_for_family("intel8080"));
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
    fn m6502_expr_candidates_use_portable_eval_under_rollout_gate() {
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
    fn ultimate64_abi_runtime_model_owns_package_bytes_after_load() {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

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
