// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Binary CPU package (`*.opcpu`) container support for hierarchy chunks.
//!
//! This module currently implements read/write for:
//! - `META` (package metadata)
//! - `STRS` (string pool)
//! - `DIAG` (diagnostic catalog)
//! - `TOKS` (token policy hints)
//! - `FAMS` (family descriptors)
//! - `CPUS` (cpu descriptors)
//! - `DIAL` (dialect descriptors)
//! - `REGS` (scoped register descriptors)
//! - `FORM` (scoped form descriptors)
//! - `TABL` (scoped VM instruction program descriptors)
//! - `TKVM` (scoped tokenizer VM program descriptors)
//! - `PARS` (scoped parser/AST contract descriptors)
//! - `PRVM` (scoped parser VM program descriptors)
//! - `EXPR` (scoped expression VM contract descriptors)

use std::collections::HashMap;

use crate::opthread::hierarchy::{
    CpuDescriptor, DialectDescriptor, FamilyDescriptor, HierarchyError, HierarchyPackage,
    ScopedFormDescriptor, ScopedOwner, ScopedRegisterDescriptor,
};

pub const OPCPU_MAGIC: [u8; 4] = *b"OPCP";
pub const OPCPU_VERSION_V1: u16 = 0x0001;
pub const OPCPU_ENDIAN_MARKER: u16 = 0x1234;

const HEADER_SIZE: usize = 12;
const TOC_ENTRY_SIZE: usize = 12;
const MAX_DECODE_ENTRY_COUNT: usize = 100_000;

const CHUNK_META: [u8; 4] = *b"META";
const CHUNK_STRS: [u8; 4] = *b"STRS";
const CHUNK_DIAG: [u8; 4] = *b"DIAG";
const CHUNK_TOKS: [u8; 4] = *b"TOKS";
const CHUNK_FAMS: [u8; 4] = *b"FAMS";
const CHUNK_CPUS: [u8; 4] = *b"CPUS";
const CHUNK_DIAL: [u8; 4] = *b"DIAL";
const CHUNK_REGS: [u8; 4] = *b"REGS";
const CHUNK_FORM: [u8; 4] = *b"FORM";
const CHUNK_TABL: [u8; 4] = *b"TABL";
const CHUNK_MSEL: [u8; 4] = *b"MSEL";
const CHUNK_TKVM: [u8; 4] = *b"TKVM";
const CHUNK_PARS: [u8; 4] = *b"PARS";
const CHUNK_PRVM: [u8; 4] = *b"PRVM";
const CHUNK_EXPR: [u8; 4] = *b"EXPR";
const CHUNK_EXPP: [u8; 4] = *b"EXPP";

pub const DIAG_OPTHREAD_MISSING_VM_PROGRAM: &str = "OTR001";
pub const DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE: &str = "OTR002";
pub const DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02: &str = "OTR003";
pub const DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502: &str = "OTR004";
pub const DIAG_TOKENIZER_INVALID_CHAR: &str = "ott001";
pub const DIAG_TOKENIZER_UNTERMINATED_STRING: &str = "ott002";
pub const DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED: &str = "ott003";
pub const DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED: &str = "ott004";
pub const DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED: &str = "ott005";
pub const DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED: &str = "ott006";
pub const DIAG_PARSER_UNEXPECTED_TOKEN: &str = "otp001";
pub const DIAG_PARSER_EXPECTED_EXPRESSION: &str = "otp002";
pub const DIAG_PARSER_EXPECTED_OPERAND: &str = "otp003";
pub const DIAG_PARSER_INVALID_STATEMENT: &str = "otp004";

/// VM opcode-version compatibility matrix for package-scoped contracts/programs.
///
/// - `TOKENIZER_VM_OPCODE_VERSION_V1`: tokenizer VM (`TKVM`) payloads.
/// - `PARSER_VM_OPCODE_VERSION_V1`: line parser VM (`PRVM`) payloads.
/// - `EXPR_PARSER_VM_OPCODE_VERSION_V1`: expression parser VM (`EXPP`) payloads.
/// - `EXPR_VM_OPCODE_VERSION_V1`: expression evaluator VM contracts (`EXPR`),
///   sourced from `core::expr_vm` to keep runtime/package compatibility strict.
///
/// Decode/validation policy for all versioned VM payloads:
/// - exact version match required for the active decoder.
/// - unknown versions must produce deterministic errors.
pub const TOKENIZER_VM_OPCODE_VERSION_V1: u16 = 0x0001;
pub const PARSER_VM_OPCODE_VERSION_V1: u16 = 0x0001;
pub const EXPR_PARSER_VM_OPCODE_VERSION_V1: u16 = 0x0001;
pub const PARSER_GRAMMAR_ID_LINE_V1: &str = "opforge.line.v1";
pub const PARSER_AST_SCHEMA_ID_LINE_V1: &str = "opforge.ast.line.v1";
pub const EXPR_VM_OPCODE_VERSION_V1: u16 = crate::core::expr_vm::EXPR_VM_OPCODE_VERSION_V1;
pub const DIAG_EXPR_INVALID_OPCODE: &str = crate::core::expr_vm::DIAG_EXPR_INVALID_OPCODE;
pub const DIAG_EXPR_STACK_UNDERFLOW: &str = crate::core::expr_vm::DIAG_EXPR_STACK_UNDERFLOW;
pub const DIAG_EXPR_STACK_DEPTH_EXCEEDED: &str =
    crate::core::expr_vm::DIAG_EXPR_STACK_DEPTH_EXCEEDED;
pub const DIAG_EXPR_UNKNOWN_SYMBOL: &str = crate::core::expr_vm::DIAG_EXPR_UNKNOWN_SYMBOL;
pub const DIAG_EXPR_EVAL_FAILURE: &str = crate::core::expr_vm::DIAG_EXPR_EVAL_FAILURE;
pub const DIAG_EXPR_UNSUPPORTED_FEATURE: &str = crate::core::expr_vm::DIAG_EXPR_UNSUPPORTED_FEATURE;
pub const DIAG_EXPR_BUDGET_EXCEEDED: &str = crate::core::expr_vm::DIAG_EXPR_BUDGET_EXCEEDED;
pub const DIAG_EXPR_INVALID_PROGRAM: &str = crate::core::expr_vm::DIAG_EXPR_INVALID_PROGRAM;

/// Package metadata descriptor (`META` chunk).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageMetaDescriptor {
    pub package_id: String,
    pub package_version: String,
    pub capability_flags: u32,
}

impl Default for PackageMetaDescriptor {
    fn default() -> Self {
        Self {
            package_id: "opforge.generated".to_string(),
            package_version: "0.1.0".to_string(),
            capability_flags: 0,
        }
    }
}

/// Diagnostic descriptor (`DIAG` chunk).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticDescriptor {
    pub code: String,
    pub message_template: String,
}

/// Scoped VM program descriptor for one mnemonic + mode-key encode template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmProgramDescriptor {
    pub owner: ScopedOwner,
    pub mnemonic: String,
    pub mode_key: String,
    pub program: Vec<u8>,
}

/// Scoped mode selector descriptor for Expr/family-operand to VM mode candidate mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeSelectorDescriptor {
    pub owner: ScopedOwner,
    pub mnemonic: String,
    pub shape_key: String,
    pub mode_key: String,
    pub operand_plan: String,
    pub priority: u16,
    pub unstable_widen: bool,
    pub width_rank: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenizerVmLimits {
    pub max_steps_per_line: u32,
    pub max_tokens_per_line: u32,
    pub max_lexeme_bytes: u32,
    pub max_errors_per_line: u32,
}

impl Default for TokenizerVmLimits {
    fn default() -> Self {
        Self {
            max_steps_per_line: 2048,
            max_tokens_per_line: 256,
            max_lexeme_bytes: 256,
            max_errors_per_line: 16,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenizerVmDiagnosticMap {
    pub invalid_char: String,
    pub unterminated_string: String,
    pub step_limit_exceeded: String,
    pub token_limit_exceeded: String,
    pub lexeme_limit_exceeded: String,
    pub error_limit_exceeded: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenizerVmOpcode {
    End = 0x00,
    ReadChar = 0x01,
    Advance = 0x02,
    StartLexeme = 0x03,
    PushChar = 0x04,
    EmitToken = 0x05,
    SetState = 0x06,
    Jump = 0x07,
    JumpIfEol = 0x08,
    JumpIfByteEq = 0x09,
    JumpIfClass = 0x0A,
    Fail = 0x0B,
    EmitDiag = 0x0C,
    DelegateCore = 0x0D,
    ScanCoreToken = 0x0E,
}

impl TokenizerVmOpcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::End),
            0x01 => Some(Self::ReadChar),
            0x02 => Some(Self::Advance),
            0x03 => Some(Self::StartLexeme),
            0x04 => Some(Self::PushChar),
            0x05 => Some(Self::EmitToken),
            0x06 => Some(Self::SetState),
            0x07 => Some(Self::Jump),
            0x08 => Some(Self::JumpIfEol),
            0x09 => Some(Self::JumpIfByteEq),
            0x0A => Some(Self::JumpIfClass),
            0x0B => Some(Self::Fail),
            0x0C => Some(Self::EmitDiag),
            0x0D => Some(Self::DelegateCore),
            0x0E => Some(Self::ScanCoreToken),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenizerVmProgramDescriptor {
    pub owner: ScopedOwner,
    pub opcode_version: u16,
    pub start_state: u16,
    pub state_entry_offsets: Vec<u32>,
    pub limits: TokenizerVmLimits,
    pub diagnostics: TokenizerVmDiagnosticMap,
    pub program: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParserDiagnosticMap {
    pub unexpected_token: String,
    pub expected_expression: String,
    pub expected_operand: String,
    pub invalid_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParserContractDescriptor {
    pub owner: ScopedOwner,
    pub grammar_id: String,
    pub ast_schema_id: String,
    pub opcode_version: u16,
    pub max_ast_nodes_per_line: u32,
    pub diagnostics: ParserDiagnosticMap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ParserVmOpcode {
    End = 0x00,
    EmitDiag = 0x02,
    Fail = 0x03,
    ParseStatementEnvelope = 0x04,
    ParseDotDirectiveEnvelope = 0x05,
    ParseAssignmentEnvelope = 0x06,
    ParseInstructionEnvelope = 0x07,
    ParseStarOrgEnvelope = 0x08,
    EmitDiagIfNoAst = 0x09,
}

impl ParserVmOpcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::End),
            0x02 => Some(Self::EmitDiag),
            0x03 => Some(Self::Fail),
            0x04 => Some(Self::ParseStatementEnvelope),
            0x05 => Some(Self::ParseDotDirectiveEnvelope),
            0x06 => Some(Self::ParseAssignmentEnvelope),
            0x07 => Some(Self::ParseInstructionEnvelope),
            0x08 => Some(Self::ParseStarOrgEnvelope),
            0x09 => Some(Self::EmitDiagIfNoAst),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExprParserVmOpcode {
    End = 0x00,
    ParseExpression = 0x01,
    EmitDiag = 0x02,
    Fail = 0x03,
    DelegateCore = 0x04,
}

impl ExprParserVmOpcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::End),
            0x01 => Some(Self::ParseExpression),
            0x02 => Some(Self::EmitDiag),
            0x03 => Some(Self::Fail),
            0x04 => Some(Self::DelegateCore),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParserVmProgramDescriptor {
    pub owner: ScopedOwner,
    pub opcode_version: u16,
    pub program: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExprDiagnosticMap {
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
pub struct ExprContractDescriptor {
    pub owner: ScopedOwner,
    pub opcode_version: u16,
    pub max_program_bytes: u32,
    pub max_stack_depth: u32,
    pub max_symbol_refs: u32,
    pub max_eval_steps: u32,
    pub diagnostics: ExprDiagnosticMap,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExprParserDiagnosticMap {
    pub invalid_expression_program: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExprParserContractDescriptor {
    pub owner: ScopedOwner,
    pub opcode_version: u16,
    pub diagnostics: ExprParserDiagnosticMap,
}

/// Case-folding behavior for tokenizer/literal matching policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenCaseRule {
    Preserve = 0,
    AsciiLower = 1,
    AsciiUpper = 2,
}

impl TokenCaseRule {
    fn from_u8(value: u8, chunk: &str) -> Result<Self, OpcpuCodecError> {
        match value {
            0 => Ok(Self::Preserve),
            1 => Ok(Self::AsciiLower),
            2 => Ok(Self::AsciiUpper),
            other => Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: chunk.to_string(),
                detail: format!("invalid token case rule: {}", other),
            }),
        }
    }
}

/// Bit flags describing allowed identifier characters for tokenizer policy hints.
pub mod token_identifier_class {
    pub const ASCII_ALPHA: u32 = 1 << 0;
    pub const ASCII_DIGIT: u32 = 1 << 1;
    pub const UNDERSCORE: u32 = 1 << 2;
    pub const DOLLAR: u32 = 1 << 3;
    pub const AT_SIGN: u32 = 1 << 4;
    pub const DOT: u32 = 1 << 5;
}

const TOKS_EXT_MARKER: u8 = 0xFF;
const TOKS_DEFAULT_COMMENT_PREFIX: &str = ";";
const TOKS_DEFAULT_QUOTE_CHARS: &str = "\"'";
const TOKS_DEFAULT_NUMBER_PREFIX_CHARS: &str = "$%@";
const TOKS_DEFAULT_NUMBER_SUFFIX_BINARY: &str = "bB";
const TOKS_DEFAULT_NUMBER_SUFFIX_OCTAL: &str = "oOqQ";
const TOKS_DEFAULT_NUMBER_SUFFIX_DECIMAL: &str = "dD";
const TOKS_DEFAULT_NUMBER_SUFFIX_HEX: &str = "hH";
const TOKS_DEFAULT_OPERATOR_CHARS: &str = "+-*/%~!&|^<>=?";
const TOKS_DEFAULT_MULTI_CHAR_OPERATORS: [&str; 11] = [
    "**", "==", "!=", "&&", "||", "^^", "<<", ">>", "<=", ">=", "<>",
];

/// Token policy descriptor (`TOKS` chunk), scoped by family/cpu/dialect owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPolicyDescriptor {
    pub owner: ScopedOwner,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPolicyLexicalDefaults {
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

pub fn default_token_policy_lexical_defaults() -> TokenPolicyLexicalDefaults {
    TokenPolicyLexicalDefaults {
        comment_prefix: TOKS_DEFAULT_COMMENT_PREFIX.to_string(),
        quote_chars: TOKS_DEFAULT_QUOTE_CHARS.to_string(),
        escape_char: Some('\\'),
        number_prefix_chars: TOKS_DEFAULT_NUMBER_PREFIX_CHARS.to_string(),
        number_suffix_binary: TOKS_DEFAULT_NUMBER_SUFFIX_BINARY.to_string(),
        number_suffix_octal: TOKS_DEFAULT_NUMBER_SUFFIX_OCTAL.to_string(),
        number_suffix_decimal: TOKS_DEFAULT_NUMBER_SUFFIX_DECIMAL.to_string(),
        number_suffix_hex: TOKS_DEFAULT_NUMBER_SUFFIX_HEX.to_string(),
        operator_chars: TOKS_DEFAULT_OPERATOR_CHARS.to_string(),
        multi_char_operators: TOKS_DEFAULT_MULTI_CHAR_OPERATORS
            .iter()
            .map(|value| value.to_string())
            .collect(),
    }
}

/// Decoded hierarchy-chunk payload set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HierarchyChunks {
    pub metadata: PackageMetaDescriptor,
    pub strings: Vec<String>,
    pub diagnostics: Vec<DiagnosticDescriptor>,
    pub token_policies: Vec<TokenPolicyDescriptor>,
    pub tokenizer_vm_programs: Vec<TokenizerVmProgramDescriptor>,
    pub parser_contracts: Vec<ParserContractDescriptor>,
    pub parser_vm_programs: Vec<ParserVmProgramDescriptor>,
    pub expr_contracts: Vec<ExprContractDescriptor>,
    pub expr_parser_contracts: Vec<ExprParserContractDescriptor>,
    pub families: Vec<FamilyDescriptor>,
    pub cpus: Vec<CpuDescriptor>,
    pub dialects: Vec<DialectDescriptor>,
    pub registers: Vec<ScopedRegisterDescriptor>,
    pub forms: Vec<ScopedFormDescriptor>,
    pub tables: Vec<VmProgramDescriptor>,
    pub selectors: Vec<ModeSelectorDescriptor>,
}

/// Deterministic package codec errors for malformed container/schema data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpcpuCodecError {
    InvalidMagic {
        found: [u8; 4],
    },
    UnsupportedVersion {
        found: u16,
    },
    InvalidEndiannessMarker {
        found: u16,
    },
    UnexpectedEof {
        context: String,
    },
    DuplicateChunk {
        chunk: String,
    },
    MissingRequiredChunk {
        chunk: String,
    },
    ChunkOutOfBounds {
        chunk: String,
        offset: u32,
        length: u32,
        file_len: usize,
    },
    CountOutOfRange {
        context: String,
    },
    InvalidChunkFormat {
        chunk: String,
        detail: String,
    },
    InvalidUtf8 {
        chunk: String,
    },
    Hierarchy(HierarchyError),
}

impl OpcpuCodecError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidMagic { .. } => "OPC001",
            Self::UnsupportedVersion { .. } => "OPC002",
            Self::InvalidEndiannessMarker { .. } => "OPC003",
            Self::UnexpectedEof { .. } => "OPC004",
            Self::DuplicateChunk { .. } => "OPC005",
            Self::MissingRequiredChunk { .. } => "OPC006",
            Self::ChunkOutOfBounds { .. } => "OPC007",
            Self::CountOutOfRange { .. } => "OPC008",
            Self::InvalidChunkFormat { .. } => "OPC009",
            Self::InvalidUtf8 { .. } => "OPC010",
            Self::Hierarchy(_) => "OPC011",
        }
    }
}

impl std::fmt::Display for OpcpuCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic { found } => write!(
                f,
                "[{}] invalid package magic: found {:?}",
                self.code(),
                found
            ),
            Self::UnsupportedVersion { found } => write!(
                f,
                "[{}] unsupported package version: {}",
                self.code(),
                found
            ),
            Self::InvalidEndiannessMarker { found } => write!(
                f,
                "[{}] invalid endianness marker: 0x{:04X}",
                self.code(),
                found
            ),
            Self::UnexpectedEof { context } => {
                write!(f, "[{}] unexpected end of file: {}", self.code(), context)
            }
            Self::DuplicateChunk { chunk } => {
                write!(f, "[{}] duplicate chunk '{}'", self.code(), chunk)
            }
            Self::MissingRequiredChunk { chunk } => {
                write!(f, "[{}] missing required chunk '{}'", self.code(), chunk)
            }
            Self::ChunkOutOfBounds {
                chunk,
                offset,
                length,
                file_len,
            } => write!(
                f,
                "[{}] chunk '{}' out of bounds (offset={}, length={}, file_len={})",
                self.code(),
                chunk,
                offset,
                length,
                file_len
            ),
            Self::CountOutOfRange { context } => {
                write!(f, "[{}] count out of range: {}", self.code(), context)
            }
            Self::InvalidChunkFormat { chunk, detail } => write!(
                f,
                "[{}] invalid chunk '{}' format: {}",
                self.code(),
                chunk,
                detail
            ),
            Self::InvalidUtf8 { chunk } => {
                write!(f, "[{}] invalid UTF-8 in chunk '{}'", self.code(), chunk)
            }
            Self::Hierarchy(err) => {
                write!(f, "[{}] hierarchy validation error: {}", self.code(), err)
            }
        }
    }
}

impl std::error::Error for OpcpuCodecError {}

impl From<HierarchyError> for OpcpuCodecError {
    fn from(value: HierarchyError) -> Self {
        Self::Hierarchy(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TocEntry {
    offset: u32,
    length: u32,
}

pub fn encode_hierarchy_chunks(
    families: &[FamilyDescriptor],
    cpus: &[CpuDescriptor],
    dialects: &[DialectDescriptor],
    registers: &[ScopedRegisterDescriptor],
    forms: &[ScopedFormDescriptor],
    tables: &[VmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    encode_hierarchy_chunks_full(families, cpus, dialects, registers, forms, tables, &[])
}

pub fn encode_hierarchy_chunks_full(
    families: &[FamilyDescriptor],
    cpus: &[CpuDescriptor],
    dialects: &[DialectDescriptor],
    registers: &[ScopedRegisterDescriptor],
    forms: &[ScopedFormDescriptor],
    tables: &[VmProgramDescriptor],
    selectors: &[ModeSelectorDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let chunks = HierarchyChunks {
        metadata: PackageMetaDescriptor::default(),
        strings: Vec::new(),
        diagnostics: Vec::new(),
        token_policies: Vec::new(),
        tokenizer_vm_programs: Vec::new(),
        parser_contracts: Vec::new(),
        parser_vm_programs: Vec::new(),
        expr_contracts: Vec::new(),
        expr_parser_contracts: Vec::new(),
        families: families.to_vec(),
        cpus: cpus.to_vec(),
        dialects: dialects.to_vec(),
        registers: registers.to_vec(),
        forms: forms.to_vec(),
        tables: tables.to_vec(),
        selectors: selectors.to_vec(),
    };
    encode_hierarchy_chunks_from_chunks(&chunks)
}

pub fn encode_hierarchy_chunks_from_chunks(
    chunks: &HierarchyChunks,
) -> Result<Vec<u8>, OpcpuCodecError> {
    // Validate cross references and compatibility before encoding.
    HierarchyPackage::new(
        chunks.families.clone(),
        chunks.cpus.clone(),
        chunks.dialects.clone(),
    )?;

    let metadata = chunks.metadata.clone();
    let mut strings = chunks.strings.to_vec();
    let mut diagnostics = chunks.diagnostics.to_vec();
    let mut token_policies = chunks.token_policies.to_vec();
    let mut tokenizer_vm_programs = chunks.tokenizer_vm_programs.to_vec();
    let mut parser_contracts = chunks.parser_contracts.to_vec();
    let mut parser_vm_programs = chunks.parser_vm_programs.to_vec();
    let mut expr_contracts = chunks.expr_contracts.to_vec();
    let mut expr_parser_contracts = chunks.expr_parser_contracts.to_vec();
    let mut fams = chunks.families.to_vec();
    let mut cpus = chunks.cpus.to_vec();
    let mut dials = chunks.dialects.to_vec();
    let mut regs = chunks.registers.to_vec();
    let mut forms = chunks.forms.to_vec();
    let mut tables = chunks.tables.to_vec();
    let mut selectors = chunks.selectors.to_vec();
    canonicalize_hierarchy_metadata(
        &mut fams,
        &mut cpus,
        &mut dials,
        &mut regs,
        &mut forms,
        &mut tables,
        &mut selectors,
    );
    canonicalize_token_policies(&mut token_policies);
    canonicalize_tokenizer_vm_programs(&mut tokenizer_vm_programs);
    canonicalize_parser_contracts(&mut parser_contracts);
    canonicalize_parser_vm_programs(&mut parser_vm_programs);
    canonicalize_expr_contracts(&mut expr_contracts);
    canonicalize_expr_parser_contracts(&mut expr_parser_contracts);
    canonicalize_package_support_chunks(&mut strings, &mut diagnostics);

    let mut chunks = vec![
        (CHUNK_META, encode_meta_chunk(&metadata)?),
        (CHUNK_STRS, encode_strs_chunk(&strings)?),
        (CHUNK_DIAG, encode_diag_chunk(&diagnostics)?),
    ];
    if !token_policies.is_empty() {
        chunks.push((CHUNK_TOKS, encode_toks_chunk(&token_policies)?));
    }
    if !tokenizer_vm_programs.is_empty() {
        chunks.push((CHUNK_TKVM, encode_tkvm_chunk(&tokenizer_vm_programs)?));
    }
    if !parser_contracts.is_empty() {
        chunks.push((CHUNK_PARS, encode_pars_chunk(&parser_contracts)?));
    }
    if !parser_vm_programs.is_empty() {
        chunks.push((CHUNK_PRVM, encode_prvm_chunk(&parser_vm_programs)?));
    }
    if !expr_contracts.is_empty() {
        chunks.push((CHUNK_EXPR, encode_expr_chunk(&expr_contracts)?));
    }
    if !expr_parser_contracts.is_empty() {
        chunks.push((CHUNK_EXPP, encode_expp_chunk(&expr_parser_contracts)?));
    }
    chunks.extend_from_slice(&[
        (CHUNK_FAMS, encode_fams_chunk(&fams)?),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus)?),
        (CHUNK_DIAL, encode_dial_chunk(&dials)?),
        (CHUNK_REGS, encode_regs_chunk(&regs)?),
        (CHUNK_FORM, encode_form_chunk(&forms)?),
        (CHUNK_TABL, encode_tabl_chunk(&tables)?),
        (CHUNK_MSEL, encode_msel_chunk(&selectors)?),
    ]);

    encode_container(&chunks)
}

pub fn default_runtime_diagnostic_catalog() -> Vec<DiagnosticDescriptor> {
    vec![
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_MISSING_VM_PROGRAM.to_string(),
            message_template: "missing opThread VM program for {mnemonic}".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE.to_string(),
            message_template: "Explicit addressing override ',{force}' is not valid for {context}"
                .to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02.to_string(),
            message_template: "65816-only addressing mode not supported on 65C02".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502.to_string(),
            message_template: "65816-only addressing mode not supported on base 6502".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_INVALID_CHAR.to_string(),
            message_template: "invalid tokenizer character".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_UNTERMINATED_STRING.to_string(),
            message_template: "unterminated string literal".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_STEP_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer step budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_TOKEN_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer token budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_LEXEME_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer lexeme budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_TOKENIZER_ERROR_LIMIT_EXCEEDED.to_string(),
            message_template: "tokenizer diagnostic budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_UNEXPECTED_TOKEN.to_string(),
            message_template: "unexpected token".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_EXPECTED_EXPRESSION.to_string(),
            message_template: "expected expression".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_EXPECTED_OPERAND.to_string(),
            message_template: "expected operand".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_PARSER_INVALID_STATEMENT.to_string(),
            message_template: "invalid statement".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_INVALID_OPCODE.to_string(),
            message_template: "invalid expression VM opcode".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_STACK_UNDERFLOW.to_string(),
            message_template: "expression VM stack underflow".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_STACK_DEPTH_EXCEEDED.to_string(),
            message_template: "expression VM stack depth exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_UNKNOWN_SYMBOL.to_string(),
            message_template: "undefined expression symbol".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_EVAL_FAILURE.to_string(),
            message_template: "expression VM evaluation failure".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_UNSUPPORTED_FEATURE.to_string(),
            message_template: "expression VM unsupported feature".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_BUDGET_EXCEEDED.to_string(),
            message_template: "expression VM budget exceeded".to_string(),
        },
        DiagnosticDescriptor {
            code: DIAG_EXPR_INVALID_PROGRAM.to_string(),
            message_template: "expression VM program is invalid".to_string(),
        },
    ]
}

fn canonicalize_package_support_chunks(
    strings: &mut Vec<String>,
    diagnostics: &mut Vec<DiagnosticDescriptor>,
) {
    strings.sort();
    strings.dedup();

    diagnostics.sort_by_key(|entry| {
        (
            entry.code.to_ascii_lowercase(),
            entry.message_template.to_ascii_lowercase(),
        )
    });
    diagnostics.dedup_by(|left, right| {
        left.code.eq_ignore_ascii_case(&right.code)
            && left
                .message_template
                .eq_ignore_ascii_case(&right.message_template)
    });
}

pub(crate) fn canonicalize_hierarchy_metadata(
    families: &mut [FamilyDescriptor],
    cpus: &mut [CpuDescriptor],
    dialects: &mut [DialectDescriptor],
    registers: &mut Vec<ScopedRegisterDescriptor>,
    forms: &mut Vec<ScopedFormDescriptor>,
    tables: &mut Vec<VmProgramDescriptor>,
    selectors: &mut Vec<ModeSelectorDescriptor>,
) {
    families.sort_by_key(|entry| entry.id.to_ascii_lowercase());
    cpus.sort_by_key(|entry| entry.id.to_ascii_lowercase());

    for entry in dialects.iter_mut() {
        if let Some(allow) = entry.cpu_allow_list.as_mut() {
            allow.sort_by_key(|cpu| cpu.to_ascii_lowercase());
            allow.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        }
    }
    dialects.sort_by_key(|entry| {
        (
            entry.family_id.to_ascii_lowercase(),
            entry.id.to_ascii_lowercase(),
        )
    });

    for entry in registers.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.id = entry.id.to_ascii_lowercase();
    }
    registers.sort_by_key(|entry| {
        (
            entry.owner.owner_tag(),
            entry.owner.owner_id().to_ascii_lowercase(),
            entry.id.to_ascii_lowercase(),
        )
    });
    registers.dedup_by(|left, right| left.id == right.id && left.owner.same_scope(&right.owner));

    for entry in forms.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
    }
    forms.sort_by_key(|entry| {
        (
            entry.owner.owner_tag(),
            entry.owner.owner_id().to_ascii_lowercase(),
            entry.mnemonic.to_ascii_lowercase(),
        )
    });
    forms.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic && left.owner.same_scope(&right.owner)
    });

    for entry in tables.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
    }
    tables.sort_by_key(|entry| {
        (
            entry.owner.owner_tag(),
            entry.owner.owner_id().to_ascii_lowercase(),
            entry.mnemonic.to_ascii_lowercase(),
            entry.mode_key.to_ascii_lowercase(),
        )
    });
    tables.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic
            && left.mode_key == right.mode_key
            && left.owner.same_scope(&right.owner)
    });

    for entry in selectors.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.shape_key = entry.shape_key.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
        entry.operand_plan = entry.operand_plan.to_ascii_lowercase();
    }
    selectors.sort_by_key(|entry| {
        (
            entry.owner.owner_tag(),
            entry.owner.owner_id().to_ascii_lowercase(),
            entry.mnemonic.to_ascii_lowercase(),
            entry.shape_key.to_ascii_lowercase(),
            entry.priority,
            entry.mode_key.to_ascii_lowercase(),
        )
    });
    selectors.dedup_by(|left, right| {
        left.priority == right.priority
            && left.mnemonic == right.mnemonic
            && left.shape_key == right.shape_key
            && left.mode_key == right.mode_key
            && left.operand_plan == right.operand_plan
            && left.unstable_widen == right.unstable_widen
            && left.width_rank == right.width_rank
            && left.owner.same_scope(&right.owner)
    });
}

pub(crate) fn canonicalize_token_policies(token_policies: &mut Vec<TokenPolicyDescriptor>) {
    for entry in token_policies.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.punctuation_chars = canonicalize_ascii_char_set(&entry.punctuation_chars);
        entry.quote_chars = canonicalize_ascii_char_set(&entry.quote_chars);
        entry.number_prefix_chars = canonicalize_ascii_char_set(&entry.number_prefix_chars);
        entry.number_suffix_binary = canonicalize_ascii_char_set(&entry.number_suffix_binary);
        entry.number_suffix_octal = canonicalize_ascii_char_set(&entry.number_suffix_octal);
        entry.number_suffix_decimal = canonicalize_ascii_char_set(&entry.number_suffix_decimal);
        entry.number_suffix_hex = canonicalize_ascii_char_set(&entry.number_suffix_hex);
        entry.operator_chars = canonicalize_ascii_char_set(&entry.operator_chars);
        entry.multi_char_operators.retain(|value| !value.is_empty());
        entry.multi_char_operators.sort();
        entry.multi_char_operators.dedup();
    }
    token_policies.sort_by(|left, right| {
        left.owner
            .owner_tag()
            .cmp(&right.owner.owner_tag())
            .then_with(|| {
                left.owner
                    .owner_id()
                    .to_ascii_lowercase()
                    .cmp(&right.owner.owner_id().to_ascii_lowercase())
            })
            .then_with(|| (left.case_rule as u8).cmp(&(right.case_rule as u8)))
            .then_with(|| {
                left.identifier_start_class
                    .cmp(&right.identifier_start_class)
            })
            .then_with(|| {
                left.identifier_continue_class
                    .cmp(&right.identifier_continue_class)
            })
            .then_with(|| left.punctuation_chars.cmp(&right.punctuation_chars))
            .then_with(|| left.comment_prefix.cmp(&right.comment_prefix))
            .then_with(|| left.quote_chars.cmp(&right.quote_chars))
            .then_with(|| left.escape_char.cmp(&right.escape_char))
            .then_with(|| left.number_prefix_chars.cmp(&right.number_prefix_chars))
            .then_with(|| left.number_suffix_binary.cmp(&right.number_suffix_binary))
            .then_with(|| left.number_suffix_octal.cmp(&right.number_suffix_octal))
            .then_with(|| left.number_suffix_decimal.cmp(&right.number_suffix_decimal))
            .then_with(|| left.number_suffix_hex.cmp(&right.number_suffix_hex))
            .then_with(|| left.operator_chars.cmp(&right.operator_chars))
            .then_with(|| left.multi_char_operators.cmp(&right.multi_char_operators))
    });
    token_policies.dedup_by(|left, right| {
        left.case_rule == right.case_rule
            && left.identifier_start_class == right.identifier_start_class
            && left.identifier_continue_class == right.identifier_continue_class
            && left.punctuation_chars == right.punctuation_chars
            && left.comment_prefix == right.comment_prefix
            && left.quote_chars == right.quote_chars
            && left.escape_char == right.escape_char
            && left.number_prefix_chars == right.number_prefix_chars
            && left.number_suffix_binary == right.number_suffix_binary
            && left.number_suffix_octal == right.number_suffix_octal
            && left.number_suffix_decimal == right.number_suffix_decimal
            && left.number_suffix_hex == right.number_suffix_hex
            && left.operator_chars == right.operator_chars
            && left.multi_char_operators == right.multi_char_operators
            && left.owner.same_scope(&right.owner)
    });
}

pub(crate) fn canonicalize_tokenizer_vm_programs(
    tokenizer_vm_programs: &mut Vec<TokenizerVmProgramDescriptor>,
) {
    for entry in tokenizer_vm_programs.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
    }
    tokenizer_vm_programs.sort_by(|left, right| {
        left.owner
            .owner_tag()
            .cmp(&right.owner.owner_tag())
            .then_with(|| {
                left.owner
                    .owner_id()
                    .to_ascii_lowercase()
                    .cmp(&right.owner.owner_id().to_ascii_lowercase())
            })
            .then_with(|| left.opcode_version.cmp(&right.opcode_version))
            .then_with(|| left.start_state.cmp(&right.start_state))
            .then_with(|| left.state_entry_offsets.cmp(&right.state_entry_offsets))
            .then_with(|| {
                left.limits
                    .max_steps_per_line
                    .cmp(&right.limits.max_steps_per_line)
            })
            .then_with(|| {
                left.limits
                    .max_tokens_per_line
                    .cmp(&right.limits.max_tokens_per_line)
            })
            .then_with(|| {
                left.limits
                    .max_lexeme_bytes
                    .cmp(&right.limits.max_lexeme_bytes)
            })
            .then_with(|| {
                left.limits
                    .max_errors_per_line
                    .cmp(&right.limits.max_errors_per_line)
            })
            .then_with(|| {
                left.diagnostics
                    .invalid_char
                    .cmp(&right.diagnostics.invalid_char)
            })
            .then_with(|| {
                left.diagnostics
                    .unterminated_string
                    .cmp(&right.diagnostics.unterminated_string)
            })
            .then_with(|| {
                left.diagnostics
                    .step_limit_exceeded
                    .cmp(&right.diagnostics.step_limit_exceeded)
            })
            .then_with(|| {
                left.diagnostics
                    .token_limit_exceeded
                    .cmp(&right.diagnostics.token_limit_exceeded)
            })
            .then_with(|| {
                left.diagnostics
                    .lexeme_limit_exceeded
                    .cmp(&right.diagnostics.lexeme_limit_exceeded)
            })
            .then_with(|| {
                left.diagnostics
                    .error_limit_exceeded
                    .cmp(&right.diagnostics.error_limit_exceeded)
            })
            .then_with(|| left.program.cmp(&right.program))
    });
    tokenizer_vm_programs.dedup_by(|left, right| {
        left.opcode_version == right.opcode_version
            && left.start_state == right.start_state
            && left.state_entry_offsets == right.state_entry_offsets
            && left.limits == right.limits
            && left.diagnostics == right.diagnostics
            && left.program == right.program
            && left.owner.same_scope(&right.owner)
    });
}

pub(crate) fn canonicalize_parser_contracts(parser_contracts: &mut Vec<ParserContractDescriptor>) {
    for entry in parser_contracts.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.grammar_id = entry.grammar_id.to_ascii_lowercase();
        entry.ast_schema_id = entry.ast_schema_id.to_ascii_lowercase();
    }
    parser_contracts.sort_by(|left, right| {
        left.owner
            .owner_tag()
            .cmp(&right.owner.owner_tag())
            .then_with(|| {
                left.owner
                    .owner_id()
                    .to_ascii_lowercase()
                    .cmp(&right.owner.owner_id().to_ascii_lowercase())
            })
            .then_with(|| left.grammar_id.cmp(&right.grammar_id))
            .then_with(|| left.ast_schema_id.cmp(&right.ast_schema_id))
            .then_with(|| left.opcode_version.cmp(&right.opcode_version))
            .then_with(|| {
                left.max_ast_nodes_per_line
                    .cmp(&right.max_ast_nodes_per_line)
            })
            .then_with(|| {
                left.diagnostics
                    .unexpected_token
                    .cmp(&right.diagnostics.unexpected_token)
            })
            .then_with(|| {
                left.diagnostics
                    .expected_expression
                    .cmp(&right.diagnostics.expected_expression)
            })
            .then_with(|| {
                left.diagnostics
                    .expected_operand
                    .cmp(&right.diagnostics.expected_operand)
            })
            .then_with(|| {
                left.diagnostics
                    .invalid_statement
                    .cmp(&right.diagnostics.invalid_statement)
            })
    });
    parser_contracts.dedup_by(|left, right| {
        left.grammar_id == right.grammar_id
            && left.ast_schema_id == right.ast_schema_id
            && left.opcode_version == right.opcode_version
            && left.max_ast_nodes_per_line == right.max_ast_nodes_per_line
            && left.diagnostics == right.diagnostics
            && left.owner.same_scope(&right.owner)
    });
}

pub(crate) fn canonicalize_parser_vm_programs(
    parser_vm_programs: &mut Vec<ParserVmProgramDescriptor>,
) {
    for entry in parser_vm_programs.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
    }
    parser_vm_programs.sort_by(|left, right| {
        left.owner
            .owner_tag()
            .cmp(&right.owner.owner_tag())
            .then_with(|| {
                left.owner
                    .owner_id()
                    .to_ascii_lowercase()
                    .cmp(&right.owner.owner_id().to_ascii_lowercase())
            })
            .then_with(|| left.opcode_version.cmp(&right.opcode_version))
            .then_with(|| left.program.cmp(&right.program))
    });
    parser_vm_programs.dedup_by(|left, right| {
        left.opcode_version == right.opcode_version
            && left.program == right.program
            && left.owner.same_scope(&right.owner)
    });
}

pub(crate) fn canonicalize_expr_contracts(expr_contracts: &mut Vec<ExprContractDescriptor>) {
    for entry in expr_contracts.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
    }
    expr_contracts.sort_by(|left, right| {
        left.owner
            .owner_tag()
            .cmp(&right.owner.owner_tag())
            .then_with(|| {
                left.owner
                    .owner_id()
                    .to_ascii_lowercase()
                    .cmp(&right.owner.owner_id().to_ascii_lowercase())
            })
            .then_with(|| left.opcode_version.cmp(&right.opcode_version))
            .then_with(|| left.max_program_bytes.cmp(&right.max_program_bytes))
            .then_with(|| left.max_stack_depth.cmp(&right.max_stack_depth))
            .then_with(|| left.max_symbol_refs.cmp(&right.max_symbol_refs))
            .then_with(|| left.max_eval_steps.cmp(&right.max_eval_steps))
            .then_with(|| {
                left.diagnostics
                    .invalid_opcode
                    .cmp(&right.diagnostics.invalid_opcode)
            })
            .then_with(|| {
                left.diagnostics
                    .stack_underflow
                    .cmp(&right.diagnostics.stack_underflow)
            })
            .then_with(|| {
                left.diagnostics
                    .stack_depth_exceeded
                    .cmp(&right.diagnostics.stack_depth_exceeded)
            })
            .then_with(|| {
                left.diagnostics
                    .unknown_symbol
                    .cmp(&right.diagnostics.unknown_symbol)
            })
            .then_with(|| {
                left.diagnostics
                    .eval_failure
                    .cmp(&right.diagnostics.eval_failure)
            })
            .then_with(|| {
                left.diagnostics
                    .unsupported_feature
                    .cmp(&right.diagnostics.unsupported_feature)
            })
            .then_with(|| {
                left.diagnostics
                    .budget_exceeded
                    .cmp(&right.diagnostics.budget_exceeded)
            })
            .then_with(|| {
                left.diagnostics
                    .invalid_program
                    .cmp(&right.diagnostics.invalid_program)
            })
    });
    expr_contracts.dedup_by(|left, right| {
        left.opcode_version == right.opcode_version
            && left.max_program_bytes == right.max_program_bytes
            && left.max_stack_depth == right.max_stack_depth
            && left.max_symbol_refs == right.max_symbol_refs
            && left.max_eval_steps == right.max_eval_steps
            && left.diagnostics == right.diagnostics
            && left.owner.same_scope(&right.owner)
    });
}

pub(crate) fn canonicalize_expr_parser_contracts(
    expr_parser_contracts: &mut Vec<ExprParserContractDescriptor>,
) {
    for entry in expr_parser_contracts.iter_mut() {
        let owner_id = entry.owner.owner_id().to_ascii_lowercase();
        *entry.owner.owner_id_mut() = owner_id;
        entry.diagnostics.invalid_expression_program = entry
            .diagnostics
            .invalid_expression_program
            .to_ascii_lowercase();
    }

    expr_parser_contracts.sort_by(|left, right| {
        left.owner
            .owner_tag()
            .cmp(&right.owner.owner_tag())
            .then_with(|| left.owner.owner_id().cmp(right.owner.owner_id()))
            .then_with(|| left.opcode_version.cmp(&right.opcode_version))
            .then_with(|| {
                left.diagnostics
                    .invalid_expression_program
                    .cmp(&right.diagnostics.invalid_expression_program)
            })
    });

    expr_parser_contracts.dedup_by(|left, right| {
        left.opcode_version == right.opcode_version
            && left.diagnostics == right.diagnostics
            && left.owner.same_scope(&right.owner)
    });
}

pub fn decode_hierarchy_chunks(bytes: &[u8]) -> Result<HierarchyChunks, OpcpuCodecError> {
    let toc = parse_toc(bytes)?;
    let meta_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_META)?;
    let strs_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_STRS)?;
    let diag_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_DIAG)?;
    let toks_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_TOKS)?;
    let tkvm_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_TKVM)?;
    let pars_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_PARS)?;
    let prvm_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_PRVM)?;
    let expr_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_EXPR)?;
    let expp_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_EXPP)?;
    let fams_bytes = slice_for_chunk(bytes, &toc, CHUNK_FAMS)?;
    let cpus_bytes = slice_for_chunk(bytes, &toc, CHUNK_CPUS)?;
    let dial_bytes = slice_for_chunk(bytes, &toc, CHUNK_DIAL)?;
    let regs_bytes = slice_for_chunk(bytes, &toc, CHUNK_REGS)?;
    let form_bytes = slice_for_chunk(bytes, &toc, CHUNK_FORM)?;
    let tabl_bytes = slice_for_chunk(bytes, &toc, CHUNK_TABL)?;
    let msel_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_MSEL)?;

    Ok(HierarchyChunks {
        metadata: match meta_bytes {
            Some(payload) => decode_meta_chunk(payload)?,
            None => PackageMetaDescriptor::default(),
        },
        strings: match strs_bytes {
            Some(payload) => decode_strs_chunk(payload)?,
            None => Vec::new(),
        },
        diagnostics: match diag_bytes {
            Some(payload) => decode_diag_chunk(payload)?,
            None => Vec::new(),
        },
        token_policies: match toks_bytes {
            Some(payload) => decode_toks_chunk(payload)?,
            None => Vec::new(),
        },
        tokenizer_vm_programs: match tkvm_bytes {
            Some(payload) => decode_tkvm_chunk(payload)?,
            None => Vec::new(),
        },
        parser_contracts: match pars_bytes {
            Some(payload) => decode_pars_chunk(payload)?,
            None => Vec::new(),
        },
        parser_vm_programs: match prvm_bytes {
            Some(payload) => decode_prvm_chunk(payload)?,
            None => Vec::new(),
        },
        expr_contracts: match expr_bytes {
            Some(payload) => decode_expr_chunk(payload)?,
            None => Vec::new(),
        },
        expr_parser_contracts: match expp_bytes {
            Some(payload) => decode_expp_chunk(payload)?,
            None => Vec::new(),
        },
        families: decode_fams_chunk(fams_bytes)?,
        cpus: decode_cpus_chunk(cpus_bytes)?,
        dialects: decode_dial_chunk(dial_bytes)?,
        registers: decode_regs_chunk(regs_bytes)?,
        forms: decode_form_chunk(form_bytes)?,
        tables: decode_tabl_chunk(tabl_bytes)?,
        selectors: match msel_bytes {
            Some(payload) => decode_msel_chunk(payload)?,
            None => Vec::new(),
        },
    })
}

pub fn load_hierarchy_package(bytes: &[u8]) -> Result<HierarchyPackage, OpcpuCodecError> {
    let decoded = decode_hierarchy_chunks(bytes)?;
    HierarchyPackage::new(decoded.families, decoded.cpus, decoded.dialects).map_err(Into::into)
}

fn encode_container(chunks: &[([u8; 4], Vec<u8>)]) -> Result<Vec<u8>, OpcpuCodecError> {
    let toc_count = u16::try_from(chunks.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: "TOC entry count exceeds u16".to_string(),
    })?;

    let header_and_toc_len = HEADER_SIZE
        .checked_add(chunks.len().checked_mul(TOC_ENTRY_SIZE).ok_or_else(|| {
            OpcpuCodecError::CountOutOfRange {
                context: "TOC byte size overflow".to_string(),
            }
        })?)
        .ok_or_else(|| OpcpuCodecError::CountOutOfRange {
            context: "header size overflow".to_string(),
        })?;

    let mut toc_entries = Vec::with_capacity(chunks.len());
    let mut next_offset =
        u32::try_from(header_and_toc_len).map_err(|_| OpcpuCodecError::CountOutOfRange {
            context: "container header offset exceeds u32".to_string(),
        })?;

    for (tag, payload) in chunks {
        let length =
            u32::try_from(payload.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
                context: format!("chunk '{}' length exceeds u32", chunk_name(tag)),
            })?;
        toc_entries.push((
            *tag,
            TocEntry {
                offset: next_offset,
                length,
            },
        ));
        next_offset =
            next_offset
                .checked_add(length)
                .ok_or_else(|| OpcpuCodecError::CountOutOfRange {
                    context: "container size exceeds u32".to_string(),
                })?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(&OPCPU_MAGIC);
    out.extend_from_slice(&OPCPU_VERSION_V1.to_le_bytes());
    out.extend_from_slice(&OPCPU_ENDIAN_MARKER.to_le_bytes());
    out.extend_from_slice(&toc_count.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    for (tag, entry) in &toc_entries {
        out.extend_from_slice(tag);
        out.extend_from_slice(&entry.offset.to_le_bytes());
        out.extend_from_slice(&entry.length.to_le_bytes());
    }

    for (_, payload) in chunks {
        out.extend_from_slice(payload);
    }

    Ok(out)
}

fn parse_toc(bytes: &[u8]) -> Result<HashMap<[u8; 4], TocEntry>, OpcpuCodecError> {
    if bytes.len() < HEADER_SIZE {
        return Err(OpcpuCodecError::UnexpectedEof {
            context: "container header".to_string(),
        });
    }

    let found_magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if found_magic != OPCPU_MAGIC {
        return Err(OpcpuCodecError::InvalidMagic { found: found_magic });
    }

    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != OPCPU_VERSION_V1 {
        return Err(OpcpuCodecError::UnsupportedVersion { found: version });
    }

    let marker = u16::from_le_bytes([bytes[6], bytes[7]]);
    if marker != OPCPU_ENDIAN_MARKER {
        return Err(OpcpuCodecError::InvalidEndiannessMarker { found: marker });
    }

    let toc_count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let toc_bytes = toc_count
        .checked_mul(TOC_ENTRY_SIZE)
        .and_then(|size| HEADER_SIZE.checked_add(size))
        .ok_or_else(|| OpcpuCodecError::CountOutOfRange {
            context: "TOC length overflow".to_string(),
        })?;

    if bytes.len() < toc_bytes {
        return Err(OpcpuCodecError::UnexpectedEof {
            context: "TOC entries".to_string(),
        });
    }

    let mut toc = HashMap::new();
    for idx in 0..toc_count {
        let start = HEADER_SIZE + idx * TOC_ENTRY_SIZE;
        let tag = [
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ];
        let offset = u32::from_le_bytes([
            bytes[start + 4],
            bytes[start + 5],
            bytes[start + 6],
            bytes[start + 7],
        ]);
        let length = u32::from_le_bytes([
            bytes[start + 8],
            bytes[start + 9],
            bytes[start + 10],
            bytes[start + 11],
        ]);

        if toc.contains_key(&tag) {
            return Err(OpcpuCodecError::DuplicateChunk {
                chunk: chunk_name(&tag),
            });
        }

        let start_usize =
            usize::try_from(offset).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
                chunk: chunk_name(&tag),
                offset,
                length,
                file_len: bytes.len(),
            })?;
        let len_usize = usize::try_from(length).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset,
            length,
            file_len: bytes.len(),
        })?;
        let end = start_usize.checked_add(len_usize).ok_or_else(|| {
            OpcpuCodecError::ChunkOutOfBounds {
                chunk: chunk_name(&tag),
                offset,
                length,
                file_len: bytes.len(),
            }
        })?;
        if end > bytes.len() {
            return Err(OpcpuCodecError::ChunkOutOfBounds {
                chunk: chunk_name(&tag),
                offset,
                length,
                file_len: bytes.len(),
            });
        }

        toc.insert(tag, TocEntry { offset, length });
    }

    Ok(toc)
}

fn slice_for_chunk<'a>(
    bytes: &'a [u8],
    toc: &HashMap<[u8; 4], TocEntry>,
    tag: [u8; 4],
) -> Result<&'a [u8], OpcpuCodecError> {
    let entry = toc
        .get(&tag)
        .ok_or_else(|| OpcpuCodecError::MissingRequiredChunk {
            chunk: chunk_name(&tag),
        })?;
    let start = usize::try_from(entry.offset).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let len = usize::try_from(entry.length).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })?;
    bytes
        .get(start..end)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })
}

fn slice_for_chunk_optional<'a>(
    bytes: &'a [u8],
    toc: &HashMap<[u8; 4], TocEntry>,
    tag: [u8; 4],
) -> Result<Option<&'a [u8]>, OpcpuCodecError> {
    let Some(entry) = toc.get(&tag) else {
        return Ok(None);
    };
    let start = usize::try_from(entry.offset).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let len = usize::try_from(entry.length).map_err(|_| OpcpuCodecError::ChunkOutOfBounds {
        chunk: chunk_name(&tag),
        offset: entry.offset,
        length: entry.length,
        file_len: bytes.len(),
    })?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })?;
    bytes
        .get(start..end)
        .map(Some)
        .ok_or_else(|| OpcpuCodecError::ChunkOutOfBounds {
            chunk: chunk_name(&tag),
            offset: entry.offset,
            length: entry.length,
            file_len: bytes.len(),
        })
}

fn encode_fams_chunk(families: &[FamilyDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(families.len(), "FAMS count")?);
    for family in families {
        write_string(&mut out, "FAMS", &family.id)?;
        write_string(&mut out, "FAMS", &family.canonical_dialect)?;
    }
    Ok(out)
}

fn decode_fams_chunk(bytes: &[u8]) -> Result<Vec<FamilyDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FAMS");
    let count = read_bounded_count(&mut cur, 8, "family entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(FamilyDescriptor {
            id: cur.read_string()?,
            canonical_dialect: cur.read_string()?,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_meta_chunk(metadata: &PackageMetaDescriptor) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_string(&mut out, "META", &metadata.package_id)?;
    write_string(&mut out, "META", &metadata.package_version)?;
    write_u32(&mut out, metadata.capability_flags);
    Ok(out)
}

fn decode_meta_chunk(bytes: &[u8]) -> Result<PackageMetaDescriptor, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "META");
    let metadata = PackageMetaDescriptor {
        package_id: cur.read_string()?,
        package_version: cur.read_string()?,
        capability_flags: cur.read_u32()?,
    };
    cur.finish()?;
    Ok(metadata)
}

fn encode_strs_chunk(strings: &[String]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(strings.len(), "STRS count")?);
    for entry in strings {
        write_string(&mut out, "STRS", entry)?;
    }
    Ok(out)
}

fn decode_strs_chunk(bytes: &[u8]) -> Result<Vec<String>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "STRS");
    let count = read_bounded_count(&mut cur, 4, "string entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(cur.read_string()?);
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_diag_chunk(diagnostics: &[DiagnosticDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(diagnostics.len(), "DIAG count")?);
    for entry in diagnostics {
        write_string(&mut out, "DIAG", &entry.code)?;
        write_string(&mut out, "DIAG", &entry.message_template)?;
    }
    Ok(out)
}

fn decode_diag_chunk(bytes: &[u8]) -> Result<Vec<DiagnosticDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "DIAG");
    let count = read_bounded_count(&mut cur, 8, "diagnostic entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(DiagnosticDescriptor {
            code: cur.read_string()?,
            message_template: cur.read_string()?,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_scoped_owner(
    out: &mut Vec<u8>,
    chunk: &str,
    owner: &ScopedOwner,
) -> Result<(), OpcpuCodecError> {
    out.push(owner.owner_tag());
    write_string(out, chunk, owner.owner_id())
}

fn decode_scoped_owner(
    cur: &mut Decoder<'_>,
    chunk: &'static str,
) -> Result<ScopedOwner, OpcpuCodecError> {
    let owner_tag = cur.read_u8()?;
    let owner_id = cur.read_string()?;
    ScopedOwner::from_owner_tag(owner_tag, owner_id).ok_or_else(|| {
        OpcpuCodecError::InvalidChunkFormat {
            chunk: chunk.to_string(),
            detail: format!("invalid owner tag: {}", owner_tag),
        }
    })
}

fn encode_toks_chunk(policies: &[TokenPolicyDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(policies.len(), "TOKS count")?);
    for entry in policies {
        encode_scoped_owner(&mut out, "TOKS", &entry.owner)?;
        out.push(entry.case_rule as u8);
        write_u32(&mut out, entry.identifier_start_class);
        write_u32(&mut out, entry.identifier_continue_class);
        write_string(&mut out, "TOKS", &entry.punctuation_chars)?;
        out.push(TOKS_EXT_MARKER);
        write_string(&mut out, "TOKS", &entry.comment_prefix)?;
        write_string(&mut out, "TOKS", &entry.quote_chars)?;
        match entry.escape_char {
            Some(ch) if ch.is_ascii() => {
                out.push(1);
                out.push(ch as u8);
            }
            Some(ch) => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "TOKS".to_string(),
                    detail: format!("escape_char must be ASCII: {:?}", ch),
                });
            }
            None => out.push(0),
        }
        write_string(&mut out, "TOKS", &entry.number_prefix_chars)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_binary)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_octal)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_decimal)?;
        write_string(&mut out, "TOKS", &entry.number_suffix_hex)?;
        write_string(&mut out, "TOKS", &entry.operator_chars)?;
        write_u32(
            &mut out,
            u32_count(
                entry.multi_char_operators.len(),
                "TOKS multi-char operator count",
            )?,
        );
        for operator in &entry.multi_char_operators {
            write_string(&mut out, "TOKS", operator)?;
        }
    }
    Ok(out)
}

fn decode_toks_chunk(bytes: &[u8]) -> Result<Vec<TokenPolicyDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TOKS");
    let count = read_bounded_count(&mut cur, 1, "token policy entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "TOKS")?;
        let case_rule = TokenCaseRule::from_u8(cur.read_u8()?, "TOKS")?;
        let identifier_start_class = cur.read_u32()?;
        let identifier_continue_class = cur.read_u32()?;
        let punctuation_chars = cur.read_string()?;
        let defaults = default_token_policy_lexical_defaults();
        let mut comment_prefix = defaults.comment_prefix;
        let mut quote_chars = defaults.quote_chars;
        let mut escape_char = defaults.escape_char;
        let mut number_prefix_chars = defaults.number_prefix_chars;
        let mut number_suffix_binary = defaults.number_suffix_binary;
        let mut number_suffix_octal = defaults.number_suffix_octal;
        let mut number_suffix_decimal = defaults.number_suffix_decimal;
        let mut number_suffix_hex = defaults.number_suffix_hex;
        let mut operator_chars = defaults.operator_chars;
        let mut multi_char_operators = defaults.multi_char_operators;
        if cur.has_remaining() {
            let marker = cur.peek_u8()?;
            if marker == TOKS_EXT_MARKER {
                let _ = cur.read_u8()?;
                comment_prefix = cur.read_string()?;
                quote_chars = cur.read_string()?;
                escape_char = match cur.read_u8()? {
                    0 => None,
                    1 => Some(cur.read_u8()? as char),
                    other => {
                        return Err(OpcpuCodecError::InvalidChunkFormat {
                            chunk: "TOKS".to_string(),
                            detail: format!("invalid bool flag for escape_char: {}", other),
                        });
                    }
                };
                number_prefix_chars = cur.read_string()?;
                number_suffix_binary = cur.read_string()?;
                number_suffix_octal = cur.read_string()?;
                number_suffix_decimal = cur.read_string()?;
                number_suffix_hex = cur.read_string()?;
                operator_chars = cur.read_string()?;
                let operator_count = read_bounded_count(&mut cur, 1, "multi-char operator")?;
                let mut operators = Vec::with_capacity(operator_count);
                for _ in 0..operator_count {
                    operators.push(cur.read_string()?);
                }
                multi_char_operators = operators;
            }
        }
        entries.push(TokenPolicyDescriptor {
            owner,
            case_rule,
            identifier_start_class,
            identifier_continue_class,
            punctuation_chars,
            comment_prefix,
            quote_chars,
            escape_char,
            number_prefix_chars,
            number_suffix_binary,
            number_suffix_octal,
            number_suffix_decimal,
            number_suffix_hex,
            operator_chars,
            multi_char_operators,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_cpus_chunk(cpus: &[CpuDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(cpus.len(), "CPUS count")?);
    for cpu in cpus {
        write_string(&mut out, "CPUS", &cpu.id)?;
        write_string(&mut out, "CPUS", &cpu.family_id)?;
        match cpu.default_dialect.as_deref() {
            Some(default_dialect) => {
                out.push(1);
                write_string(&mut out, "CPUS", default_dialect)?;
            }
            None => out.push(0),
        }
    }
    Ok(out)
}

fn decode_cpus_chunk(bytes: &[u8]) -> Result<Vec<CpuDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "CPUS");
    let count = read_bounded_count(&mut cur, 1, "cpu entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cur.read_string()?;
        let family_id = cur.read_string()?;
        let has_default = cur.read_u8()?;
        let default_dialect = match has_default {
            0 => None,
            1 => Some(cur.read_string()?),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "CPUS".to_string(),
                    detail: format!("invalid bool flag for default_dialect: {}", other),
                });
            }
        };
        entries.push(CpuDescriptor {
            id,
            family_id,
            default_dialect,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_dial_chunk(dialects: &[DialectDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(dialects.len(), "DIAL count")?);
    for dialect in dialects {
        write_string(&mut out, "DIAL", &dialect.id)?;
        write_string(&mut out, "DIAL", &dialect.family_id)?;
        match dialect.cpu_allow_list.as_deref() {
            Some(allow_list) => {
                out.push(1);
                write_u32(
                    &mut out,
                    u32_count(allow_list.len(), "DIAL allow-list count")?,
                );
                for cpu_id in allow_list {
                    write_string(&mut out, "DIAL", cpu_id)?;
                }
            }
            None => out.push(0),
        }
    }
    Ok(out)
}

fn decode_dial_chunk(bytes: &[u8]) -> Result<Vec<DialectDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "DIAL");
    let count = read_bounded_count(&mut cur, 1, "dialect entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cur.read_string()?;
        let family_id = cur.read_string()?;
        let has_allow_list = cur.read_u8()?;
        let cpu_allow_list = match has_allow_list {
            0 => None,
            1 => {
                let allow_count = read_bounded_count(&mut cur, 1, "dialect allow-list entry")?;
                let mut allow = Vec::with_capacity(allow_count);
                for _ in 0..allow_count {
                    allow.push(cur.read_string()?);
                }
                Some(allow)
            }
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "DIAL".to_string(),
                    detail: format!("invalid bool flag for cpu_allow_list: {}", other),
                });
            }
        };
        entries.push(DialectDescriptor {
            id,
            family_id,
            cpu_allow_list,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_regs_chunk(registers: &[ScopedRegisterDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(registers.len(), "REGS count")?);
    for register in registers {
        encode_scoped_owner(&mut out, "REGS", &register.owner)?;
        write_string(&mut out, "REGS", &register.id)?;
    }
    Ok(out)
}

fn decode_regs_chunk(bytes: &[u8]) -> Result<Vec<ScopedRegisterDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "REGS");
    let count = read_bounded_count(&mut cur, 1, "register entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "REGS")?;
        let id = cur.read_string()?;
        entries.push(ScopedRegisterDescriptor { owner, id });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_form_chunk(forms: &[ScopedFormDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(forms.len(), "FORM count")?);
    for form in forms {
        encode_scoped_owner(&mut out, "FORM", &form.owner)?;
        write_string(&mut out, "FORM", &form.mnemonic)?;
    }
    Ok(out)
}

fn decode_form_chunk(bytes: &[u8]) -> Result<Vec<ScopedFormDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FORM");
    let count = read_bounded_count(&mut cur, 1, "form entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "FORM")?;
        let mnemonic = cur.read_string()?;
        entries.push(ScopedFormDescriptor { owner, mnemonic });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_tabl_chunk(tables: &[VmProgramDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(tables.len(), "TABL count")?);
    for entry in tables {
        encode_scoped_owner(&mut out, "TABL", &entry.owner)?;
        write_string(&mut out, "TABL", &entry.mnemonic)?;
        write_string(&mut out, "TABL", &entry.mode_key)?;
        write_u32(
            &mut out,
            u32_count(entry.program.len(), "TABL program byte length")?,
        );
        out.extend_from_slice(&entry.program);
    }
    Ok(out)
}

fn decode_tabl_chunk(bytes: &[u8]) -> Result<Vec<VmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TABL");
    let count = read_bounded_count(&mut cur, 1, "table entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "TABL")?;
        let mnemonic = cur.read_string()?;
        let mode_key = cur.read_string()?;
        let byte_count = cur.read_u32()? as usize;
        let program = cur.read_exact(byte_count, "program bytes")?.to_vec();
        entries.push(VmProgramDescriptor {
            owner,
            mnemonic,
            mode_key,
            program,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_msel_chunk(selectors: &[ModeSelectorDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(selectors.len(), "MSEL count")?);
    for entry in selectors {
        encode_scoped_owner(&mut out, "MSEL", &entry.owner)?;
        write_string(&mut out, "MSEL", &entry.mnemonic)?;
        write_string(&mut out, "MSEL", &entry.shape_key)?;
        write_string(&mut out, "MSEL", &entry.mode_key)?;
        write_string(&mut out, "MSEL", &entry.operand_plan)?;
        out.extend_from_slice(&entry.priority.to_le_bytes());
        out.push(u8::from(entry.unstable_widen));
        out.push(entry.width_rank);
    }
    Ok(out)
}

fn decode_msel_chunk(bytes: &[u8]) -> Result<Vec<ModeSelectorDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "MSEL");
    let count = read_bounded_count(&mut cur, 1, "mode selector entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "MSEL")?;
        let mnemonic = cur.read_string()?;
        let shape_key = cur.read_string()?;
        let mode_key = cur.read_string()?;
        let operand_plan = cur.read_string()?;
        let priority_bytes = cur.read_exact(2, "priority")?;
        let priority = u16::from_le_bytes([priority_bytes[0], priority_bytes[1]]);
        let unstable_widen = match cur.read_u8()? {
            0 => false,
            1 => true,
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "MSEL".to_string(),
                    detail: format!("invalid bool flag for unstable_widen: {}", other),
                });
            }
        };
        let width_rank = cur.read_u8()?;
        entries.push(ModeSelectorDescriptor {
            owner,
            mnemonic,
            shape_key,
            mode_key,
            operand_plan,
            priority,
            unstable_widen,
            width_rank,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_tkvm_chunk(
    programs: &[TokenizerVmProgramDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(programs.len(), "TKVM count")?);
    for entry in programs {
        encode_scoped_owner(&mut out, "TKVM", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_u16(&mut out, entry.start_state);
        write_u32(
            &mut out,
            u32_count(
                entry.state_entry_offsets.len(),
                "TKVM state_entry_offsets count",
            )?,
        );
        for offset in &entry.state_entry_offsets {
            write_u32(&mut out, *offset);
        }
        write_u32(&mut out, entry.limits.max_steps_per_line);
        write_u32(&mut out, entry.limits.max_tokens_per_line);
        write_u32(&mut out, entry.limits.max_lexeme_bytes);
        write_u32(&mut out, entry.limits.max_errors_per_line);
        write_string(&mut out, "TKVM", &entry.diagnostics.invalid_char)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.unterminated_string)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.step_limit_exceeded)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.token_limit_exceeded)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.lexeme_limit_exceeded)?;
        write_string(&mut out, "TKVM", &entry.diagnostics.error_limit_exceeded)?;
        write_u32(
            &mut out,
            u32_count(entry.program.len(), "TKVM program byte length")?,
        );
        out.extend_from_slice(&entry.program);
    }
    Ok(out)
}

fn decode_tkvm_chunk(bytes: &[u8]) -> Result<Vec<TokenizerVmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "TKVM");
    let count = read_bounded_count(&mut cur, 1, "tokenizer VM entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "TKVM")?;
        let opcode_version = cur.read_u16()?;
        let start_state = cur.read_u16()?;
        let state_count = read_bounded_count(&mut cur, 4, "state-entry offset")?;
        let mut state_entry_offsets = Vec::with_capacity(state_count);
        for _ in 0..state_count {
            state_entry_offsets.push(cur.read_u32()?);
        }
        let limits = TokenizerVmLimits {
            max_steps_per_line: cur.read_u32()?,
            max_tokens_per_line: cur.read_u32()?,
            max_lexeme_bytes: cur.read_u32()?,
            max_errors_per_line: cur.read_u32()?,
        };
        let diagnostics = TokenizerVmDiagnosticMap {
            invalid_char: cur.read_string()?,
            unterminated_string: cur.read_string()?,
            step_limit_exceeded: cur.read_string()?,
            token_limit_exceeded: cur.read_string()?,
            lexeme_limit_exceeded: cur.read_string()?,
            error_limit_exceeded: cur.read_string()?,
        };
        let program_len = cur.read_u32()? as usize;
        let program = cur
            .read_exact(program_len, "tokenizer vm program")?
            .to_vec();
        entries.push(TokenizerVmProgramDescriptor {
            owner,
            opcode_version,
            start_state,
            state_entry_offsets,
            limits,
            diagnostics,
            program,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_pars_chunk(contracts: &[ParserContractDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(contracts.len(), "PARS count")?);
    for entry in contracts {
        encode_scoped_owner(&mut out, "PARS", &entry.owner)?;
        write_string(&mut out, "PARS", &entry.grammar_id)?;
        write_string(&mut out, "PARS", &entry.ast_schema_id)?;
        write_u16(&mut out, entry.opcode_version);
        write_u32(&mut out, entry.max_ast_nodes_per_line);
        write_string(&mut out, "PARS", &entry.diagnostics.unexpected_token)?;
        write_string(&mut out, "PARS", &entry.diagnostics.expected_expression)?;
        write_string(&mut out, "PARS", &entry.diagnostics.expected_operand)?;
        write_string(&mut out, "PARS", &entry.diagnostics.invalid_statement)?;
    }
    Ok(out)
}

fn decode_pars_chunk(bytes: &[u8]) -> Result<Vec<ParserContractDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "PARS");
    let count = read_bounded_count(&mut cur, 1, "parser contract entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "PARS")?;
        let grammar_id = cur.read_string()?;
        let ast_schema_id = cur.read_string()?;
        let opcode_version = cur.read_u16()?;
        let max_ast_nodes_per_line = cur.read_u32()?;
        let diagnostics = ParserDiagnosticMap {
            unexpected_token: cur.read_string()?,
            expected_expression: cur.read_string()?,
            expected_operand: cur.read_string()?,
            invalid_statement: cur.read_string()?,
        };
        entries.push(ParserContractDescriptor {
            owner,
            grammar_id,
            ast_schema_id,
            opcode_version,
            max_ast_nodes_per_line,
            diagnostics,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_prvm_chunk(programs: &[ParserVmProgramDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(programs.len(), "PRVM count")?);
    for entry in programs {
        encode_scoped_owner(&mut out, "PRVM", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_u32(
            &mut out,
            u32_count(entry.program.len(), "PRVM program byte length")?,
        );
        out.extend_from_slice(&entry.program);
    }
    Ok(out)
}

fn decode_prvm_chunk(bytes: &[u8]) -> Result<Vec<ParserVmProgramDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "PRVM");
    let count = read_bounded_count(&mut cur, 1, "parser VM entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "PRVM")?;
        let opcode_version = cur.read_u16()?;
        let program_len = cur.read_u32()? as usize;
        let program = cur.read_exact(program_len, "parser vm program")?.to_vec();
        entries.push(ParserVmProgramDescriptor {
            owner,
            opcode_version,
            program,
        });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_expr_chunk(contracts: &[ExprContractDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(contracts.len(), "EXPR count")?);
    for entry in contracts {
        encode_scoped_owner(&mut out, "EXPR", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_u32(&mut out, entry.max_program_bytes);
        write_u32(&mut out, entry.max_stack_depth);
        write_u32(&mut out, entry.max_symbol_refs);
        write_u32(&mut out, entry.max_eval_steps);
        write_string(&mut out, "EXPR", &entry.diagnostics.invalid_opcode)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.stack_underflow)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.stack_depth_exceeded)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.unknown_symbol)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.eval_failure)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.unsupported_feature)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.budget_exceeded)?;
        write_string(&mut out, "EXPR", &entry.diagnostics.invalid_program)?;
    }
    Ok(out)
}

fn decode_expr_chunk(bytes: &[u8]) -> Result<Vec<ExprContractDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "EXPR");
    let count = read_bounded_count(&mut cur, 1, "expression contract entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "EXPR")?;
        let opcode_version = cur.read_u16()?;
        let max_program_bytes = cur.read_u32()?;
        let max_stack_depth = cur.read_u32()?;
        let max_symbol_refs = cur.read_u32()?;
        let max_eval_steps = cur.read_u32()?;
        let diagnostics = ExprDiagnosticMap {
            invalid_opcode: cur.read_string()?,
            stack_underflow: cur.read_string()?,
            stack_depth_exceeded: cur.read_string()?,
            unknown_symbol: cur.read_string()?,
            eval_failure: cur.read_string()?,
            unsupported_feature: cur.read_string()?,
            budget_exceeded: cur.read_string()?,
            invalid_program: cur.read_string()?,
        };
        entries.push(ExprContractDescriptor {
            owner,
            opcode_version,
            max_program_bytes,
            max_stack_depth,
            max_symbol_refs,
            max_eval_steps,
            diagnostics,
        });
        if let Some(entry) = entries.last() {
            validate_expr_contract_descriptor(entry)?;
        }
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_expp_chunk(
    contracts: &[ExprParserContractDescriptor],
) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(contracts.len(), "EXPP count")?);
    for entry in contracts {
        encode_scoped_owner(&mut out, "EXPP", &entry.owner)?;
        write_u16(&mut out, entry.opcode_version);
        write_string(
            &mut out,
            "EXPP",
            &entry.diagnostics.invalid_expression_program,
        )?;
    }
    Ok(out)
}

fn decode_expp_chunk(bytes: &[u8]) -> Result<Vec<ExprParserContractDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "EXPP");
    let count = read_bounded_count(&mut cur, 1, "expression parser contract entry")?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner = decode_scoped_owner(&mut cur, "EXPP")?;
        let opcode_version = cur.read_u16()?;
        let diagnostics = ExprParserDiagnosticMap {
            invalid_expression_program: cur.read_string()?,
        };
        entries.push(ExprParserContractDescriptor {
            owner,
            opcode_version,
            diagnostics,
        });
        if let Some(entry) = entries.last() {
            validate_expr_parser_contract_descriptor(entry)?;
        }
    }
    cur.finish()?;
    Ok(entries)
}

fn validate_expr_contract_descriptor(
    descriptor: &ExprContractDescriptor,
) -> Result<(), OpcpuCodecError> {
    if descriptor.opcode_version != EXPR_VM_OPCODE_VERSION_V1 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: format!("unsupported opcode_version: {}", descriptor.opcode_version),
        });
    }

    if descriptor.max_program_bytes == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_program_bytes must be > 0".to_string(),
        });
    }
    if descriptor.max_stack_depth == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_stack_depth must be > 0".to_string(),
        });
    }
    if descriptor.max_symbol_refs == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_symbol_refs must be > 0".to_string(),
        });
    }
    if descriptor.max_eval_steps == 0 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPR".to_string(),
            detail: "max_eval_steps must be > 0".to_string(),
        });
    }

    let diagnostics = &descriptor.diagnostics;
    let required_codes = [
        (
            "diagnostics.invalid_opcode",
            diagnostics.invalid_opcode.as_str(),
        ),
        (
            "diagnostics.stack_underflow",
            diagnostics.stack_underflow.as_str(),
        ),
        (
            "diagnostics.stack_depth_exceeded",
            diagnostics.stack_depth_exceeded.as_str(),
        ),
        (
            "diagnostics.unknown_symbol",
            diagnostics.unknown_symbol.as_str(),
        ),
        (
            "diagnostics.eval_failure",
            diagnostics.eval_failure.as_str(),
        ),
        (
            "diagnostics.unsupported_feature",
            diagnostics.unsupported_feature.as_str(),
        ),
        (
            "diagnostics.budget_exceeded",
            diagnostics.budget_exceeded.as_str(),
        ),
        (
            "diagnostics.invalid_program",
            diagnostics.invalid_program.as_str(),
        ),
    ];
    for (name, code) in required_codes {
        if code.trim().is_empty() {
            return Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: "EXPR".to_string(),
                detail: format!("missing {} code", name),
            });
        }
    }

    Ok(())
}

fn validate_expr_parser_contract_descriptor(
    descriptor: &ExprParserContractDescriptor,
) -> Result<(), OpcpuCodecError> {
    if descriptor.opcode_version != EXPR_PARSER_VM_OPCODE_VERSION_V1 {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPP".to_string(),
            detail: format!("unsupported opcode_version: {}", descriptor.opcode_version),
        });
    }

    if descriptor
        .diagnostics
        .invalid_expression_program
        .trim()
        .is_empty()
    {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: "EXPP".to_string(),
            detail: "missing diagnostics.invalid_expression_program code".to_string(),
        });
    }

    Ok(())
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_string(out: &mut Vec<u8>, chunk: &str, value: &str) -> Result<(), OpcpuCodecError> {
    let len = u32::try_from(value.len()).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: format!("{} string length exceeds u32", chunk),
    })?;
    write_u32(out, len);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn u32_count(count: usize, context: &str) -> Result<u32, OpcpuCodecError> {
    u32::try_from(count).map_err(|_| OpcpuCodecError::CountOutOfRange {
        context: context.to_string(),
    })
}

fn canonicalize_ascii_char_set(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    chars.sort_unstable();
    chars.dedup();
    chars.into_iter().collect()
}

fn chunk_name(tag: &[u8; 4]) -> String {
    std::str::from_utf8(tag)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| format!("{:02X?}", tag))
}

fn read_bounded_count(
    cur: &mut Decoder<'_>,
    min_record_bytes: usize,
    detail: &str,
) -> Result<usize, OpcpuCodecError> {
    let count = cur.read_u32()? as usize;
    if min_record_bytes == 0 {
        if count > MAX_DECODE_ENTRY_COUNT {
            return Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: cur.chunk.to_string(),
                detail: format!(
                    "{} count {} exceeds hard limit {}",
                    detail, count, MAX_DECODE_ENTRY_COUNT
                ),
            });
        }
        return Ok(count);
    }

    let max_by_payload = cur.remaining_len() / min_record_bytes;
    if count > MAX_DECODE_ENTRY_COUNT {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: cur.chunk.to_string(),
            detail: format!(
                "{} count {} exceeds hard limit {}",
                detail, count, MAX_DECODE_ENTRY_COUNT
            ),
        });
    }

    if count > max_by_payload {
        return Err(OpcpuCodecError::InvalidChunkFormat {
            chunk: cur.chunk.to_string(),
            detail: format!(
                "{} count {} exceeds remaining payload bound {}",
                detail, count, max_by_payload
            ),
        });
    }

    Ok(count)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    chunk: &'static str,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], chunk: &'static str) -> Self {
        Self {
            bytes,
            pos: 0,
            chunk,
        }
    }

    fn read_u8(&mut self) -> Result<u8, OpcpuCodecError> {
        let slice = self.read_exact(1, "u8")?;
        Ok(slice[0])
    }

    fn peek_u8(&self) -> Result<u8, OpcpuCodecError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| OpcpuCodecError::UnexpectedEof {
                context: format!("chunk {} u8", self.chunk),
            })
    }

    fn has_remaining(&self) -> bool {
        self.pos < self.bytes.len()
    }

    fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u32(&mut self) -> Result<u32, OpcpuCodecError> {
        let slice = self.read_exact(4, "u32")?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_u16(&mut self) -> Result<u16, OpcpuCodecError> {
        let slice = self.read_exact(2, "u16")?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_string(&mut self) -> Result<String, OpcpuCodecError> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_exact(len, "string bytes")?;
        String::from_utf8(bytes.to_vec()).map_err(|_| OpcpuCodecError::InvalidUtf8 {
            chunk: self.chunk.to_string(),
        })
    }

    fn read_exact(&mut self, len: usize, detail: &str) -> Result<&'a [u8], OpcpuCodecError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| OpcpuCodecError::InvalidChunkFormat {
                chunk: self.chunk.to_string(),
                detail: format!("{} overflow", detail),
            })?;
        if end > self.bytes.len() {
            return Err(OpcpuCodecError::UnexpectedEof {
                context: format!("chunk {} {}", self.chunk, detail),
            });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn finish(&self) -> Result<(), OpcpuCodecError> {
        if self.pos != self.bytes.len() {
            return Err(OpcpuCodecError::InvalidChunkFormat {
                chunk: self.chunk.to_string(),
                detail: "trailing bytes".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
            err.to_string().contains("family entry count")
                || err.to_string().contains("family entry")
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
                    panic!(
                        "decode outcome changed for same bytes: first={left:?}, second={right:?}"
                    )
                }
            }
        }
    }
}
