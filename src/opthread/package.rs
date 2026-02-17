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

pub const DIAG_OPTHREAD_MISSING_VM_PROGRAM: &str = "OTR001";
pub const DIAG_OPTHREAD_INVALID_FORCE_OVERRIDE: &str = "OTR002";
pub const DIAG_OPTHREAD_FORCE_UNSUPPORTED_65C02: &str = "OTR003";
pub const DIAG_OPTHREAD_FORCE_UNSUPPORTED_6502: &str = "OTR004";
pub const TOKENIZER_VM_OPCODE_VERSION_V1: u16 = 0x0001;

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
    canonicalize_package_support_chunks(&mut strings, &mut diagnostics);

    let mut chunks = vec![
        (CHUNK_META, encode_meta_chunk(&metadata)?),
        (CHUNK_STRS, encode_strs_chunk(&strings)?),
        (CHUNK_DIAG, encode_diag_chunk(&diagnostics)?),
        (CHUNK_FAMS, encode_fams_chunk(&fams)?),
        (CHUNK_CPUS, encode_cpus_chunk(&cpus)?),
        (CHUNK_DIAL, encode_dial_chunk(&dials)?),
        (CHUNK_REGS, encode_regs_chunk(&regs)?),
        (CHUNK_FORM, encode_form_chunk(&forms)?),
        (CHUNK_TABL, encode_tabl_chunk(&tables)?),
        (CHUNK_MSEL, encode_msel_chunk(&selectors)?),
    ];
    if !token_policies.is_empty() {
        chunks.insert(3, (CHUNK_TOKS, encode_toks_chunk(&token_policies)?));
    }
    if !tokenizer_vm_programs.is_empty() {
        chunks.insert(4, (CHUNK_TKVM, encode_tkvm_chunk(&tokenizer_vm_programs)?));
    }

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
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.id = entry.id.to_ascii_lowercase();
    }
    registers.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (owner_kind, owner_id, entry.id.to_ascii_lowercase())
    });
    registers.dedup_by(|left, right| {
        left.id == right.id
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });

    for entry in forms.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
    }
    forms.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (owner_kind, owner_id, entry.mnemonic.to_ascii_lowercase())
    });
    forms.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });

    for entry in tables.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
    }
    tables.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (
            owner_kind,
            owner_id,
            entry.mnemonic.to_ascii_lowercase(),
            entry.mode_key.to_ascii_lowercase(),
        )
    });
    tables.dedup_by(|left, right| {
        left.mnemonic == right.mnemonic
            && left.mode_key == right.mode_key
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });

    for entry in selectors.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
        entry.mnemonic = entry.mnemonic.to_ascii_lowercase();
        entry.shape_key = entry.shape_key.to_ascii_lowercase();
        entry.mode_key = entry.mode_key.to_ascii_lowercase();
        entry.operand_plan = entry.operand_plan.to_ascii_lowercase();
    }
    selectors.sort_by_key(|entry| {
        let owner_kind = match entry.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let owner_id = match &entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        (
            owner_kind,
            owner_id,
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
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });
}

pub(crate) fn canonicalize_token_policies(token_policies: &mut Vec<TokenPolicyDescriptor>) {
    for entry in token_policies.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
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
        let left_owner_kind = match left.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let right_owner_kind = match right.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let left_owner_id = match &left.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        let right_owner_id = match &right.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        left_owner_kind
            .cmp(&right_owner_kind)
            .then_with(|| left_owner_id.cmp(&right_owner_id))
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
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });
}

pub(crate) fn canonicalize_tokenizer_vm_programs(
    tokenizer_vm_programs: &mut Vec<TokenizerVmProgramDescriptor>,
) {
    for entry in tokenizer_vm_programs.iter_mut() {
        match &mut entry.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                *id = id.to_ascii_lowercase();
            }
        }
    }
    tokenizer_vm_programs.sort_by(|left, right| {
        let left_owner_kind = match left.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let right_owner_kind = match right.owner {
            ScopedOwner::Family(_) => 0u8,
            ScopedOwner::Cpu(_) => 1u8,
            ScopedOwner::Dialect(_) => 2u8,
        };
        let left_owner_id = match &left.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        let right_owner_id = match &right.owner {
            ScopedOwner::Family(id) | ScopedOwner::Cpu(id) | ScopedOwner::Dialect(id) => {
                id.to_ascii_lowercase()
            }
        };
        left_owner_kind
            .cmp(&right_owner_kind)
            .then_with(|| left_owner_id.cmp(&right_owner_id))
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
            && match (&left.owner, &right.owner) {
                (ScopedOwner::Family(left), ScopedOwner::Family(right)) => left == right,
                (ScopedOwner::Cpu(left), ScopedOwner::Cpu(right)) => left == right,
                (ScopedOwner::Dialect(left), ScopedOwner::Dialect(right)) => left == right,
                _ => false,
            }
    });
}

pub fn decode_hierarchy_chunks(bytes: &[u8]) -> Result<HierarchyChunks, OpcpuCodecError> {
    let toc = parse_toc(bytes)?;
    let meta_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_META)?;
    let strs_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_STRS)?;
    let diag_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_DIAG)?;
    let toks_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_TOKS)?;
    let tkvm_bytes = slice_for_chunk_optional(bytes, &toc, CHUNK_TKVM)?;
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
    let count = cur.read_u32()? as usize;
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
    let count = cur.read_u32()? as usize;
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
    let count = cur.read_u32()? as usize;
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

fn encode_toks_chunk(policies: &[TokenPolicyDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(policies.len(), "TOKS count")?);
    for entry in policies {
        let (owner_tag, owner_id) = match &entry.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "TOKS", owner_id)?;
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
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
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
                let operator_count = cur.read_u32()? as usize;
                let mut operators = Vec::with_capacity(operator_count);
                for _ in 0..operator_count {
                    operators.push(cur.read_string()?);
                }
                multi_char_operators = operators;
            }
        }
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "TOKS".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
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
    let count = cur.read_u32()? as usize;
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
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id = cur.read_string()?;
        let family_id = cur.read_string()?;
        let has_allow_list = cur.read_u8()?;
        let cpu_allow_list = match has_allow_list {
            0 => None,
            1 => {
                let allow_count = cur.read_u32()? as usize;
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
        let (owner_tag, owner_id) = match &register.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "REGS", owner_id)?;
        write_string(&mut out, "REGS", &register.id)?;
    }
    Ok(out)
}

fn decode_regs_chunk(bytes: &[u8]) -> Result<Vec<ScopedRegisterDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "REGS");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let id = cur.read_string()?;
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "REGS".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        entries.push(ScopedRegisterDescriptor { owner, id });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_form_chunk(forms: &[ScopedFormDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(forms.len(), "FORM count")?);
    for form in forms {
        let (owner_tag, owner_id) = match &form.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "FORM", owner_id)?;
        write_string(&mut out, "FORM", &form.mnemonic)?;
    }
    Ok(out)
}

fn decode_form_chunk(bytes: &[u8]) -> Result<Vec<ScopedFormDescriptor>, OpcpuCodecError> {
    let mut cur = Decoder::new(bytes, "FORM");
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let mnemonic = cur.read_string()?;
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "FORM".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        entries.push(ScopedFormDescriptor { owner, mnemonic });
    }
    cur.finish()?;
    Ok(entries)
}

fn encode_tabl_chunk(tables: &[VmProgramDescriptor]) -> Result<Vec<u8>, OpcpuCodecError> {
    let mut out = Vec::new();
    write_u32(&mut out, u32_count(tables.len(), "TABL count")?);
    for entry in tables {
        let (owner_tag, owner_id) = match &entry.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "TABL", owner_id)?;
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
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let mnemonic = cur.read_string()?;
        let mode_key = cur.read_string()?;
        let byte_count = cur.read_u32()? as usize;
        let program = cur.read_exact(byte_count, "program bytes")?.to_vec();
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "TABL".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
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
        let (owner_tag, owner_id) = match &entry.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "MSEL", owner_id)?;
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
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
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
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "MSEL".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
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
        let (owner_tag, owner_id) = match &entry.owner {
            ScopedOwner::Family(id) => (0u8, id.as_str()),
            ScopedOwner::Cpu(id) => (1u8, id.as_str()),
            ScopedOwner::Dialect(id) => (2u8, id.as_str()),
        };
        out.push(owner_tag);
        write_string(&mut out, "TKVM", owner_id)?;
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
    let count = cur.read_u32()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let owner_tag = cur.read_u8()?;
        let owner_id = cur.read_string()?;
        let owner = match owner_tag {
            0 => ScopedOwner::Family(owner_id),
            1 => ScopedOwner::Cpu(owner_id),
            2 => ScopedOwner::Dialect(owner_id),
            other => {
                return Err(OpcpuCodecError::InvalidChunkFormat {
                    chunk: "TKVM".to_string(),
                    detail: format!("invalid owner tag: {}", other),
                });
            }
        };
        let opcode_version = cur.read_u16()?;
        let start_state = cur.read_u16()?;
        let state_count = cur.read_u32()? as usize;
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
    }

    #[test]
    fn encode_decode_round_trip_preserves_toks_policy() {
        let chunks = HierarchyChunks {
            metadata: PackageMetaDescriptor::default(),
            strings: Vec::new(),
            diagnostics: Vec::new(),
            token_policies: sample_token_policies(),
            tokenizer_vm_programs: Vec::new(),
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
}
