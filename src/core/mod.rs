// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! CPU-agnostic assembler core.
//!
//! This module provides reusable assembler infrastructure that can be shared
//! across different CPU targets (e.g., 8085, Z80, 6502).
//!
//! # Components
//!
//! - [`cpu`] - CPU type abstraction for multi-processor support
//! - [`text_utils`] - Text processing utilities (cursor, identifiers, comments)
//! - [`tokenizer`] - Token scanning with configurable register detection
//! - [`parser`] - Expression and statement parsing
//! - [`symbol_table`] - Symbol management
//! - [`imagestore`] - Binary and hex output generation
//! - [`preprocess`] - Preprocessor (macros, conditionals, includes)
//! - [`macro_processor`] - Assembler macro expansion
//! - [`assembler`] - Core assembler components (conditionals, scopes, expressions)
//! - [`text_encoding`] - Text encoding tables for directive string emission

pub mod assembler;
pub mod cpu;
pub mod expr;
pub mod expr_vm;
pub mod family;
pub mod imagestore;
pub mod macro_processor;
pub mod operand;
pub mod parser;
pub mod parser_reporter;
pub mod preprocess;
pub mod registry;
pub mod report;
pub mod source_map;
pub mod symbol_stability;
pub mod symbol_table;
pub mod text_encoding;
pub mod text_utils;
pub mod token_value;
pub mod tokenizer;

// Re-exports for convenience
pub use cpu::{CpuType, EncodeError, OperandParseError};
pub use expr::{
    eval_expr, parse_number, EvalContext, EvalError, SimpleEvalContext, SymbolTableContext,
};
pub use expr_vm::{
    compile_core_expr_to_portable_program, eval_portable_expr_program,
    expr_program_has_unstable_symbols, PortableExprBudgets, PortableExprError,
    PortableExprEvalContext, PortableExprEvaluation, PortableExprProgram, PortableExprRef,
    EXPR_VM_OPCODE_VERSION_V1,
};
pub use family::{AssemblerContext, CpuHandler, EncodeResult, FamilyHandler, FamilyParseError};
pub use operand::{Operand, SizeSuffix};
pub use parser::ParseError;
pub use symbol_table::SymbolTable;
pub use text_encoding::{TextEncodingError, TextEncodingRegistry};
pub use tokenizer::{RegisterChecker, Span, Token, TokenKind, TokenizeError, Tokenizer};
