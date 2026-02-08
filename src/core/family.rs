// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! CPU family abstraction for hierarchical parsing and encoding.
//!
//! This module defines the traits for family-level and CPU-level handlers
//! that implement the hierarchical processing model described in the architecture.
//!
//! # Architecture Overview
//!
//! ```text
//! Generic Parser → Family Handler → CPU Handler → Output
//! ```
//!
//! - **Generic Parser**: Handles labels, directives, macros, scopes, expressions
//! - **Family Handler**: Parses operands into family addressing modes, encodes common instructions
//! - **CPU Handler**: Resolves ambiguous operands, encodes CPU-specific instructions

use crate::core::parser::Expr;
use crate::core::symbol_table::SymbolTable;
use crate::core::tokenizer::Span;

/// Error returned when the family handler cannot parse an operand.
///
/// The family handler returns this when it encounters syntax it doesn't recognize,
/// signaling that the CPU handler should attempt to resolve it.
#[derive(Debug, Clone)]
pub struct FamilyParseError {
    pub message: String,
    pub span: Span,
}

impl FamilyParseError {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

impl std::fmt::Display for FamilyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Error returned when encoding fails.
#[derive(Debug, Clone)]
pub enum EncodeResult<T> {
    /// Successfully encoded
    Ok(T),
    /// Instruction not in this handler's table (try next handler)
    NotFound,
    /// Encoding failed with an error
    Error(String, Option<Span>),
}

impl<T> EncodeResult<T> {
    pub fn error(message: impl Into<String>) -> Self {
        EncodeResult::Error(message.into(), None)
    }

    pub fn error_with_span(message: impl Into<String>, span: Span) -> Self {
        EncodeResult::Error(message.into(), Some(span))
    }
}

/// Result of family-level encoding before CPU operand resolution.
///
/// This allows family handlers to emit bytes even when reporting an error,
/// preserving legacy behavior for partial encodes.
#[derive(Debug, Clone)]
pub enum FamilyEncodeResult<T> {
    /// Successfully encoded
    Ok(T),
    /// Instruction not handled at the family pre-encode layer
    NotFound,
    /// Encoding failed with an error, optionally with partial bytes.
    Error {
        bytes: T,
        message: String,
        span: Option<Span>,
        param: Option<String>,
    },
}

impl<T> FamilyEncodeResult<T> {
    pub fn ok(bytes: T) -> Self {
        FamilyEncodeResult::Ok(bytes)
    }

    pub fn not_found() -> Self {
        FamilyEncodeResult::NotFound
    }

    pub fn error(
        bytes: T,
        message: impl Into<String>,
        span: Option<Span>,
        param: Option<String>,
    ) -> Self {
        FamilyEncodeResult::Error {
            bytes,
            message: message.into(),
            span,
            param,
        }
    }
}

/// Context provided to handlers for expression evaluation and symbol lookup.
///
/// Family and CPU handlers need access to generic assembler services like
/// expression evaluation and symbol lookup. This trait provides that access
/// without coupling handlers to the full assembler implementation.
pub trait AssemblerContext {
    /// Evaluate an expression to a value.
    fn eval_expr(&self, expr: &Expr) -> Result<i64, String>;

    /// Get the symbol table for label resolution.
    fn symbols(&self) -> &SymbolTable;

    /// Check whether an identifier currently resolves in this context.
    fn has_symbol(&self, name: &str) -> bool;

    /// Get the current assembly address.
    fn current_address(&self) -> u32;

    /// Get the current assembler pass (1 or 2).
    fn pass(&self) -> u8;
}

/// Family-level handler for parsing and encoding.
///
/// The family handler processes syntax and instructions common to all CPUs in
/// a family. For example, the MOS 6502 family handler handles modes like
/// `#$20` (immediate) and `$20,X` (zero page indexed) that work the same
/// on both 6502 and 65C02.
///
/// # Type Isolation
///
/// Each family defines its own operand types. The `FamilyOperand` associated
/// type represents operands parsed at the family level, which may include
/// ambiguous cases that require CPU-level resolution.
pub trait FamilyHandler: Send + Sync {
    /// The intermediate operand type for this family.
    ///
    /// This type represents operands as parsed by the family handler.
    /// It may include ambiguous cases like `Indirect(expr)` that could
    /// mean different things depending on the target CPU.
    type FamilyOperand: Clone + std::fmt::Debug;

    /// The final operand type for this family.
    ///
    /// This type represents fully-resolved operands with evaluated values,
    /// ready for instruction encoding.
    type Operand: Clone + std::fmt::Debug;

    /// Parse expressions into family-level operands.
    ///
    /// This method interprets addressing mode syntax common to the family.
    /// For example, the 6502 family parser recognizes `#expr` as immediate
    /// and `(expr,X)` as indexed indirect.
    ///
    /// Returns a vector of family operands, which may include ambiguous cases
    /// that require CPU-level resolution.
    fn parse_operands(
        &self,
        mnemonic: &str,
        exprs: &[Expr],
    ) -> Result<Vec<Self::FamilyOperand>, FamilyParseError>;

    /// Encode an instruction using the family's common instruction table.
    ///
    /// Returns `EncodeResult::NotFound` if the mnemonic is not in the family
    /// table, signaling that the CPU handler should try its extension table.
    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[Self::Operand],
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>>;

    /// Optional family-level encoding using family operands before CPU resolution.
    ///
    /// The default implementation returns `NotFound`.
    fn encode_family_operands(
        &self,
        _canonical_mnemonic: &str,
        _display_mnemonic: &str,
        _operands: &[Self::FamilyOperand],
        _ctx: &dyn AssemblerContext,
    ) -> FamilyEncodeResult<Vec<u8>> {
        FamilyEncodeResult::NotFound
    }

    /// Check if an identifier is a register for this family.
    fn is_register(&self, name: &str) -> bool;

    /// Check if an identifier is a condition code for this family.
    fn is_condition(&self, _name: &str) -> bool {
        false
    }
}

/// CPU-level handler for resolving operands and encoding CPU-specific instructions.
///
/// The CPU handler extends the family handler with CPU-specific behavior:
/// - Resolving ambiguous operands (e.g., `($20)` → zero page indirect on 65C02)
/// - Encoding CPU-specific instructions (e.g., BRA, PHX on 65C02)
/// - Validating that addressing modes are supported by the target CPU
pub trait CpuHandler: Send + Sync {
    /// The family handler type for this CPU.
    type Family: FamilyHandler;

    /// Get the family handler.
    fn family(&self) -> &Self::Family;

    /// Resolve family-level operands to CPU-specific operands.
    ///
    /// This method handles CPU-specific operand resolution, such as:
    /// - Disambiguating `($20)` as JMP indirect (6502) vs zero page indirect (65C02)
    /// - Validating that addressing modes are supported
    /// - Evaluating expressions to final values
    fn resolve_operands(
        &self,
        mnemonic: &str,
        family_operands: &[<Self::Family as FamilyHandler>::FamilyOperand],
        ctx: &dyn AssemblerContext,
    ) -> Result<Vec<<Self::Family as FamilyHandler>::Operand>, String>;

    /// Encode an instruction using the CPU's extension table.
    ///
    /// This is called when the family handler returns `NotFound`, indicating
    /// the instruction might be CPU-specific (like BRA on 65C02).
    fn encode_instruction(
        &self,
        mnemonic: &str,
        operands: &[<Self::Family as FamilyHandler>::Operand],
        ctx: &dyn AssemblerContext,
    ) -> EncodeResult<Vec<u8>>;

    /// Check if this CPU supports a specific instruction.
    fn supports_mnemonic(&self, mnemonic: &str) -> bool;
}
