// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! CPU identifiers and shared error types.
//!
//! This module intentionally avoids hardcoding specific CPU families or types.
//! Family and CPU modules define their own identifiers and expose them through
//! the registry at runtime.

use crate::core::tokenizer::Span;

/// Identifier for a CPU family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuFamily(&'static str);

impl CpuFamily {
    /// Create a new CPU family identifier.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// Return the identifier string.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Identifier for a CPU type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuType(&'static str);

impl CpuType {
    /// Create a new CPU type identifier.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// Return the identifier string.
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Error returned by operand parsing.
#[derive(Debug, Clone)]
pub struct OperandParseError {
    pub message: String,
    pub span: Span,
}

impl std::fmt::Display for OperandParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OperandParseError {}

/// Error returned by instruction encoding.
#[derive(Debug, Clone)]
pub struct EncodeError {
    pub message: String,
    pub span: Option<Span>,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EncodeError {}

impl EncodeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
        }
    }

    pub fn with_span(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span: Some(span),
        }
    }

    pub fn with_span_opt(message: impl Into<String>, span: Option<Span>) -> Self {
        Self {
            message: message.into(),
            span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CpuFamily, CpuType, EncodeError};
    use crate::core::tokenizer::Span;

    #[test]
    fn cpu_identifiers_round_trip_strings() {
        let family = CpuFamily::new("mos6502");
        let cpu = CpuType::new("m6502");
        assert_eq!(family.as_str(), "mos6502");
        assert_eq!(cpu.as_str(), "m6502");
    }

    #[test]
    fn encode_error_with_span_opt_preserves_span() {
        let span = Span {
            line: 12,
            col_start: 3,
            col_end: 7,
        };
        let err = EncodeError::with_span_opt("boom", Some(span));
        assert_eq!(err.message, "boom");
        assert_eq!(err.span, Some(span));
    }
}
