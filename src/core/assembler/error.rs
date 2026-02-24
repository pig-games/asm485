// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Error types, diagnostics, and reporting for the assembler.

use std::fmt;
use std::sync::Arc;

use crate::core::parser::ParseError;
use crate::core::parser_reporter::format_parse_error;

/// Line processing status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LineStatus {
    Ok = 0,
    DirEqu = 1,
    DirDs = 2,
    NothingDone = 3,
    Skip = 4,
    Warning = 5,
    Error = 6,
    Pass1Error = 7,
}

/// Categories of assembler errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsmErrorKind {
    Assembler,
    Cli,
    Conditional,
    Directive,
    Expression,
    Instruction,
    Io,
    Parser,
    Preprocess,
    Symbol,
}

/// An assembler error with a kind and message.
#[derive(Debug, Clone)]
pub struct AsmError {
    kind: AsmErrorKind,
    message: String,
}

impl AsmError {
    pub fn new(kind: AsmErrorKind, msg: &str, param: Option<&str>) -> Self {
        Self {
            kind,
            message: format_error(msg, param),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn kind(&self) -> AsmErrorKind {
        self.kind
    }
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AsmError {}

/// Severity level for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

/// A diagnostic message with location and context.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub(crate) line: u32,
    pub(crate) column: Option<usize>,
    pub(crate) col_end: Option<usize>,
    pub(crate) code: String,
    pub(crate) severity: Severity,
    pub(crate) error: AsmError,
    pub(crate) file: Option<String>,
    pub(crate) source: Option<String>,
    pub(crate) parser_error: Option<ParseError>,
}

impl Diagnostic {
    pub fn new(line: u32, severity: Severity, error: AsmError) -> Self {
        Self {
            line,
            column: None,
            col_end: None,
            code: default_diagnostic_code(error.kind()).to_string(),
            severity,
            error,
            file: None,
            source: None,
            parser_error: None,
        }
    }

    pub fn with_column(mut self, column: Option<usize>) -> Self {
        self.column = column;
        self
    }

    pub fn with_col_end(mut self, col_end: Option<usize>) -> Self {
        self.col_end = col_end;
        self
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = code.into();
        self
    }

    pub fn with_file(mut self, file: Option<String>) -> Self {
        self.file = file;
        self
    }

    pub fn with_source(mut self, source: Option<String>) -> Self {
        self.source = source;
        self
    }

    pub fn with_parser_error(mut self, parser_error: Option<ParseError>) -> Self {
        self.parser_error = parser_error;
        self
    }

    pub fn format(&self) -> String {
        let sev = match self.severity {
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
        };
        format!(
            "{}: {} [{}] - {}",
            self.line,
            sev,
            self.code,
            self.error.message()
        )
    }

    pub fn format_with_context(&self, lines: Option<&[String]>, use_color: bool) -> String {
        if let Some(parser_error) = &self.parser_error {
            return format_parse_error(parser_error, self.file.as_deref(), lines, use_color);
        }
        let sev = match self.severity {
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
        };
        let header = match &self.file {
            Some(file) => format!("{file}:{}: {sev} [{}]", self.line, self.code),
            None => format!("{}: {sev} [{}]", self.line, self.code),
        };

        let mut out = String::new();
        out.push_str(&header);
        out.push('\n');

        let context = build_context_lines(
            self.line,
            self.column,
            lines,
            self.source.as_deref(),
            use_color,
        );
        for line in context {
            out.push_str(&line);
            out.push('\n');
        }
        out.push_str(&format!("{sev}: {}", self.error.message()));
        out
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn column(&self) -> Option<usize> {
        self.column
    }

    pub fn col_end(&self) -> Option<usize> {
        self.col_end
    }

    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    pub fn message(&self) -> &str {
        self.error.message()
    }
}

/// Report from a successful assembly run.
pub struct AsmRunReport {
    diagnostics: Vec<Diagnostic>,
    source_lines: Arc<Vec<String>>,
}

impl AsmRunReport {
    pub fn new(diagnostics: Vec<Diagnostic>, source_lines: impl Into<Arc<Vec<String>>>) -> Self {
        Self {
            diagnostics,
            source_lines: source_lines.into(),
        }
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn source_lines(&self) -> &[String] {
        &self.source_lines
    }

    pub fn error_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }
}

/// Error from a failed assembly run.
#[derive(Debug)]
pub struct AsmRunError {
    error: AsmError,
    diagnostics: Vec<Diagnostic>,
    source_lines: Arc<Vec<String>>,
}

impl AsmRunError {
    pub fn new(
        error: AsmError,
        diagnostics: Vec<Diagnostic>,
        source_lines: impl Into<Arc<Vec<String>>>,
    ) -> Self {
        Self {
            error,
            diagnostics,
            source_lines: source_lines.into(),
        }
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn source_lines(&self) -> &[String] {
        &self.source_lines
    }
}

impl fmt::Display for AsmRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for AsmRunError {}

/// Pass statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct PassCounts {
    pub lines: u32,
    pub errors: u32,
    pub warnings: u32,
}

impl PassCounts {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Build context lines for error display.
pub fn build_context_lines(
    line_num: u32,
    column: Option<usize>,
    lines: Option<&[String]>,
    source_override: Option<&str>,
    use_color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let line_idx = line_num.saturating_sub(1) as usize;

    if let Some(source) = source_override {
        let highlighted = highlight_line(source, column, use_color);
        out.push(format!("{:>5} | {}", line_num, highlighted));
        return out;
    }

    let lines = match lines {
        Some(lines) if !lines.is_empty() => lines,
        _ => {
            out.push(format!("{:>5} | <source unavailable>", line_num));
            return out;
        }
    };

    if line_idx >= lines.len() {
        out.push(format!("{:>5} | <source unavailable>", line_num));
        return out;
    }

    let line = &lines[line_idx];
    let display = highlight_line(line, column, use_color);
    out.push(format!("{:>5} | {}", line_num, display));

    out
}

fn highlight_line(line: &str, column: Option<usize>, use_color: bool) -> String {
    crate::report::highlight_line(line, column, use_color)
}

fn default_diagnostic_code(kind: AsmErrorKind) -> &'static str {
    match kind {
        AsmErrorKind::Assembler => "asm001",
        AsmErrorKind::Cli => "asm101",
        AsmErrorKind::Conditional => "asm201",
        AsmErrorKind::Directive => "asm202",
        AsmErrorKind::Expression => "asm401",
        AsmErrorKind::Instruction => "asm402",
        AsmErrorKind::Io => "asm501",
        AsmErrorKind::Parser => "otp004",
        AsmErrorKind::Preprocess => "asm102",
        AsmErrorKind::Symbol => "asm301",
    }
}

/// Format an error message with an optional parameter.
pub fn format_error(msg: &str, param: Option<&str>) -> String {
    match param {
        Some(p) => format!("{msg}: {p}"),
        None => msg.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_format_includes_line_and_severity() {
        let err = AsmError::new(AsmErrorKind::Assembler, "Bad thing", None);
        let diag = Diagnostic::new(12, Severity::Error, err);
        assert_eq!(diag.format(), "12: ERROR [asm001] - Bad thing");
    }
}
