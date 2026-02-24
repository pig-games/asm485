// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Error types, diagnostics, and reporting for the assembler.

use std::fmt;
use std::sync::Arc;

use crate::core::parser::ParseError;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabeledSpan {
    pub file: Option<String>,
    pub line: u32,
    pub col_start: Option<usize>,
    pub col_end: Option<usize>,
    pub label: Option<String>,
    pub is_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixit {
    pub file: Option<String>,
    pub line: u32,
    pub col_start: Option<usize>,
    pub col_end: Option<usize>,
    pub replacement: String,
    pub applicability: String,
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
    pub(crate) related_spans: Vec<LabeledSpan>,
    pub(crate) notes: Vec<String>,
    pub(crate) help: Vec<String>,
    pub(crate) fixits: Vec<Fixit>,
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
            related_spans: Vec::new(),
            notes: Vec::new(),
            help: Vec::new(),
            fixits: Vec::new(),
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
        if let Some(parser_error) = &self.parser_error {
            if self.column.is_none() {
                self.column = Some(parser_error.span.col_start);
            }
            if self.col_end.is_none() {
                self.col_end = Some(parser_error.span.col_end);
            }
            if self.related_spans.is_empty() {
                self.related_spans.push(LabeledSpan {
                    file: self.file.clone(),
                    line: parser_error.span.line,
                    col_start: Some(parser_error.span.col_start),
                    col_end: Some(parser_error.span.col_end),
                    label: Some("while parsing this statement".to_string()),
                    is_primary: true,
                });
            }
            if let Some((code, message)) = split_prefixed_diagnostic(parser_error.message.as_str())
            {
                self.code = code.to_string();
                self.error.message = message.to_string();
            }
            if self.fixits.is_empty() {
                if let Some(fixit) = parser_error_default_fixit(&self, parser_error) {
                    self.fixits.push(fixit);
                }
            }
        }
        self
    }

    pub fn with_related_span(mut self, span: LabeledSpan) -> Self {
        self.related_spans.push(span);
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help.push(help.into());
        self
    }

    pub fn with_fixit(mut self, fixit: Fixit) -> Self {
        self.fixits.push(fixit);
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

        for related in self.related_spans.iter().filter(|span| !span.is_primary) {
            let ctx = build_context_lines(related.line, related.col_start, lines, None, use_color);
            for line in ctx {
                out.push_str("      = ");
                out.push_str(line.trim_start());
                out.push('\n');
            }
            if let Some(label) = &related.label {
                out.push_str("      = note: ");
                out.push_str(label);
                out.push('\n');
            }
        }

        for note in &self.notes {
            out.push_str("note: ");
            out.push_str(note);
            out.push('\n');
        }

        for help in &self.help {
            out.push_str("help: ");
            out.push_str(help);
            out.push('\n');
        }

        for fixit in &self.fixits {
            out.push_str("suggestion: replace ");
            out.push_str(&format_span_bounds(
                fixit.line,
                fixit.col_start,
                fixit.col_end,
            ));
            out.push_str(" with ");
            out.push_str(&format!("{:?}", fixit.replacement));
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

    pub fn related_spans(&self) -> &[LabeledSpan] {
        &self.related_spans
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    pub fn help(&self) -> &[String] {
        &self.help
    }

    pub fn fixits(&self) -> &[Fixit] {
        &self.fixits
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

fn split_prefixed_diagnostic(message: &str) -> Option<(&str, &str)> {
    let (code, tail) = message.split_once(':')?;
    let code = code.trim();
    if code.len() < 6 || code.len() > 8 {
        return None;
    }
    let mut chars = code.chars();
    let prefix_ok = chars
        .by_ref()
        .take_while(|ch| ch.is_ascii_alphabetic())
        .count()
        >= 2;
    let digits: String = chars.collect();
    if !prefix_ok || digits.len() != 3 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some((code, tail.trim_start()))
}

fn parser_error_default_fixit(diag: &Diagnostic, parser_error: &ParseError) -> Option<Fixit> {
    match diag.code.as_str() {
        "otp002" | "otp003" => Some(Fixit {
            file: diag.file.clone(),
            line: parser_error.span.line,
            col_start: Some(parser_error.span.col_start),
            col_end: Some(parser_error.span.col_start),
            replacement: "0".to_string(),
            applicability: "maybe-incorrect".to_string(),
        }),
        _ => None,
    }
}

fn format_span_bounds(line: u32, col_start: Option<usize>, col_end: Option<usize>) -> String {
    match (col_start, col_end) {
        (Some(start), Some(end)) => format!("{line}:{start}-{end}"),
        (Some(start), None) => format!("{line}:{start}"),
        _ => format!("{line}"),
    }
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

    #[test]
    fn format_with_context_renders_notes_and_help_after_related_spans() {
        let err = AsmError::new(AsmErrorKind::Parser, "unexpected token", None);
        let diag = Diagnostic::new(3, Severity::Error, err)
            .with_file(Some("example.asm".to_string()))
            .with_column(Some(5))
            .with_related_span(LabeledSpan {
                file: Some("example.asm".to_string()),
                line: 1,
                col_start: Some(1),
                col_end: Some(4),
                label: Some("opened here".to_string()),
                is_primary: false,
            })
            .with_note("insert a matching terminator")
            .with_help("add `.endif` after the block");

        let lines = vec![
            ".if 1".to_string(),
            "lda #$01".to_string(),
            "lda #$02".to_string(),
        ];

        let rendered = diag.format_with_context(Some(&lines), false);
        assert!(rendered.contains("example.asm:3: ERROR [otp004]"));
        assert!(rendered.contains("      = 1 | .if 1"));
        assert!(rendered.contains("      = note: opened here"));
        assert!(rendered.contains("note: insert a matching terminator"));
        assert!(rendered.contains("help: add `.endif` after the block"));
        assert!(rendered.ends_with("ERROR: unexpected token"));

        let related_idx = rendered
            .find("      = note: opened here")
            .expect("related note label should be present");
        let note_idx = rendered
            .find("note: insert a matching terminator")
            .expect("note should be present");
        let help_idx = rendered
            .find("help: add `.endif` after the block")
            .expect("help should be present");
        assert!(
            related_idx < note_idx,
            "related label must render before notes"
        );
        assert!(note_idx < help_idx, "notes must render before help");
    }

    #[test]
    fn format_with_context_renders_fixit_suggestion_after_help() {
        let err = AsmError::new(AsmErrorKind::Directive, "missing argument", None);
        let diag = Diagnostic::new(8, Severity::Error, err)
            .with_file(Some("example.asm".to_string()))
            .with_help("provide an expression")
            .with_fixit(Fixit {
                file: Some("example.asm".to_string()),
                line: 8,
                col_start: Some(6),
                col_end: Some(6),
                replacement: "0".to_string(),
                applicability: "machine-applicable".to_string(),
            });
        let lines = vec![".byte".to_string(); 8];

        let rendered = diag.format_with_context(Some(&lines), false);
        let expected = [
            "example.asm:8: ERROR [asm202]",
            "    8 | .byte",
            "help: provide an expression",
            "suggestion: replace 8:6-6 with \"0\"",
            "ERROR: missing argument",
        ]
        .join("\n");

        assert_eq!(rendered, expected);
    }
}
