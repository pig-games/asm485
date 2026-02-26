// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::SurfaceParsedDocument;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatterDiagnostic {
    pub line_number: usize,
    pub message: String,
}

pub fn collect_fallback_diagnostics(parsed: &SurfaceParsedDocument) -> Vec<FormatterDiagnostic> {
    let mut diagnostics = Vec::new();
    for (idx, line) in parsed.lines.iter().enumerate() {
        if line.is_fallback() {
            diagnostics.push(FormatterDiagnostic {
                line_number: idx + 1,
                message: "Formatter fallback preserved original line due parse ambiguity"
                    .to_string(),
            });
        }
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::collect_fallback_diagnostics;
    use crate::formatter::{parse_document, tokenize_source};

    #[test]
    fn collects_warning_for_unparsed_line() {
        let source = "    lda #1\n.+bad\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let diagnostics = collect_fallback_diagnostics(&parsed);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].line_number, 2);
    }
}
