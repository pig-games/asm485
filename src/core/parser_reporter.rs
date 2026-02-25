// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Reporter for parser errors with source context.

use crate::core::parser::ParseError;

pub fn format_parse_error(
    err: &ParseError,
    file: Option<&str>,
    lines: Option<&[String]>,
    use_color: bool,
) -> String {
    let header = match file {
        Some(file) => format!("{file}:{}: ERROR", err.span.line),
        None => format!("{}: ERROR", err.span.line),
    };

    let mut out = String::new();
    out.push_str(&header);
    out.push('\n');

    let line_num = err.span.line;
    let line_idx = line_num.saturating_sub(1) as usize;
    let line_text = lines
        .and_then(|lines| lines.get(line_idx))
        .map(|s| s.as_str())
        .unwrap_or("<source unavailable>");

    let highlighted = highlight_line(line_text, err.span.col_start, use_color);
    out.push_str(&format!("{:>5} | {}", line_num, highlighted));
    out.push('\n');
    out.push_str(&format!("ERROR: {}", err.message));
    out
}

pub fn format_parse_error_listing(
    err: &ParseError,
    lines: Option<&[String]>,
    use_color: bool,
) -> String {
    let line_num = err.span.line;
    let line_idx = line_num.saturating_sub(1) as usize;
    let line_text = lines
        .and_then(|lines| lines.get(line_idx))
        .map(|s| s.as_str())
        .unwrap_or("<source unavailable>");

    let highlighted = highlight_line(line_text, err.span.col_start, use_color);
    let mut out = String::new();
    out.push_str(&format!("{:>5} | {}", line_num, highlighted));
    out.push('\n');
    out.push_str(&format!("ERROR: {}", err.message));
    out
}

fn highlight_line(line: &str, column: usize, use_color: bool) -> String {
    let col_opt = if column == 0 { None } else { Some(column) };
    crate::report::highlight_line(line, col_opt, use_color)
}

#[cfg(test)]
mod tests {
    use super::{format_parse_error, format_parse_error_listing};
    use crate::core::parser::ParseError;
    use crate::core::tokenizer::Span;

    #[test]
    fn format_parse_error_includes_file_and_message() {
        let err = ParseError {
            message: "unexpected token".to_string(),
            span: Span {
                line: 1,
                col_start: 2,
                col_end: 2,
            },
        };
        let lines = vec!["lda #".to_string()];
        let out = format_parse_error(&err, Some("test.asm"), Some(&lines), false);
        assert!(out.contains("test.asm:1: ERROR"));
        assert!(out.contains("ERROR: unexpected token"));
    }

    #[test]
    fn format_parse_error_listing_uses_source_unavailable_fallback() {
        let err = ParseError {
            message: "bad line".to_string(),
            span: Span {
                line: 9,
                col_start: 1,
                col_end: 1,
            },
        };
        let out = format_parse_error_listing(&err, None, false);
        assert!(out.contains("<source unavailable>"));
        assert!(out.contains("ERROR: bad line"));
    }
}
