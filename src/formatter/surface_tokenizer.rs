// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::text_utils::split_comment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnding {
    None,
    Lf,
    Crlf,
}

impl LineEnding {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Lf => "\n",
            Self::Crlf => "\r\n",
        }
    }
}

/// Trivia-preserving line representation for formatter planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceLine {
    pub indent: String,
    pub code: String,
    pub comment: Option<String>,
    pub line_ending: LineEnding,
}

impl SurfaceLine {
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(
            self.indent.len()
                + self.code.len()
                + self
                    .comment
                    .as_ref()
                    .map(|comment| comment.len())
                    .unwrap_or(0)
                + self.line_ending.as_str().len(),
        );
        out.push_str(&self.indent);
        out.push_str(&self.code);
        if let Some(comment) = &self.comment {
            out.push_str(comment);
        }
        out.push_str(self.line_ending.as_str());
        out
    }

    pub fn has_comment(&self) -> bool {
        self.comment.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SurfaceDocument {
    pub lines: Vec<SurfaceLine>,
}

impl SurfaceDocument {
    pub fn render(&self) -> String {
        let total_len: usize = self.lines.iter().map(|line| line.render().len()).sum();
        let mut out = String::with_capacity(total_len);
        for line in &self.lines {
            out.push_str(&line.render());
        }
        out
    }
}

pub fn tokenize_source(source: &str) -> SurfaceDocument {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let bytes = source.as_bytes();

    while start < bytes.len() {
        let mut end = start;
        while end < bytes.len() && bytes[end] != b'\n' {
            end += 1;
        }

        let (line_text, line_ending, next_start) = if end < bytes.len() {
            if end > start && bytes[end - 1] == b'\r' {
                (&source[start..end - 1], LineEnding::Crlf, end + 1)
            } else {
                (&source[start..end], LineEnding::Lf, end + 1)
            }
        } else {
            (&source[start..end], LineEnding::None, end)
        };

        lines.push(tokenize_line(line_text, line_ending));
        start = next_start;
    }

    SurfaceDocument { lines }
}

fn tokenize_line(line: &str, line_ending: LineEnding) -> SurfaceLine {
    let (code_part, comment_part) = split_comment(line);
    let indent_len = code_part
        .as_bytes()
        .iter()
        .take_while(|byte| **byte == b' ' || **byte == b'\t')
        .count();

    SurfaceLine {
        indent: code_part[..indent_len].to_string(),
        code: code_part[indent_len..].to_string(),
        comment: if comment_part.is_empty() {
            None
        } else {
            Some(comment_part.to_string())
        },
        line_ending,
    }
}

#[cfg(test)]
mod tests {
    use super::{tokenize_source, LineEnding};

    #[test]
    fn tokenizer_preserves_comment_split_for_semicolon_inside_quotes() {
        let doc = tokenize_source("msg .text \"a;b\" ; trailing\n");
        assert_eq!(doc.lines.len(), 1);
        let line = &doc.lines[0];
        assert_eq!(line.indent, "");
        assert_eq!(line.code, "msg .text \"a;b\" ");
        assert_eq!(line.comment.as_deref(), Some("; trailing"));
        assert_eq!(line.line_ending, LineEnding::Lf);
        assert!(line.has_comment());
    }

    #[test]
    fn tokenizer_round_trips_tabs_spaces_and_comments() {
        let source = "\t  lda\t#1  ; c1\r\n  ; only comment\t\r\n\t\t\r\n";
        let doc = tokenize_source(source);
        assert_eq!(doc.lines.len(), 3);
        assert_eq!(doc.lines[0].line_ending, LineEnding::Crlf);
        assert_eq!(doc.lines[1].line_ending, LineEnding::Crlf);
        assert_eq!(doc.lines[2].line_ending, LineEnding::Crlf);
        assert_eq!(doc.render(), source);
    }

    #[test]
    fn tokenizer_handles_empty_and_whitespace_only_lines() {
        let source = "\n   \n";
        let doc = tokenize_source(source);
        assert_eq!(doc.lines.len(), 2);
        assert_eq!(doc.lines[0].indent, "");
        assert_eq!(doc.lines[0].code, "");
        assert!(doc.lines[0].comment.is_none());
        assert_eq!(doc.lines[0].line_ending, LineEnding::Lf);
        assert_eq!(doc.lines[1].indent, "   ");
        assert_eq!(doc.lines[1].code, "");
        assert!(doc.lines[1].comment.is_none());
        assert_eq!(doc.lines[1].line_ending, LineEnding::Lf);
        assert_eq!(doc.render(), source);
    }
}
