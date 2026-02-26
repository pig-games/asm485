// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use crate::core::text_utils::{is_ident_char, is_ident_start};

use super::surface_tokenizer::{SurfaceDocument, SurfaceLine};

const ASSIGNMENT_OPERATORS: &[&str] = &[
    ":?=", "||=", "&&=", "<<=", ">>=", "**=", "+=", "-=", "*=", "/=", "%=", "|=", "^=", "&=", ".=",
    "<?=", ">?=", ":=", "=",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceLineKind {
    Empty,
    CommentOnly,
    LabelOnly,
    Directive,
    Instruction,
    Assignment,
    Unparsed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceParsedLine {
    pub kind: SurfaceLineKind,
    pub label: Option<String>,
    pub head: Option<String>,
    pub tail: String,
    pub raw_code: String,
}

impl SurfaceParsedLine {
    pub fn is_fallback(&self) -> bool {
        self.kind == SurfaceLineKind::Unparsed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SurfaceParsedDocument {
    pub lines: Vec<SurfaceParsedLine>,
}

pub fn parse_document(doc: &SurfaceDocument) -> SurfaceParsedDocument {
    let lines = doc.lines.iter().map(parse_line).collect();
    SurfaceParsedDocument { lines }
}

pub fn parse_line(line: &SurfaceLine) -> SurfaceParsedLine {
    let raw_code = line.code.clone();
    let code = trim_end_spaces_tabs(&line.code);
    if code.is_empty() {
        let kind = if line.comment.is_some() {
            SurfaceLineKind::CommentOnly
        } else {
            SurfaceLineKind::Empty
        };
        return SurfaceParsedLine {
            kind,
            label: None,
            head: None,
            tail: String::new(),
            raw_code,
        };
    }

    let mut cursor = 0usize;
    let mut label = None;

    if line.indent.is_empty() {
        if let Some((name, len)) = take_ident_at(code, 0) {
            if code.get(len..).is_some_and(|rest| rest.starts_with(':')) {
                label = Some(name);
                cursor = len + 1;
            } else if len == code.len() {
                return SurfaceParsedLine {
                    kind: SurfaceLineKind::LabelOnly,
                    label: Some(name),
                    head: None,
                    tail: String::new(),
                    raw_code,
                };
            } else {
                let next = skip_spaces_tabs(code, len);
                let assign_at_split = has_assignment_prefix(code, len);
                let assign_after_spaces = has_assignment_prefix(code, next);
                let looks_like_label_prefix = next < code.len()
                    && (code.as_bytes()[next] == b'.' || is_ident_start(code.as_bytes()[next]));
                if assign_at_split || assign_after_spaces || looks_like_label_prefix {
                    label = Some(name);
                    cursor = next;
                }
            }
        }
    }

    cursor = skip_spaces_tabs(code, cursor);
    if cursor >= code.len() {
        return SurfaceParsedLine {
            kind: SurfaceLineKind::LabelOnly,
            label,
            head: None,
            tail: String::new(),
            raw_code,
        };
    }

    let rest = &code[cursor..];
    if let Some(op) = match_assignment_operator_prefix(rest) {
        return SurfaceParsedLine {
            kind: SurfaceLineKind::Assignment,
            label,
            head: Some(op.to_string()),
            tail: rest[op.len()..].to_string(),
            raw_code,
        };
    }

    if rest.starts_with('*') {
        let idx = skip_spaces_tabs(rest, 1);
        if idx < rest.len() {
            let assignment_tail = &rest[idx..];
            if let Some(op) = match_assignment_operator_prefix(assignment_tail) {
                return SurfaceParsedLine {
                    kind: SurfaceLineKind::Assignment,
                    label: Some("*".to_string()),
                    head: Some(op.to_string()),
                    tail: assignment_tail[op.len()..].to_string(),
                    raw_code,
                };
            }
        }
    }

    if let Some(after_dot) = rest.strip_prefix('.') {
        if let Some((directive_name, len)) = take_ident_at(after_dot, 0) {
            return SurfaceParsedLine {
                kind: SurfaceLineKind::Directive,
                label,
                head: Some(format!(".{directive_name}")),
                tail: after_dot[len..].to_string(),
                raw_code,
            };
        }
        return SurfaceParsedLine {
            kind: SurfaceLineKind::Unparsed,
            label,
            head: None,
            tail: rest.to_string(),
            raw_code,
        };
    }

    if let Some((mnemonic, len)) = take_ident_at(rest, 0) {
        return SurfaceParsedLine {
            kind: SurfaceLineKind::Instruction,
            label,
            head: Some(mnemonic),
            tail: rest[len..].to_string(),
            raw_code,
        };
    }

    SurfaceParsedLine {
        kind: SurfaceLineKind::Unparsed,
        label,
        head: None,
        tail: rest.to_string(),
        raw_code,
    }
}

fn trim_end_spaces_tabs(input: &str) -> &str {
    input.trim_end_matches([' ', '\t'])
}

fn skip_spaces_tabs(input: &str, mut idx: usize) -> usize {
    let bytes = input.as_bytes();
    while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
        idx += 1;
    }
    idx
}

fn has_assignment_prefix(input: &str, idx: usize) -> bool {
    if idx >= input.len() {
        return false;
    }
    match_assignment_operator_prefix(&input[idx..]).is_some()
}

fn match_assignment_operator_prefix(input: &str) -> Option<&'static str> {
    ASSIGNMENT_OPERATORS
        .iter()
        .copied()
        .find(|operator| input.starts_with(operator))
}

fn take_ident_at(input: &str, start: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    let first = *bytes.get(start)?;
    if !is_ident_start(first) {
        return None;
    }
    let mut idx = start + 1;
    while idx < bytes.len() && is_ident_char(bytes[idx]) {
        idx += 1;
    }
    Some((input[start..idx].to_string(), idx))
}

#[cfg(test)]
mod tests {
    use super::{parse_document, parse_line, SurfaceLineKind};
    use crate::formatter::{tokenize_source, LineEnding, SurfaceLine};

    #[test]
    fn parses_label_with_colon_and_instruction() {
        let line = SurfaceLine {
            indent: String::new(),
            code: "start: lda #1".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, SurfaceLineKind::Instruction);
        assert_eq!(parsed.label.as_deref(), Some("start"));
        assert_eq!(parsed.head.as_deref(), Some("lda"));
        assert_eq!(parsed.tail, " #1");
        assert!(!parsed.is_fallback());
    }

    #[test]
    fn parses_label_without_colon_and_instruction() {
        let line = SurfaceLine {
            indent: String::new(),
            code: "start lda #1".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, SurfaceLineKind::Instruction);
        assert_eq!(parsed.label.as_deref(), Some("start"));
        assert_eq!(parsed.head.as_deref(), Some("lda"));
        assert_eq!(parsed.tail, " #1");
    }

    #[test]
    fn parses_column_one_instruction_without_label() {
        let line = SurfaceLine {
            indent: String::new(),
            code: "lda #1".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, SurfaceLineKind::Instruction);
        assert_eq!(parsed.label, None);
        assert_eq!(parsed.head.as_deref(), Some("lda"));
        assert_eq!(parsed.tail, " #1");
    }

    #[test]
    fn parses_assignment_with_space_after_symbol() {
        let line = SurfaceLine {
            indent: String::new(),
            code: "value = $10".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, SurfaceLineKind::Assignment);
        assert_eq!(parsed.label.as_deref(), Some("value"));
        assert_eq!(parsed.head.as_deref(), Some("="));
    }

    #[test]
    fn classifies_directive_and_instruction_lines() {
        let directive = SurfaceLine {
            indent: "    ".to_string(),
            code: ".cpu 65816".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let instruction = SurfaceLine {
            indent: "    ".to_string(),
            code: "lda #$10".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let directive_parsed = parse_line(&directive);
        let instruction_parsed = parse_line(&instruction);
        assert_eq!(directive_parsed.kind, SurfaceLineKind::Directive);
        assert_eq!(directive_parsed.head.as_deref(), Some(".cpu"));
        assert_eq!(instruction_parsed.kind, SurfaceLineKind::Instruction);
        assert_eq!(instruction_parsed.head.as_deref(), Some("lda"));
    }

    #[test]
    fn marks_unparsed_lines_as_fallback() {
        let line = SurfaceLine {
            indent: String::new(),
            code: "(bad".to_string(),
            comment: None,
            line_ending: LineEnding::Lf,
        };
        let parsed = parse_line(&line);
        assert_eq!(parsed.kind, SurfaceLineKind::Unparsed);
        assert!(parsed.is_fallback());
    }

    #[test]
    fn parse_document_maps_every_surface_line() {
        let doc = tokenize_source("label\n    .cpu 65816\n");
        let parsed = parse_document(&doc);
        assert_eq!(parsed.lines.len(), 2);
        assert_eq!(parsed.lines[0].kind, SurfaceLineKind::LabelOnly);
        assert_eq!(parsed.lines[1].kind, SurfaceLineKind::Directive);
    }
}
