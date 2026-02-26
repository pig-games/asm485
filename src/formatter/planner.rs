// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::{
    CaseStyle, FormatterConfig, LabelColonStyle, SurfaceDocument, SurfaceLine, SurfaceLineKind,
    SurfaceParsedDocument, SurfaceParsedLine,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLine {
    pub line_number: usize,
    pub output: Option<SurfaceLine>,
    pub changed: bool,
    pub preserved_original: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormatPlan {
    pub lines: Vec<PlannedLine>,
}

impl FormatPlan {
    pub fn changed_line_count(&self) -> usize {
        self.lines.iter().filter(|line| line.changed).count()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            if let Some(surface) = &line.output {
                out.push_str(&surface.render());
            }
        }
        out
    }
}

pub fn plan_document(
    doc: &SurfaceDocument,
    parsed: &SurfaceParsedDocument,
    config: &FormatterConfig,
) -> FormatPlan {
    let mut plan = FormatPlan {
        lines: Vec::with_capacity(doc.lines.len()),
    };
    let mut blank_run = 0usize;

    for (idx, line) in doc.lines.iter().enumerate() {
        let line_number = idx + 1;
        let original = line.render();
        let is_blank = line.code.is_empty() && line.comment.is_none();
        if is_blank {
            blank_run += 1;
        } else {
            blank_run = 0;
        }

        if is_blank && blank_run > config.max_consecutive_blank_lines {
            plan.lines.push(PlannedLine {
                line_number,
                output: None,
                changed: true,
                preserved_original: false,
            });
            continue;
        }

        let parsed_line = parsed.lines.get(idx);
        let (output, preserved_original) = if let Some(parsed_line) = parsed_line {
            if parsed_line.is_fallback() || parsed_line.kind == SurfaceLineKind::Unparsed {
                (line.clone(), true)
            } else {
                (normalize_line(line, parsed_line, config), false)
            }
        } else {
            (line.clone(), true)
        };
        let changed = output.render() != original;

        plan.lines.push(PlannedLine {
            line_number,
            output: Some(output),
            changed,
            preserved_original,
        });
    }

    plan
}

fn normalize_line(
    line: &SurfaceLine,
    parsed: &SurfaceParsedLine,
    config: &FormatterConfig,
) -> SurfaceLine {
    match parsed.kind {
        SurfaceLineKind::Directive | SurfaceLineKind::Instruction => {}
        SurfaceLineKind::LabelOnly => {
            if config.label_colon_style == LabelColonStyle::Keep
                && config.label_case == CaseStyle::Keep
            {
                return line.clone();
            }
            return normalize_label_only_line(line, parsed, config);
        }
        _ => return line.clone(),
    }

    let Some(raw_head) = parsed.head.as_deref() else {
        return line.clone();
    };

    let mut indent = line.indent.clone();
    let mut code = String::new();
    if let Some(label) = parsed.label.as_deref() {
        indent.clear();
        let label_token = format_label_token(label, parsed, config);
        let spacing = if config.label_alignment_column > label_token.len() {
            config.label_alignment_column - label_token.len()
        } else {
            1
        };
        code.push_str(&label_token);
        code.push_str(&" ".repeat(spacing.max(1)));
    }
    let head = if parsed.kind == SurfaceLineKind::Instruction {
        config.mnemonic_case.apply(raw_head)
    } else {
        raw_head.to_string()
    };
    code.push_str(&head);

    let mut tail = normalize_operand_tail(&parsed.tail);
    tail = apply_hex_literal_case(&tail, config.hex_literal_case);
    if !tail.is_empty() {
        code.push(' ');
        code.push_str(&tail);
    }

    let comment = line
        .comment
        .as_deref()
        .map(|comment| comment.trim_start_matches([' ', '\t']).to_string());
    if let Some(comment) = comment {
        code = code.trim_end_matches([' ', '\t']).to_string();
        if !code.is_empty() {
            code.push_str("  ");
        }
        SurfaceLine {
            indent,
            code,
            comment: Some(comment),
            line_ending: line.line_ending,
        }
    } else {
        SurfaceLine {
            indent,
            code,
            comment: None,
            line_ending: line.line_ending,
        }
    }
}

fn normalize_label_only_line(
    line: &SurfaceLine,
    parsed: &SurfaceParsedLine,
    config: &FormatterConfig,
) -> SurfaceLine {
    let Some(label) = parsed.label.as_deref() else {
        return line.clone();
    };
    let mut code = apply_case_to_label(label, config.label_case);
    if label_should_have_colon(
        raw_label_has_colon(&parsed.raw_code, label),
        config.label_colon_style,
    ) {
        code.push(':');
    }
    SurfaceLine {
        indent: line.indent.clone(),
        code,
        comment: line.comment.clone(),
        line_ending: line.line_ending,
    }
}

fn format_label_token(label: &str, parsed: &SurfaceParsedLine, config: &FormatterConfig) -> String {
    let mut label_token = apply_case_to_label(label, config.label_case);
    if label_should_have_colon(
        raw_label_has_colon(&parsed.raw_code, label),
        config.label_colon_style,
    ) {
        label_token.push(':');
    }
    label_token
}

fn apply_case_to_label(label: &str, case: CaseStyle) -> String {
    if label == "*" {
        return label.to_string();
    }
    case.apply(label)
}

fn label_should_have_colon(has_colon: bool, style: LabelColonStyle) -> bool {
    match style {
        LabelColonStyle::Keep => has_colon,
        LabelColonStyle::With => true,
        LabelColonStyle::Without => false,
    }
}

fn raw_label_has_colon(raw_code: &str, label: &str) -> bool {
    raw_code
        .as_bytes()
        .get(label.len())
        .is_some_and(|byte| *byte == b':')
}

fn normalize_operand_tail(tail: &str) -> String {
    let trimmed = tail.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut chars = trimmed.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && (in_single || in_double) {
            out.push(ch);
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            out.push(ch);
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            out.push(ch);
            continue;
        }
        if ch == ',' && !in_single && !in_double {
            trim_trailing_space(&mut out);
            out.push(',');
            while matches!(chars.peek(), Some(' ' | '\t')) {
                chars.next();
            }
            if chars.peek().is_some() {
                out.push(' ');
            }
            continue;
        }
        out.push(ch);
    }

    out
}

fn apply_hex_literal_case(input: &str, case: CaseStyle) -> String {
    if case == CaseStyle::Keep {
        return input.to_string();
    }

    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut idx = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while idx < chars.len() {
        let ch = chars[idx];
        if escaped {
            out.push(ch);
            escaped = false;
            idx += 1;
            continue;
        }
        if ch == '\\' && (in_single || in_double) {
            out.push(ch);
            escaped = true;
            idx += 1;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            out.push(ch);
            idx += 1;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            out.push(ch);
            idx += 1;
            continue;
        }
        if in_single || in_double {
            out.push(ch);
            idx += 1;
            continue;
        }

        if ch == '$' {
            out.push(ch);
            idx += 1;
            let start = idx;
            while idx < chars.len() && is_hex_digit_or_underscore(chars[idx]) {
                idx += 1;
            }
            if idx > start {
                out.push_str(&apply_case_to_hex_digits(
                    &chars[start..idx].iter().collect::<String>(),
                    case,
                ));
            }
            continue;
        }

        if is_hex_digit_or_underscore(ch) && is_hex_token_boundary_before(&chars, idx) {
            let start = idx;
            idx += 1;
            while idx < chars.len() && is_hex_digit_or_underscore(chars[idx]) {
                idx += 1;
            }
            if idx < chars.len()
                && (chars[idx] == 'h' || chars[idx] == 'H')
                && is_hex_token_boundary_after(&chars, idx + 1)
            {
                out.push_str(&apply_case_to_hex_digits(
                    &chars[start..idx].iter().collect::<String>(),
                    case,
                ));
                out.push(match case {
                    CaseStyle::Upper => 'H',
                    CaseStyle::Lower => 'h',
                    CaseStyle::Keep => chars[idx],
                });
                idx += 1;
                continue;
            }
            out.push_str(&chars[start..idx].iter().collect::<String>());
            continue;
        }

        out.push(ch);
        idx += 1;
    }

    out
}

fn apply_case_to_hex_digits(input: &str, case: CaseStyle) -> String {
    input
        .chars()
        .map(|ch| match case {
            CaseStyle::Upper => {
                if ch.is_ascii_hexdigit() {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                }
            }
            CaseStyle::Lower => {
                if ch.is_ascii_hexdigit() {
                    ch.to_ascii_lowercase()
                } else {
                    ch
                }
            }
            CaseStyle::Keep => ch,
        })
        .collect()
}

fn is_hex_digit_or_underscore(ch: char) -> bool {
    ch.is_ascii_hexdigit() || ch == '_'
}

fn is_identish(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_hex_token_boundary_before(chars: &[char], idx: usize) -> bool {
    if idx == 0 {
        true
    } else {
        !is_identish(chars[idx - 1])
    }
}

fn is_hex_token_boundary_after(chars: &[char], idx: usize) -> bool {
    if idx >= chars.len() {
        true
    } else {
        !is_identish(chars[idx])
    }
}

fn trim_trailing_space(out: &mut String) {
    while matches!(out.chars().last(), Some(' ' | '\t')) {
        out.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::plan_document;
    use crate::formatter::{
        parse_document, tokenize_source, CaseStyle, FormatterConfig, LabelColonStyle,
    };

    #[test]
    fn planner_normalizes_intel_spacing_with_label_and_comment() {
        let source = "start:   mvi a,1 ;c\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), "start:      mvi a, 1  ;c\n");
        assert_eq!(plan.changed_line_count(), 1);
    }

    #[test]
    fn planner_normalizes_mos_spacing_and_preserves_mnemonic_case() {
        let source = "    Lda $20,x ; note\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), "    Lda $20, x  ; note\n");
        assert_eq!(plan.changed_line_count(), 1);
    }

    #[test]
    fn planner_preserves_unparsed_fallback_lines() {
        let source = "    .+bad ; keep\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), source);
        assert!(plan.lines[0].preserved_original);
    }

    #[test]
    fn planner_collapses_blank_runs_to_configured_max() {
        let source = "nop\n\n\t\n\nlda #1\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), "nop\n\nlda #1\n");
        assert_eq!(plan.changed_line_count(), 2);
    }

    #[test]
    fn planner_is_noop_when_line_already_matches_policy() {
        let source = "label:      lda #1  ; c\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), source);
        assert_eq!(plan.changed_line_count(), 0);
    }

    #[test]
    fn planner_applies_opt_in_lowercase_style_and_colonless_labels() {
        let source = "Start: LDA #$ABCD, 1AFH ; note\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(
            &doc,
            &parsed,
            &FormatterConfig {
                label_colon_style: LabelColonStyle::Without,
                label_case: CaseStyle::Lower,
                mnemonic_case: CaseStyle::Lower,
                hex_literal_case: CaseStyle::Lower,
                ..FormatterConfig::default()
            },
        );
        assert_eq!(plan.render(), "start       lda #$abcd, 1afh  ; note\n");
        assert_eq!(plan.changed_line_count(), 1);
    }

    #[test]
    fn planner_applies_opt_in_label_only_colonless_style() {
        let source = "Entry:\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(
            &doc,
            &parsed,
            &FormatterConfig {
                label_colon_style: LabelColonStyle::Without,
                label_case: CaseStyle::Lower,
                ..FormatterConfig::default()
            },
        );
        assert_eq!(plan.render(), "entry\n");
        assert_eq!(plan.changed_line_count(), 1);
    }
}
