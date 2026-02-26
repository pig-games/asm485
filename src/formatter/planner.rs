// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::{
    CaseStyle, FormatterConfig, LabelColonStyle, SurfaceDocument, SurfaceLine, SurfaceLineKind,
    SurfaceParsedDocument, SurfaceParsedLine,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLine {
    pub line_number: usize,
    pub output: Vec<SurfaceLine>,
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
            for surface in &line.output {
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
                output: Vec::new(),
                changed: true,
                preserved_original: false,
            });
            continue;
        }

        let parsed_line = parsed.lines.get(idx);
        let (output, preserved_original) = if let Some(parsed_line) = parsed_line {
            if parsed_line.is_fallback() || parsed_line.kind == SurfaceLineKind::Unparsed {
                (vec![line.clone()], true)
            } else {
                (normalize_line(line, parsed_line, config), false)
            }
        } else {
            (vec![line.clone()], true)
        };
        let changed = render_surface_lines(&output) != original;

        plan.lines.push(PlannedLine {
            line_number,
            output,
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
) -> Vec<SurfaceLine> {
    match parsed.kind {
        SurfaceLineKind::Directive | SurfaceLineKind::Instruction => {}
        SurfaceLineKind::LabelOnly => {
            if config.label_colon_style == LabelColonStyle::Keep
                && config.label_case == CaseStyle::Keep
            {
                return vec![line.clone()];
            }
            return vec![normalize_label_only_line(line, parsed, config)];
        }
        _ => return vec![line.clone()],
    }

    let Some(raw_head) = parsed.head.as_deref() else {
        return vec![line.clone()];
    };

    let mut indent = line.indent.clone();
    let mut label_token = None;
    let mut code = String::new();
    if let Some(label) = parsed.label.as_deref() {
        indent.clear();
        let current_label_token = format_label_token(label, parsed, config);
        let spacing = if config.label_alignment_column > current_label_token.len() {
            config.label_alignment_column - current_label_token.len()
        } else {
            1
        };
        code.push_str(&current_label_token);
        code.push_str(&" ".repeat(spacing.max(1)));
        label_token = Some(current_label_token);
    } else if parsed.kind == SurfaceLineKind::Instruction && config.align_unlabeled_instructions {
        indent = " ".repeat(config.label_alignment_column);
    }
    let head = if parsed.kind == SurfaceLineKind::Instruction {
        config.mnemonic_case.apply(raw_head)
    } else if parsed.kind == SurfaceLineKind::Directive {
        config.directive_case.apply(raw_head)
    } else {
        raw_head.to_string()
    };
    code.push_str(&head);

    let mut tail = normalize_operand_tail(&parsed.tail);
    if parsed.kind == SurfaceLineKind::Instruction {
        tail = apply_register_case(&tail, config.register_case);
    }
    tail = apply_hex_literal_case(&tail, config.hex_literal_case);
    if !tail.is_empty() {
        code.push(' ');
        code.push_str(&tail);
    }

    let comment = line
        .comment
        .as_deref()
        .map(|comment| comment.trim_start_matches([' ', '\t']).to_string());

    if parsed.kind == SurfaceLineKind::Instruction
        && config.split_long_label_instructions
        && label_token
            .as_ref()
            .is_some_and(|token| token.len() >= config.label_alignment_column)
    {
        let mut instruction_code = head;
        if !tail.is_empty() {
            instruction_code.push(' ');
            instruction_code.push_str(&tail);
        }
        if comment.is_some() {
            instruction_code = instruction_code.trim_end_matches([' ', '\t']).to_string();
            instruction_code.push_str("  ");
        }
        return vec![
            SurfaceLine {
                indent: String::new(),
                code: label_token.expect("label token"),
                comment: None,
                line_ending: split_inserted_line_ending(line.line_ending),
            },
            SurfaceLine {
                indent: " ".repeat(config.label_alignment_column),
                code: instruction_code,
                comment,
                line_ending: line.line_ending,
            },
        ];
    }

    if let Some(comment) = comment {
        code = code.trim_end_matches([' ', '\t']).to_string();
        if !code.is_empty() {
            code.push_str("  ");
        }
        return vec![SurfaceLine {
            indent,
            code,
            comment: Some(comment),
            line_ending: line.line_ending,
        }];
    }

    vec![SurfaceLine {
        indent,
        code,
        comment: None,
        line_ending: line.line_ending,
    }]
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

fn render_surface_lines(lines: &[SurfaceLine]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(&line.render());
    }
    out
}

fn split_inserted_line_ending(
    source: crate::formatter::LineEnding,
) -> crate::formatter::LineEnding {
    match source {
        crate::formatter::LineEnding::Crlf => crate::formatter::LineEnding::Crlf,
        _ => crate::formatter::LineEnding::Lf,
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

fn apply_register_case(input: &str, case: CaseStyle) -> String {
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

        if ch.is_ascii_alphabetic() || ch == '_' {
            let token_start = idx;
            idx += 1;
            while idx < chars.len() && is_identish(chars[idx]) {
                idx += 1;
            }
            let token: String = chars[token_start..idx].iter().collect();
            if should_case_register_token(&chars, token_start, &token) {
                out.push_str(&case.apply(&token));
            } else {
                out.push_str(&token);
            }
            continue;
        }

        out.push(ch);
        idx += 1;
    }

    out
}

fn should_case_register_token(chars: &[char], token_start: usize, token: &str) -> bool {
    if token_start > 0 && chars[token_start - 1] == '$' {
        return false;
    }
    is_known_register_token(token)
}

fn is_known_register_token(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        // Intel 8080/8085 register names and pairs.
        "A"
            | "B"
            | "C"
            | "D"
            | "E"
            | "H"
            | "L"
            | "M"
            | "BC"
            | "DE"
            | "HL"
            | "SP"
            | "PSW"
            // Z80 register names and pairs.
            | "AF"
            | "AF'"
            | "I"
            | "R"
            | "IX"
            | "IY"
            | "IXH"
            | "IXL"
            | "IYH"
            | "IYL"
            // MOS-family register names.
            | "X"
            | "Y"
            | "S"
    )
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
        assert_eq!(plan.render(), "start:  mvi a, 1  ;c\n");
        assert_eq!(plan.changed_line_count(), 1);
    }

    #[test]
    fn planner_normalizes_mos_spacing_and_preserves_mnemonic_case() {
        let source = "    Lda $20,x ; note\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), "        Lda $20, x  ; note\n");
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
        assert_eq!(plan.render(), "nop\n\n        lda #1\n");
        assert_eq!(plan.changed_line_count(), 3);
    }

    #[test]
    fn planner_is_noop_when_line_already_matches_policy() {
        let source = "label:  lda #1  ; c\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        assert_eq!(plan.render(), source);
        assert_eq!(plan.changed_line_count(), 0);
    }

    #[test]
    fn planner_applies_opt_in_lowercase_style_and_colonless_labels() {
        let source = "Start: LDA #$ABCD, 1AFH ; note\n    STA $20\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(
            &doc,
            &parsed,
            &FormatterConfig {
                align_unlabeled_instructions: true,
                label_colon_style: LabelColonStyle::Without,
                label_case: CaseStyle::Lower,
                mnemonic_case: CaseStyle::Lower,
                hex_literal_case: CaseStyle::Lower,
                ..FormatterConfig::default()
            },
        );
        assert_eq!(
            plan.render(),
            "start   lda #$abcd, 1afh  ; note\n        sta $20\n"
        );
        assert_eq!(plan.changed_line_count(), 2);
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

    #[test]
    fn planner_applies_opt_in_directive_and_register_case() {
        let source = ".CpU z80\nLoop ld a,(ix+1)\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(
            &doc,
            &parsed,
            &FormatterConfig {
                directive_case: CaseStyle::Lower,
                register_case: CaseStyle::Upper,
                ..FormatterConfig::default()
            },
        );
        assert_eq!(plan.render(), ".cpu z80\nLoop    ld A, (IX+1)\n");
        assert_eq!(plan.changed_line_count(), 2);
    }

    #[test]
    fn planner_splits_long_instruction_label_when_configured() {
        let source = "VeryLongLabel: lda #1 ; c\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(
            &doc,
            &parsed,
            &FormatterConfig {
                label_alignment_column: 8,
                split_long_label_instructions: true,
                ..FormatterConfig::default()
            },
        );
        assert_eq!(plan.render(), "VeryLongLabel:\n        lda #1  ; c\n");
        assert_eq!(plan.changed_line_count(), 1);
    }
}
