// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::{FormatPlan, FormatterConfig, LineEnding, SurfaceDocument, SurfaceLine};

pub fn render_plan(
    plan: &FormatPlan,
    source_doc: &SurfaceDocument,
    config: &FormatterConfig,
) -> String {
    let source_had_final_newline = source_doc
        .lines
        .last()
        .is_some_and(|line| line.line_ending != LineEnding::None);
    let preferred_line_ending = preferred_line_ending(source_doc, config);

    let mut out = String::new();
    for planned in &plan.lines {
        let Some(line) = &planned.output else {
            continue;
        };
        let rendered = if config.preserve_line_endings {
            line.render()
        } else {
            normalize_rendered_line_ending(line)
        };
        out.push_str(&rendered);
    }

    apply_final_newline_policy(
        &mut out,
        config.preserve_final_newline,
        source_had_final_newline,
        preferred_line_ending,
    );
    out
}

fn preferred_line_ending(doc: &SurfaceDocument, config: &FormatterConfig) -> &'static str {
    if !config.preserve_line_endings {
        return "\n";
    }
    for line in &doc.lines {
        match line.line_ending {
            LineEnding::Lf => return "\n",
            LineEnding::Crlf => return "\r\n",
            LineEnding::None => {}
        }
    }
    "\n"
}

fn normalize_rendered_line_ending(line: &SurfaceLine) -> String {
    let mut cloned = line.clone();
    if cloned.line_ending != LineEnding::None {
        cloned.line_ending = LineEnding::Lf;
    }
    cloned.render()
}

fn apply_final_newline_policy(
    out: &mut String,
    preserve_final_newline: bool,
    source_had_final_newline: bool,
    preferred_line_ending: &str,
) {
    if preserve_final_newline {
        if source_had_final_newline && !out.is_empty() && !out.ends_with('\n') {
            out.push_str(preferred_line_ending);
        }
        if !source_had_final_newline {
            trim_final_newline(out);
        }
        return;
    }
    trim_final_newline(out);
}

fn trim_final_newline(out: &mut String) {
    if out.ends_with("\r\n") {
        out.truncate(out.len() - 2);
    } else if out.ends_with('\n') {
        out.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::render_plan;
    use crate::formatter::{parse_document, plan_document, tokenize_source, FormatterConfig};

    #[test]
    fn renderer_preserves_line_endings_by_default() {
        let source = "label: mvi a,1 ;c\r\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        let rendered = render_plan(&plan, &doc, &FormatterConfig::default());
        assert_eq!(rendered, "label:      mvi a, 1  ;c\r\n");
    }

    #[test]
    fn renderer_can_normalize_line_endings_to_lf() {
        let source = "label: mvi a,1 ;c\r\n";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());
        let config = FormatterConfig {
            preserve_line_endings: false,
            ..FormatterConfig::default()
        };
        let rendered = render_plan(&plan, &doc, &config);
        assert_eq!(rendered, "label:      mvi a, 1  ;c\n");
    }

    #[test]
    fn renderer_respects_final_newline_policy() {
        let source = "lda #1";
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &FormatterConfig::default());

        let keep_config = FormatterConfig {
            preserve_final_newline: true,
            ..FormatterConfig::default()
        };
        assert_eq!(render_plan(&plan, &doc, &keep_config), "lda #1");

        let drop_config = FormatterConfig {
            preserve_final_newline: false,
            ..FormatterConfig::default()
        };
        assert_eq!(render_plan(&plan, &doc, &drop_config), "lda #1");
    }
}
