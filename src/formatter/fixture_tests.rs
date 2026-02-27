// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::tokenizer::{Token, TokenKind, Tokenizer};

use super::{FormatterConfig, FormatterEngine, LabelColonStyle};

const REPRESENTATIVE_SNAPSHOT_STEMS: &[&str] = &[
    "intel8085_intel",
    "z80_zilog",
    "m6502_basic",
    "m65c02_basic",
    "m65816_basic",
    "m45gs02_basic",
    "directives_heavy",
    "macro_preproc_heavy",
];

const FULL_CORPUS_STEMS: &[&str] = &[
    "intel8085_intel",
    "z80_zilog",
    "m6502_basic",
    "m65c02_basic",
    "m65816_basic",
    "m45gs02_basic",
    "directives_heavy",
    "data_directives_alignment",
    "directive_alignment",
    "comment_alignment",
    "macro_preproc_heavy",
    "fallback_ambiguous",
];

#[test]
fn formatter_golden_snapshots_match_fixture_expectations() {
    let engine = FormatterEngine::new(FormatterConfig::default());
    for stem in REPRESENTATIVE_SNAPSHOT_STEMS {
        let input = read_fixture(stem, "input");
        let expected = read_fixture(stem, "expected");
        let output = engine.format_source_with_diagnostics(&input);
        assert_eq!(
            output.rendered, expected,
            "formatter fixture mismatch for {stem}"
        );
    }
}

#[test]
fn formatter_is_idempotent_across_fixture_corpus() {
    let engine = FormatterEngine::new(FormatterConfig::default());
    for stem in FULL_CORPUS_STEMS {
        let expected = read_fixture(stem, "expected");
        let once = engine.format_source(&expected);
        let twice = engine.format_source(&once);
        assert_eq!(once, twice, "formatter idempotence failed for {stem}");
    }
}

#[test]
fn formatter_preserves_semantic_token_stream_across_fixture_corpus() {
    let engine = FormatterEngine::new(FormatterConfig::default());
    for stem in FULL_CORPUS_STEMS {
        let input = read_fixture(stem, "input");
        let output = engine.format_source(&input);
        let input_projection = semantic_projection(&input);
        let output_projection = semantic_projection(&output);
        assert_eq!(
            input_projection, output_projection,
            "formatter semantic token projection drift for {stem}"
        );
    }
}

#[test]
fn fallback_fixture_emits_warning_without_changing_source() {
    let engine = FormatterEngine::new(FormatterConfig::default());
    let input = read_fixture("fallback_ambiguous", "input");
    let output = engine.format_source_with_diagnostics(&input);
    assert_eq!(output.rendered, input);
    assert_eq!(output.diagnostics.len(), 1);
    assert_eq!(output.diagnostics[0].line_number, 2);
}

#[test]
fn colon_removal_fixture_applies_when_style_is_enabled() {
    let engine = FormatterEngine::new(FormatterConfig {
        label_colon_style: LabelColonStyle::Without,
        ..FormatterConfig::default()
    });
    let input = read_fixture("label_colon_removal", "input");
    let expected = read_fixture("label_colon_removal", "expected");
    let output = engine.format_source_with_diagnostics(&input);
    assert_eq!(output.rendered, expected);
}

#[test]
fn long_label_split_fixture_applies_at_boundary_when_enabled() {
    let engine = FormatterEngine::new(FormatterConfig {
        label_alignment_column: 8,
        split_long_label_instructions: true,
        ..FormatterConfig::default()
    });
    let input = read_fixture("label_split_boundary", "input");
    let expected = read_fixture("label_split_boundary", "expected");
    let output = engine.format_source_with_diagnostics(&input);
    assert_eq!(output.rendered, expected);
}

#[test]
fn directive_case_fixture_applies_when_enabled() {
    let engine = FormatterEngine::new(FormatterConfig {
        directive_case: super::CaseStyle::Lower,
        ..FormatterConfig::default()
    });
    let input = read_fixture("directive_case", "input");
    let expected = read_fixture("directive_case", "expected");
    let output = engine.format_source_with_diagnostics(&input);
    assert_eq!(output.rendered, expected);
}

#[test]
fn register_case_fixture_applies_when_enabled() {
    let engine = FormatterEngine::new(FormatterConfig {
        register_case: super::CaseStyle::Upper,
        ..FormatterConfig::default()
    });
    let input = read_fixture("register_case", "input");
    let expected = read_fixture("register_case", "expected");
    let output = engine.format_source_with_diagnostics(&input);
    assert_eq!(output.rendered, expected);
}

#[test]
fn label_case_fixture_changes_definition_without_rewriting_usages() {
    let engine = FormatterEngine::new(FormatterConfig {
        label_case: super::CaseStyle::Lower,
        ..FormatterConfig::default()
    });
    let input = read_fixture("label_case_usage", "input");
    let expected = read_fixture("label_case_usage", "expected");
    let output = engine.format_source_with_diagnostics(&input);
    assert_eq!(output.rendered, expected);
}

fn read_fixture(stem: &str, kind: &str) -> String {
    let path = fixture_path(stem, kind);
    fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("missing fixture {}: {err}", path.display());
    })
}

fn fixture_path(stem: &str, kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("formatter")
        .join("fixtures")
        .join(format!("{stem}.{kind}.asm"))
}

fn semantic_projection(source: &str) -> Vec<Vec<String>> {
    source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let tokens = tokenize_line_semantics(line, (index + 1) as u32);
            if tokens.is_empty() {
                None
            } else {
                Some(tokens)
            }
        })
        .collect()
}

fn tokenize_line_semantics(line: &str, line_number: u32) -> Vec<String> {
    let mut tokenizer = Tokenizer::new(line, line_number);
    let mut out = Vec::new();
    loop {
        let token = tokenizer.next_token().unwrap_or_else(|err| {
            panic!("tokenization failure on line {line_number}: {err}");
        });
        if token.kind == TokenKind::End {
            break;
        }
        out.push(semantic_token_text(&token));
    }
    out
}

fn semantic_token_text(token: &Token) -> String {
    match &token.kind {
        TokenKind::Identifier(name) => format!("id:{}", name.to_ascii_uppercase()),
        TokenKind::Register(name) => format!("reg:{}", name.to_ascii_uppercase()),
        TokenKind::Number(number) => {
            format!("num{}:{}", number.base, number.text.to_ascii_uppercase())
        }
        TokenKind::String(lit) => format!("str:{}", lit.raw),
        _ => token.to_source_text(),
    }
}
