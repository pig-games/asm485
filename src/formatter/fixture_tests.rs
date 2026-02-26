// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::fs;
use std::path::{Path, PathBuf};

use super::{FormatterConfig, FormatterEngine, LabelColonStyle};

const FIXTURE_STEMS: &[&str] = &[
    "intel8085_intel",
    "z80_zilog",
    "m6502_basic",
    "m65c02_basic",
    "m65816_basic",
    "m45gs02_basic",
    "directives_heavy",
    "macro_preproc_heavy",
    "fallback_ambiguous",
];

#[test]
fn formatter_golden_snapshots_match_fixture_expectations() {
    let engine = FormatterEngine::new(FormatterConfig::default());
    for stem in FIXTURE_STEMS {
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
    for stem in FIXTURE_STEMS {
        let expected = read_fixture(stem, "expected");
        let once = engine.format_source(&expected);
        let twice = engine.format_source(&once);
        assert_eq!(once, twice, "formatter idempotence failed for {stem}");
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
