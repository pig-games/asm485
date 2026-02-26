// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{parse_document, plan_document, render_plan, tokenize_source, FormatterConfig};

/// Formatter execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatMode {
    Check,
    Write,
    Stdout,
}

/// Aggregate formatter run summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FormatterRunSummary {
    pub files_seen: usize,
    pub files_changed: usize,
}

/// Phase-1 formatter engine.
#[derive(Debug, Clone)]
pub struct FormatterEngine {
    config: FormatterConfig,
}

impl FormatterEngine {
    pub fn new(config: FormatterConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &FormatterConfig {
        &self.config
    }

    pub fn format_source(&self, source: &str) -> String {
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let plan = plan_document(&doc, &parsed, &self.config);
        render_plan(&plan, &doc, &self.config)
    }

    pub fn format_path_to_string(&self, path: &Path) -> io::Result<String> {
        let input = fs::read_to_string(path)?;
        Ok(self.format_source(&input))
    }

    pub fn run_paths(
        &self,
        paths: &[PathBuf],
        mode: FormatMode,
    ) -> io::Result<FormatterRunSummary> {
        let mut summary = FormatterRunSummary::default();
        for path in paths {
            summary.files_seen += 1;
            let input = fs::read_to_string(path)?;
            let output = self.format_source(&input);
            let changed = output != input;
            if changed {
                summary.files_changed += 1;
                if mode == FormatMode::Write {
                    fs::write(path, output)?;
                }
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::{FormatMode, FormatterEngine};
    use crate::formatter::FormatterConfig;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn format_source_applies_safe_profile_normalization() {
        let engine = FormatterEngine::new(FormatterConfig::default());
        let source = "start:  lda #$10,x ; comment\n";
        assert_eq!(
            engine.format_source(source),
            "start:      lda #$10, x  ; comment\n"
        );
    }

    #[test]
    fn format_source_is_idempotent() {
        let engine = FormatterEngine::new(FormatterConfig::default());
        let source = "start:  lda #$10,x ; comment\n\n\n";
        let once = engine.format_source(source);
        let twice = engine.format_source(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn run_paths_counts_seen_and_changed_for_check_mode() {
        let file = create_temp_file("run-paths-check", "lda #1\n");
        let engine = FormatterEngine::new(FormatterConfig::default());
        let summary = engine
            .run_paths(std::slice::from_ref(&file), FormatMode::Check)
            .expect("run formatter");
        assert_eq!(summary.files_seen, 1);
        assert_eq!(summary.files_changed, 0);
    }

    #[test]
    fn format_path_to_string_returns_file_contents() {
        let file = create_temp_file("path-to-string", "start:  nop ;x\n");
        let engine = FormatterEngine::new(FormatterConfig::default());
        let output = engine
            .format_path_to_string(&file)
            .expect("format path to string");
        assert_eq!(output, "start:      nop  ;x\n");
    }

    #[test]
    fn format_source_can_normalize_line_endings_when_configured() {
        let engine = FormatterEngine::new(FormatterConfig {
            preserve_line_endings: false,
            ..FormatterConfig::default()
        });
        let source = "start:  nop ;x\r\n";
        assert_eq!(engine.format_source(source), "start:      nop  ;x\n");
    }

    fn create_temp_file(label: &str, content: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("test-formatter-{label}-{}-{nanos}", process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("sample.asm");
        fs::write(&path, content).expect("write temp file");
        assert!(Path::new(&path).exists());
        path
    }
}
