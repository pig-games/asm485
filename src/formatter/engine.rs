// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::FormatterConfig;

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
///
/// The implementation is intentionally conservative and semantic-preserving:
/// it currently performs passthrough formatting while the source-preserving
/// tokenizer/parser/planner are implemented.
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
        let _ = &self.config;
        source.to_string()
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
    fn format_source_is_passthrough_in_phase1() {
        let engine = FormatterEngine::new(FormatterConfig::default());
        let source = "start:  lda #$10   ; comment\n";
        assert_eq!(engine.format_source(source), source);
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
        let file = create_temp_file("path-to-string", "nop\n");
        let engine = FormatterEngine::new(FormatterConfig::default());
        let output = engine
            .format_path_to_string(&file)
            .expect("format path to string");
        assert_eq!(output, "nop\n");
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
