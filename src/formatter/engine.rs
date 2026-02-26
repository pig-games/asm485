// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{
    collect_fallback_diagnostics, parse_document, plan_document, render_plan, tokenize_source,
    FormatterConfig, FormatterDiagnostic,
};

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
    pub warnings: usize,
    pub files_with_warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatterOutput {
    pub rendered: String,
    pub diagnostics: Vec<FormatterDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatterFileReport {
    pub path: PathBuf,
    pub changed: bool,
    pub diagnostics: Vec<FormatterDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormatterRunReport {
    pub summary: FormatterRunSummary,
    pub files: Vec<FormatterFileReport>,
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

    pub fn format_source_with_diagnostics(&self, source: &str) -> FormatterOutput {
        let doc = tokenize_source(source);
        let parsed = parse_document(&doc);
        let diagnostics = collect_fallback_diagnostics(&parsed);
        let plan = plan_document(&doc, &parsed, &self.config);
        let rendered = render_plan(&plan, &doc, &self.config);
        FormatterOutput {
            rendered,
            diagnostics,
        }
    }

    pub fn format_source(&self, source: &str) -> String {
        self.format_source_with_diagnostics(source).rendered
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
        let report = self.run_paths_with_report(paths, mode)?;
        Ok(report.summary)
    }

    pub fn run_paths_with_report(
        &self,
        paths: &[PathBuf],
        mode: FormatMode,
    ) -> io::Result<FormatterRunReport> {
        let mut report = FormatterRunReport {
            summary: FormatterRunSummary::default(),
            files: Vec::with_capacity(paths.len()),
        };
        for path in paths {
            report.summary.files_seen += 1;
            let input = fs::read_to_string(path)?;
            let output = self.format_source_with_diagnostics(&input);
            let changed = output.rendered != input;
            if changed {
                report.summary.files_changed += 1;
                if mode == FormatMode::Write {
                    fs::write(path, &output.rendered)?;
                }
            }
            if !output.diagnostics.is_empty() {
                report.summary.warnings += output.diagnostics.len();
                report.summary.files_with_warnings += 1;
            }
            report.files.push(FormatterFileReport {
                path: path.clone(),
                changed,
                diagnostics: output.diagnostics,
            });
        }
        Ok(report)
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
            "start:  lda #$10, x  ; comment\n"
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
        let file = create_temp_file("run-paths-check", "        lda #1\n");
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
        assert_eq!(output, "start:  nop  ;x\n");
    }

    #[test]
    fn format_source_can_normalize_line_endings_when_configured() {
        let engine = FormatterEngine::new(FormatterConfig {
            preserve_line_endings: false,
            ..FormatterConfig::default()
        });
        let source = "start:  nop ;x\r\n";
        assert_eq!(engine.format_source(source), "start:  nop  ;x\n");
    }

    #[test]
    fn format_source_reports_fallback_diagnostic_and_keeps_line() {
        let engine = FormatterEngine::new(FormatterConfig::default());
        let source = "        lda #1\n.+bad\n";
        let output = engine.format_source_with_diagnostics(source);
        assert_eq!(output.rendered, source);
        assert_eq!(output.diagnostics.len(), 1);
        assert_eq!(output.diagnostics[0].line_number, 2);
    }

    #[test]
    fn run_paths_with_report_tracks_warnings_and_continues() {
        let file = create_temp_file("run-paths-warnings", "start: lda #1 ;c\n.+bad\n");
        let engine = FormatterEngine::new(FormatterConfig::default());
        let report = engine
            .run_paths_with_report(std::slice::from_ref(&file), FormatMode::Check)
            .expect("run formatter report");
        assert_eq!(report.summary.files_seen, 1);
        assert_eq!(report.summary.files_changed, 1);
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(report.summary.files_with_warnings, 1);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].diagnostics.len(), 1);
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
