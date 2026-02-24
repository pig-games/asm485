// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// CLI entrypoint for opForge.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use serde_json::json;

use opforge::assembler::cli::{
    validate_cli, Cli, DiagnosticsSinkConfig, DiagnosticsStyle, OutputFormat,
};
use opforge::core::assembler::error::{
    build_context_lines, AsmRunError, AsmRunReport, Diagnostic, Severity,
};

struct DiagnosticsSink {
    writer: Option<Box<dyn Write>>,
}

impl DiagnosticsSink {
    fn from_config(config: &DiagnosticsSinkConfig) -> io::Result<Self> {
        match config {
            DiagnosticsSinkConfig::Disabled => Ok(Self { writer: None }),
            DiagnosticsSinkConfig::Stderr => Ok(Self {
                writer: Some(Box::new(io::stderr())),
            }),
            DiagnosticsSinkConfig::File { path, append } => {
                let mut opts = OpenOptions::new();
                opts.create(true).write(true);
                if *append {
                    opts.append(true);
                } else {
                    opts.truncate(true);
                }
                let file = opts.open(path)?;
                Ok(Self {
                    writer: Some(Box::new(file)),
                })
            }
        }
    }

    fn emit_line(&mut self, line: &str) {
        if let Some(writer) = &mut self.writer {
            let _ = writeln!(writer, "{line}");
        }
    }

    fn emit_report_diagnostics(
        &mut self,
        report: &AsmRunReport,
        diagnostics: &[Diagnostic],
        use_color: bool,
        format: OutputFormat,
        style: DiagnosticsStyle,
    ) {
        for diag in diagnostics {
            self.emit_line(&format_diagnostic_line(
                diag,
                Some(report.source_lines()),
                use_color,
                format,
                style,
            ));
        }
    }

    fn emit_error_diagnostics(
        &mut self,
        err: &AsmRunError,
        diagnostics: &[Diagnostic],
        use_color: bool,
        format: OutputFormat,
        style: DiagnosticsStyle,
    ) {
        for diag in diagnostics {
            self.emit_line(&format_diagnostic_line(
                diag,
                Some(err.source_lines()),
                use_color,
                format,
                style,
            ));
        }
    }
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn format_diagnostic_line(
    diag: &Diagnostic,
    source_lines: Option<&[String]>,
    use_color: bool,
    format: OutputFormat,
    style: DiagnosticsStyle,
) -> String {
    if format == OutputFormat::Json {
        json!({
            "code": diag.code(),
            "severity": severity_to_str(diag.severity()),
            "message": diag.message(),
            "file": diag.file(),
            "line": diag.line(),
            "col_start": diag.column(),
            "col_end": diag.col_end(),
            "related_spans": diagnostic_related_spans_json(diag),
            "notes": diag.notes(),
            "help": diag.help(),
            "fixits": diagnostic_fixits_json(diag),
        })
        .to_string()
    } else if style == DiagnosticsStyle::Classic {
        format_diagnostic_line_classic(diag, source_lines, use_color)
    } else {
        diag.format_with_context(source_lines, use_color)
    }
}

fn diagnostic_related_spans_json(diag: &Diagnostic) -> Vec<serde_json::Value> {
    diag.related_spans()
        .iter()
        .map(|span| {
            json!({
                "file": span.file.clone(),
                "line": span.line,
                "col_start": span.col_start,
                "col_end": span.col_end,
                "label": span.label.clone(),
                "is_primary": span.is_primary,
            })
        })
        .collect()
}

fn diagnostic_fixits_json(diag: &Diagnostic) -> Vec<serde_json::Value> {
    diag.fixits()
        .iter()
        .map(|fixit| {
            json!({
                "file": fixit.file.clone(),
                "line": fixit.line,
                "col_start": fixit.col_start,
                "col_end": fixit.col_end,
                "replacement": fixit.replacement.clone(),
                "applicability": fixit.applicability.clone(),
            })
        })
        .collect()
}

fn format_diagnostic_line_classic(
    diag: &Diagnostic,
    source_lines: Option<&[String]>,
    use_color: bool,
) -> String {
    let sev = match diag.severity() {
        Severity::Warning => "WARNING",
        Severity::Error => "ERROR",
    };
    let header = match diag.file() {
        Some(file) => format!("{file}:{}: {sev} [{}]", diag.line(), diag.code()),
        None => format!("{}: {sev} [{}]", diag.line(), diag.code()),
    };
    let mut out = String::new();
    out.push_str(&header);
    out.push('\n');
    for line in build_context_lines(diag.line(), diag.column(), source_lines, None, use_color) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!("{sev}: {}", diag.message()));
    out
}

#[derive(Debug, Clone)]
struct PlannedFixit {
    file: PathBuf,
    line: u32,
    col_start: usize,
    col_end: usize,
    replacement: String,
    applicability: String,
}

fn collect_machine_applicable_fixits(
    diagnostics: &[Diagnostic],
    fallback_file: Option<&Path>,
) -> Vec<PlannedFixit> {
    let mut planned = Vec::new();
    for diag in diagnostics {
        for fixit in diag.fixits() {
            if !fixit
                .applicability
                .eq_ignore_ascii_case("machine-applicable")
            {
                continue;
            }
            let file_path = match fixit.file.as_deref() {
                Some(path) => PathBuf::from(path),
                None => match fallback_file {
                    Some(path) => path.to_path_buf(),
                    None => continue,
                },
            };
            planned.push(PlannedFixit {
                file: file_path,
                line: fixit.line,
                col_start: fixit.col_start.unwrap_or(1).max(1),
                col_end: fixit.col_end.unwrap_or(fixit.col_start.unwrap_or(1)).max(1),
                replacement: fixit.replacement.clone(),
                applicability: fixit.applicability.clone(),
            });
        }
    }
    planned
}

fn with_fallback_file(
    diagnostics: Vec<Diagnostic>,
    fallback_file: Option<&Path>,
) -> Vec<Diagnostic> {
    let fallback = fallback_file.map(|path| path.to_string_lossy().to_string());
    diagnostics
        .into_iter()
        .map(|diag| {
            if diag.file().is_none() {
                diag.with_file(fallback.clone())
            } else {
                diag
            }
        })
        .collect()
}

fn fixits_have_overlaps(fixits: &[PlannedFixit]) -> bool {
    let mut by_file: std::collections::HashMap<&Path, Vec<&PlannedFixit>> =
        std::collections::HashMap::new();
    for fixit in fixits {
        by_file.entry(fixit.file.as_path()).or_default().push(fixit);
    }
    for edits in by_file.values_mut() {
        edits.sort_by_key(|edit| (edit.line, edit.col_start, edit.col_end));
        for pair in edits.windows(2) {
            let left = pair[0];
            let right = pair[1];
            if left.line == right.line && right.col_start <= left.col_end {
                return true;
            }
        }
    }
    false
}

fn apply_fixits_in_place(fixits: &[PlannedFixit]) -> io::Result<usize> {
    let mut by_file: std::collections::HashMap<&Path, Vec<&PlannedFixit>> =
        std::collections::HashMap::new();
    for fixit in fixits {
        by_file.entry(fixit.file.as_path()).or_default().push(fixit);
    }

    let mut applied = 0usize;
    for (file, edits) in by_file {
        let mut text = std::fs::read_to_string(file)?;
        let mut edits = edits;
        edits.sort_by_key(|edit| {
            (
                std::cmp::Reverse(edit.line),
                std::cmp::Reverse(edit.col_start),
            )
        });
        for edit in edits {
            let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
            let target_idx = edit.line.saturating_sub(1) as usize;
            if target_idx >= lines.len() {
                lines.push(edit.replacement.clone());
                text = lines.join("\n");
                applied += 1;
                continue;
            }
            let line = &lines[target_idx];
            let start = edit.col_start.saturating_sub(1).min(line.len());
            let end = edit.col_end.saturating_sub(1).min(line.len());
            let (a, b) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            let mut next = String::new();
            next.push_str(&line[..a]);
            next.push_str(&edit.replacement);
            next.push_str(&line[b..]);
            lines[target_idx] = next;
            text = lines.join("\n");
            applied += 1;
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        std::fs::write(file, text)?;
    }
    Ok(applied)
}

fn write_fixit_report(path: &Path, fixits: &[PlannedFixit], applied: bool) -> io::Result<()> {
    let payload = json!({
        "schema": "opforge-fixits-v2",
        "applied": applied,
        "fixits": fixits.iter().map(|fixit| {
            json!({
                "file": fixit.file.to_string_lossy().to_string(),
                "line": fixit.line,
                "col_start": fixit.col_start,
                "col_end": fixit.col_end,
                "replacement": fixit.replacement,
                "applicability": fixit.applicability,
            })
        }).collect::<Vec<_>>(),
    });
    let mut serialized = serde_json::to_string_pretty(&payload).map_err(io::Error::other)?;
    serialized.push('\n');
    std::fs::write(path, serialized)
}

fn main() {
    let cli = Cli::parse();
    if cli.print_cpusupport {
        if cli.format == OutputFormat::Json {
            println!("{}", opforge::assembler::cpusupport_report_json());
        } else {
            println!("{}", opforge::assembler::cpusupport_report());
        }
        return;
    }
    if cli.print_capabilities {
        if cli.format == OutputFormat::Json {
            println!("{}", opforge::assembler::capabilities_report_json());
        } else {
            println!("{}", opforge::assembler::capabilities_report());
        }
        return;
    }
    let cli_config = match validate_cli(&cli) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let mut sink = match DiagnosticsSink::from_config(&cli_config.diagnostics_sink) {
        Ok(sink) => sink,
        Err(err) => {
            eprintln!("Failed to open diagnostics sink: {err}");
            std::process::exit(1);
        }
    };

    let use_color = std::env::var("NO_COLOR").is_err();
    match opforge::assembler::run_with_cli(&cli) {
        Ok(reports) => {
            if cli_config.quiet {
                return;
            }
            for report in &reports {
                let diagnostics: Vec<Diagnostic> = report
                    .diagnostics()
                    .iter()
                    .filter(|diag| {
                        cli_config.warning_policy.emit_warnings
                            || diag.severity() != Severity::Warning
                    })
                    .cloned()
                    .collect();
                let fallback = cli_config.input_paths.first().map(PathBuf::as_path);
                let diagnostics = with_fallback_file(diagnostics, fallback);
                sink.emit_report_diagnostics(
                    report,
                    &diagnostics,
                    use_color,
                    cli_config.output_format,
                    cli_config.diagnostics_style,
                );

                if cli_config.apply_fixits
                    || cli_config.fixits_dry_run
                    || cli_config.fixits_output.is_some()
                {
                    let planned = collect_machine_applicable_fixits(&diagnostics, fallback);
                    if fixits_have_overlaps(&planned) {
                        sink.emit_line("fixits: overlap detected; aborting fixit application");
                    } else {
                        if cli_config.apply_fixits {
                            match apply_fixits_in_place(&planned) {
                                Ok(applied) => {
                                    sink.emit_line(&format!("fixits: applied {applied} edits"))
                                }
                                Err(err) => sink.emit_line(&format!("fixits: apply failed: {err}")),
                            }
                        } else if cli_config.fixits_dry_run {
                            sink.emit_line(&format!(
                                "fixits: dry-run planned {} edits",
                                planned.len()
                            ));
                        }
                        if let Some(path) = cli_config.fixits_output.as_deref() {
                            if let Err(err) =
                                write_fixit_report(path, &planned, cli_config.apply_fixits)
                            {
                                sink.emit_line(&format!("fixits: failed to write report: {err}"));
                            }
                        }
                    }
                }
            }
        }
        Err(err) => {
            let diagnostics: Vec<Diagnostic> = err
                .diagnostics()
                .iter()
                .filter(|diag| {
                    cli_config.warning_policy.emit_warnings || diag.severity() != Severity::Warning
                })
                .cloned()
                .collect();
            let fallback = cli_config.input_paths.first().map(PathBuf::as_path);
            let diagnostics = with_fallback_file(diagnostics, fallback);
            sink.emit_error_diagnostics(
                &err,
                &diagnostics,
                use_color,
                cli_config.output_format,
                cli_config.diagnostics_style,
            );

            if cli_config.apply_fixits
                || cli_config.fixits_dry_run
                || cli_config.fixits_output.is_some()
            {
                let planned = collect_machine_applicable_fixits(&diagnostics, fallback);
                if fixits_have_overlaps(&planned) {
                    sink.emit_line("fixits: overlap detected; aborting fixit application");
                } else {
                    if cli_config.apply_fixits {
                        match apply_fixits_in_place(&planned) {
                            Ok(applied) => {
                                sink.emit_line(&format!("fixits: applied {applied} edits"))
                            }
                            Err(err) => sink.emit_line(&format!("fixits: apply failed: {err}")),
                        }
                    } else if cli_config.fixits_dry_run {
                        sink.emit_line(&format!("fixits: dry-run planned {} edits", planned.len()));
                    }
                    if let Some(path) = cli_config.fixits_output.as_deref() {
                        if let Err(err) =
                            write_fixit_report(path, &planned, cli_config.apply_fixits)
                        {
                            sink.emit_line(&format!("fixits: failed to write report: {err}"));
                        }
                    }
                }
            }

            if cli_config.output_format != OutputFormat::Json
                && !matches!(cli_config.diagnostics_sink, DiagnosticsSinkConfig::Disabled)
            {
                sink.emit_line(&err.to_string());
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opforge::core::assembler::error::{AsmError, AsmErrorKind};

    #[test]
    fn format_diagnostic_line_json_has_expected_keys_with_nulls() {
        let diag = Diagnostic::new(
            7,
            Severity::Error,
            AsmError::new(AsmErrorKind::Assembler, "boom", None),
        )
        .with_code("ope999");
        let line = format_diagnostic_line(
            &diag,
            None,
            false,
            OutputFormat::Json,
            DiagnosticsStyle::Classic,
        );
        let value: serde_json::Value = serde_json::from_str(&line).expect("valid json");
        assert_eq!(value["code"], "ope999");
        assert_eq!(value["severity"], "error");
        assert_eq!(value["message"], "boom");
        assert_eq!(value["line"], 7);
        assert!(value["file"].is_null());
        assert!(value["col_start"].is_null());
        assert!(value["col_end"].is_null());
        assert!(value["related_spans"].is_array());
        assert!(value["notes"].is_array());
        assert!(value["help"].is_array());
        assert!(value["fixits"].is_array());
    }
}
