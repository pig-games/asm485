// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// CLI entrypoint for opForge.

use std::fs::OpenOptions;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use serde_json::json;

use opforge::assembler::cli::{
    validate_cli, Cli, CliConfig, DiagnosticsSinkConfig, DiagnosticsStyle,
    FormatterMode as CliFormatterMode, OutputFormat,
};
use opforge::core::assembler::error::{build_context_lines, Diagnostic, Severity};
use opforge::formatter::{FormatMode, FormatterConfig, FormatterEngine};

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

    fn emit_diagnostics(
        &mut self,
        source_lines: Option<&[String]>,
        diagnostics: &[Diagnostic],
        use_color: bool,
        format: OutputFormat,
        style: DiagnosticsStyle,
    ) {
        for diag in diagnostics {
            self.emit_line(&format_diagnostic_line(
                diag,
                source_lines,
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

#[derive(Debug, Clone)]
struct FileGuard {
    len: u64,
    content_hash: u64,
}

fn collect_machine_applicable_fixits(
    diagnostics: &[Diagnostic],
    fallback_file: Option<&Path>,
) -> Vec<PlannedFixit> {
    let mut planned = Vec::new();
    let mut seen = std::collections::HashSet::new();
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
            let col_start = fixit.col_start.unwrap_or(1).max(1);
            let col_end = fixit.col_end.unwrap_or(fixit.col_start.unwrap_or(1)).max(1);
            let dedup_key = (
                file_path.clone(),
                fixit.line,
                col_start,
                col_end,
                fixit.replacement.clone(),
                fixit.applicability.to_ascii_lowercase(),
            );
            if !seen.insert(dedup_key) {
                continue;
            }
            planned.push(PlannedFixit {
                file: file_path,
                line: fixit.line,
                col_start,
                col_end,
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

fn compute_file_guard(path: &Path) -> io::Result<FileGuard> {
    let content = std::fs::read(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut hasher);
    Ok(FileGuard {
        len: content.len() as u64,
        content_hash: hasher.finish(),
    })
}

fn capture_fixit_guards(
    fixits: &[PlannedFixit],
) -> io::Result<std::collections::HashMap<PathBuf, FileGuard>> {
    let mut guards = std::collections::HashMap::new();
    for fixit in fixits {
        guards
            .entry(fixit.file.clone())
            .or_insert(compute_file_guard(fixit.file.as_path())?);
    }
    Ok(guards)
}

fn verify_fixit_guards(
    guards: &std::collections::HashMap<PathBuf, FileGuard>,
    path: &Path,
) -> io::Result<()> {
    let Some(expected) = guards.get(path) else {
        return Ok(());
    };
    let current = compute_file_guard(path)?;
    if expected.len != current.len || expected.content_hash != current.content_hash {
        return Err(io::Error::other(format!(
            "stale source detected before applying fixits for {}",
            path.display()
        )));
    }
    Ok(())
}

fn apply_fixits_in_place(
    fixits: &[PlannedFixit],
    guards: Option<&std::collections::HashMap<PathBuf, FileGuard>>,
) -> io::Result<usize> {
    let mut by_file: std::collections::HashMap<&Path, Vec<&PlannedFixit>> =
        std::collections::HashMap::new();
    for fixit in fixits {
        by_file.entry(fixit.file.as_path()).or_default().push(fixit);
    }

    let mut applied = 0usize;
    for (file, edits) in by_file {
        if let Some(guards) = guards {
            verify_fixit_guards(guards, file)?;
        }
        let text = std::fs::read_to_string(file)?;
        let mut edits = edits;
        edits.sort_by_key(|edit| {
            (
                std::cmp::Reverse(edit.line),
                std::cmp::Reverse(edit.col_start),
            )
        });
        let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
        for edit in edits {
            let target_idx = edit.line.saturating_sub(1) as usize;
            if target_idx >= lines.len() {
                lines.push(edit.replacement.clone());
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
            applied += 1;
        }
        let mut text = lines.join("\n");
        if !text.ends_with('\n') {
            text.push('\n');
        }
        std::fs::write(file, text)?;
    }
    Ok(applied)
}

fn handle_fixits(
    sink: &mut DiagnosticsSink,
    cli_config: &opforge::assembler::cli::CliConfig,
    diagnostics: &[Diagnostic],
    fallback: Option<&Path>,
) {
    if !(cli_config.apply_fixits || cli_config.fixits_dry_run || cli_config.fixits_output.is_some())
    {
        return;
    }

    let planned = collect_machine_applicable_fixits(diagnostics, fallback);
    if fixits_have_overlaps(&planned) {
        sink.emit_line("fixits: overlap detected; aborting fixit application");
        return;
    }

    let guards = capture_fixit_guards(&planned);
    if cli_config.apply_fixits {
        match guards.and_then(|guards| apply_fixits_in_place(&planned, Some(&guards))) {
            Ok(applied) => sink.emit_line(&format!("fixits: applied {applied} edits")),
            Err(err) => sink.emit_line(&format!("fixits: apply failed: {err}")),
        }
    } else if cli_config.fixits_dry_run {
        sink.emit_line(&format!("fixits: dry-run planned {} edits", planned.len()));
    }

    if let Some(path) = cli_config.fixits_output.as_deref() {
        if let Err(err) = write_fixit_report(path, &planned, cli_config.apply_fixits) {
            sink.emit_line(&format!("fixits: failed to write report: {err}"));
        }
    }
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

fn run_formatter_mode(cli_config: &CliConfig) -> Result<i32, String> {
    let Some(formatter) = cli_config.formatter.as_ref() else {
        return Ok(0);
    };
    let formatter_config = if let Some(path) = formatter.config_path.as_deref() {
        FormatterConfig::load_from_path(path)
            .map_err(|err| format!("formatter config load failed: {err}"))?
    } else {
        FormatterConfig::default()
    };
    let engine = FormatterEngine::new(formatter_config);
    let mode = match formatter.mode {
        CliFormatterMode::Check => FormatMode::Check,
        CliFormatterMode::Write => FormatMode::Write,
        CliFormatterMode::Stdout => FormatMode::Stdout,
    };

    if mode == FormatMode::Stdout {
        let input = cli_config
            .input_paths
            .first()
            .ok_or_else(|| "--fmt-stdout requires exactly one input".to_string())?;
        let rendered = engine
            .format_path_to_string(input)
            .map_err(|err| format!("formatter read failed: {err}"))?;
        print!("{rendered}");
        return Ok(0);
    }

    let report = engine
        .run_paths_with_report(&cli_config.input_paths, mode)
        .map_err(|err| format!("formatter run failed: {err}"))?;
    let summary = report.summary;

    for file in &report.files {
        for diagnostic in &file.diagnostics {
            eprintln!(
                "fmt warning: {}:{}: {}",
                file.path.display(),
                diagnostic.line_number,
                diagnostic.message
            );
        }
    }

    if cli_config.output_format == OutputFormat::Json {
        println!(
            "{}",
            json!({
                "schema": "opforge-formatter-v1",
                "mode": match formatter.mode {
                    CliFormatterMode::Check => "check",
                    CliFormatterMode::Write => "write",
                    CliFormatterMode::Stdout => "stdout",
                },
                "files_seen": summary.files_seen,
                "files_changed": summary.files_changed,
                "warnings": summary.warnings,
                "files_with_warnings": summary.files_with_warnings,
            })
        );
    } else {
        match formatter.mode {
            CliFormatterMode::Check => {
                println!(
                    "fmt: checked {} file(s), {} would change, {} warning(s)",
                    summary.files_seen, summary.files_changed, summary.warnings
                );
            }
            CliFormatterMode::Write => {
                println!(
                    "fmt: processed {} file(s), {} changed, {} warning(s)",
                    summary.files_seen, summary.files_changed, summary.warnings
                );
            }
            CliFormatterMode::Stdout => {}
        }
    }

    if formatter.mode == CliFormatterMode::Check && summary.files_changed > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
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

    if cli_config.formatter.is_some() {
        match run_formatter_mode(&cli_config) {
            Ok(code) => {
                if code != 0 {
                    std::process::exit(code);
                }
                return;
            }
            Err(message) => {
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }

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
                sink.emit_diagnostics(
                    Some(report.source_lines()),
                    &diagnostics,
                    use_color,
                    cli_config.output_format,
                    cli_config.diagnostics_style,
                );
                handle_fixits(&mut sink, &cli_config, &diagnostics, fallback);
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
            sink.emit_diagnostics(
                Some(err.source_lines()),
                &diagnostics,
                use_color,
                cli_config.output_format,
                cli_config.diagnostics_style,
            );
            handle_fixits(&mut sink, &cli_config, &diagnostics, fallback);

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
    use clap::Parser;
    use opforge::assembler::cli::{validate_cli, Cli as AsmCli};
    use opforge::core::assembler::error::{AsmError, AsmErrorKind};
    use std::fs;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn format_diagnostic_line_json_matches_v2_schema_fixture() {
        let diag = Diagnostic::new(
            12,
            Severity::Error,
            AsmError::new(AsmErrorKind::Parser, "unexpected token", None),
        )
        .with_code("otp004")
        .with_file(Some("examples/sample.asm".to_string()))
        .with_column(Some(9))
        .with_col_end(Some(11))
        .with_related_span(opforge::core::assembler::error::LabeledSpan {
            file: Some("examples/sample.asm".to_string()),
            line: 3,
            col_start: Some(1),
            col_end: Some(4),
            label: Some("opened here".to_string()),
            is_primary: false,
        })
        .with_note("opened from a conditional block")
        .with_help("insert `.endif`")
        .with_fixit(opforge::core::assembler::error::Fixit {
            file: Some("examples/sample.asm".to_string()),
            line: 12,
            col_start: Some(9),
            col_end: Some(11),
            replacement: "0".to_string(),
            applicability: "machine-applicable".to_string(),
        });

        let actual_line = format_diagnostic_line(
            &diag,
            None,
            false,
            OutputFormat::Json,
            DiagnosticsStyle::Classic,
        );
        let actual: serde_json::Value = serde_json::from_str(&actual_line).expect("valid json");

        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("reference")
            .join("diagnostics_v2_schema.json");
        let fixture_text = fs::read_to_string(&fixture_path).unwrap_or_else(|err| {
            panic!(
                "missing diagnostics schema fixture {}: {err}",
                fixture_path.display()
            )
        });
        let expected: serde_json::Value =
            serde_json::from_str(&fixture_text).unwrap_or_else(|err| {
                panic!(
                    "invalid diagnostics schema fixture JSON {}: {err}",
                    fixture_path.display()
                )
            });

        assert_eq!(actual, expected, "diagnostics schema fixture mismatch");
    }

    #[test]
    fn format_diagnostic_line_json_is_backward_compatible_for_v1_consumers() {
        let diag = Diagnostic::new(
            5,
            Severity::Warning,
            AsmError::new(AsmErrorKind::Directive, "deprecated directive", None),
        )
        .with_code("asm202")
        .with_file(Some("legacy.asm".to_string()));
        let json_line = format_diagnostic_line(
            &diag,
            None,
            false,
            OutputFormat::Json,
            DiagnosticsStyle::Classic,
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&json_line).expect("v1-compatible parsing should succeed");
        assert_eq!(parsed["code"], "asm202");
        assert_eq!(parsed["severity"], "warning");
        assert_eq!(parsed["message"], "deprecated directive");
        assert_eq!(parsed["file"], "legacy.asm");
        assert_eq!(parsed["line"], 5);
        assert!(parsed["col_start"].is_null());
        assert!(parsed["col_end"].is_null());
    }

    #[test]
    fn fixit_overlap_detection_flags_same_line_collision() {
        let path = PathBuf::from("sample.asm");
        let fixits = vec![
            PlannedFixit {
                file: path.clone(),
                line: 10,
                col_start: 5,
                col_end: 8,
                replacement: "AAA".to_string(),
                applicability: "machine-applicable".to_string(),
            },
            PlannedFixit {
                file: path,
                line: 10,
                col_start: 8,
                col_end: 12,
                replacement: "BBB".to_string(),
                applicability: "machine-applicable".to_string(),
            },
        ];

        assert!(fixits_have_overlaps(&fixits));
    }

    #[test]
    fn collect_machine_applicable_fixits_deduplicates_identical_edits() {
        let fixit = opforge::core::assembler::error::Fixit {
            file: None,
            line: 7,
            col_start: Some(1),
            col_end: Some(1),
            replacement: ".endif".to_string(),
            applicability: "machine-applicable".to_string(),
        };
        let diagnostics = vec![
            Diagnostic::new(
                7,
                Severity::Error,
                AsmError::new(AsmErrorKind::Conditional, "Found .if without .endif", None),
            )
            .with_fixit(fixit.clone()),
            Diagnostic::new(
                7,
                Severity::Error,
                AsmError::new(AsmErrorKind::Conditional, "Found .if without .endif", None),
            )
            .with_fixit(fixit),
        ];

        let planned =
            collect_machine_applicable_fixits(&diagnostics, Some(Path::new("sample.asm")));
        assert_eq!(planned.len(), 1);
        assert!(!fixits_have_overlaps(&planned));
    }

    #[test]
    fn apply_fixits_in_place_updates_file_content() {
        let dir = create_temp_dir("fixit-apply");
        let file = dir.join("sample.asm");
        fs::write(&file, "lda #1\n").expect("write source");

        let fixits = vec![PlannedFixit {
            file: file.clone(),
            line: 1,
            col_start: 6,
            col_end: 7,
            replacement: "2".to_string(),
            applicability: "machine-applicable".to_string(),
        }];

        let guards = capture_fixit_guards(&fixits).expect("capture guards");
        let applied = apply_fixits_in_place(&fixits, Some(&guards)).expect("apply fixits");
        assert_eq!(applied, 1);

        let content = fs::read_to_string(&file).expect("read source");
        assert_eq!(content, "lda #2\n");
    }

    #[test]
    fn apply_fixits_in_place_rejects_stale_source() {
        let dir = create_temp_dir("fixit-stale");
        let file = dir.join("sample.asm");
        fs::write(&file, "lda #1\n").expect("write source");

        let fixits = vec![PlannedFixit {
            file: file.clone(),
            line: 1,
            col_start: 6,
            col_end: 7,
            replacement: "2".to_string(),
            applicability: "machine-applicable".to_string(),
        }];

        let guards = capture_fixit_guards(&fixits).expect("capture guards");
        fs::write(&file, "lda #9\n").expect("mutate source");

        let err =
            apply_fixits_in_place(&fixits, Some(&guards)).expect_err("stale source must fail");
        assert!(
            err.to_string().contains("stale source detected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_formatter_mode_check_returns_zero_for_clean_file() {
        let dir = create_temp_dir("fmt-check");
        let file = dir.join("input.asm");
        fs::write(&file, "lda #1\n").expect("write source");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-check",
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 0);
    }

    #[test]
    fn run_formatter_mode_check_returns_nonzero_for_unformatted_file() {
        let dir = create_temp_dir("fmt-check-dirty");
        let file = dir.join("input.asm");
        fs::write(&file, "start: lda #1,x ;c\n").expect("write source");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-check",
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 1);
    }

    #[test]
    fn run_formatter_mode_write_updates_file_content() {
        let dir = create_temp_dir("fmt-write");
        let file = dir.join("input.asm");
        fs::write(&file, "start: lda #1,x ;c\n").expect("write source");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-write",
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 0);

        let updated = fs::read_to_string(&file).expect("read updated source");
        assert_eq!(updated, "start:      lda #1, x  ;c\n");
    }

    #[test]
    fn run_formatter_mode_fmt_shorthand_updates_file_content() {
        let dir = create_temp_dir("fmt-shorthand");
        let file = dir.join("input.asm");
        fs::write(&file, "start: lda #1,x ;c\n").expect("write source");

        let cli = AsmCli::parse_from(["opForge", "--fmt", file.to_string_lossy().as_ref()]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 0);

        let updated = fs::read_to_string(&file).expect("read updated source");
        assert_eq!(updated, "start:      lda #1, x  ;c\n");
    }

    #[test]
    fn run_formatter_mode_write_applies_fmt_config_overrides() {
        let dir = create_temp_dir("fmt-config-write");
        let file = dir.join("input.asm");
        let config_file = dir.join("fmt.toml");
        fs::write(&file, "start: lda #1,x ;c\n").expect("write source");
        fs::write(
            &config_file,
            "[formatter]\nlabel_alignment_column = 8\nmax_consecutive_blank_lines = 0\n",
        )
        .expect("write config");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-write",
            "--fmt-config",
            config_file.to_string_lossy().as_ref(),
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 0);

        let updated = fs::read_to_string(&file).expect("read updated source");
        assert_eq!(updated, "start:  lda #1, x  ;c\n");
    }

    #[test]
    fn run_formatter_mode_write_applies_style_config_overrides() {
        let dir = create_temp_dir("fmt-style-config-write");
        let file = dir.join("input.asm");
        let config_file = dir.join("fmt.toml");
        fs::write(&file, "Start: LDA #$ABCD, 1AFH ;c\n    STA $20\n").expect("write source");
        fs::write(
            &config_file,
            "[formatter]
align_unlabeled_instructions = true
label_colon_style = \"without\"
label_case = \"lower\"
mnemonic_case = \"lower\"
hex_literal_case = \"lower\"
",
        )
        .expect("write config");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-write",
            "--fmt-config",
            config_file.to_string_lossy().as_ref(),
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 0);

        let updated = fs::read_to_string(&file).expect("read updated source");
        assert_eq!(
            updated,
            "start       lda #$abcd, 1afh  ;c\n            sta $20\n"
        );
    }

    #[test]
    fn run_formatter_mode_does_not_autoload_default_config_file() {
        let dir = create_temp_dir("fmt-config-no-autoload");
        let file = dir.join("input.asm");
        let default_config = dir.join(".opforgefmt.toml");
        fs::write(&file, "start: lda #1,x ;c\n").expect("write source");
        fs::write(&default_config, "[formatter]\nlabel_alignment_column = 8\n")
            .expect("write default config");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-write",
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let code = run_formatter_mode(&config).expect("run formatter");
        assert_eq!(code, 0);

        // No implicit config discovery: defaults still apply without --fmt-config.
        let updated = fs::read_to_string(&file).expect("read updated source");
        assert_eq!(updated, "start:      lda #1, x  ;c\n");
    }

    #[test]
    fn run_formatter_mode_reports_invalid_fmt_config() {
        let dir = create_temp_dir("fmt-config-invalid");
        let file = dir.join("input.asm");
        let config_file = dir.join("fmt.toml");
        fs::write(&file, "start: lda #1,x ;c\n").expect("write source");
        fs::write(&config_file, "unknown_key = true\n").expect("write config");

        let cli = AsmCli::parse_from([
            "opForge",
            "-i",
            file.to_string_lossy().as_ref(),
            "--fmt-check",
            "--fmt-config",
            config_file.to_string_lossy().as_ref(),
        ]);
        let config = validate_cli(&cli).expect("validate cli");
        let err = run_formatter_mode(&config).expect_err("invalid config should fail");
        assert!(err.contains("formatter config load failed"));
        assert!(err.contains("unknown key"));
    }

    fn create_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("main-test-{label}-{}-{nanos}", process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
