// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// CLI entrypoint for opForge.

use std::fs::OpenOptions;
use std::io::{self, Write};

use clap::Parser;

use opforge::assembler::cli::{validate_cli, Cli, DiagnosticsSinkConfig};
use opforge::core::assembler::error::{AsmRunError, AsmRunReport, Diagnostic, Severity};

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
    ) {
        for diag in diagnostics {
            self.emit_line(&diag.format_with_context(Some(report.source_lines()), use_color));
        }
    }

    fn emit_error_diagnostics(
        &mut self,
        err: &AsmRunError,
        diagnostics: &[Diagnostic],
        use_color: bool,
    ) {
        for diag in diagnostics {
            self.emit_line(&diag.format_with_context(Some(err.source_lines()), use_color));
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if cli.print_cpusupport {
        println!("{}", opforge::assembler::cpusupport_report());
        return;
    }
    if cli.print_capabilities {
        println!("{}", opforge::assembler::capabilities_report());
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
                sink.emit_report_diagnostics(report, &diagnostics, use_color);
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
            sink.emit_error_diagnostics(&err, &diagnostics, use_color);
            if !matches!(cli_config.diagnostics_sink, DiagnosticsSinkConfig::Disabled) {
                sink.emit_line(&err.to_string());
            }
            std::process::exit(1);
        }
    }
}
