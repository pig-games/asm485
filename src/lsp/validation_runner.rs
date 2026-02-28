// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use crate::lsp::config::LspConfig;

#[derive(Debug, Clone, Default)]
pub struct ValidationFixit {
    pub file: Option<String>,
    pub line: u32,
    pub col_start: Option<u32>,
    pub col_end: Option<u32>,
    pub replacement: String,
    pub applicability: String,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationDiagnostic {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub file: Option<String>,
    pub line: u32,
    pub col_start: Option<u32>,
    pub col_end: Option<u32>,
    pub fixits: Vec<ValidationFixit>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationRunResult {
    pub diagnostics: Vec<ValidationDiagnostic>,
}

pub fn run_cli_validation(
    config: &LspConfig,
    root_file: &Path,
    working_dir: &Path,
) -> ValidationRunResult {
    let mut cmd = Command::new(resolve_opforge_path(config));
    cmd.arg("--format")
        .arg("json")
        .arg("--diagnostics-style")
        .arg("rustc")
        .arg("--infile")
        .arg(root_file);
    if let Some(cpu) = &config.default_cpu {
        cmd.arg("--cpu").arg(cpu);
    }
    for include in &config.include_paths {
        cmd.arg("--include-path").arg(include);
    }
    for module in &config.module_paths {
        cmd.arg("--module-path").arg(module);
    }
    for define in &config.defines {
        cmd.arg("--define").arg(define);
    }
    cmd.current_dir(working_dir);

    let output = match cmd.output() {
        Ok(out) => out,
        Err(_) => return ValidationRunResult::default(),
    };

    let mut diagnostics = Vec::new();
    diagnostics.extend(parse_json_diag_lines(&String::from_utf8_lossy(
        &output.stdout,
    )));
    diagnostics.extend(parse_json_diag_lines(&String::from_utf8_lossy(
        &output.stderr,
    )));
    ValidationRunResult { diagnostics }
}

fn resolve_opforge_path(config: &LspConfig) -> String {
    if let Some(path) = &config.opforge_path {
        return path.clone();
    }
    "opforge".to_string()
}

fn parse_json_diag_lines(text: &str) -> Vec<ValidationDiagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let code = value
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if code.is_empty() && message.is_empty() {
            continue;
        }
        let severity = value
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .to_string();
        let file = value
            .get("file")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let line_num = value.get("line").and_then(Value::as_u64).unwrap_or(1) as u32;
        let col_start = value
            .get("col_start")
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        let col_end = value
            .get("col_end")
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        let fixits = value
            .get("fixits")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| ValidationFixit {
                        file: item
                            .get("file")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                        line: item.get("line").and_then(Value::as_u64).unwrap_or(1) as u32,
                        col_start: item
                            .get("col_start")
                            .and_then(Value::as_u64)
                            .map(|v| v as u32),
                        col_end: item
                            .get("col_end")
                            .and_then(Value::as_u64)
                            .map(|v| v as u32),
                        replacement: item
                            .get("replacement")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        applicability: item
                            .get("applicability")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(ValidationDiagnostic {
            code,
            severity,
            message,
            file,
            line: line_num,
            col_start,
            col_end,
            fixits,
        });
    }
    out
}
