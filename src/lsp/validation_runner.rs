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
    resolve_opforge_path_with_current_exe(config, std::env::current_exe().ok().as_deref())
}

fn resolve_opforge_path_with_current_exe(config: &LspConfig, current_exe: Option<&Path>) -> String {
    if let Some(path) = &config.opforge_path {
        return path.clone();
    }

    for root in &config.roots {
        let workspace_candidate = Path::new(root)
            .join("target")
            .join("debug")
            .join(opforge_binary_name());
        if workspace_candidate.is_file() {
            return workspace_candidate.to_string_lossy().to_string();
        }
    }

    if let Some(current_exe) = current_exe {
        if let Some(current_exe_dir) = current_exe.parent() {
            let candidate = current_exe_dir.join(opforge_binary_name());
            if candidate.is_file() {
                return candidate.to_string_lossy().to_string();
            }

            if current_exe_dir.file_name().and_then(|name| name.to_str()) == Some("deps") {
                if let Some(parent_dir) = current_exe_dir.parent() {
                    let parent_candidate = parent_dir.join(opforge_binary_name());
                    if parent_candidate.is_file() {
                        return parent_candidate.to_string_lossy().to_string();
                    }
                }
            }
        }
    }

    "opforge".to_string()
}

fn opforge_binary_name() -> &'static str {
    if cfg!(windows) {
        "opforge.exe"
    } else {
        "opforge"
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_path_prefers_configured_binary() {
        let config = LspConfig {
            opforge_path: Some("/tmp/custom-opforge".to_string()),
            ..LspConfig::default()
        };

        let resolved = resolve_opforge_path_with_current_exe(&config, None);
        assert_eq!(resolved, "/tmp/custom-opforge");
    }

    #[test]
    fn resolve_path_falls_back_to_path_when_no_local_binary_found() {
        let config = LspConfig::default();
        let resolved = resolve_opforge_path_with_current_exe(
            &config,
            Some(Path::new("/definitely/not/a/real/path/opforge-lsp")),
        );
        assert_eq!(resolved, "opforge");
    }

    #[test]
    fn resolve_path_uses_binary_adjacent_to_lsp() {
        let temp_dir =
            std::env::temp_dir().join(format!("opforge-lsp-test-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).expect("create temp test dir");
        let opforge_path = temp_dir.join(opforge_binary_name());
        std::fs::write(&opforge_path, b"#!/bin/sh\n").expect("write fake opforge");

        let lsp_path = temp_dir.join("opforge-lsp");
        let config = LspConfig::default();
        let resolved = resolve_opforge_path_with_current_exe(&config, Some(&lsp_path));

        assert_eq!(resolved, opforge_path.to_string_lossy());

        let _ = std::fs::remove_file(opforge_path);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn resolve_path_prefers_workspace_target_debug_binary() {
        let temp_root =
            std::env::temp_dir().join(format!("opforge-lsp-workspace-test-{}", std::process::id()));
        let target_debug = temp_root.join("target").join("debug");
        std::fs::create_dir_all(&target_debug).expect("create target/debug");
        let workspace_opforge = target_debug.join(opforge_binary_name());
        std::fs::write(&workspace_opforge, b"#!/bin/sh\n").expect("write fake opforge");

        let config = LspConfig {
            roots: vec![temp_root.to_string_lossy().to_string()],
            ..LspConfig::default()
        };
        let resolved = resolve_opforge_path_with_current_exe(&config, None);
        assert_eq!(resolved, workspace_opforge.to_string_lossy());

        let _ = std::fs::remove_file(workspace_opforge);
        let _ = std::fs::remove_dir_all(temp_root);
    }
}
