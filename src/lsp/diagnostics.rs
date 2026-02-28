// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::lsp::validation_runner::ValidationDiagnostic;

pub fn dedup_diagnostics(input: Vec<ValidationDiagnostic>) -> Vec<ValidationDiagnostic> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for diag in input {
        let key = (
            diag.code.to_ascii_lowercase(),
            diag.file.clone().unwrap_or_default(),
            diag.line,
            diag.col_start.unwrap_or(0),
            diag.col_end.unwrap_or(0),
            diag.message.clone(),
        );
        if seen.insert(key) {
            out.push(diag);
        }
    }
    out
}

pub fn diagnostics_for_uri(uri: &str, input: &[ValidationDiagnostic]) -> Vec<Value> {
    let target_path = crate::lsp::session::uri_to_path(uri);
    let mut out = Vec::new();
    for diag in input {
        if let Some(file) = &diag.file {
            if let Some(target) = &target_path {
                let candidate = std::path::PathBuf::from(file);
                if &candidate != target {
                    continue;
                }
            }
        }
        let line = diag.line.saturating_sub(1);
        let start_char = diag.col_start.unwrap_or(1).saturating_sub(1);
        let end_char = diag
            .col_end
            .unwrap_or(diag.col_start.unwrap_or(1))
            .saturating_sub(1);
        out.push(json!({
            "range": {
                "start": {"line": line, "character": start_char},
                "end": {"line": line, "character": end_char.max(start_char + 1)},
            },
            "severity": severity_to_lsp(&diag.severity),
            "code": diag.code,
            "source": "opforge",
            "message": diag.message,
            "data": {
                "fixits": diag.fixits.iter().map(|fixit| {
                    json!({
                        "file": fixit.file,
                        "line": fixit.line,
                        "col_start": fixit.col_start,
                        "col_end": fixit.col_end,
                        "replacement": fixit.replacement,
                        "applicability": fixit.applicability,
                    })
                }).collect::<Vec<Value>>(),
            }
        }));
    }
    out
}

fn severity_to_lsp(value: &str) -> u32 {
    match value.to_ascii_lowercase().as_str() {
        "warning" => 2,
        "information" => 3,
        "hint" => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp::validation_runner::ValidationFixit;

    #[test]
    fn dedup_uses_stable_tuple_key() {
        let a = ValidationDiagnostic {
            code: "E001".to_string(),
            severity: "error".to_string(),
            message: "boom".to_string(),
            file: Some("/tmp/a.asm".to_string()),
            line: 2,
            col_start: Some(3),
            col_end: Some(4),
            fixits: vec![ValidationFixit::default()],
        };
        let b = a.clone();
        let out = dedup_diagnostics(vec![a, b]);
        assert_eq!(out.len(), 1);
    }
}
