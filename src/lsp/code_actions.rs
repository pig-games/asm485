// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use serde_json::{json, Value};

pub fn quick_fix_actions(params: &Value) -> Vec<Value> {
    let uri = params
        .get("textDocument")
        .and_then(|value| value.get("uri"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if uri.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let diagnostics = params
        .get("context")
        .and_then(|value| value.get("diagnostics"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for diagnostic in diagnostics {
        let fixits = diagnostic
            .get("data")
            .and_then(|value| value.get("fixits"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for fixit in fixits {
            let line = fixit.get("line").and_then(Value::as_u64).unwrap_or(1) as u32;
            let col_start = fixit.get("col_start").and_then(Value::as_u64).unwrap_or(1) as u32;
            let col_end = fixit
                .get("col_end")
                .and_then(Value::as_u64)
                .unwrap_or(col_start as u64) as u32;
            let replacement = fixit
                .get("replacement")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let applicability = fixit
                .get("applicability")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if replacement.is_empty() && col_end == col_start {
                continue;
            }
            let preferred = applicability == "machine-applicable";
            out.push(json!({
                "title": format!("Apply fix: {}", replacement),
                "kind": "quickfix",
                "isPreferred": preferred,
                "diagnostics": [diagnostic.clone()],
                "edit": {
                    "changes": {
                        uri.clone(): [{
                            "range": {
                                "start": {"line": line.saturating_sub(1), "character": col_start.saturating_sub(1)},
                                "end": {"line": line.saturating_sub(1), "character": col_end.saturating_sub(1)},
                            },
                            "newText": replacement,
                        }]
                    }
                }
            }));
        }
    }

    dedup(out)
}

fn dedup(items: Vec<Value>) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let key = item.to_string();
        if seen.insert(key) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_applicable_fixits_are_preferred() {
        let params = json!({
            "textDocument": { "uri": "file:///tmp/sample.asm" },
            "context": {
                "diagnostics": [{
                    "data": {
                        "fixits": [{
                            "line": 1,
                            "col_start": 1,
                            "col_end": 2,
                            "replacement": ".endif",
                            "applicability": "machine-applicable"
                        }]
                    }
                }]
            }
        });
        let actions = quick_fix_actions(&params);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0]
                .get("isPreferred")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            true
        );
    }
}
