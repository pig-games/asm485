// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use serde_json::{json, Value};

use crate::core::cpu::CpuType;
use crate::lsp::capabilities::CapabilitySnapshot;
use crate::lsp::document_state::DocumentState;
use crate::lsp::member_context::MemberCompletionContext;
use crate::lsp::workspace_index::WorkspaceIndex;

pub struct CompletionRequestContext<'a> {
    pub current_uri: &'a str,
    pub cursor_line: u32,
    pub prefix: &'a str,
    pub member_ctx: Option<&'a MemberCompletionContext>,
}

pub fn completion_items(
    snapshot: &CapabilitySnapshot,
    workspace: &WorkspaceIndex,
    doc: Option<&DocumentState>,
    cpu: CpuType,
    ctx: CompletionRequestContext<'_>,
) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();
    let prefix_lower = ctx.prefix.to_ascii_lowercase();

    for directive in &snapshot.directive_keywords {
        if !prefix_lower.is_empty() && !directive.starts_with(&prefix_lower) {
            continue;
        }
        items.push(json!({
            "label": directive,
            "kind": 14,
            "detail": "directive",
        }));
    }

    for alias in &snapshot.cpu_name_aliases {
        if !prefix_lower.is_empty() && !alias.starts_with(&prefix_lower) {
            continue;
        }
        items.push(json!({
            "label": alias,
            "kind": 13,
            "detail": "cpu alias",
        }));
    }

    if let Some(view) = snapshot.view_for_cpu(cpu) {
        for mnemonic in &view.mnemonics {
            if !prefix_lower.is_empty() && !mnemonic.starts_with(&prefix_lower) {
                continue;
            }
            items.push(json!({
                "label": mnemonic,
                "kind": 14,
                "detail": format!("mnemonic ({})", view.mnemonic_owner.get(mnemonic).cloned().unwrap_or_else(|| "pipeline".to_string())),
            }));
        }
        for register in &view.registers {
            if !prefix_lower.is_empty() && !register.to_ascii_lowercase().starts_with(&prefix_lower)
            {
                continue;
            }
            items.push(json!({
                "label": register,
                "kind": 6,
                "detail": "register",
            }));
        }
    }

    if let Some(member_ctx) = ctx.member_ctx {
        let field_prefix = member_ctx.field_prefix.to_ascii_lowercase();
        for field in workspace.member_fields_for_symbol(
            ctx.current_uri,
            doc,
            ctx.cursor_line,
            member_ctx.base_symbol.as_str(),
        ) {
            if !field_prefix.is_empty()
                && !field.name.to_ascii_lowercase().starts_with(&field_prefix)
            {
                continue;
            }
            items.push(json!({
                "label": field.name,
                "kind": 5,
                "detail": format!("field of {}", field.owner_name),
                "documentation": field.declaration,
            }));
        }
    }

    if let Some(doc) = doc {
        for symbol in &doc.symbols {
            if symbol.line > ctx.cursor_line {
                continue;
            }
            let lower = symbol.name.to_ascii_lowercase();
            if !prefix_lower.is_empty() && !lower.starts_with(&prefix_lower) {
                continue;
            }
            items.push(json!({
                "label": symbol.name,
                "kind": 6,
                "detail": format!(
                    "{} · {} · {}",
                    symbol.kind.as_str(),
                    symbol.visibility.as_str(),
                    format_scope_hint(&symbol.scope_path),
                ),
                "documentation": symbol.declaration,
            }));
        }
    }

    if !ctx.prefix.is_empty() {
        for imported in workspace.imported_symbols_starting_with(ctx.current_uri, doc, ctx.prefix) {
            let symbol = imported.origin;
            items.push(json!({
                "label": imported.label,
                "kind": 6,
                "detail": format!(
                    "imported {} · {} · {}",
                    symbol.kind.as_str(),
                    symbol.visibility.as_str(),
                    format_scope_hint(&symbol.scope_path),
                ),
                "documentation": symbol.declaration,
            }));
        }

        for symbol in workspace.symbols_starting_with(ctx.prefix) {
            items.push(json!({
                "label": symbol.name,
                "kind": 6,
                "detail": format!(
                    "{} · {} · {}",
                    symbol.kind.as_str(),
                    symbol.visibility.as_str(),
                    format_scope_hint(&symbol.scope_path),
                ),
                "documentation": symbol.declaration,
            }));
        }
    }

    dedup_items(items)
}

fn format_scope_hint(scope_path: &str) -> String {
    if scope_path.is_empty() {
        "global".to_string()
    } else {
        scope_path.to_string()
    }
}

fn dedup_items(items: Vec<Value>) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let key = item
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if seen.insert(key) {
            out.push(item);
        }
    }
    out
}
