// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use serde_json::{json, Value};

use crate::lsp::config::LspConfig;
use crate::lsp::document_state::DocumentState;
use crate::lsp::member_context::MemberLookupContext;
use crate::lsp::workspace_index::{
    local_definition_candidates, resolve_module_target, WorkspaceIndex,
};

pub fn definition_locations(
    config: &LspConfig,
    workspace: &WorkspaceIndex,
    doc: Option<&DocumentState>,
    current_uri: &str,
    request_line: u32,
    word: &str,
    member_ctx: Option<&MemberLookupContext>,
) -> Vec<Value> {
    if word.is_empty() {
        return Vec::new();
    }

    if let Some(member_ctx) = member_ctx
        .cloned()
        .or_else(|| member_lookup_from_word(word))
    {
        let mut field_out = Vec::new();
        for field in workspace.member_fields_for_symbol(
            current_uri,
            doc,
            request_line,
            member_ctx.base_symbol.as_str(),
        ) {
            if !field
                .name
                .eq_ignore_ascii_case(member_ctx.field_name.as_str())
            {
                continue;
            }
            field_out.push(json!({
                "uri": field.uri,
                "range": {
                    "start": {"line": field.line.saturating_sub(1), "character": field.col_start.saturating_sub(1)},
                    "end": {"line": field.line.saturating_sub(1), "character": field.col_end.saturating_sub(1)},
                }
            }));
        }
        if !field_out.is_empty() {
            return dedup_locations(field_out);
        }
    }

    let mut out = Vec::new();

    if let Some(doc) = doc {
        for symbol in local_definition_candidates(doc, word, request_line) {
            out.push(json!({
                "uri": doc.uri,
                "range": {
                    "start": {"line": symbol.line.saturating_sub(1), "character": symbol.col_start.saturating_sub(1)},
                    "end": {"line": symbol.line.saturating_sub(1), "character": symbol.col_end.saturating_sub(1)},
                }
            }));
        }
    }

    for symbol in workspace.imported_symbols_named(current_uri, doc, word) {
        out.push(json!({
            "uri": symbol.uri,
            "range": {
                "start": {"line": symbol.line.saturating_sub(1), "character": symbol.col_start.saturating_sub(1)},
                "end": {"line": symbol.line.saturating_sub(1), "character": symbol.col_end.saturating_sub(1)},
            }
        }));
    }

    for symbol in workspace.symbols_named(word) {
        out.push(json!({
            "uri": symbol.uri,
            "range": {
                "start": {"line": symbol.line.saturating_sub(1), "character": symbol.col_start.saturating_sub(1)},
                "end": {"line": symbol.line.saturating_sub(1), "character": symbol.col_end.saturating_sub(1)},
            }
        }));
    }

    for path in resolve_module_target(word, config, current_uri) {
        out.push(json!({
            "uri": crate::lsp::session::path_to_file_uri(&path),
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 0},
            }
        }));
    }

    dedup_locations(out)
}

fn dedup_locations(items: Vec<Value>) -> Vec<Value> {
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

fn member_lookup_from_word(word: &str) -> Option<MemberLookupContext> {
    let (base_symbol, field_name) = word.rsplit_once('.')?;
    if base_symbol.is_empty() || field_name.is_empty() {
        return None;
    }
    Some(MemberLookupContext {
        base_symbol: base_symbol.to_string(),
        field_name: field_name.to_string(),
    })
}
