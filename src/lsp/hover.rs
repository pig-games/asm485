// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use serde_json::{json, Value};

use crate::core::cpu::CpuType;
use crate::lsp::capabilities::CapabilitySnapshot;
use crate::lsp::document_state::DocumentState;
use crate::lsp::member_context::MemberLookupContext;
use crate::lsp::workspace_index::WorkspaceIndex;

pub struct HoverRequestContext<'a> {
    pub current_uri: &'a str,
    pub request_line: u32,
    pub word: &'a str,
    pub member_ctx: Option<&'a MemberLookupContext>,
}

pub fn hover_response(
    snapshot: &CapabilitySnapshot,
    workspace: &WorkspaceIndex,
    doc: Option<&DocumentState>,
    cpu: CpuType,
    ctx: HoverRequestContext<'_>,
) -> Option<Value> {
    if ctx.word.is_empty() {
        return None;
    }

    if let Some(member_ctx) = ctx
        .member_ctx
        .cloned()
        .or_else(|| member_lookup_from_word(ctx.word))
    {
        let fields = workspace.member_fields_for_symbol(
            ctx.current_uri,
            doc,
            ctx.request_line,
            member_ctx.base_symbol.as_str(),
        );
        if let Some(field) = fields.iter().find(|field| {
            field
                .name
                .eq_ignore_ascii_case(member_ctx.field_name.as_str())
        }) {
            return Some(json!({
                "contents": {
                    "kind": "markdown",
                    "value": format!(
                        "`{}`\n\nKind: `field`\nOwner: `{}`\nLine: `{}`\n\nDecl: `{}`",
                        field.name, field.owner_name, field.line, field.declaration
                    ),
                }
            }));
        }
    }

    if let Some(doc) = doc {
        if let Some(symbol) = doc
            .symbols
            .iter()
            .find(|symbol| symbol.name.eq_ignore_ascii_case(ctx.word))
        {
            return Some(json!({
                "contents": {
                    "kind": "markdown",
                    "value": render_symbol_hover(&HoverSymbol {
                        name: &symbol.name,
                        kind: symbol.kind.as_str(),
                        visibility: symbol.visibility.as_str(),
                        scope_path: &symbol.scope_path,
                        owner_module: symbol.owner_module.as_deref(),
                        line: symbol.line,
                        declaration: symbol.declaration.as_str(),
                        value_excerpt: symbol.value_excerpt.as_deref(),
                    }),
                }
            }));
        }
    }

    let imported = workspace.imported_symbols_named(ctx.current_uri, doc, ctx.word);
    if let Some(symbol) = imported.first() {
        return Some(json!({
            "contents": {
                "kind": "markdown",
                "value": render_symbol_hover(&HoverSymbol {
                    name: &symbol.name,
                    kind: symbol.kind.as_str(),
                    visibility: symbol.visibility.as_str(),
                    scope_path: &symbol.scope_path,
                    owner_module: symbol.owner_module.as_deref(),
                    line: symbol.line,
                    declaration: symbol.declaration.as_str(),
                    value_excerpt: symbol.value_excerpt.as_deref(),
                }),
            }
        }));
    }

    if let Some(view) = snapshot.view_for_cpu(cpu) {
        let needle = ctx.word.to_ascii_lowercase();
        if view.mnemonics.iter().any(|mnemonic| mnemonic == &needle) {
            let owner = view
                .mnemonic_owner
                .get(&needle)
                .cloned()
                .unwrap_or_else(|| "pipeline".to_string());
            return Some(json!({
                "contents": {
                    "kind": "markdown",
                    "value": format!("`{}`\n\nOwner: `{}`\n\nFamily: `{}`\nDialect: `{}`", ctx.word, owner, view.family_id, view.dialect_id),
                }
            }));
        }
        if view
            .runtime_directives
            .iter()
            .any(|directive| directive.eq_ignore_ascii_case(ctx.word))
        {
            return Some(json!({
                "contents": {
                    "kind": "markdown",
                    "value": format!("`{}`\n\nCPU runtime directive for `{}`.", ctx.word, cpu.as_str()),
                }
            }));
        }
    }

    let matches = workspace.symbols_named(ctx.word);
    if let Some(symbol) = matches.first() {
        return Some(json!({
            "contents": {
                "kind": "markdown",
                "value": render_symbol_hover(&HoverSymbol {
                    name: &symbol.name,
                    kind: symbol.kind.as_str(),
                    visibility: symbol.visibility.as_str(),
                    scope_path: &symbol.scope_path,
                    owner_module: symbol.owner_module.as_deref(),
                    line: symbol.line,
                    declaration: symbol.declaration.as_str(),
                    value_excerpt: symbol.value_excerpt.as_deref(),
                }),
            }
        }));
    }

    None
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

struct HoverSymbol<'a> {
    name: &'a str,
    kind: &'a str,
    visibility: &'a str,
    scope_path: &'a str,
    owner_module: Option<&'a str>,
    line: u32,
    declaration: &'a str,
    value_excerpt: Option<&'a str>,
}

fn render_symbol_hover(symbol: &HoverSymbol<'_>) -> String {
    let scope = if symbol.scope_path.is_empty() {
        "global"
    } else {
        symbol.scope_path
    };
    let mut lines = vec![
        format!("`{}`", symbol.name),
        String::new(),
        format!("Kind: `{}`", symbol.kind),
        format!("Visibility: `{}`", symbol.visibility),
        format!("Scope: `{scope}`"),
        format!("Line: `{}`", symbol.line),
    ];
    if let Some(module) = symbol.owner_module {
        lines.push(format!("Module: `{module}`"));
    }
    if let Some(value) = symbol.value_excerpt {
        lines.push(format!("Value: `{value}`"));
    }
    if !symbol.declaration.is_empty() {
        lines.push(String::new());
        lines.push(format!("Decl: `{}`", symbol.declaration));
    }
    lines.join("\n")
}
