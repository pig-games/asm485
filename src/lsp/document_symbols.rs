// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use serde_json::{json, Value};

use crate::lsp::document_state::{DocumentState, SymbolKind};

pub fn document_symbols(doc: &DocumentState) -> Vec<Value> {
    let mut out = Vec::new();
    for symbol in &doc.symbols {
        let line = symbol.line.saturating_sub(1);
        let col = symbol.col_start.saturating_sub(1);
        let col_end = symbol.col_end.saturating_sub(1).max(col + 1);
        out.push(json!({
            "name": symbol.name,
            "kind": symbol_kind_to_lsp(&symbol.kind),
            "range": {
                "start": {"line": line, "character": col},
                "end": {"line": line, "character": col_end},
            },
            "selectionRange": {
                "start": {"line": line, "character": col},
                "end": {"line": line, "character": col_end},
            },
        }));
    }
    out
}

fn symbol_kind_to_lsp(kind: &SymbolKind) -> u32 {
    match kind {
        SymbolKind::Module => 2,
        SymbolKind::Namespace => 3,
        SymbolKind::Macro => 12,
        SymbolKind::Label | SymbolKind::Assignment => 13,
        SymbolKind::Section => 5,
        SymbolKind::Statement => 6,
        SymbolKind::UseImport => 9,
    }
}
