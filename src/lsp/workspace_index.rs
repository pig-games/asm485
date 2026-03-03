// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::registry::ModuleRegistry;
use crate::lsp::config::LspConfig;
use crate::lsp::document_state::{
    DocumentState, RepetitionStructDecl, StructFieldDecl, StructTypeDecl, SymbolDecl, SymbolKind,
    SymbolVisibility, TypedSymbolDecl, UseImportDecl,
};
use crate::lsp::session::{path_to_file_uri, uri_to_path};

#[derive(Debug, Clone)]
pub struct IndexedSymbol {
    pub name: String,
    pub kind: SymbolKind,
    pub uri: String,
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub scope_path: String,
    pub owner_module: Option<String>,
    pub visibility: SymbolVisibility,
    pub detail: String,
    pub declaration: String,
    pub value_excerpt: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct WorkspaceIndex {
    per_uri: HashMap<String, Vec<IndexedSymbol>>,
    by_name: HashMap<String, Vec<IndexedSymbol>>,
    imports_by_uri: HashMap<String, Vec<UseImportDecl>>,
    struct_types_by_uri: HashMap<String, Vec<StructTypeDecl>>,
    typed_symbols_by_uri: HashMap<String, Vec<TypedSymbolDecl>>,
    repetition_structs_by_uri: HashMap<String, Vec<RepetitionStructDecl>>,
    module_to_uris: HashMap<String, Vec<String>>,
}

impl WorkspaceIndex {
    pub fn rebuild(
        &mut self,
        registry: &ModuleRegistry,
        config: &LspConfig,
        documents: &HashMap<String, DocumentState>,
    ) {
        self.per_uri.clear();
        self.by_name.clear();
        self.imports_by_uri.clear();
        self.struct_types_by_uri.clear();
        self.typed_symbols_by_uri.clear();
        self.repetition_structs_by_uri.clear();
        self.module_to_uris.clear();

        for doc in documents.values() {
            self.index_document(doc);
        }

        let root_docs = load_documents_from_roots(registry, config);
        for doc in root_docs {
            if !documents.contains_key(&doc.uri) {
                self.index_document(&doc);
            }
        }
    }

    pub fn index_document(&mut self, doc: &DocumentState) {
        let mut entries = Vec::new();
        for symbol in &doc.symbols {
            entries.push(IndexedSymbol {
                name: symbol.name.clone(),
                kind: symbol.kind.clone(),
                uri: doc.uri.clone(),
                line: symbol.line,
                col_start: symbol.col_start,
                col_end: symbol.col_end,
                scope_path: symbol.scope_path.clone(),
                owner_module: symbol.owner_module.clone(),
                visibility: symbol.visibility.clone(),
                detail: symbol.detail.clone(),
                declaration: symbol.declaration.clone(),
                value_excerpt: symbol.value_excerpt.clone(),
            });
        }
        self.per_uri.insert(doc.uri.clone(), entries);
        self.imports_by_uri
            .insert(doc.uri.clone(), doc.imports.clone());
        self.struct_types_by_uri
            .insert(doc.uri.clone(), doc.struct_types.clone());
        self.typed_symbols_by_uri
            .insert(doc.uri.clone(), doc.typed_symbols.clone());
        self.repetition_structs_by_uri
            .insert(doc.uri.clone(), doc.repetition_structs.clone());
        self.index_module_candidates(doc);
        self.rebuild_name_index();
    }

    pub fn remove_document(&mut self, uri: &str) {
        self.per_uri.remove(uri);
        self.imports_by_uri.remove(uri);
        self.struct_types_by_uri.remove(uri);
        self.typed_symbols_by_uri.remove(uri);
        self.repetition_structs_by_uri.remove(uri);
        self.rebuild_module_index();
        self.rebuild_name_index();
    }

    pub fn symbols_named(&self, name: &str) -> Vec<IndexedSymbol> {
        self.by_name
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    pub fn all_symbols_for_uri(&self, uri: &str) -> Vec<IndexedSymbol> {
        self.per_uri.get(uri).cloned().unwrap_or_default()
    }

    pub fn imports_for_uri(&self, uri: &str) -> Vec<UseImportDecl> {
        self.imports_by_uri.get(uri).cloned().unwrap_or_default()
    }

    pub fn document_uris(&self) -> Vec<String> {
        let mut uris: Vec<String> = self.per_uri.keys().cloned().collect();
        uris.sort();
        uris
    }

    pub fn symbols_starting_with(&self, prefix: &str) -> Vec<IndexedSymbol> {
        if prefix.is_empty() {
            return Vec::new();
        }
        let prefix_lower = prefix.to_ascii_lowercase();
        let mut out = Vec::new();
        for symbols in self.by_name.values() {
            for symbol in symbols {
                if symbol.name.to_ascii_lowercase().starts_with(&prefix_lower) {
                    out.push(symbol.clone());
                }
            }
        }
        out.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then(a.uri.cmp(&b.uri))
                .then(a.line.cmp(&b.line))
                .then(a.col_start.cmp(&b.col_start))
        });
        out
    }

    pub fn search_symbols(&self, query: &str, limit: usize) -> Vec<IndexedSymbol> {
        if query.is_empty() {
            return Vec::new();
        }
        let query_lower = query.to_ascii_lowercase();
        let mut ranked: Vec<(u8, IndexedSymbol)> = Vec::new();
        for symbols in self.per_uri.values() {
            for symbol in symbols {
                let name_lower = symbol.name.to_ascii_lowercase();
                let rank = if name_lower == query_lower {
                    Some(0u8)
                } else if name_lower.starts_with(&query_lower) {
                    Some(1u8)
                } else if name_lower.contains(&query_lower) {
                    Some(2u8)
                } else {
                    None
                };
                if let Some(rank) = rank {
                    ranked.push((rank, symbol.clone()));
                }
            }
        }
        ranked.sort_by(|(left_rank, left), (right_rank, right)| {
            left_rank
                .cmp(right_rank)
                .then(
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase()),
                )
                .then(left.uri.cmp(&right.uri))
                .then(left.line.cmp(&right.line))
                .then(left.col_start.cmp(&right.col_start))
        });
        let symbols = ranked.into_iter().map(|(_, symbol)| symbol).collect();
        let mut out = dedup_indexed_symbols(symbols);
        out.truncate(limit);
        out
    }

    pub fn imported_symbols_named(
        &self,
        current_uri: &str,
        current_doc: Option<&DocumentState>,
        word: &str,
    ) -> Vec<IndexedSymbol> {
        if word.is_empty() {
            return Vec::new();
        }
        let imports = self.imports_for_context(current_uri, current_doc);
        if imports.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let (qualifier, leaf) = split_qualified_symbol(word);
        for import in imports {
            if let Some(qualified) = qualifier {
                if !import_matches_qualifier(import, qualified) {
                    continue;
                }
                for symbol in self.module_export_symbols(import.module_id.as_str()) {
                    if symbol.name.eq_ignore_ascii_case(leaf) {
                        out.push(symbol);
                    }
                }
                continue;
            }
            if import.items.is_empty() && !import.wildcard {
                continue;
            }
            if import.wildcard {
                for symbol in self.module_export_symbols(import.module_id.as_str()) {
                    if symbol.name.eq_ignore_ascii_case(leaf) {
                        out.push(symbol);
                    }
                }
                continue;
            }
            for item in &import.items {
                if !item.local_name.eq_ignore_ascii_case(leaf) {
                    continue;
                }
                for symbol in self.module_export_symbols(import.module_id.as_str()) {
                    if symbol.name.eq_ignore_ascii_case(&item.source_name) {
                        out.push(symbol);
                    }
                }
            }
        }
        dedup_indexed_symbols(out)
    }

    pub fn imported_symbols_starting_with(
        &self,
        current_uri: &str,
        current_doc: Option<&DocumentState>,
        prefix: &str,
    ) -> Vec<ImportedCompletionSymbol> {
        if prefix.is_empty() {
            return Vec::new();
        }
        let imports = self.imports_for_context(current_uri, current_doc);
        if imports.is_empty() {
            return Vec::new();
        }
        let (qualifier, leaf_prefix) = split_qualified_prefix(prefix);
        let leaf_prefix_lower = leaf_prefix.to_ascii_lowercase();
        let mut out = Vec::new();

        for import in imports {
            if let Some(qualified) = qualifier {
                if !import_matches_qualifier(import, qualified) {
                    continue;
                }
                let qualifier_label = import.alias.as_deref().unwrap_or(&import.module_id);
                for symbol in self.module_export_symbols(import.module_id.as_str()) {
                    if !symbol
                        .name
                        .to_ascii_lowercase()
                        .starts_with(&leaf_prefix_lower)
                    {
                        continue;
                    }
                    out.push(ImportedCompletionSymbol {
                        label: format!("{qualifier_label}.{}", symbol.name),
                        origin: symbol,
                    });
                }
                continue;
            }

            if import.wildcard {
                for symbol in self.module_export_symbols(import.module_id.as_str()) {
                    if !symbol
                        .name
                        .to_ascii_lowercase()
                        .starts_with(&leaf_prefix_lower)
                    {
                        continue;
                    }
                    out.push(ImportedCompletionSymbol {
                        label: symbol.name.clone(),
                        origin: symbol,
                    });
                }
                continue;
            }

            for item in &import.items {
                if !item
                    .local_name
                    .to_ascii_lowercase()
                    .starts_with(&leaf_prefix_lower)
                {
                    continue;
                }
                for symbol in self.module_export_symbols(import.module_id.as_str()) {
                    if !symbol.name.eq_ignore_ascii_case(&item.source_name) {
                        continue;
                    }
                    out.push(ImportedCompletionSymbol {
                        label: item.local_name.clone(),
                        origin: symbol,
                    });
                }
            }
        }

        out.sort_by(|a, b| {
            a.label
                .to_ascii_lowercase()
                .cmp(&b.label.to_ascii_lowercase())
                .then(a.origin.uri.cmp(&b.origin.uri))
                .then(a.origin.line.cmp(&b.origin.line))
                .then(a.origin.col_start.cmp(&b.origin.col_start))
        });
        dedup_imported_completion(out)
    }

    pub fn member_fields_for_symbol(
        &self,
        current_uri: &str,
        current_doc: Option<&DocumentState>,
        request_line: u32,
        base_symbol: &str,
    ) -> Vec<MemberFieldCandidate> {
        if base_symbol.is_empty() {
            return Vec::new();
        }
        let mut out =
            self.repetition_fields_for_symbol(current_uri, current_doc, request_line, base_symbol);
        if let Some(type_name) =
            self.resolve_struct_type_for_symbol(current_uri, current_doc, request_line, base_symbol)
        {
            out.extend(self.struct_fields_for_type(current_uri, current_doc, &type_name));
        }
        dedup_member_fields(out)
    }

    fn repetition_fields_for_symbol(
        &self,
        current_uri: &str,
        current_doc: Option<&DocumentState>,
        request_line: u32,
        base_symbol: &str,
    ) -> Vec<MemberFieldCandidate> {
        let mut out = Vec::new();
        if let Some(repeat) = find_repetition_struct_in_set(
            self.repetition_structs_for_context(current_uri, current_doc),
            base_symbol,
            request_line,
        ) {
            collect_member_fields_from_struct(
                &mut out,
                current_uri,
                &repeat.symbol_name,
                &repeat.fields,
            );
        }

        for imported in self.imported_symbols_named(current_uri, current_doc, base_symbol) {
            if let Some(repeats) = self.repetition_structs_by_uri.get(&imported.uri) {
                if let Some(repeat) =
                    find_repetition_struct_in_set(repeats, &imported.name, request_line)
                {
                    collect_member_fields_from_struct(
                        &mut out,
                        imported.uri.as_str(),
                        &repeat.symbol_name,
                        &repeat.fields,
                    );
                }
            }
        }

        for symbol in self.symbols_named(base_symbol) {
            if let Some(repeats) = self.repetition_structs_by_uri.get(&symbol.uri) {
                if let Some(repeat) =
                    find_repetition_struct_in_set(repeats, &symbol.name, request_line)
                {
                    collect_member_fields_from_struct(
                        &mut out,
                        symbol.uri.as_str(),
                        &repeat.symbol_name,
                        &repeat.fields,
                    );
                }
            }
        }

        out
    }

    fn resolve_struct_type_for_symbol(
        &self,
        current_uri: &str,
        current_doc: Option<&DocumentState>,
        request_line: u32,
        base_symbol: &str,
    ) -> Option<String> {
        if let Some(typed) = find_typed_symbol_in_set(
            self.typed_symbols_for_context(current_uri, current_doc),
            base_symbol,
            request_line,
        ) {
            return Some(typed.type_name.clone());
        }

        for imported in self.imported_symbols_named(current_uri, current_doc, base_symbol) {
            let Some(typed) = self
                .typed_symbols_by_uri
                .get(&imported.uri)
                .and_then(|symbols| {
                    find_typed_symbol_in_set(symbols, &imported.name, request_line)
                })
            else {
                continue;
            };
            return Some(typed.type_name.clone());
        }

        for symbol in self.symbols_named(base_symbol) {
            let Some(typed) = self
                .typed_symbols_by_uri
                .get(&symbol.uri)
                .and_then(|symbols| find_typed_symbol_in_set(symbols, &symbol.name, request_line))
            else {
                continue;
            };
            return Some(typed.type_name.clone());
        }

        None
    }

    fn struct_fields_for_type(
        &self,
        current_uri: &str,
        current_doc: Option<&DocumentState>,
        type_name: &str,
    ) -> Vec<MemberFieldCandidate> {
        let mut out = Vec::new();

        for struct_decl in self.struct_types_for_context(current_uri, current_doc) {
            if struct_decl.name.eq_ignore_ascii_case(type_name) {
                collect_member_fields_from_struct(
                    &mut out,
                    current_uri,
                    &struct_decl.name,
                    &struct_decl.fields,
                );
            }
        }

        for (uri, decls) in &self.struct_types_by_uri {
            for struct_decl in decls {
                if !struct_decl.name.eq_ignore_ascii_case(type_name) {
                    continue;
                }
                collect_member_fields_from_struct(
                    &mut out,
                    uri,
                    &struct_decl.name,
                    &struct_decl.fields,
                );
            }
        }

        out
    }

    fn typed_symbols_for_context<'a>(
        &'a self,
        current_uri: &str,
        current_doc: Option<&'a DocumentState>,
    ) -> &'a [TypedSymbolDecl] {
        if let Some(doc) = current_doc {
            return doc.typed_symbols.as_slice();
        }
        self.typed_symbols_by_uri
            .get(current_uri)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn struct_types_for_context<'a>(
        &'a self,
        current_uri: &str,
        current_doc: Option<&'a DocumentState>,
    ) -> &'a [StructTypeDecl] {
        if let Some(doc) = current_doc {
            return doc.struct_types.as_slice();
        }
        self.struct_types_by_uri
            .get(current_uri)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn repetition_structs_for_context<'a>(
        &'a self,
        current_uri: &str,
        current_doc: Option<&'a DocumentState>,
    ) -> &'a [RepetitionStructDecl] {
        if let Some(doc) = current_doc {
            return doc.repetition_structs.as_slice();
        }
        self.repetition_structs_by_uri
            .get(current_uri)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone)]
pub struct ImportedCompletionSymbol {
    pub label: String,
    pub origin: IndexedSymbol,
}

#[derive(Debug, Clone)]
pub struct MemberFieldCandidate {
    pub name: String,
    pub owner_name: String,
    pub uri: String,
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub declaration: String,
}

fn load_documents_from_roots(registry: &ModuleRegistry, config: &LspConfig) -> Vec<DocumentState> {
    let mut out = Vec::new();
    for root in &config.roots {
        let path = PathBuf::from(root);
        if path.is_file() {
            if let Some(doc) = build_document_state_from_file(registry, &path) {
                out.push(doc);
            }
            continue;
        }
        if path.is_dir() {
            collect_documents_from_dir(registry, &path, &mut out);
        }
    }
    out
}

fn collect_documents_from_dir(registry: &ModuleRegistry, dir: &Path, out: &mut Vec<DocumentState>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_documents_from_dir(registry, &path, out);
            continue;
        }
        if !is_source_file(&path) {
            continue;
        }
        if let Some(doc) = build_document_state_from_file(registry, &path) {
            out.push(doc);
        }
    }
}

fn is_source_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(ext.as_str(), "asm" | "inc")
}

fn build_document_state_from_file(registry: &ModuleRegistry, path: &Path) -> Option<DocumentState> {
    let text = fs::read_to_string(path).ok()?;
    let uri = path_to_file_uri(path);
    let mut doc = DocumentState::new(uri, Some(path.to_path_buf()), 0, text);
    doc.refresh_derived_state(registry);
    Some(doc)
}

impl WorkspaceIndex {
    fn rebuild_name_index(&mut self) {
        self.by_name.clear();
        for symbols in self.per_uri.values() {
            for symbol in symbols {
                self.by_name
                    .entry(symbol.name.to_ascii_lowercase())
                    .or_default()
                    .push(symbol.clone());
            }
        }
        for symbols in self.by_name.values_mut() {
            symbols.sort_by(|a, b| {
                a.uri
                    .cmp(&b.uri)
                    .then(a.line.cmp(&b.line))
                    .then(a.col_start.cmp(&b.col_start))
            });
        }
    }

    fn imports_for_context<'a>(
        &'a self,
        current_uri: &str,
        current_doc: Option<&'a DocumentState>,
    ) -> &'a [UseImportDecl] {
        if let Some(doc) = current_doc {
            return doc.imports.as_slice();
        }
        self.imports_by_uri
            .get(current_uri)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn index_module_candidates(&mut self, doc: &DocumentState) {
        let mut module_ids: Vec<String> = doc
            .symbols
            .iter()
            .filter(|symbol| matches!(symbol.kind, SymbolKind::Module))
            .map(|symbol| symbol.name.clone())
            .collect();
        if let Some(path) = &doc.path {
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                module_ids.push(stem.to_string());
            }
        }
        for module_id in module_ids {
            let key = canonical_module_id(&module_id);
            self.module_to_uris
                .entry(key)
                .or_default()
                .push(doc.uri.clone());
        }
        for uris in self.module_to_uris.values_mut() {
            uris.sort();
            uris.dedup();
        }
    }

    fn rebuild_module_index(&mut self) {
        self.module_to_uris.clear();
        let uris: Vec<String> = self.per_uri.keys().cloned().collect();
        for uri in uris {
            let Some(path) = uri_to_path(&uri) else {
                continue;
            };
            let symbols = self.per_uri.get(&uri).cloned().unwrap_or_default();
            let mut module_ids: Vec<String> = symbols
                .iter()
                .filter(|symbol| matches!(symbol.kind, SymbolKind::Module))
                .map(|symbol| symbol.name.clone())
                .collect();
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                module_ids.push(stem.to_string());
            }
            for module_id in module_ids {
                let key = canonical_module_id(&module_id);
                self.module_to_uris
                    .entry(key)
                    .or_default()
                    .push(uri.clone());
            }
        }
        for uris in self.module_to_uris.values_mut() {
            uris.sort();
            uris.dedup();
        }
    }

    fn module_export_symbols(&self, module_id: &str) -> Vec<IndexedSymbol> {
        let Some(candidate_uris) = self.module_to_uris.get(&canonical_module_id(module_id)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for uri in candidate_uris {
            if let Some(symbols) = self.per_uri.get(uri) {
                for symbol in symbols {
                    if !is_module_export_symbol(symbol) {
                        continue;
                    }
                    out.push(symbol.clone());
                }
            }
        }
        out.sort_by(|a, b| {
            a.uri
                .cmp(&b.uri)
                .then(a.line.cmp(&b.line))
                .then(a.col_start.cmp(&b.col_start))
        });
        dedup_indexed_symbols(out)
    }
}

pub fn local_definition_candidates(
    doc: &DocumentState,
    word: &str,
    request_line: u32,
) -> Vec<SymbolDecl> {
    let mut out: Vec<SymbolDecl> = doc
        .symbols
        .iter()
        .filter(|symbol| symbol.name.eq_ignore_ascii_case(word))
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        definition_line_rank(a.line, request_line)
            .cmp(&definition_line_rank(b.line, request_line))
            .then(a.line.cmp(&b.line))
            .then(a.col_start.cmp(&b.col_start))
    });
    out
}

fn definition_line_rank(def_line: u32, request_line: u32) -> (u8, u32) {
    if def_line <= request_line {
        (0, request_line.saturating_sub(def_line))
    } else {
        (1, def_line.saturating_sub(request_line))
    }
}

pub fn resolve_module_target(word: &str, config: &LspConfig, current_uri: &str) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut candidates = Vec::new();
    if let Some(path) = uri_to_path(current_uri) {
        if let Some(parent) = path.parent() {
            candidates.push(parent.to_path_buf());
        }
    }
    candidates.extend(config.module_paths.iter().map(PathBuf::from));

    for base in candidates {
        let asm = base.join(format!("{word}.asm"));
        let inc = base.join(format!("{word}.inc"));
        if asm.exists() {
            results.push(asm);
        }
        if inc.exists() {
            results.push(inc);
        }
    }
    results.sort();
    results.dedup();
    results
}

fn split_qualified_symbol(word: &str) -> (Option<&str>, &str) {
    if let Some((qualifier, leaf)) = word.split_once('.') {
        if !qualifier.is_empty() && !leaf.is_empty() {
            return (Some(qualifier), leaf);
        }
    }
    (None, word)
}

fn split_qualified_prefix(prefix: &str) -> (Option<&str>, &str) {
    if let Some((qualifier, leaf)) = prefix.split_once('.') {
        if !qualifier.is_empty() {
            return (Some(qualifier), leaf);
        }
    }
    (None, prefix)
}

fn import_matches_qualifier(import: &UseImportDecl, qualifier: &str) -> bool {
    import
        .alias
        .as_deref()
        .is_some_and(|alias| alias.eq_ignore_ascii_case(qualifier))
        || import.module_id.eq_ignore_ascii_case(qualifier)
}

fn canonical_module_id(module_id: &str) -> String {
    module_id.to_ascii_lowercase()
}

fn is_module_export_symbol(symbol: &IndexedSymbol) -> bool {
    if symbol.visibility != SymbolVisibility::Public {
        return false;
    }
    !matches!(
        symbol.kind,
        SymbolKind::Module | SymbolKind::UseImport | SymbolKind::Section
    )
}

fn find_typed_symbol_in_set<'a>(
    symbols: &'a [TypedSymbolDecl],
    name: &str,
    request_line: u32,
) -> Option<&'a TypedSymbolDecl> {
    symbols
        .iter()
        .filter(|symbol| symbol.name.eq_ignore_ascii_case(name))
        .min_by_key(|symbol| {
            (
                definition_line_rank(symbol.line, request_line),
                symbol.line,
                symbol.col_start,
            )
        })
}

fn find_repetition_struct_in_set<'a>(
    reps: &'a [RepetitionStructDecl],
    symbol_name: &str,
    request_line: u32,
) -> Option<&'a RepetitionStructDecl> {
    reps.iter()
        .filter(|decl| decl.symbol_name.eq_ignore_ascii_case(symbol_name))
        .min_by_key(|decl| {
            (
                definition_line_rank(decl.line, request_line),
                decl.line,
                decl.col_start,
            )
        })
}

fn collect_member_fields_from_struct(
    out: &mut Vec<MemberFieldCandidate>,
    uri: &str,
    owner_name: &str,
    fields: &[StructFieldDecl],
) {
    for field in fields {
        out.push(MemberFieldCandidate {
            name: field.name.clone(),
            owner_name: owner_name.to_string(),
            uri: uri.to_string(),
            line: field.line,
            col_start: field.col_start,
            col_end: field.col_end,
            declaration: field.declaration.clone(),
        });
    }
}

fn dedup_indexed_symbols(items: Vec<IndexedSymbol>) -> Vec<IndexedSymbol> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let key = (
            item.name.to_ascii_lowercase(),
            item.uri.clone(),
            item.line,
            item.col_start,
        );
        if seen.insert(key) {
            out.push(item);
        }
    }
    out
}

fn dedup_member_fields(items: Vec<MemberFieldCandidate>) -> Vec<MemberFieldCandidate> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let key = (
            item.name.to_ascii_lowercase(),
            item.owner_name.to_ascii_lowercase(),
            item.uri.clone(),
            item.line,
            item.col_start,
        );
        if seen.insert(key) {
            out.push(item);
        }
    }
    out.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then(
                a.owner_name
                    .to_ascii_lowercase()
                    .cmp(&b.owner_name.to_ascii_lowercase()),
            )
            .then(a.uri.cmp(&b.uri))
            .then(a.line.cmp(&b.line))
            .then(a.col_start.cmp(&b.col_start))
    });
    out
}

fn dedup_imported_completion(
    items: Vec<ImportedCompletionSymbol>,
) -> Vec<ImportedCompletionSymbol> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in items {
        let key = (
            item.label.to_ascii_lowercase(),
            item.origin.uri.clone(),
            item.origin.line,
            item.origin.col_start,
        );
        if seen.insert(key) {
            out.push(item);
        }
    }
    out
}
