// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::core::cpu::CpuType;
use crate::core::registry::ModuleRegistry;
use crate::lsp::capabilities::CapabilitySnapshot;
use crate::lsp::code_actions::quick_fix_actions;
use crate::lsp::completion::completion_items;
use crate::lsp::config::LspConfig;
use crate::lsp::cpu_context::resolve_cpu_for_line;
use crate::lsp::definition::definition_locations;
use crate::lsp::diagnostics::{dedup_diagnostics, diagnostics_for_uri};
use crate::lsp::document_state::{DocumentState, UseImportDecl};
use crate::lsp::document_symbols::document_symbols;
use crate::lsp::hover::hover_response;
use crate::lsp::validation_runner::{run_cli_validation, ValidationDiagnostic};
use crate::lsp::workspace_index::{IndexedSymbol, WorkspaceIndex};

#[derive(Debug, Clone)]
pub enum OutboundMessage {
    Response {
        id: Value,
        result: Value,
    },
    Error {
        id: Value,
        code: i64,
        message: String,
    },
    Notification {
        method: String,
        params: Value,
    },
}

pub struct LspSession {
    config: LspConfig,
    registry: ModuleRegistry,
    snapshot: CapabilitySnapshot,
    documents: HashMap<String, DocumentState>,
    workspace_index: WorkspaceIndex,
    last_validation_at: HashMap<String, Instant>,
    validation_tx: Sender<ValidationTaskResult>,
    validation_rx: Receiver<ValidationTaskResult>,
    latest_validation_generation: HashMap<String, u64>,
    next_validation_generation: u64,
    published_diagnostics: HashMap<String, Vec<ValidationDiagnostic>>,
    published_uris_by_root: HashMap<String, HashSet<String>>,
    shutdown_requested: bool,
}

impl Default for LspSession {
    fn default() -> Self {
        Self::new()
    }
}

impl LspSession {
    pub fn new() -> Self {
        let registry = crate::build_default_registry();
        let snapshot = CapabilitySnapshot::from_registry(&registry);
        let (validation_tx, validation_rx) = mpsc::channel();
        Self {
            config: LspConfig::default(),
            registry,
            snapshot,
            documents: HashMap::new(),
            workspace_index: WorkspaceIndex::default(),
            last_validation_at: HashMap::new(),
            validation_tx,
            validation_rx,
            latest_validation_generation: HashMap::new(),
            next_validation_generation: 1,
            published_diagnostics: HashMap::new(),
            published_uris_by_root: HashMap::new(),
            shutdown_requested: false,
        }
    }

    pub fn should_exit(&self) -> bool {
        self.shutdown_requested
    }

    pub fn poll_async_notifications(&mut self) -> Vec<OutboundMessage> {
        self.drain_validation_results()
    }

    pub fn handle_message(&mut self, message: &Value) -> Vec<OutboundMessage> {
        let mut out = self.drain_validation_results();
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id").cloned();

        let Some(method) = method else {
            return out;
        };
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        if let Some(id) = id {
            match self.handle_request(method, &params) {
                Ok(result) => out.push(OutboundMessage::Response { id, result }),
                Err((code, msg)) => out.push(OutboundMessage::Error {
                    id,
                    code,
                    message: msg,
                }),
            }
            return out;
        }

        out.extend(self.handle_notification(method, &params));
        out
    }

    fn handle_request(&mut self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(self.handle_initialize(params)),
            "shutdown" => {
                self.shutdown_requested = true;
                Ok(Value::Null)
            }
            "textDocument/completion" => Ok(self.handle_completion(params)),
            "textDocument/hover" => Ok(self.handle_hover(params)),
            "textDocument/definition" => Ok(self.handle_definition(params)),
            "textDocument/references" => Ok(self.handle_references(params)),
            "textDocument/prepareRename" => Ok(self.handle_prepare_rename(params)),
            "textDocument/rename" => self.handle_rename(params),
            "textDocument/documentSymbol" => Ok(self.handle_document_symbol(params)),
            "textDocument/codeAction" => Ok(Value::Array(quick_fix_actions(params))),
            "workspace/symbol" => Ok(self.handle_workspace_symbol(params)),
            _ => Err((-32601, format!("method not found: {method}"))),
        }
    }

    fn handle_notification(&mut self, method: &str, params: &Value) -> Vec<OutboundMessage> {
        match method {
            "initialized" => Vec::new(),
            "exit" => {
                self.shutdown_requested = true;
                Vec::new()
            }
            "workspace/didChangeConfiguration" => self.handle_config_change(params),
            "textDocument/didOpen" => self.handle_did_open(params),
            "textDocument/didChange" => self.handle_did_change(params),
            "textDocument/didSave" => self.handle_did_save(params),
            "textDocument/didClose" => self.handle_did_close(params),
            _ => Vec::new(),
        }
    }

    fn handle_initialize(&mut self, params: &Value) -> Value {
        self.config
            .update_from_workspace_settings(params.get("initializationOptions"));
        self.rebuild_workspace_index();

        json!({
            "capabilities": {
                "textDocumentSync": {
                    "openClose": true,
                    "change": 1,
                    "save": { "includeText": true }
                },
                "completionProvider": { "resolveProvider": false, "triggerCharacters": ["."] },
                "hoverProvider": true,
                "definitionProvider": true,
                "referencesProvider": true,
                "renameProvider": { "prepareProvider": true },
                "documentSymbolProvider": true,
                "codeActionProvider": { "codeActionKinds": ["quickfix"] },
                "workspaceSymbolProvider": true
            },
            "serverInfo": {
                "name": "opforge-lsp",
                "version": env!("CARGO_PKG_VERSION")
            }
        })
    }

    fn handle_config_change(&mut self, params: &Value) -> Vec<OutboundMessage> {
        self.config
            .update_from_workspace_settings(params.get("settings"));
        self.rebuild_workspace_index();
        Vec::new()
    }

    fn handle_did_open(&mut self, params: &Value) -> Vec<OutboundMessage> {
        let Some(doc) = params.get("textDocument") else {
            return Vec::new();
        };
        let Some(uri) = doc.get("uri").and_then(Value::as_str) else {
            return Vec::new();
        };
        let text = doc
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let version = doc.get("version").and_then(Value::as_i64).unwrap_or(0);
        let path = uri_to_path(uri);
        let mut state = DocumentState::new(uri.to_string(), path, version, text);
        state.refresh_derived_state(&self.registry);
        self.documents.insert(uri.to_string(), state);
        self.rebuild_workspace_index();
        self.maybe_validate_and_publish(uri, false)
    }

    fn handle_did_change(&mut self, params: &Value) -> Vec<OutboundMessage> {
        let Some(doc) = params.get("textDocument") else {
            return Vec::new();
        };
        let Some(uri) = doc.get("uri").and_then(Value::as_str) else {
            return Vec::new();
        };
        let version = doc.get("version").and_then(Value::as_i64).unwrap_or(0);
        let text = params
            .get("contentChanges")
            .and_then(Value::as_array)
            .and_then(|changes| changes.last())
            .and_then(|entry| entry.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if text.is_empty() && !self.documents.contains_key(uri) {
            return Vec::new();
        }
        let path = uri_to_path(uri);
        let mut state = DocumentState::new(uri.to_string(), path, version, text);
        state.refresh_derived_state(&self.registry);
        self.documents.insert(uri.to_string(), state);
        self.rebuild_workspace_index();
        self.maybe_validate_and_publish(uri, false)
    }

    fn handle_did_save(&mut self, params: &Value) -> Vec<OutboundMessage> {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };
        if let Some(text) = params.get("text").and_then(Value::as_str) {
            if let Some(state) = self.documents.get_mut(uri) {
                state.text = text.to_string();
                state.refresh_derived_state(&self.registry);
            }
        }
        self.rebuild_workspace_index();
        self.maybe_validate_and_publish(uri, true)
    }

    fn handle_did_close(&mut self, params: &Value) -> Vec<OutboundMessage> {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Vec::new();
        };
        self.invalidate_validation_generation(uri);
        self.documents.remove(uri);
        self.workspace_index.remove_document(uri);
        self.published_diagnostics.remove(uri);
        let mut targets: HashSet<String> = self
            .published_uris_by_root
            .remove(uri)
            .unwrap_or_default()
            .into_iter()
            .collect();
        targets.insert(uri.to_string());
        let mut sorted_targets: Vec<String> = targets.into_iter().collect();
        sorted_targets.sort();
        sorted_targets
            .into_iter()
            .map(|target_uri| {
                self.published_diagnostics.remove(&target_uri);
                OutboundMessage::Notification {
                    method: "textDocument/publishDiagnostics".to_string(),
                    params: json!({
                        "uri": target_uri,
                        "diagnostics": [],
                    }),
                }
            })
            .collect()
    }

    fn handle_completion(&self, params: &Value) -> Value {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Value::Array(Vec::new());
        };
        let line = params
            .get("position")
            .and_then(|value| value.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let character = params
            .get("position")
            .and_then(|value| value.get("character"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let doc = self.documents.get(uri);
        let cpu = self.resolve_cpu_for_request(doc, line + 1);
        let prefix = doc
            .and_then(|state| state.lines.get(line as usize))
            .map(|line_text| token_prefix_at(line_text, character))
            .unwrap_or_default();
        Value::Array(completion_items(
            &self.snapshot,
            &self.workspace_index,
            doc,
            uri,
            cpu,
            line + 1,
            prefix.as_str(),
        ))
    }

    fn handle_hover(&self, params: &Value) -> Value {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Value::Null;
        };
        let line = params
            .get("position")
            .and_then(|value| value.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let character = params
            .get("position")
            .and_then(|value| value.get("character"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let doc = self.documents.get(uri);
        let cpu = self.resolve_cpu_for_request(doc, line + 1);
        let word = doc
            .and_then(|state| state.lines.get(line as usize))
            .map(|line_text| token_word_at(line_text, character))
            .unwrap_or_default();
        hover_response(
            &self.snapshot,
            &self.workspace_index,
            doc,
            uri,
            cpu,
            word.as_str(),
        )
        .unwrap_or(Value::Null)
    }

    fn handle_definition(&self, params: &Value) -> Value {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Value::Array(Vec::new());
        };
        let line = params
            .get("position")
            .and_then(|value| value.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let character = params
            .get("position")
            .and_then(|value| value.get("character"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let doc = self.documents.get(uri);
        let word = doc
            .and_then(|state| state.lines.get(line))
            .map(|line_text| token_word_at(line_text, character))
            .unwrap_or_default();
        Value::Array(definition_locations(
            &self.config,
            &self.workspace_index,
            doc,
            uri,
            (line + 1) as u32,
            word.as_str(),
        ))
    }

    fn handle_document_symbol(&self, params: &Value) -> Value {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Value::Array(Vec::new());
        };
        let Some(doc) = self.documents.get(uri) else {
            return Value::Array(Vec::new());
        };
        Value::Array(document_symbols(doc))
    }

    fn handle_references(&self, params: &Value) -> Value {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Value::Array(Vec::new());
        };
        let line = params
            .get("position")
            .and_then(|value| value.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let character = params
            .get("position")
            .and_then(|value| value.get("character"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let include_declaration = params
            .get("context")
            .and_then(|value| value.get("includeDeclaration"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let doc = self.documents.get(uri);
        let word = doc
            .and_then(|state| state.lines.get(line))
            .map(|line_text| token_word_at(line_text, character))
            .unwrap_or_default();
        if word.is_empty() {
            return Value::Array(Vec::new());
        }

        let defs = definition_locations(
            &self.config,
            &self.workspace_index,
            doc,
            uri,
            (line + 1) as u32,
            word.as_str(),
        );
        let Some(target) = defs
            .first()
            .and_then(|value| self.symbol_from_location_value(value))
        else {
            return Value::Array(Vec::new());
        };

        Value::Array(self.reference_locations_for_target(&target, include_declaration))
    }

    fn handle_workspace_symbol(&self, params: &Value) -> Value {
        let query = params
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if query.is_empty() {
            return Value::Array(Vec::new());
        }
        let symbols = self.workspace_index.search_symbols(query, 100);
        Value::Array(
            symbols
                .into_iter()
                .map(|symbol| {
                    json!({
                        "name": symbol.name,
                        "kind": workspace_symbol_kind_to_lsp(&symbol.kind),
                        "location": {
                            "uri": symbol.uri,
                            "range": {
                                "start": {"line": symbol.line.saturating_sub(1), "character": symbol.col_start.saturating_sub(1)},
                                "end": {"line": symbol.line.saturating_sub(1), "character": symbol.col_end.saturating_sub(1).max(symbol.col_start.saturating_sub(1) + 1)},
                            }
                        }
                    })
                })
                .collect(),
        )
    }

    fn handle_prepare_rename(&self, params: &Value) -> Value {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Value::Null;
        };
        let line = params
            .get("position")
            .and_then(|value| value.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let character = params
            .get("position")
            .and_then(|value| value.get("character"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;

        let Some((target, current_word, line_text)) =
            self.resolve_rename_target(uri, line, character)
        else {
            return Value::Null;
        };
        let Some((start_col, end_col, _)) = token_span_at(line_text, character) else {
            return Value::Null;
        };
        let (rename_start, rename_end, placeholder) =
            rename_span_for_word(&current_word, start_col, end_col, &target.name);
        json!({
            "range": {
                "start": {"line": line as u32, "character": rename_start.saturating_sub(1)},
                "end": {"line": line as u32, "character": rename_end.saturating_sub(1)},
            },
            "placeholder": placeholder,
        })
    }

    fn handle_rename(&self, params: &Value) -> Result<Value, (i64, String)> {
        let Some(uri) = params
            .get("textDocument")
            .and_then(|value| value.get("uri"))
            .and_then(Value::as_str)
        else {
            return Ok(Value::Null);
        };
        let Some(new_name) = params.get("newName").and_then(Value::as_str) else {
            return Err((-32602, "missing rename newName".to_string()));
        };
        if !is_valid_rename_identifier(new_name) {
            return Err((-32602, "invalid rename identifier".to_string()));
        }

        let line = params
            .get("position")
            .and_then(|value| value.get("line"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let character = params
            .get("position")
            .and_then(|value| value.get("character"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let Some((target, _, _)) = self.resolve_rename_target(uri, line, character) else {
            return Ok(Value::Null);
        };

        let edits_by_uri = self.rename_text_edits_for_target(&target, new_name);
        if edits_by_uri.is_empty() {
            return Ok(Value::Null);
        }

        let mut changes = Map::new();
        for (edit_uri, edits) in edits_by_uri {
            changes.insert(edit_uri, Value::Array(edits));
        }
        Ok(json!({ "changes": Value::Object(changes) }))
    }

    fn resolve_rename_target(
        &self,
        uri: &str,
        line: usize,
        character: usize,
    ) -> Option<(IndexedSymbol, String, &str)> {
        let doc = self.documents.get(uri)?;
        let line_text = doc.lines.get(line)?;
        let word = token_word_at(line_text, character);
        if word.is_empty() {
            return None;
        }
        let defs = definition_locations(
            &self.config,
            &self.workspace_index,
            Some(doc),
            uri,
            (line + 1) as u32,
            word.as_str(),
        );
        let target = defs
            .first()
            .and_then(|value| self.symbol_from_location_value(value))?;
        Some((target, word, line_text.as_str()))
    }

    fn resolve_cpu_for_request(&self, doc: Option<&DocumentState>, line: u32) -> CpuType {
        let workspace_default = self
            .config
            .default_cpu
            .as_deref()
            .and_then(|name| self.registry.resolve_cpu_name(name));
        if let Some(doc) = doc {
            resolve_cpu_for_line(line, &doc.cpu_transitions, workspace_default)
        } else {
            workspace_default.unwrap_or(crate::i8085::module::CPU_ID)
        }
    }

    fn symbol_from_location_value(&self, location: &Value) -> Option<IndexedSymbol> {
        let uri = location.get("uri").and_then(Value::as_str)?;
        let start = location.get("range")?.get("start")?;
        let line0 = start.get("line").and_then(Value::as_u64)? as u32;
        let char0 = start.get("character").and_then(Value::as_u64)? as u32;
        let line = line0.saturating_add(1);
        let col = char0.saturating_add(1);
        self.workspace_index
            .all_symbols_for_uri(uri)
            .into_iter()
            .find(|symbol| {
                symbol.line == line
                    && col >= symbol.col_start
                    && col <= symbol.col_end.max(symbol.col_start)
            })
    }

    fn reference_locations_for_target(
        &self,
        target: &IndexedSymbol,
        include_declaration: bool,
    ) -> Vec<Value> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for uri in self.workspace_index.document_uris() {
            let spellings = self.reference_spellings_for_document(&uri, target);
            if spellings.is_empty() {
                continue;
            }
            let spelling_set: HashSet<String> = spellings
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            let lines = self.lines_for_uri(&uri);
            for (line_idx, line_text) in lines.iter().enumerate() {
                for (start_col, end_col, token) in symbol_token_spans(line_text) {
                    if !spelling_set.contains(&token.to_ascii_lowercase()) {
                        continue;
                    }
                    if !include_declaration
                        && uri == target.uri
                        && (line_idx as u32 + 1) == target.line
                        && start_col == target.col_start
                    {
                        continue;
                    }
                    let key = (uri.clone(), line_idx as u32, start_col);
                    if !seen.insert(key) {
                        continue;
                    }
                    out.push(json!({
                        "uri": uri,
                        "range": {
                            "start": {"line": line_idx as u32, "character": start_col.saturating_sub(1)},
                            "end": {"line": line_idx as u32, "character": end_col.saturating_sub(1)},
                        }
                    }));
                }
            }
        }
        out.sort_by(|a, b| {
            let a_uri = a.get("uri").and_then(Value::as_str).unwrap_or_default();
            let b_uri = b.get("uri").and_then(Value::as_str).unwrap_or_default();
            let a_line = a
                .get("range")
                .and_then(|range| range.get("start"))
                .and_then(|start| start.get("line"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let b_line = b
                .get("range")
                .and_then(|range| range.get("start"))
                .and_then(|start| start.get("line"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let a_char = a
                .get("range")
                .and_then(|range| range.get("start"))
                .and_then(|start| start.get("character"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let b_char = b
                .get("range")
                .and_then(|range| range.get("start"))
                .and_then(|start| start.get("character"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            a_uri
                .cmp(b_uri)
                .then(a_line.cmp(&b_line))
                .then(a_char.cmp(&b_char))
        });
        out
    }

    fn rename_text_edits_for_target(
        &self,
        target: &IndexedSymbol,
        new_name: &str,
    ) -> Vec<(String, Vec<Value>)> {
        let mut out: Vec<(String, Vec<Value>)> = Vec::new();
        for uri in self.workspace_index.document_uris() {
            let rules = self.rename_rules_for_document(&uri, target, new_name);
            if rules.is_empty() {
                continue;
            }
            let lines = self.lines_for_uri(&uri);
            let mut edits = Vec::new();
            for (line_idx, line_text) in lines.iter().enumerate() {
                for (start_col, end_col, token) in symbol_token_spans(line_text) {
                    let lower = token.to_ascii_lowercase();
                    let Some(replacement) = rules.get(&lower) else {
                        continue;
                    };
                    if token == *replacement {
                        continue;
                    }
                    edits.push(json!({
                        "range": {
                            "start": {"line": line_idx as u32, "character": start_col.saturating_sub(1)},
                            "end": {"line": line_idx as u32, "character": end_col.saturating_sub(1)},
                        },
                        "newText": replacement,
                    }));
                }
            }
            if !edits.is_empty() {
                out.push((uri, edits));
            }
        }
        out.sort_by(|(left_uri, _), (right_uri, _)| left_uri.cmp(right_uri));
        out
    }

    fn rename_rules_for_document(
        &self,
        uri: &str,
        target: &IndexedSymbol,
        new_name: &str,
    ) -> HashMap<String, String> {
        let mut rules = HashMap::new();
        if uri == target.uri
            || self.document_matches_owner_module(uri, target.owner_module.as_deref())
        {
            rules.insert(target.name.to_ascii_lowercase(), new_name.to_string());
        }

        if let Some(module_id) = target.owner_module.as_deref() {
            let module_qualified = format!("{module_id}.{}", target.name);
            let module_replacement = format!("{module_id}.{new_name}");
            rules.insert(
                module_qualified.to_ascii_lowercase(),
                module_replacement.to_string(),
            );

            for import in self.imports_for_uri(uri) {
                if !import.module_id.eq_ignore_ascii_case(module_id) {
                    continue;
                }
                if let Some(alias) = &import.alias {
                    let old = format!("{alias}.{}", target.name);
                    let new = format!("{alias}.{new_name}");
                    rules.insert(old.to_ascii_lowercase(), new);
                }
            }
        }

        rules
    }

    fn reference_spellings_for_document(&self, uri: &str, target: &IndexedSymbol) -> Vec<String> {
        let mut out = HashSet::new();
        let same_doc = uri == target.uri;
        if same_doc || self.document_matches_owner_module(uri, target.owner_module.as_deref()) {
            out.insert(target.name.clone());
        }

        if let Some(module_id) = target.owner_module.as_deref() {
            out.insert(format!("{module_id}.{}", target.name));
            for import in self.imports_for_uri(uri) {
                if !import.module_id.eq_ignore_ascii_case(module_id) {
                    continue;
                }
                if let Some(alias) = &import.alias {
                    out.insert(format!("{alias}.{}", target.name));
                }
                if import.wildcard {
                    out.insert(target.name.clone());
                }
                for item in &import.items {
                    if item.source_name.eq_ignore_ascii_case(&target.name) {
                        out.insert(item.local_name.clone());
                    }
                }
            }
        } else if same_doc {
            out.insert(target.name.clone());
        }

        let mut values: Vec<String> = out.into_iter().collect();
        values.sort_by_key(|item| item.to_ascii_lowercase());
        values
    }

    fn imports_for_uri(&self, uri: &str) -> Vec<UseImportDecl> {
        if let Some(doc) = self.documents.get(uri) {
            return doc.imports.clone();
        }
        self.workspace_index.imports_for_uri(uri)
    }

    fn document_matches_owner_module(&self, uri: &str, owner_module: Option<&str>) -> bool {
        let Some(owner_module) = owner_module else {
            return false;
        };
        self.workspace_index
            .all_symbols_for_uri(uri)
            .into_iter()
            .any(|symbol| {
                matches!(symbol.kind, crate::lsp::document_state::SymbolKind::Module)
                    && symbol.name.eq_ignore_ascii_case(owner_module)
            })
    }

    fn lines_for_uri(&self, uri: &str) -> Vec<String> {
        if let Some(doc) = self.documents.get(uri) {
            return doc.lines.clone();
        }
        let Some(path) = uri_to_path(uri) else {
            return Vec::new();
        };
        let Ok(text) = fs::read_to_string(path) else {
            return Vec::new();
        };
        let mut lines: Vec<String> = text.split('\n').map(ToString::to_string).collect();
        if text.ends_with('\n') {
            lines.push(String::new());
        }
        lines
    }

    fn maybe_validate_and_publish(&mut self, uri: &str, force: bool) -> Vec<OutboundMessage> {
        if !force && self.config.validation.debounce_ms > 0 {
            let now = Instant::now();
            if let Some(previous) = self.last_validation_at.get(uri) {
                let elapsed = now.saturating_duration_since(*previous);
                if elapsed < Duration::from_millis(self.config.validation.debounce_ms) {
                    return self.drain_validation_results();
                }
            }
            self.last_validation_at.insert(uri.to_string(), now);
        }
        if force && !self.config.validation.on_save {
            return self.drain_validation_results();
        }
        self.schedule_validation(uri);
        self.drain_validation_results()
    }

    fn schedule_validation(&mut self, uri: &str) {
        let Some(doc) = self.documents.get(uri).cloned() else {
            return;
        };
        if doc.path.is_none() {
            return;
        }
        let generation = self.issue_validation_generation(uri);
        let config = self.config.clone();
        let documents = self.documents.clone();
        let tx = self.validation_tx.clone();
        let root_uri = uri.to_string();
        thread::spawn(move || {
            if let Some(task_result) =
                run_validation_task(config, doc, documents, generation, root_uri)
            {
                let _ = tx.send(task_result);
            }
        });
    }

    fn drain_validation_results(&mut self) -> Vec<OutboundMessage> {
        let mut out = Vec::new();
        loop {
            match self.validation_rx.try_recv() {
                Ok(result) => out.extend(self.apply_validation_result(result)),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        out
    }

    fn apply_validation_result(&mut self, result: ValidationTaskResult) -> Vec<OutboundMessage> {
        let latest_generation = self
            .latest_validation_generation
            .get(&result.root_uri)
            .copied()
            .unwrap_or_default();
        if result.generation != latest_generation {
            return Vec::new();
        }

        if let Some(current) = self.documents.get(&result.root_uri) {
            if current.version != result.version {
                return Vec::new();
            }
        } else {
            return Vec::new();
        }

        self.publish_validation_diagnostics(&result.root_uri, result.diagnostics)
    }

    fn publish_validation_diagnostics(
        &mut self,
        root_uri: &str,
        diagnostics: Vec<ValidationDiagnostic>,
    ) -> Vec<OutboundMessage> {
        let diagnostics = dedup_diagnostics(diagnostics);

        let grouped = group_diagnostics_by_uri(root_uri, &diagnostics);
        let new_uris: HashSet<String> = grouped.keys().cloned().collect();
        let previous_uris = self
            .published_uris_by_root
            .get(root_uri)
            .cloned()
            .unwrap_or_default();

        let mut notifications = Vec::new();
        for stale_uri in previous_uris.difference(&new_uris) {
            self.published_diagnostics.remove(stale_uri);
            notifications.push(OutboundMessage::Notification {
                method: "textDocument/publishDiagnostics".to_string(),
                params: json!({
                    "uri": stale_uri,
                    "diagnostics": [],
                }),
            });
        }

        let mut sorted_uris: Vec<String> = grouped.keys().cloned().collect();
        sorted_uris.sort();
        for target_uri in sorted_uris {
            let target_diags = grouped.get(&target_uri).cloned().unwrap_or_default();
            self.published_diagnostics
                .insert(target_uri.clone(), target_diags.clone());
            notifications.push(OutboundMessage::Notification {
                method: "textDocument/publishDiagnostics".to_string(),
                params: json!({
                    "uri": target_uri,
                    "diagnostics": diagnostics_for_uri(&target_uri, &target_diags),
                }),
            });
        }
        self.published_uris_by_root
            .insert(root_uri.to_string(), new_uris);

        notifications
    }

    fn issue_validation_generation(&mut self, uri: &str) -> u64 {
        let generation = self.next_validation_generation;
        self.next_validation_generation = self.next_validation_generation.saturating_add(1);
        self.latest_validation_generation
            .insert(uri.to_string(), generation);
        generation
    }

    fn invalidate_validation_generation(&mut self, uri: &str) {
        let generation = self.next_validation_generation;
        self.next_validation_generation = self.next_validation_generation.saturating_add(1);
        self.latest_validation_generation
            .insert(uri.to_string(), generation);
    }

    fn rebuild_workspace_index(&mut self) {
        self.workspace_index
            .rebuild(&self.registry, &self.config, &self.documents);
        self.snapshot = CapabilitySnapshot::from_registry(&self.registry);
    }
}

fn workspace_symbol_kind_to_lsp(kind: &crate::lsp::document_state::SymbolKind) -> u32 {
    match kind {
        crate::lsp::document_state::SymbolKind::Module => 2,
        crate::lsp::document_state::SymbolKind::Namespace => 3,
        crate::lsp::document_state::SymbolKind::Macro => 12,
        crate::lsp::document_state::SymbolKind::Label
        | crate::lsp::document_state::SymbolKind::Assignment => 13,
        crate::lsp::document_state::SymbolKind::Section => 5,
        crate::lsp::document_state::SymbolKind::Statement => 6,
        crate::lsp::document_state::SymbolKind::UseImport => 9,
    }
}

fn group_diagnostics_by_uri(
    active_uri: &str,
    diagnostics: &[ValidationDiagnostic],
) -> HashMap<String, Vec<ValidationDiagnostic>> {
    let mut grouped: HashMap<String, Vec<ValidationDiagnostic>> = HashMap::new();
    for diagnostic in diagnostics {
        let target_uri = diagnostic
            .file
            .as_ref()
            .map(|path| path_to_file_uri(Path::new(path)))
            .unwrap_or_else(|| active_uri.to_string());
        grouped
            .entry(target_uri)
            .or_default()
            .push(diagnostic.clone());
    }
    if grouped.is_empty() {
        grouped.insert(active_uri.to_string(), Vec::new());
    }
    grouped
}

#[derive(Debug)]
struct OverlayWorkspace {
    temp_root: PathBuf,
    working_dir: PathBuf,
    root_file: PathBuf,
    original_root: PathBuf,
}

#[derive(Debug)]
struct ValidationTaskResult {
    root_uri: String,
    version: i64,
    generation: u64,
    diagnostics: Vec<ValidationDiagnostic>,
}

fn run_validation_task(
    config: LspConfig,
    doc: DocumentState,
    open_docs: HashMap<String, DocumentState>,
    generation: u64,
    root_uri: String,
) -> Option<ValidationTaskResult> {
    let overlay = create_overlay_workspace(&doc, &open_docs)?;
    let result = run_cli_validation(&config, &overlay.root_file, &overlay.working_dir);

    let diagnostics = remap_overlay_diagnostics(
        result.diagnostics,
        &overlay.working_dir,
        &overlay.original_root,
    );
    let _ = fs::remove_dir_all(&overlay.temp_root);

    Some(ValidationTaskResult {
        root_uri,
        version: doc.version,
        generation,
        diagnostics,
    })
}

fn create_overlay_workspace(
    active_doc: &DocumentState,
    open_docs: &HashMap<String, DocumentState>,
) -> Option<OverlayWorkspace> {
    let original_file = active_doc.path.as_ref()?;
    let original_root = original_file.parent()?.to_path_buf();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    let temp_root = std::env::temp_dir().join(format!("opforge-lsp-overlay-{unique}"));
    let working_dir = temp_root.join("workspace");
    fs::create_dir_all(&working_dir).ok()?;

    copy_dir_recursive(&original_root, &working_dir)?;

    let file_name = original_file.file_name()?.to_string_lossy().to_string();
    let root_file = working_dir.join(file_name);

    for doc in open_docs.values() {
        let Some(path) = &doc.path else {
            continue;
        };
        let Ok(relative) = path.strip_prefix(&original_root) else {
            continue;
        };
        let target = working_dir.join(relative);
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(target, doc.text.as_bytes());
    }

    Some(OverlayWorkspace {
        temp_root,
        working_dir,
        root_file,
        original_root,
    })
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Option<()> {
    fs::create_dir_all(dst).ok()?;
    for entry in fs::read_dir(src).ok()? {
        let entry = entry.ok()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if src_path.is_file() {
            fs::copy(&src_path, &dst_path).ok()?;
        }
    }
    Some(())
}

fn remap_overlay_diagnostics(
    mut diagnostics: Vec<ValidationDiagnostic>,
    overlay_root: &Path,
    original_root: &Path,
) -> Vec<ValidationDiagnostic> {
    for diag in &mut diagnostics {
        if let Some(file) = &diag.file {
            let candidate = PathBuf::from(file);
            if let Ok(relative) = candidate.strip_prefix(overlay_root) {
                let remapped = original_root.join(relative);
                diag.file = Some(remapped.to_string_lossy().to_string());
            }
        }
    }
    diagnostics
}

pub fn uri_to_path(uri: &str) -> Option<PathBuf> {
    if !uri.starts_with("file://") {
        return None;
    }
    let raw = uri.trim_start_matches("file://");
    let decoded = percent_decode(raw);
    if decoded.is_empty() {
        None
    } else {
        Some(PathBuf::from(decoded))
    }
}

pub fn path_to_file_uri(path: &Path) -> String {
    let raw = path.to_string_lossy();
    format!("file://{}", percent_encode(raw.as_ref()))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = bytes[i + 1] as char;
            let lo = bytes[i + 2] as char;
            if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                let hex = format!("{hi}{lo}");
                if let Ok(value) = u8::from_str_radix(&hex, 16) {
                    out.push(value as char);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~' | ':') {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

fn token_prefix_at(line: &str, char_index: usize) -> String {
    let mut idx = char_index.min(line.len());
    let bytes = line.as_bytes();
    while idx > 0 && is_symbol_char(bytes[idx - 1] as char) {
        idx -= 1;
    }
    line.get(idx..char_index.min(line.len()))
        .unwrap_or_default()
        .to_string()
}

fn token_word_at(line: &str, char_index: usize) -> String {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return String::new();
    }
    let mut start = char_index.min(bytes.len());
    if start == bytes.len() && start > 0 {
        start -= 1;
    }
    while start > 0 && is_symbol_char(bytes[start - 1] as char) {
        start -= 1;
    }
    let mut end = char_index.min(bytes.len());
    while end < bytes.len() && is_symbol_char(bytes[end] as char) {
        end += 1;
    }
    line.get(start..end).unwrap_or_default().to_string()
}

fn is_symbol_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '$')
}

fn is_valid_rename_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || matches!(first, '_' | '.' | '$')) {
        return false;
    }
    chars.all(is_symbol_char)
}

fn symbol_token_spans(line: &str) -> Vec<(u32, u32, String)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if !is_symbol_char(bytes[idx] as char) {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < bytes.len() && is_symbol_char(bytes[idx] as char) {
            idx += 1;
        }
        let end = idx;
        let token = line.get(start..end).unwrap_or_default().to_string();
        if !token.is_empty() {
            out.push((start as u32 + 1, end as u32 + 1, token));
        }
    }
    out
}

fn token_span_at(line: &str, char_index: usize) -> Option<(u32, u32, String)> {
    let char1 = char_index as u32 + 1;
    symbol_token_spans(line)
        .into_iter()
        .find(|(start, end, _)| char1 >= *start && char1 < *end)
}

fn rename_span_for_word(
    current_word: &str,
    token_start: u32,
    token_end: u32,
    target_name: &str,
) -> (u32, u32, String) {
    if let Some(dot) = current_word.rfind('.') {
        let leaf = &current_word[dot + 1..];
        if leaf.eq_ignore_ascii_case(target_name) {
            let leaf_start = token_start.saturating_add(dot as u32 + 1);
            return (leaf_start, token_end, target_name.to_string());
        }
    }
    (token_start, token_end, target_name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uri_roundtrip_smoke() {
        let path = PathBuf::from("/tmp/opforge test.asm");
        let uri = path_to_file_uri(&path);
        let parsed = uri_to_path(&uri).expect("uri should parse");
        assert_eq!(parsed, path);
    }

    #[test]
    fn completion_tracks_nearest_prior_cpu_directive() {
        let mut session = LspSession::new();
        let uri = "file:///tmp/opforge_lsp_completion.asm";

        let _ = session.handle_message(&json!({
            "jsonrpc":"2.0",
            "id": 1,
            "method":"initialize",
            "params": {}
        }));
        let _ = session.handle_message(&json!({
            "jsonrpc":"2.0",
            "method":"textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": uri,
                    "version": 1,
                    "text": ".cpu 6502\n    brk\n.cpu z80\n    djnz label\n"
                }
            }
        }));

        let z80_response = session.handle_message(&json!({
            "jsonrpc":"2.0",
            "id": 2,
            "method":"textDocument/completion",
            "params":{
                "textDocument":{"uri": uri},
                "position":{"line":3,"character":6}
            }
        }));
        let mut has_djnz = false;
        for msg in z80_response {
            if let OutboundMessage::Response { result, .. } = msg {
                if let Some(items) = result.as_array() {
                    has_djnz = items.iter().any(|item| {
                        item.get("label")
                            .and_then(Value::as_str)
                            .is_some_and(|label| label.eq_ignore_ascii_case("djnz"))
                    });
                }
            }
        }
        assert!(has_djnz, "z80 completion should include djnz");
    }
}
