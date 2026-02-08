// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Symbol table for labels and constants.

use crate::core::parser::{UseItem, UseParam};
use crate::core::tokenizer::Span;

use std::collections::HashMap;
use std::io::{self, Write};

#[derive(Debug, Clone)]
pub struct SymbolTableEntry {
    pub name: String,
    pub val: u32,
    pub rw: bool,
    pub updated: bool,
    pub visibility: SymbolVisibility,
    pub module_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolVisibility {
    Public,
    Private,
}

#[derive(Debug, Clone)]
pub struct ModuleImport {
    pub module_id: String,
    pub alias: Option<String>,
    pub items: Vec<UseItem>,
    pub params: Vec<UseParam>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub imports: Vec<ModuleImport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportIssueKind {
    Directive,
    Symbol,
}

#[derive(Debug, Clone)]
pub struct ImportIssue {
    pub line: u32,
    pub column: Option<usize>,
    pub kind: ImportIssueKind,
    pub message: String,
    pub param: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportResult {
    Ok,
    AliasCollision,
    SelectiveCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum SymbolTableResult {
    Ok,
    Duplicate,
    NotFound,
    TableFull,
}

pub const MAX_ENTRIES: usize = 66000;

#[derive(Debug, Default)]
pub struct SymbolTable {
    entries: Vec<SymbolTableEntry>,
    /// Case-normalized name → index into `entries` for O(1) lookup.
    index: HashMap<String, usize>,
    modules: Vec<String>,
    module_info: Vec<ModuleInfo>,
}

impl SymbolTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
            modules: Vec::new(),
            module_info: Vec::new(),
        }
    }

    pub fn register_module(&mut self, name: &str) -> SymbolTableResult {
        if self
            .modules
            .iter()
            .any(|module| module.eq_ignore_ascii_case(name))
        {
            return SymbolTableResult::Duplicate;
        }
        self.modules.push(name.to_string());
        self.module_info.push(ModuleInfo {
            name: name.to_string(),
            imports: Vec::new(),
        });
        SymbolTableResult::Ok
    }

    #[must_use]
    pub fn has_module(&self, name: &str) -> bool {
        self.modules
            .iter()
            .any(|module| module.eq_ignore_ascii_case(name))
    }

    pub fn add_import(&mut self, module: &str, import: ModuleImport) -> ImportResult {
        let info = match self.module_info_mut(module) {
            Some(info) => info,
            None => {
                self.module_info.push(ModuleInfo {
                    name: module.to_string(),
                    imports: Vec::new(),
                });
                self.module_info_mut(module).expect("module info")
            }
        };

        if let Some(alias) = &import.alias {
            if info
                .imports
                .iter()
                .filter_map(|existing| existing.alias.as_ref())
                .any(|existing| existing.eq_ignore_ascii_case(alias))
            {
                return ImportResult::AliasCollision;
            }
        }

        for item in &import.items {
            if item.name == "*" && item.alias.is_none() {
                continue;
            }
            let local = item.alias.as_deref().unwrap_or(&item.name);
            if info
                .imports
                .iter()
                .flat_map(|existing| existing.items.iter())
                .any(|existing| {
                    if existing.name == "*" && existing.alias.is_none() {
                        return false;
                    }
                    let existing_local = existing.alias.as_deref().unwrap_or(&existing.name);
                    existing_local.eq_ignore_ascii_case(local)
                })
            {
                return ImportResult::SelectiveCollision;
            }
        }

        info.imports.push(import);
        ImportResult::Ok
    }

    #[must_use]
    pub fn module_imports(&self, name: &str) -> Option<&[ModuleImport]> {
        self.module_info(name).map(|info| info.imports.as_slice())
    }

    fn module_info(&self, name: &str) -> Option<&ModuleInfo> {
        self.module_info
            .iter()
            .find(|module| module.name.eq_ignore_ascii_case(name))
    }

    fn module_info_mut(&mut self, name: &str) -> Option<&mut ModuleInfo> {
        self.module_info
            .iter_mut()
            .find(|module| module.name.eq_ignore_ascii_case(name))
    }

    #[must_use]
    pub fn resolve_import_alias(&self, module: &str, alias: &str) -> Option<&str> {
        self.module_info(module).and_then(|info| {
            info.imports.iter().find_map(|import| {
                import.alias.as_ref().and_then(|candidate| {
                    if candidate.eq_ignore_ascii_case(alias) {
                        Some(import.module_id.as_str())
                    } else {
                        None
                    }
                })
            })
        })
    }

    #[must_use]
    pub fn resolve_selective_import(&self, module: &str, name: &str) -> Option<(&str, &str)> {
        self.module_info(module).and_then(|info| {
            info.imports.iter().find_map(|import| {
                import.items.iter().find_map(|item| {
                    if item.name == "*" && item.alias.is_none() {
                        let full_name = format!("{}.{}", import.module_id, name);
                        if let Some(entry) = self.entry(&full_name) {
                            if entry.visibility == SymbolVisibility::Public {
                                let target_name =
                                    entry.name.rsplit('.').next().unwrap_or(&entry.name);
                                return Some((import.module_id.as_str(), target_name));
                            }
                        }
                        return None;
                    }
                    let local = item.alias.as_deref().unwrap_or(&item.name);
                    if local.eq_ignore_ascii_case(name) {
                        Some((import.module_id.as_str(), item.name.as_str()))
                    } else {
                        None
                    }
                })
            })
        })
    }

    #[must_use]
    pub fn validate_imports(
        &self,
        known_compile_time_symbols: &HashMap<String, HashMap<String, SymbolVisibility>>,
    ) -> Vec<ImportIssue> {
        let mut issues = Vec::new();

        for info in &self.module_info {
            for import in &info.imports {
                if !self.has_module(&import.module_id) {
                    issues.push(ImportIssue {
                        line: import.span.line,
                        column: Some(import.span.col_start),
                        kind: ImportIssueKind::Directive,
                        message: "Missing module".to_string(),
                        param: Some(import.module_id.clone()),
                    });
                    continue;
                }
                for item in &import.items {
                    if item.name == "*" && item.alias.is_none() {
                        continue;
                    }
                    let full_name = format!("{}.{}", import.module_id, item.name);
                    match self.entry(&full_name) {
                        Some(entry) => {
                            if entry.visibility == SymbolVisibility::Private {
                                issues.push(ImportIssue {
                                    line: item.span.line,
                                    column: Some(item.span.col_start),
                                    kind: ImportIssueKind::Symbol,
                                    message: "Symbol is private".to_string(),
                                    param: Some(item.name.clone()),
                                });
                            }
                        }
                        None => {
                            // Validate compile-time symbols (macro/segment/statement)
                            let dep_canonical = import.module_id.to_ascii_lowercase();
                            if let Some(symbols) = known_compile_time_symbols.get(&dep_canonical) {
                                if let Some(visibility) =
                                    symbols.get(&item.name.to_ascii_uppercase())
                                {
                                    if *visibility == SymbolVisibility::Private {
                                        issues.push(ImportIssue {
                                            line: item.span.line,
                                            column: Some(item.span.col_start),
                                            kind: ImportIssueKind::Symbol,
                                            message: "Symbol is private".to_string(),
                                            param: Some(item.name.clone()),
                                        });
                                    }
                                    continue;
                                }
                            }
                            issues.push(ImportIssue {
                                line: item.span.line,
                                column: Some(item.span.col_start),
                                kind: ImportIssueKind::Directive,
                                message: "Missing imported symbol".to_string(),
                                param: Some(item.name.clone()),
                            });
                        }
                    }
                }
            }
        }

        let mut visiting = Vec::new();
        let mut visited = Vec::new();
        for module in &self.module_info {
            self.detect_import_cycles(
                module.name.as_str(),
                &mut visiting,
                &mut visited,
                &mut issues,
            );
        }

        issues
    }

    fn detect_import_cycles(
        &self,
        module: &str,
        visiting: &mut Vec<String>,
        visited: &mut Vec<String>,
        issues: &mut Vec<ImportIssue>,
    ) {
        if visited.iter().any(|name| name.eq_ignore_ascii_case(module)) {
            return;
        }
        if let Some(pos) = visiting
            .iter()
            .position(|name| name.eq_ignore_ascii_case(module))
        {
            let cycle = &visiting[pos..];
            for window in cycle.windows(2) {
                let from = &window[0];
                let to = &window[1];
                self.push_cycle_issue(from, to, issues);
            }
            if let (Some(first), Some(last)) = (cycle.first(), cycle.last()) {
                self.push_cycle_issue(last, first, issues);
            }
            return;
        }

        visiting.push(module.to_string());
        if let Some(info) = self.module_info(module) {
            for import in &info.imports {
                self.detect_import_cycles(&import.module_id, visiting, visited, issues);
            }
        }
        visiting.pop();
        visited.push(module.to_string());
    }

    fn push_cycle_issue(&self, from: &str, to: &str, issues: &mut Vec<ImportIssue>) {
        if let Some(info) = self.module_info(from) {
            for import in &info.imports {
                if import.module_id.eq_ignore_ascii_case(to) {
                    issues.push(ImportIssue {
                        line: import.span.line,
                        column: Some(import.span.col_start),
                        kind: ImportIssueKind::Directive,
                        message: "Import cycle detected".to_string(),
                        param: Some(import.module_id.clone()),
                    });
                }
            }
        }
    }

    pub fn add(
        &mut self,
        name: &str,
        val: u32,
        rw: bool,
        visibility: SymbolVisibility,
        module_id: Option<&str>,
    ) -> SymbolTableResult {
        if self.entries.len() >= MAX_ENTRIES {
            return SymbolTableResult::TableFull;
        }

        let key = name.to_ascii_uppercase();
        if let Some(&idx) = self.index.get(&key) {
            let entry = &mut self.entries[idx];
            if entry.rw {
                entry.val = val;
                return SymbolTableResult::Ok;
            }
            return SymbolTableResult::Duplicate;
        }

        let idx = self.entries.len();
        self.entries.push(SymbolTableEntry {
            name: name.to_string(),
            val,
            rw,
            updated: false,
            visibility,
            module_id: module_id.map(str::to_string),
        });
        self.index.insert(key, idx);
        SymbolTableResult::Ok
    }

    pub fn update(&mut self, name: &str, val: u32) -> SymbolTableResult {
        if let Some(entry) = self.entry_mut(name) {
            if entry.rw || !entry.updated {
                entry.val = val;
                entry.updated = true;
                return SymbolTableResult::Ok;
            }
            return SymbolTableResult::Duplicate;
        }
        SymbolTableResult::NotFound
    }

    /// Look up a symbol by name (case-insensitive).
    /// Returns `Some(value)` if found, `None` otherwise.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<u32> {
        self.entry(name).map(|e| e.val)
    }

    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&SymbolTableEntry> {
        let key = name.to_ascii_uppercase();
        self.index.get(&key).map(|&idx| &self.entries[idx])
    }

    pub fn entry_mut(&mut self, name: &str) -> Option<&mut SymbolTableEntry> {
        let key = name.to_ascii_uppercase();
        self.index
            .get(&key)
            .copied()
            .map(|idx| &mut self.entries[idx])
    }

    #[must_use]
    pub fn entries(&self) -> &[SymbolTableEntry] {
        &self.entries
    }

    pub fn dump<W: Write>(&self, mut out: W) -> io::Result<()> {
        for entry in &self.entries {
            writeln!(out, "{:<16}: {:04x} ({})", entry.name, entry.val, entry.val)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ImportResult, ModuleImport, SymbolTable, SymbolTableResult, SymbolVisibility};
    use crate::core::parser::{Expr, UseItem, UseParam};
    use crate::core::tokenizer::Span;

    #[test]
    fn add_and_lookup_are_case_insensitive() {
        let mut table = SymbolTable::new();
        assert_eq!(
            table.add("Foo", 0x10, false, SymbolVisibility::Private, None),
            SymbolTableResult::Ok
        );
        assert_eq!(table.lookup("foo"), Some(0x10));
        assert_eq!(table.lookup("FOO"), Some(0x10));
    }

    #[test]
    fn duplicate_and_rw_behavior() {
        let mut table = SymbolTable::new();
        assert_eq!(
            table.add("Val", 1, false, SymbolVisibility::Private, None),
            SymbolTableResult::Ok
        );
        assert_eq!(
            table.add("val", 2, false, SymbolVisibility::Private, None),
            SymbolTableResult::Duplicate
        );

        assert_eq!(
            table.add("Rw", 3, true, SymbolVisibility::Private, None),
            SymbolTableResult::Ok
        );
        assert_eq!(
            table.add("rw", 4, true, SymbolVisibility::Private, None),
            SymbolTableResult::Ok
        );
        assert_eq!(table.lookup("RW"), Some(4));
    }

    #[test]
    fn update_rules() {
        let mut table = SymbolTable::new();
        assert_eq!(table.update("missing", 1), SymbolTableResult::NotFound);
        assert_eq!(
            table.add("Once", 1, false, SymbolVisibility::Private, None),
            SymbolTableResult::Ok
        );
        assert_eq!(table.update("once", 2), SymbolTableResult::Ok);
        assert_eq!(table.update("ONCE", 3), SymbolTableResult::Duplicate);
        assert_eq!(table.lookup("once"), Some(2));

        assert_eq!(table.lookup("nope"), None);
    }

    #[test]
    fn registers_modules_case_insensitively() {
        let mut table = SymbolTable::new();
        assert_eq!(table.register_module("Core.Utils"), SymbolTableResult::Ok);
        assert!(table.has_module("core.utils"));
        assert_eq!(
            table.register_module("CORE.UTILS"),
            SymbolTableResult::Duplicate
        );
    }

    #[test]
    fn add_import_detects_alias_collision() {
        let mut table = SymbolTable::new();
        assert_eq!(table.register_module("alpha"), SymbolTableResult::Ok);
        let span = Span {
            line: 1,
            col_start: 1,
            col_end: 1,
        };
        let import = ModuleImport {
            module_id: "beta".to_string(),
            alias: Some("M".to_string()),
            items: Vec::new(),
            params: Vec::new(),
            span,
        };
        assert_eq!(table.add_import("alpha", import), ImportResult::Ok);

        let import = ModuleImport {
            module_id: "gamma".to_string(),
            alias: Some("m".to_string()),
            items: Vec::new(),
            params: Vec::new(),
            span,
        };
        assert_eq!(
            table.add_import("alpha", import),
            ImportResult::AliasCollision
        );
    }

    #[test]
    fn add_import_detects_selective_collision() {
        let mut table = SymbolTable::new();
        assert_eq!(table.register_module("alpha"), SymbolTableResult::Ok);
        let span = Span {
            line: 1,
            col_start: 1,
            col_end: 1,
        };
        let import = ModuleImport {
            module_id: "beta".to_string(),
            alias: None,
            items: vec![UseItem {
                name: "add".to_string(),
                alias: None,
                span,
            }],
            params: vec![UseParam {
                name: "FEATURE".to_string(),
                value: Expr::Number("1".to_string(), span),
                span,
            }],
            span,
        };
        assert_eq!(table.add_import("alpha", import), ImportResult::Ok);

        let import = ModuleImport {
            module_id: "gamma".to_string(),
            alias: None,
            items: vec![UseItem {
                name: "mul".to_string(),
                alias: Some("ADD".to_string()),
                span,
            }],
            params: Vec::new(),
            span,
        };
        assert_eq!(
            table.add_import("alpha", import),
            ImportResult::SelectiveCollision
        );
    }
}
