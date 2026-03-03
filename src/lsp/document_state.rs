// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::path::PathBuf;

use crate::core::assembler::expression::expr_text;
use crate::core::parser::{AssignOp, Expr, Label, LineAst, UseItem};
use crate::core::registry::ModuleRegistry;
use crate::lsp::cpu_context::scan_cpu_transitions;
use crate::vm::editor_parse_line;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    Label,
    Assignment,
    Module,
    Namespace,
    Macro,
    Section,
    Statement,
    UseImport,
}

impl SymbolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SymbolKind::Label => "label",
            SymbolKind::Assignment => "assignment",
            SymbolKind::Module => "module",
            SymbolKind::Namespace => "namespace",
            SymbolKind::Macro => "macro",
            SymbolKind::Section => "section",
            SymbolKind::Statement => "statement",
            SymbolKind::UseImport => "import",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolVisibility {
    Public,
    Local,
}

impl SymbolVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            SymbolVisibility::Public => "public",
            SymbolVisibility::Local => "local",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SymbolDecl {
    pub name: String,
    pub kind: SymbolKind,
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

#[derive(Debug, Clone)]
pub struct UseImportItemDecl {
    pub source_name: String,
    pub local_name: String,
}

#[derive(Debug, Clone)]
pub struct UseImportDecl {
    pub module_id: String,
    pub alias: Option<String>,
    pub wildcard: bool,
    pub items: Vec<UseImportItemDecl>,
    pub line: u32,
    pub owner_module: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StructFieldDecl {
    pub name: String,
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub declaration: String,
}

#[derive(Debug, Clone)]
pub struct StructTypeDecl {
    pub name: String,
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub scope_path: String,
    pub owner_module: Option<String>,
    pub declaration: String,
    pub fields: Vec<StructFieldDecl>,
}

#[derive(Debug, Clone)]
pub struct TypedSymbolDecl {
    pub name: String,
    pub type_name: String,
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub scope_path: String,
    pub owner_module: Option<String>,
    pub visibility: SymbolVisibility,
    pub declaration: String,
}

#[derive(Debug, Clone)]
pub struct RepetitionStructDecl {
    pub symbol_name: String,
    pub line: u32,
    pub col_start: u32,
    pub col_end: u32,
    pub scope_path: String,
    pub owner_module: Option<String>,
    pub declaration: String,
    pub fields: Vec<StructFieldDecl>,
}

#[derive(Debug, Clone)]
pub struct DocumentState {
    pub uri: String,
    pub path: Option<PathBuf>,
    pub version: i64,
    pub text: String,
    pub lines: Vec<String>,
    pub cpu_transitions: Vec<(u32, crate::core::cpu::CpuType)>,
    pub symbols: Vec<SymbolDecl>,
    pub imports: Vec<UseImportDecl>,
    pub struct_types: Vec<StructTypeDecl>,
    pub typed_symbols: Vec<TypedSymbolDecl>,
    pub repetition_structs: Vec<RepetitionStructDecl>,
}

struct CollectedSemantics {
    symbols: Vec<SymbolDecl>,
    imports: Vec<UseImportDecl>,
    struct_types: Vec<StructTypeDecl>,
    typed_symbols: Vec<TypedSymbolDecl>,
    repetition_structs: Vec<RepetitionStructDecl>,
}

impl DocumentState {
    pub fn new(uri: String, path: Option<PathBuf>, version: i64, text: String) -> Self {
        Self {
            uri,
            path,
            version,
            text,
            lines: Vec::new(),
            cpu_transitions: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            struct_types: Vec::new(),
            typed_symbols: Vec::new(),
            repetition_structs: Vec::new(),
        }
    }

    pub fn refresh_derived_state(&mut self, registry: &ModuleRegistry) {
        self.lines = split_lines(&self.text);
        self.cpu_transitions = scan_cpu_transitions(&self.lines, registry);
        let semantics = collect_semantics(&self.lines);
        self.symbols = semantics.symbols;
        self.imports = semantics.imports;
        self.struct_types = semantics.struct_types;
        self.typed_symbols = semantics.typed_symbols;
        self.repetition_structs = semantics.repetition_structs;
    }
}

fn split_lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text.split('\n').map(ToString::to_string).collect();
    if text.ends_with('\n') {
        out.push(String::new());
    }
    out
}

fn collect_semantics(lines: &[String]) -> CollectedSemantics {
    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    let mut struct_types = Vec::new();
    let mut typed_symbols = Vec::new();
    let mut repetition_structs = Vec::new();
    let mut active_struct: Option<ActiveStructDecl> = None;
    let mut active_repeats: Vec<ActiveRepeatDecl> = Vec::new();
    let mut scope = ScopeState::default();
    for (idx, line) in lines.iter().enumerate() {
        let line_num = (idx + 1) as u32;
        let Ok(ast) = editor_parse_line(line, line_num) else {
            continue;
        };
        let declaration = declaration_snippet(line);
        let scope_path = scope.path();
        let owner_module = scope.current_module();
        let base_meta = SymbolBuildMeta {
            scope_path,
            owner_module,
            declaration,
            value_excerpt: None,
        };
        match &ast {
            LineAst::Assignment {
                label,
                op,
                expr,
                span,
                ..
            } => {
                let kind = if matches!(op, AssignOp::Const | AssignOp::Var | AssignOp::VarIfUndef) {
                    SymbolKind::Assignment
                } else {
                    SymbolKind::Statement
                };
                symbols.push(build_symbol(
                    label.name.clone(),
                    kind,
                    span.line,
                    span.col_start as u32,
                    SymbolBuildMeta {
                        value_excerpt: assignment_value_excerpt(line),
                        ..base_meta.clone()
                    },
                ));
                if let Some(type_name) = typed_symbol_type_from_assignment(*op, expr) {
                    typed_symbols.push(build_typed_symbol_decl(
                        label, type_name, span.line, &base_meta,
                    ));
                }
            }
            LineAst::Use {
                module_id,
                alias,
                items,
                span,
                ..
            } => {
                symbols.push(build_symbol(
                    module_id.clone(),
                    SymbolKind::UseImport,
                    span.line,
                    span.col_start as u32,
                    SymbolBuildMeta {
                        value_excerpt: alias.clone(),
                        ..base_meta.clone()
                    },
                ));
                imports.push(build_import_decl(
                    module_id.clone(),
                    alias.clone(),
                    items,
                    span.line,
                    base_meta.owner_module.clone(),
                ));
            }
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => {
                let mnemonic_lower = mnemonic.as_ref().map(|value| value.to_ascii_lowercase());
                if let Some(label) = label {
                    symbols.push(build_symbol(
                        label.name.clone(),
                        SymbolKind::Label,
                        label.span.line,
                        label.span.col_start as u32,
                        base_meta.clone(),
                    ));
                    if let Some(active) = active_struct.as_mut() {
                        if !matches!(mnemonic_lower.as_deref(), Some(".struct" | ".endstruct")) {
                            active
                                .add_field(build_struct_field_decl(label, &base_meta.declaration));
                        }
                    }
                    if let Some(active) = active_repeats.last_mut() {
                        if !matches!(mnemonic_lower.as_deref(), Some(".bfor" | ".endfor")) {
                            active
                                .add_field(build_struct_field_decl(label, &base_meta.declaration));
                        }
                    }
                }
                if let (Some(label), Some(mnemonic)) = (label, mnemonic) {
                    if let Some(type_name) = typed_symbol_type_from_statement(mnemonic, operands) {
                        typed_symbols.push(build_typed_symbol_decl(
                            label, type_name, line_num, &base_meta,
                        ));
                    }
                }
                if let Some(mnemonic) = mnemonic {
                    if let Some(kind) = classify_directive_symbol_kind(mnemonic) {
                        symbols.push(build_symbol(
                            directive_symbol_name(mnemonic, statement_operand_name(&ast)),
                            kind,
                            line_num,
                            1,
                            base_meta.clone(),
                        ));
                    }
                    match mnemonic_lower.as_deref() {
                        Some(".struct") => {
                            if let Some(label) = label {
                                active_struct = Some(ActiveStructDecl::new(label, &base_meta));
                            }
                        }
                        Some(".endstruct") => {
                            if let Some(active) = active_struct.take() {
                                struct_types.push(active.finish());
                            }
                        }
                        Some(".bfor") => {
                            active_repeats.push(ActiveRepeatDecl::new(
                                label.as_ref(),
                                line_num,
                                &base_meta,
                            ));
                        }
                        Some(".endfor") => {
                            if let Some(active) = active_repeats.pop() {
                                if let Some(decl) = active.finish() {
                                    repetition_structs.push(decl);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            LineAst::StatementDef { keyword, span, .. } => {
                symbols.push(build_symbol(
                    keyword.clone(),
                    SymbolKind::Statement,
                    span.line,
                    span.col_start as u32,
                    base_meta.clone(),
                ));
            }
            _ => {}
        }
        apply_scope_transition(&ast, &mut scope);
    }
    if let Some(active) = active_struct.take() {
        struct_types.push(active.finish());
    }
    for active in active_repeats {
        if let Some(decl) = active.finish() {
            repetition_structs.push(decl);
        }
    }
    CollectedSemantics {
        symbols,
        imports,
        struct_types,
        typed_symbols,
        repetition_structs,
    }
}

#[derive(Debug, Clone)]
struct ActiveStructDecl {
    decl: StructTypeDecl,
}

impl ActiveStructDecl {
    fn new(label: &Label, meta: &SymbolBuildMeta) -> Self {
        Self {
            decl: StructTypeDecl {
                name: label.name.clone(),
                line: label.span.line,
                col_start: label.span.col_start as u32,
                col_end: label.span.col_end as u32,
                scope_path: meta.scope_path.clone(),
                owner_module: meta.owner_module.clone(),
                declaration: meta.declaration.clone(),
                fields: Vec::new(),
            },
        }
    }

    fn add_field(&mut self, field: StructFieldDecl) {
        if self
            .decl
            .fields
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(&field.name))
        {
            return;
        }
        self.decl.fields.push(field);
    }

    fn finish(self) -> StructTypeDecl {
        self.decl
    }
}

#[derive(Debug, Clone)]
struct ActiveRepeatDecl {
    symbol_name: Option<String>,
    line: u32,
    col_start: u32,
    col_end: u32,
    scope_path: String,
    owner_module: Option<String>,
    declaration: String,
    fields: Vec<StructFieldDecl>,
}

impl ActiveRepeatDecl {
    fn new(label: Option<&Label>, line: u32, meta: &SymbolBuildMeta) -> Self {
        let (symbol_name, col_start, col_end) = match label {
            Some(label) => (
                Some(label.name.clone()),
                label.span.col_start as u32,
                label.span.col_end as u32,
            ),
            None => (None, 1, 1),
        };
        Self {
            symbol_name,
            line,
            col_start,
            col_end,
            scope_path: meta.scope_path.clone(),
            owner_module: meta.owner_module.clone(),
            declaration: meta.declaration.clone(),
            fields: Vec::new(),
        }
    }

    fn add_field(&mut self, field: StructFieldDecl) {
        if self
            .fields
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(&field.name))
        {
            return;
        }
        self.fields.push(field);
    }

    fn finish(self) -> Option<RepetitionStructDecl> {
        let symbol_name = self.symbol_name?;
        if self.fields.is_empty() {
            return None;
        }
        Some(RepetitionStructDecl {
            symbol_name,
            line: self.line,
            col_start: self.col_start,
            col_end: self.col_end,
            scope_path: self.scope_path,
            owner_module: self.owner_module,
            declaration: self.declaration,
            fields: self.fields,
        })
    }
}

fn build_struct_field_decl(label: &Label, declaration: &str) -> StructFieldDecl {
    StructFieldDecl {
        name: label.name.clone(),
        line: label.span.line,
        col_start: label.span.col_start as u32,
        col_end: label.span.col_end as u32,
        declaration: declaration.to_string(),
    }
}

fn build_typed_symbol_decl(
    label: &Label,
    type_name: String,
    line: u32,
    meta: &SymbolBuildMeta,
) -> TypedSymbolDecl {
    TypedSymbolDecl {
        name: label.name.clone(),
        type_name,
        line,
        col_start: label.span.col_start as u32,
        col_end: label.span.col_end as u32,
        scope_path: meta.scope_path.clone(),
        owner_module: meta.owner_module.clone(),
        visibility: classify_visibility(&label.name),
        declaration: meta.declaration.clone(),
    }
}

fn typed_symbol_type_from_statement(mnemonic: &str, operands: &[Expr]) -> Option<String> {
    match mnemonic.to_ascii_lowercase().as_str() {
        ".const" | ".var" | ".set" => {}
        _ => return None,
    }
    typed_symbol_type_from_expr(operands.first()?)
}

fn typed_symbol_type_from_assignment(op: AssignOp, expr: &Expr) -> Option<String> {
    match op {
        AssignOp::Const | AssignOp::Var | AssignOp::VarIfUndef => {}
        _ => return None,
    }
    typed_symbol_type_from_expr(expr)
}

fn typed_symbol_type_from_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StructLiteral { type_name, .. } => Some(type_name.clone()),
        Expr::Identifier(name, _) | Expr::Register(name, _) => Some(name.clone()),
        _ => None,
    }
}

fn build_symbol(
    name: String,
    kind: SymbolKind,
    line: u32,
    col_start: u32,
    meta: SymbolBuildMeta,
) -> SymbolDecl {
    let col_end = col_start.saturating_add(name.len() as u32);
    let visibility = classify_visibility(&name);
    let detail = format!(
        "{} in {} scope",
        kind.as_str(),
        if meta.scope_path.is_empty() {
            "global"
        } else {
            "nested"
        }
    );
    SymbolDecl {
        name,
        kind,
        line,
        col_start,
        col_end,
        scope_path: meta.scope_path,
        owner_module: meta.owner_module,
        visibility,
        detail,
        declaration: meta.declaration,
        value_excerpt: meta.value_excerpt,
    }
}

#[derive(Debug, Clone)]
struct SymbolBuildMeta {
    scope_path: String,
    owner_module: Option<String>,
    declaration: String,
    value_excerpt: Option<String>,
}

fn build_import_decl(
    module_id: String,
    alias: Option<String>,
    items: &[UseItem],
    line: u32,
    owner_module: Option<String>,
) -> UseImportDecl {
    let wildcard = items.len() == 1 && items[0].name == "*" && items[0].alias.is_none();
    let mapped_items = if wildcard {
        Vec::new()
    } else {
        items
            .iter()
            .map(|item| UseImportItemDecl {
                source_name: item.name.clone(),
                local_name: item.alias.clone().unwrap_or_else(|| item.name.clone()),
            })
            .collect()
    };
    UseImportDecl {
        module_id,
        alias,
        wildcard,
        items: mapped_items,
        line,
        owner_module,
    }
}

fn classify_directive_symbol_kind(mnemonic: &str) -> Option<SymbolKind> {
    match mnemonic.to_ascii_lowercase().as_str() {
        ".module" => Some(SymbolKind::Module),
        ".namespace" => Some(SymbolKind::Namespace),
        ".macro" => Some(SymbolKind::Macro),
        ".section" | ".segment" => Some(SymbolKind::Section),
        _ => None,
    }
}

fn directive_symbol_name(mnemonic: &str, operand_name: Option<String>) -> String {
    if let Some(name) = operand_name {
        return name;
    }
    mnemonic.to_string()
}

#[derive(Debug, Default)]
struct ScopeState {
    modules: Vec<String>,
    namespaces: Vec<String>,
    macros: Vec<String>,
    sections: Vec<String>,
}

impl ScopeState {
    fn path(&self) -> String {
        let mut parts = Vec::new();
        if let Some(module) = self.modules.last() {
            parts.push(format!("module:{module}"));
        }
        for namespace in &self.namespaces {
            parts.push(format!("namespace:{namespace}"));
        }
        for section in &self.sections {
            parts.push(format!("section:{section}"));
        }
        for macro_name in &self.macros {
            parts.push(format!("macro:{macro_name}"));
        }
        parts.join(" / ")
    }

    fn current_module(&self) -> Option<String> {
        self.modules.last().cloned()
    }
}

fn apply_scope_transition(ast: &LineAst, scope: &mut ScopeState) {
    let LineAst::Statement {
        mnemonic, operands, ..
    } = ast
    else {
        return;
    };
    let Some(mnemonic) = mnemonic else {
        return;
    };
    match mnemonic.to_ascii_lowercase().as_str() {
        ".module" => {
            if let Some(name) = operand_name(operands) {
                scope.modules.push(name);
            }
        }
        ".endmodule" => {
            scope.modules.pop();
        }
        ".namespace" => {
            if let Some(name) = operand_name(operands) {
                scope.namespaces.push(name);
            }
        }
        ".endnamespace" => {
            scope.namespaces.pop();
        }
        ".macro" => {
            if let Some(name) = operand_name(operands) {
                scope.macros.push(name);
            }
        }
        ".endmacro" => {
            scope.macros.pop();
        }
        ".section" | ".segment" => {
            if let Some(name) = operand_name(operands) {
                scope.sections.push(name);
            }
        }
        ".endsection" => {
            scope.sections.pop();
        }
        _ => {}
    }
}

fn statement_operand_name(ast: &LineAst) -> Option<String> {
    let LineAst::Statement { operands, .. } = ast else {
        return None;
    };
    operand_name(operands)
}

fn operand_name(operands: &[Expr]) -> Option<String> {
    let first = operands.first()?;
    match first {
        Expr::Identifier(name, _) | Expr::Register(name, _) | Expr::Number(name, _) => {
            Some(name.clone())
        }
        Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
        _ => expr_text(first),
    }
}

fn classify_visibility(name: &str) -> SymbolVisibility {
    if name.starts_with('.') || name.starts_with('_') {
        SymbolVisibility::Local
    } else {
        SymbolVisibility::Public
    }
}

fn assignment_value_excerpt(line: &str) -> Option<String> {
    let (_, rhs) = line.split_once('=')?;
    let value = rhs.split(';').next().unwrap_or_default().trim();
    if value.is_empty() {
        None
    } else {
        Some(truncate_chars(value, 96))
    }
}

fn declaration_snippet(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        truncate_chars(trimmed, 96)
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in input.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_state_collects_cpu_transitions_and_symbols() {
        let registry = crate::build_default_registry();
        let mut state = DocumentState::new(
            "file:///tmp/test.asm".to_string(),
            None,
            1,
            ".cpu 6502\nstart: nop\nvalue = 1\n".to_string(),
        );
        state.refresh_derived_state(&registry);
        assert_eq!(state.cpu_transitions.len(), 1);
        assert!(state
            .symbols
            .iter()
            .any(|symbol| symbol.name.eq_ignore_ascii_case("start")));
        assert!(state
            .symbols
            .iter()
            .any(|symbol| symbol.name.eq_ignore_ascii_case("value")));
    }

    #[test]
    fn document_state_extracts_struct_types_and_typed_symbols() {
        let registry = crate::build_default_registry();
        let mut state = DocumentState::new(
            "file:///tmp/test_structs.asm".to_string(),
            None,
            1,
            "Point .struct\nx .byte ?\ny .word ?\n.endstruct\npt .var Point\np0 := Point { x: 1, y: 2 }\n".to_string(),
        );
        state.refresh_derived_state(&registry);
        assert_eq!(state.struct_types.len(), 1);
        assert!(state.struct_types[0].name.eq_ignore_ascii_case("Point"));
        assert_eq!(state.struct_types[0].fields.len(), 2);
        assert!(state.struct_types[0].fields[0]
            .name
            .eq_ignore_ascii_case("x"));
        assert!(state.struct_types[0].fields[1]
            .name
            .eq_ignore_ascii_case("y"));
        assert!(state
            .typed_symbols
            .iter()
            .any(|symbol| symbol.name.eq_ignore_ascii_case("pt")
                && symbol.type_name.eq_ignore_ascii_case("Point")));
        assert!(state
            .typed_symbols
            .iter()
            .any(|symbol| symbol.name.eq_ignore_ascii_case("p0")
                && symbol.type_name.eq_ignore_ascii_case("Point")));
    }

    #[test]
    fn document_state_extracts_labeled_bfor_fields() {
        let registry = crate::build_default_registry();
        let mut state = DocumentState::new(
            "file:///tmp/test_repeat.asm".to_string(),
            None,
            1,
            "points .bfor i in 0..=1\nx .byte i\ny .byte i + 1\n.endfor\n".to_string(),
        );
        state.refresh_derived_state(&registry);
        assert_eq!(state.repetition_structs.len(), 1);
        let repeat = &state.repetition_structs[0];
        assert!(repeat.symbol_name.eq_ignore_ascii_case("points"));
        assert_eq!(repeat.fields.len(), 2);
        assert!(repeat.fields[0].name.eq_ignore_ascii_case("x"));
        assert!(repeat.fields[1].name.eq_ignore_ascii_case("y"));
    }
}
