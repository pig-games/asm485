// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Assembler macro processor implementing 64tass-style .macro/.endmacro expansion.

use crate::core::parser::StatementSignature;
use crate::core::text_utils::to_upper;
use std::collections::{HashMap, HashSet};

#[path = "macro_processor_args_subst.rs"]
mod macro_processor_args_subst;
#[path = "macro_processor_definitions.rs"]
mod macro_processor_definitions;
#[path = "macro_processor_directives.rs"]
mod macro_processor_directives;
#[path = "macro_processor_statements.rs"]
mod macro_processor_statements;
use macro_processor_args_subst::{parse_macro_params, substitute_line};
use macro_processor_definitions::{
    build_macro_args, format_macro_block_start, parse_macro_def_line, parse_macro_end_line,
    parse_macro_invocation,
};
use macro_processor_directives::{
    parse_namespace_directive, parse_statement_directive, parse_visibility_directive,
    NamespaceDirective, StatementDirective, VisibilityDirective,
};
use macro_processor_statements::{expand_statement_invocation, parse_statement_def_line};

#[derive(Debug, Clone)]
pub struct MacroError {
    message: String,
    line: Option<u32>,
    column: Option<usize>,
}

impl MacroError {
    pub fn new(message: impl Into<String>, line: Option<u32>, column: Option<usize>) -> Self {
        Self {
            message: message.into(),
            line,
            column,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn line(&self) -> Option<u32> {
        self.line
    }

    pub fn column(&self) -> Option<usize> {
        self.column
    }
}

#[derive(Debug, Clone)]
struct MacroParam {
    name: Option<String>,
    default: Option<String>,
    #[allow(dead_code)]
    type_name: Option<String>,
}

#[derive(Debug, Clone)]
struct MacroDef {
    params: Vec<MacroParam>,
    body: Vec<String>,
    wrap_scope: bool,
    visibility: CompileTimeVisibility,
}

#[derive(Debug, Clone)]
struct StatementDef {
    keyword: String,
    signature: StatementSignature,
    body: Vec<String>,
    visibility: CompileTimeVisibility,
}

#[derive(Debug, Clone)]
struct MacroInvocation {
    label: Option<String>,
    resolved_key: String,
    args: Vec<String>,
    full_list: String,
    indent: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacroKind {
    Macro,
    Segment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileTimeVisibility {
    Public,
    Private,
}

impl CompileTimeVisibility {
    fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Debug, Clone)]
struct MacroArgs {
    positional: Vec<String>,
    named: HashMap<String, String>,
    full_list: String,
}

/// Opaque collection of macro/segment/statement definitions exported by a module.
#[derive(Debug, Clone, Default)]
pub struct MacroExports {
    macros: HashMap<String, MacroDef>,
    statements: HashMap<String, Vec<StatementDef>>,
}

impl MacroExports {
    /// All exported macro/segment/statement names (uppercased).
    pub fn names(&self) -> HashSet<String> {
        let mut names: HashSet<String> = self.macros.keys().cloned().collect();
        names.extend(self.statements.keys().cloned());
        names
    }

    /// Exported compile-time symbol visibilities (uppercased names).
    pub fn visibility_index(&self) -> HashMap<String, CompileTimeVisibility> {
        let mut vis = HashMap::new();
        for (name, def) in &self.macros {
            vis.insert(name.clone(), def.visibility);
        }
        for (name, defs) in &self.statements {
            let statement_vis = if defs.iter().any(|def| def.visibility.is_public()) {
                CompileTimeVisibility::Public
            } else {
                CompileTimeVisibility::Private
            };
            vis.entry(name.clone())
                .and_modify(|entry| {
                    if statement_vis.is_public() {
                        *entry = CompileTimeVisibility::Public;
                    }
                })
                .or_insert(statement_vis);
        }
        vis
    }
}

pub struct MacroProcessor {
    macros: HashMap<String, MacroDef>,
    statements: HashMap<String, Vec<StatementDef>>,
    injected_names: HashSet<String>,
    visibility_stack: Vec<CompileTimeVisibility>,
    namespace_stack: Vec<Option<String>>,
    max_depth: usize,
}

impl Default for MacroProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl MacroProcessor {
    pub fn new() -> Self {
        Self {
            macros: HashMap::new(),
            statements: HashMap::new(),
            injected_names: HashSet::new(),
            visibility_stack: vec![CompileTimeVisibility::Private],
            namespace_stack: Vec::new(),
            max_depth: 64,
        }
    }

    /// Inject selected exports by name (for selective `.use` imports).
    pub fn inject_from(&mut self, exports: &MacroExports, names: &[String]) {
        for name in names {
            let upper = name.to_ascii_uppercase();
            if let Some(def) = exports.macros.get(&upper) {
                if def.visibility.is_public() {
                    self.injected_names.insert(upper.clone());
                    self.macros.insert(upper.clone(), def.clone());
                }
            }
            if let Some(defs) = exports.statements.get(&upper) {
                let public_defs: Vec<StatementDef> = defs
                    .iter()
                    .filter(|def| def.visibility.is_public())
                    .cloned()
                    .collect();
                if !public_defs.is_empty() {
                    self.injected_names.insert(upper.clone());
                    self.statements.insert(upper.clone(), public_defs);
                }
            }
        }
    }

    /// Inject all exports (for wildcard `.use` without an items list).
    pub fn inject_all(&mut self, exports: &MacroExports) {
        for (name, def) in &exports.macros {
            if def.visibility.is_public() {
                self.injected_names.insert(name.clone());
                self.macros.insert(name.clone(), def.clone());
            }
        }
        for (name, defs) in &exports.statements {
            let public_defs: Vec<StatementDef> = defs
                .iter()
                .filter(|def| def.visibility.is_public())
                .cloned()
                .collect();
            if !public_defs.is_empty() {
                self.injected_names.insert(name.clone());
                self.statements.insert(name.clone(), public_defs);
            }
        }
    }

    /// Inject all exports under a qualifier (for bare `.use module` and aliases).
    pub fn inject_qualified(&mut self, exports: &MacroExports, qualifier: &str) {
        for (name, def) in &exports.macros {
            if def.visibility.is_public() {
                let qualified = to_upper(&format!("{qualifier}.{name}"));
                self.injected_names.insert(qualified.clone());
                self.macros.insert(qualified, def.clone());
            }
        }
        for (name, defs) in &exports.statements {
            let public_defs: Vec<StatementDef> = defs
                .iter()
                .filter(|def| def.visibility.is_public())
                .cloned()
                .collect();
            if !public_defs.is_empty() {
                let qualified = to_upper(&format!("{qualifier}.{name}"));
                self.injected_names.insert(qualified.clone());
                self.statements.insert(qualified, public_defs);
            }
        }
    }

    /// Take the natively-defined (not injected) exports from this processor.
    pub fn take_native_exports(&mut self) -> MacroExports {
        let all_macros = std::mem::take(&mut self.macros);
        let all_statements = std::mem::take(&mut self.statements);
        let injected = &self.injected_names;
        let macros = all_macros
            .into_iter()
            .filter(|(name, _)| !injected.contains(name))
            .collect();
        let statements = all_statements
            .into_iter()
            .filter(|(name, _)| !injected.contains(name))
            .collect();
        MacroExports { macros, statements }
    }

    pub fn expand(&mut self, lines: &[String]) -> Result<Vec<String>, MacroError> {
        self.expand_lines(lines, 0)
    }

    fn current_visibility(&self) -> CompileTimeVisibility {
        self.visibility_stack
            .last()
            .copied()
            .unwrap_or(CompileTimeVisibility::Private)
    }

    fn push_visibility(&mut self) {
        let current = self.current_visibility();
        self.visibility_stack.push(current);
    }

    fn pop_visibility(&mut self) {
        if self.visibility_stack.len() > 1 {
            self.visibility_stack.pop();
        }
    }

    fn set_visibility(&mut self, visibility: CompileTimeVisibility) {
        if let Some(current) = self.visibility_stack.last_mut() {
            *current = visibility;
        } else {
            self.visibility_stack.push(visibility);
        }
    }

    fn push_namespace_scope(&mut self, name: Option<String>) {
        self.namespace_stack
            .push(name.map(|part| part.to_ascii_uppercase()));
    }

    fn pop_namespace_scope(&mut self) {
        self.namespace_stack.pop();
    }

    fn current_namespace_parts(&self) -> Vec<&str> {
        self.namespace_stack
            .iter()
            .filter_map(|part| part.as_deref())
            .collect()
    }

    fn qualify_macro_name(&self, name: &str) -> String {
        let mut parts = self.current_namespace_parts();
        let macro_name = name.to_ascii_uppercase();
        if parts.is_empty() {
            macro_name
        } else {
            parts.push(macro_name.as_str());
            parts.join(".")
        }
    }

    fn apply_visibility_directive(&mut self, directive: VisibilityDirective) {
        match directive {
            VisibilityDirective::SetPublic => self.set_visibility(CompileTimeVisibility::Public),
            VisibilityDirective::SetPrivate => self.set_visibility(CompileTimeVisibility::Private),
            VisibilityDirective::PushScope => self.push_visibility(),
            VisibilityDirective::PopScope => self.pop_visibility(),
        }
    }

    fn expand_lines(&mut self, lines: &[String], depth: usize) -> Result<Vec<String>, MacroError> {
        if depth > self.max_depth {
            return Err(MacroError::new(
                "Expansion exceeded maximum depth (macro or statement)",
                None,
                None,
            ));
        }

        let mut out = Vec::new();
        let mut current: Option<(String, MacroDef, MacroKind)> = None;
        let mut current_statement: Option<StatementDef> = None;
        let mut skip_statement_body = false;

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx as u32 + 1;
            let (code, _) = crate::core::text_utils::split_comment(line);

            if current.is_none() && current_statement.is_none() && !skip_statement_body {
                if let Some(directive) = parse_visibility_directive(code) {
                    self.apply_visibility_directive(directive);
                }
                if let Some(namespace_directive) = parse_namespace_directive(code) {
                    match namespace_directive {
                        NamespaceDirective::Push(name) => self.push_namespace_scope(name),
                        NamespaceDirective::Pop => self.pop_namespace_scope(),
                    }
                }
            }

            if let Some((name, params, kind)) = parse_macro_def_line(code, line_num)? {
                if current.is_some() {
                    return Err(MacroError::new(
                        "Nested .macro/.segment definitions are not supported",
                        Some(line_num),
                        Some(1),
                    ));
                }
                if current_statement.is_some() {
                    return Err(MacroError::new(
                        "Nested .statement definitions are not supported",
                        Some(line_num),
                        Some(1),
                    ));
                }
                if name.is_empty() {
                    return Err(MacroError::new(
                        "Macro name is required before .macro",
                        Some(line_num),
                        Some(1),
                    ));
                }
                let macro_key = self.qualify_macro_name(&name);
                if self.macros.contains_key(&macro_key) {
                    return Err(MacroError::new(
                        "Macro already defined",
                        Some(line_num),
                        Some(1),
                    ));
                }
                let param_defs = parse_macro_params(&params, line_num)?;
                let wrap_scope = kind == MacroKind::Macro;
                current = Some((
                    macro_key,
                    MacroDef {
                        params: param_defs,
                        body: Vec::new(),
                        wrap_scope,
                        visibility: self.current_visibility(),
                    },
                    kind,
                ));
                continue;
            }

            if let Some(kind) = parse_macro_end_line(code) {
                let Some((name, def, active_kind)) = current.take() else {
                    let message = match kind {
                        MacroKind::Macro => ".endmacro found without matching .macro",
                        MacroKind::Segment => ".endsegment found without matching .segment",
                    };
                    return Err(MacroError::new(message, Some(line_num), Some(1)));
                };
                if kind != active_kind {
                    let message = match kind {
                        MacroKind::Macro => "Expected .endsegment for .segment",
                        MacroKind::Segment => "Expected .endmacro for .macro",
                    };
                    return Err(MacroError::new(message, Some(line_num), Some(1)));
                }
                self.macros.insert(name, def);
                continue;
            }

            if skip_statement_body {
                if let Some(StatementDirective::End) = parse_statement_directive(code) {
                    skip_statement_body = false;
                }
                continue;
            }

            if let Some(kind) = parse_statement_directive(code) {
                match kind {
                    StatementDirective::Def => {
                        if current_statement.is_some() {
                            return Err(MacroError::new(
                                "Nested .statement definitions are not supported",
                                Some(line_num),
                                Some(1),
                            ));
                        }
                        if current.is_some() {
                            return Err(MacroError::new(
                                "Cannot define .statement inside .macro/.segment",
                                Some(line_num),
                                Some(1),
                            ));
                        }
                        match parse_statement_def_line(code, line_num) {
                            Ok((keyword, signature)) => {
                                current_statement = Some(StatementDef {
                                    keyword,
                                    signature,
                                    body: Vec::new(),
                                    visibility: self.current_visibility(),
                                });
                                continue;
                            }
                            Err(err) => {
                                return Err(err);
                            }
                        }
                    }
                    StatementDirective::End => {
                        if let Some(def) = current_statement.take() {
                            let key = to_upper(&def.keyword);
                            self.statements.entry(key).or_default().push(def);
                            continue;
                        }
                        out.push(line.clone());
                        continue;
                    }
                }
            }

            if let Some(def) = current_statement.as_mut() {
                def.body.push(line.clone());
                continue;
            }

            if let Some((name, def, _kind)) = current.as_mut() {
                let _ = name;
                def.body.push(line.clone());
                continue;
            }

            if let Some(inv) =
                parse_macro_invocation(code, &self.macros, &self.namespace_stack, line_num)?
            {
                let def = self
                    .macros
                    .get(&inv.resolved_key)
                    .cloned()
                    .ok_or_else(|| MacroError::new("Unknown macro", Some(line_num), Some(1)))?;
                let args = build_macro_args(&def, &inv);
                let mut expanded = Vec::new();
                if def.wrap_scope {
                    expanded.push(format_macro_block_start(&inv));
                }
                for body_line in &def.body {
                    expanded.push(substitute_line(body_line, &args));
                }
                if def.wrap_scope {
                    expanded.push(format!("{}{}", inv.indent, ".endblock"));
                } else if let Some(label) = &inv.label {
                    if let Some(first) = expanded.first_mut() {
                        let trimmed = first.trim_start();
                        if trimmed.is_empty() {
                            *first = label.clone();
                        } else {
                            *first = format!("{label} {trimmed}");
                        }
                    } else {
                        expanded.push(label.clone());
                    }
                }
                let nested = self.expand_lines(&expanded, depth + 1)?;
                out.extend(nested);
                continue;
            }

            if let Some(expanded) = expand_statement_invocation(code, line_num, depth, self)? {
                out.extend(expanded);
                continue;
            }

            out.push(line.clone());
        }

        if let Some((_name, _def, kind)) = current {
            let message = match kind {
                MacroKind::Macro => "Missing .endmacro for macro definition",
                MacroKind::Segment => "Missing .endsegment for segment definition",
            };
            return Err(MacroError::new(message, None, None));
        }

        if current_statement.is_some() {
            return Err(MacroError::new(
                "Missing .endstatement for statement definition",
                None,
                None,
            ));
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{CompileTimeVisibility, MacroProcessor};

    #[test]
    fn visibility_index_tracks_public_and_private_macros() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".pub".to_string(),
            "PUB .macro".to_string(),
            "    .byte 1".to_string(),
            ".endmacro".to_string(),
            ".priv".to_string(),
            "PRIV .macro".to_string(),
            "    .byte 2".to_string(),
            ".endmacro".to_string(),
        ];

        let _ = mp.expand(&lines).expect("expand");
        let exports = mp.take_native_exports();
        let visibility = exports.visibility_index();

        assert_eq!(visibility.get("PUB"), Some(&CompileTimeVisibility::Public));
        assert_eq!(
            visibility.get("PRIV"),
            Some(&CompileTimeVisibility::Private)
        );
    }

    #[test]
    fn inject_all_imports_only_public_macros() {
        let mut producer = MacroProcessor::new();
        let lines = vec![
            ".pub".to_string(),
            "PUB .macro".to_string(),
            "    .byte 1".to_string(),
            ".endmacro".to_string(),
            ".priv".to_string(),
            "PRIV .macro".to_string(),
            "    .byte 2".to_string(),
            ".endmacro".to_string(),
        ];

        let _ = producer.expand(&lines).expect("expand");
        let exports = producer.take_native_exports();

        let mut consumer = MacroProcessor::new();
        consumer.inject_all(&exports);

        assert!(consumer.macros.contains_key("PUB"));
        assert!(!consumer.macros.contains_key("PRIV"));
    }

    #[test]
    fn expands_simple_macro_with_params() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "COPY .macro src, dst".to_string(),
            "    lda .src".to_string(),
            "    sta .dst".to_string(),
            ".endmacro".to_string(),
            "    .COPY $12, $34".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".block"));
        assert!(out.contains(&"    lda $12".to_string()));
        assert!(out.contains(&"    sta $34".to_string()));
        assert!(out.iter().any(|line| line.trim() == ".endblock"));
    }

    #[test]
    fn expands_named_and_default_params() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "M .macro first, second=2".to_string(),
            "    .byte .first, .second".to_string(),
            ".endmacro".to_string(),
            "    .M 1".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 1, 2".to_string()));
    }

    #[test]
    fn expands_text_and_list_refs() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "MSG .macro text".to_string(),
            "    .byte @1".to_string(),
            "    .word .@".to_string(),
            ".endmacro".to_string(),
            "    .MSG 1+2".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 1+2".to_string()));
        assert!(out.contains(&"    .word 1+2".to_string()));
    }

    #[test]
    fn expands_segment_without_scope_block() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "INLINE .segment val".to_string(),
            "    .byte .val".to_string(),
            ".endsegment".to_string(),
            "    .INLINE 7".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 7".to_string()));
        assert!(!out.iter().any(|line| line.trim() == ".block"));
        assert!(!out.iter().any(|line| line.trim() == ".endblock"));
    }

    #[test]
    fn expands_directive_first_macro_with_paren_call() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".macro COPY(src, dst)".to_string(),
            "    lda .src".to_string(),
            "    sta .dst".to_string(),
            ".endmacro".to_string(),
            "    .COPY($12, $34)".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".block"));
        assert!(out.contains(&"    lda $12".to_string()));
        assert!(out.contains(&"    sta $34".to_string()));
        assert!(out.iter().any(|line| line.trim() == ".endblock"));
    }

    #[test]
    fn expands_zero_arg_macro_with_and_without_parens() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "PING .macro".to_string(),
            "    .byte 1".to_string(),
            ".endmacro".to_string(),
            "    .PING".to_string(),
            "    .PING()".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".block"));
        assert!(out.iter().filter(|line| line.trim() == ".byte 1").count() >= 2);
    }

    #[test]
    fn expands_statement_with_capture() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement LOAD byte:val".to_string(),
            "    .byte .val".to_string(),
            ".endstatement".to_string(),
            "    LOAD 7".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 7".to_string()));
        assert!(!out
            .iter()
            .any(|line| line.trim_start().starts_with(".statement")));
    }

    #[test]
    fn expands_statement_with_keyword_parameterization() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement move.b char:dst \",\" char:src".to_string(),
            "    .byte 'b'".to_string(),
            ".endstatement".to_string(),
            "    move.b a,b".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 'b'".to_string()));
    }

    #[test]
    fn statement_with_label_attaches_correctly() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement LOAD byte:val".to_string(),
            "    .byte .val".to_string(),
            ".endstatement".to_string(),
            "label: LOAD 7".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("label") && line.contains(".byte 7")
        }));
    }

    #[test]
    fn empty_statement_body_expands_to_nothing() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement NOOP".to_string(),
            ".endstatement".to_string(),
            "    NOOP".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(!out.iter().any(|line| line.contains("NOOP")));
    }

    #[test]
    fn statement_longest_keyword_wins() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement MOVE byte:val".to_string(),
            "    .byte .val".to_string(),
            ".endstatement".to_string(),
            ".statement MOVE.B byte:val".to_string(),
            "    .byte .val + 1".to_string(),
            ".endstatement".to_string(),
            "    MOVE.B 3".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 3 + 1".to_string()));
        assert!(!out.contains(&"    .byte 3".to_string()));
    }

    #[test]
    fn statement_numeric_literal_spelling_is_preserved() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement LOAD byte:val".to_string(),
            "    .byte .val".to_string(),
            ".endstatement".to_string(),
            "    LOAD 0ffh".to_string(),
            "    LOAD %1010".to_string(),
            "    LOAD $ff".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte 0ffh".to_string()));
        assert!(out.contains(&"    .byte %1010".to_string()));
        assert!(out.contains(&"    .byte $ff".to_string()));
    }

    #[test]
    fn statement_dollar_hex_ending_in_suffix_chars() {
        // Regression: $BB was misinterpreted because the trailing-B binary
        // suffix heuristic in parse_number fired before the $ prefix check,
        // causing byte-capture matching to fail.
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".statement PUSHB byte:v".to_string(),
            "    .byte .v".to_string(),
            ".endstatement".to_string(),
            "    PUSHB $AA".to_string(),
            "    PUSHB $BB".to_string(),
            "    PUSHB $AB".to_string(),
            "    PUSHB $0B".to_string(),
            "    PUSHB $FB".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.contains(&"    .byte $AA".to_string()), "missing $AA");
        assert!(out.contains(&"    .byte $BB".to_string()), "missing $BB");
        assert!(out.contains(&"    .byte $AB".to_string()), "missing $AB");
        assert!(out.contains(&"    .byte $0B".to_string()), "missing $0B");
        assert!(out.contains(&"    .byte $FB".to_string()), "missing $FB");
    }

    #[test]
    fn resolves_same_macro_name_by_nearest_namespace_scope() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            ".namespace outer".to_string(),
            "BEGIN .macro".to_string(),
            "    .byte 1".to_string(),
            ".endmacro".to_string(),
            "    .BEGIN".to_string(),
            "    .namespace inner".to_string(),
            "BEGIN .macro".to_string(),
            "    .byte 2".to_string(),
            ".endmacro".to_string(),
            "    .BEGIN".to_string(),
            "    .endn".to_string(),
            "    .BEGIN".to_string(),
            ".endn".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        let rendered = out.join("\n");
        assert!(
            rendered.contains(".byte 1\n") || rendered.contains(".byte 1\r\n"),
            "expected outer namespace expansion: {rendered}"
        );
        assert!(
            rendered.contains(".byte 2\n") || rendered.contains(".byte 2\r\n"),
            "expected inner namespace expansion: {rendered}"
        );
        let one_count = out.iter().filter(|line| line.trim() == ".byte 1").count();
        let two_count = out.iter().filter(|line| line.trim() == ".byte 2").count();
        assert_eq!(one_count, 2, "outer macro should be selected twice");
        assert_eq!(two_count, 1, "inner macro should be selected once");
    }

    #[test]
    fn falls_back_to_global_macro_when_namespace_local_not_found() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "GLOBAL .macro".to_string(),
            "    .byte 9".to_string(),
            ".endmacro".to_string(),
            ".namespace outer".to_string(),
            "    .GLOBAL".to_string(),
            ".endn".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".byte 9"));
    }

    #[test]
    fn supports_name_first_namespace_spelling_for_macro_resolution() {
        let mut mp = MacroProcessor::new();
        let lines = vec![
            "outer .namespace".to_string(),
            "BEGIN .macro".to_string(),
            "    .byte 3".to_string(),
            ".endmacro".to_string(),
            "    .BEGIN".to_string(),
            ".endn".to_string(),
        ];
        let out = mp.expand(&lines).expect("expand");
        assert!(out.iter().any(|line| line.trim() == ".byte 3"));
    }
}
