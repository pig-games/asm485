// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;
use crate::core::assembler::scope::{ScopeKind, ScopePopError};

impl<'a> AsmLine<'a> {
    pub(crate) fn route_scope_directive_ast(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> Option<LineStatus> {
        match directive {
            "MODULE" => Some(self.begin_module_directive_ast(operands)),
            "ENDMODULE" => Some(self.end_module_directive_ast(operands)),
            "BLOCK" => Some(self.begin_block_directive_ast(operands)),
            "ENDBLOCK" | "BEND" => {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for block close directive",
                        None,
                    ));
                }
                Some(self.close_scope(
                    ScopeKind::Block,
                    ".endblock",
                    ".block",
                    ".endblock found without matching .block",
                ))
            }
            "NAMESPACE" => Some(self.begin_namespace_directive_ast(operands)),
            "ENDN" | "ENDNAMESPACE" => {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for namespace close directive",
                        None,
                    ));
                }
                Some(self.close_scope(
                    ScopeKind::Namespace,
                    ".endnamespace",
                    ".namespace",
                    ".endnamespace found without matching .namespace",
                ))
            }
            "PUB" => {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .pub",
                        None,
                    ));
                }
                self.set_visibility(SymbolVisibility::Public);
                Some(LineStatus::Ok)
            }
            "PRIV" => {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .priv",
                        None,
                    ));
                }
                self.set_visibility(SymbolVisibility::Private);
                Some(LineStatus::Ok)
            }
            _ => None,
        }
    }

    pub(crate) fn begin_module_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() != 1 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing module id for .module",
                None,
            );
        }
        if self.in_module() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Nested .module is not allowed",
                None,
            );
        }
        if self.symbol_scope.scope_stack.depth() > 0 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".module must appear at top level",
                None,
            );
        }
        if self.symbol_scope.top_level_content_seen {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Top-level content must be inside a .module block",
                None,
            );
        }
        let module_id = match operands.first() {
            Some(Expr::Identifier(name, _)) => name.clone(),
            _ => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Invalid module id for .module",
                    None,
                );
            }
        };
        self.symbol_scope.saw_explicit_module = true;
        if self.pass == 1 {
            let res = self.symbols.register_module(&module_id);
            if res == crate::symbol_table::SymbolTableResult::Duplicate {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Duplicate module id",
                    Some(&module_id),
                );
            }
        } else if !self.symbols.has_module(&module_id) {
            let _ = self.symbols.register_module(&module_id);
        }
        if let Err(message) = self
            .symbol_scope
            .scope_stack
            .push_named_with_kind(&module_id, ScopeKind::Module)
        {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                message,
                Some(&module_id),
            );
        }
        self.push_visibility();
        self.symbol_scope.module_active = Some(module_id);
        self.symbol_scope.module_scope_depth = self.symbol_scope.scope_stack.depth();
        self.reset_text_encoding_profile();
        LineStatus::Ok
    }

    pub(crate) fn end_module_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unexpected operands for .endmodule",
                None,
            );
        }
        if self.output_state.in_meta_block {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Cannot close module with open .meta block",
                None,
            );
        }
        if self.in_section() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Cannot close module with open .section block",
                None,
            );
        }
        if self.has_open_encoding_scope() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Cannot close module with open .encode block",
                None,
            );
        }
        if !self.in_module() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".endmodule found without matching .module",
                None,
            );
        }
        if self.symbol_scope.scope_stack.depth() != self.symbol_scope.module_scope_depth {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Cannot close module with open scopes",
                None,
            );
        }
        if !self.symbol_scope.scope_stack.pop() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".endmodule found without matching .module",
                None,
            );
        }
        self.pop_visibility();
        self.symbol_scope.module_active = None;
        self.symbol_scope.module_scope_depth = 0;
        LineStatus::Ok
    }

    pub(crate) fn begin_block_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unexpected operands for .block",
                None,
            );
        }
        if let Some(label) = self.label.clone() {
            if let Err(message) = self
                .symbol_scope
                .scope_stack
                .push_named_with_kind(&label, ScopeKind::Block)
            {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    message,
                    Some(&label),
                );
            }
        } else {
            self.symbol_scope
                .scope_stack
                .push_anonymous_with_kind(ScopeKind::Block);
        }
        self.push_visibility();
        LineStatus::Ok
    }

    pub(crate) fn begin_namespace_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        let namespace_name = match operands {
            [] => {
                if let Some(label) = self.label.clone() {
                    label
                } else {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Missing namespace id for .namespace",
                        None,
                    );
                }
            }
            [Expr::Identifier(name, _)] => name.clone(),
            [_] => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Invalid namespace id for .namespace",
                    None,
                );
            }
            _ => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Expected .namespace <name>",
                    None,
                );
            }
        };
        if let Err(message) = self
            .symbol_scope
            .scope_stack
            .push_named_with_kind(&namespace_name, ScopeKind::Namespace)
        {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                message,
                Some(&namespace_name),
            );
        }
        self.push_visibility();
        LineStatus::Ok
    }

    pub(crate) fn close_scope(
        &mut self,
        expected: ScopeKind,
        close_directive: &str,
        open_directive: &str,
        missing_message: &str,
    ) -> LineStatus {
        match self.symbol_scope.scope_stack.pop_expected(expected) {
            Ok(()) => {
                self.pop_visibility();
                LineStatus::Ok
            }
            Err(ScopePopError::Empty) => self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                missing_message,
                None,
            ),
            Err(ScopePopError::KindMismatch { found, .. }) => self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!(
                    "{} found but current scope was opened by {} (expected {})",
                    close_directive,
                    found.opening_directive(),
                    open_directive
                ),
                None,
            ),
        }
    }
}
