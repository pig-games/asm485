// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;
use crate::core::asm_value::StructDef;
use crate::core::assembler::scope::{ScopeKind, ScopePopError};
use crate::core::symbol_table::SymbolTableResult;

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
            "STRUCT" => Some(self.begin_struct_directive_ast(operands)),
            "ENDSTRUCT" => Some(self.end_struct_directive_ast(operands)),
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

    pub(crate) fn process_struct_mode_statement_ast(
        &mut self,
        label: Option<&Label>,
        mnemonic: Option<&str>,
        operands: &[Expr],
    ) -> LineStatus {
        let Some(name) = mnemonic else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "invalid field directive in struct body",
                None,
            );
        };
        if !name.starts_with('.') {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "invalid field directive in struct body",
                None,
            );
        }

        let upper = name.to_ascii_uppercase();
        let directive = upper.trim_start_matches('.');
        match directive {
            "ENDSTRUCT" => {
                if label.is_some() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "label not allowed on .endstruct",
                        None,
                    );
                }
                self.end_struct_directive_ast(operands)
            }
            "BYTE" | "DB" | "WORD" | "DW" | "LONG" | "RES" => {
                self.struct_field_directive_ast(label, directive, operands)
            }
            _ => self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "invalid field directive in struct body",
                None,
            ),
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

    pub(crate) fn begin_struct_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if self.in_struct_definition() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "nested .struct is not supported",
                None,
            );
        }

        let struct_name = if let Some(label) = self.label.clone() {
            if !operands.is_empty() {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Expected either '<name> .struct' or '.struct <name>', not both",
                    None,
                );
            }
            label
        } else {
            match operands {
                [Expr::Identifier(name, _)] | [Expr::Register(name, _)] => name.clone(),
                [] => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Missing struct name before .struct",
                        None,
                    );
                }
                _ => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Expected .struct <name>",
                        None,
                    );
                }
            }
        };

        if struct_name.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing struct name before .struct",
                None,
            );
        }
        let full_name = self.scoped_define_name(&struct_name);
        self.active_struct = Some(ActiveStructDefinition::new(
            full_name,
            self.current_line_num,
        ));
        LineStatus::Ok
    }

    pub(crate) fn end_struct_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unexpected operands for .endstruct",
                None,
            );
        }
        let Some(active_struct) = self.active_struct.take() else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".endstruct without matching .struct",
                None,
            );
        };

        let struct_def = StructDef {
            name: active_struct.name.clone(),
            fields: active_struct.fields.clone(),
            size: active_struct.size,
        };
        if let Err(err) = self.struct_table.register(struct_def) {
            let message = match err {
                crate::core::StructTableError::Duplicate(name) => {
                    format!("struct has already been defined: {name}")
                }
            };
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &message, None);
        }

        if let Some(status) = self.define_struct_symbol_ast(&active_struct.name, active_struct.size)
        {
            return status;
        }
        for field in &active_struct.fields {
            let field_name = format!("{}.{}", active_struct.name, field.name);
            if let Some(status) = self.define_struct_symbol_ast(&field_name, field.offset) {
                return status;
            }
        }
        LineStatus::Ok
    }

    fn struct_field_directive_ast(
        &mut self,
        label: Option<&Label>,
        directive: &str,
        operands: &[Expr],
    ) -> LineStatus {
        let field_label = match label {
            Some(label) => label,
            None => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Struct field declarations require a label",
                    None,
                );
            }
        };
        let field_size = match directive {
            "BYTE" | "DB" => match operands {
                [Expr::Placeholder(_)] => 1,
                _ => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Struct .byte/.db field must use placeholder '?'",
                        None,
                    );
                }
            },
            "WORD" | "DW" => match operands {
                [Expr::Placeholder(_)] => 2,
                _ => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Struct .word/.dw field must use placeholder '?'",
                        None,
                    );
                }
            },
            "LONG" => match operands {
                [Expr::Placeholder(_)] => 4,
                _ => {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Struct .long field must use placeholder '?'",
                        None,
                    );
                }
            },
            "RES" => {
                let expr = match operands {
                    [expr] => expr,
                    _ => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Struct .res field requires one size expression",
                            None,
                        );
                    }
                };
                match self.eval_expr_for_non_negative_directive(expr, ".res field size") {
                    Ok(value) => value,
                    Err(err) => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            err.error.kind(),
                            err.error.message(),
                            None,
                            err.span,
                        );
                    }
                }
            }
            _ => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "invalid field directive in struct body",
                    None,
                );
            }
        };

        let Some(active_struct) = self.active_struct.as_ref() else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".struct state is not active",
                None,
            );
        };
        if active_struct
            .fields
            .iter()
            .any(|field| field.name.eq_ignore_ascii_case(field_label.name.as_str()))
        {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Struct field has already been defined",
                Some(field_label.name.as_str()),
                field_label.span,
            );
        }

        let active_struct = self
            .active_struct
            .as_mut()
            .expect("active struct checked above");
        let offset = active_struct.size;
        let size = match offset.checked_add(field_size) {
            Some(size) => size,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Struct size overflow exceeds supported range",
                    None,
                    field_label.span,
                );
            }
        };

        active_struct.fields.push(StructField {
            name: field_label.name.clone(),
            offset,
            size: field_size,
        });
        active_struct.size = size;

        LineStatus::Ok
    }

    fn define_struct_symbol_ast(&mut self, name: &str, value: u32) -> Option<LineStatus> {
        let result = if self.pass == 1 {
            self.symbols.add(
                name,
                value,
                false,
                self.current_visibility(),
                self.symbol_scope.module_active.as_deref(),
            )
        } else {
            self.symbols.update(name, value)
        };
        match result {
            SymbolTableResult::Ok => None,
            SymbolTableResult::Duplicate => Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "symbol has already been defined",
                Some(name),
            )),
            SymbolTableResult::TableFull => Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "could not add symbol, table full",
                Some(name),
            )),
            SymbolTableResult::NotFound => {
                let add_result = self.symbols.add(
                    name,
                    value,
                    false,
                    self.current_visibility(),
                    self.symbol_scope.module_active.as_deref(),
                );
                match add_result {
                    SymbolTableResult::Ok => None,
                    SymbolTableResult::Duplicate => Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "symbol has already been defined",
                        Some(name),
                    )),
                    SymbolTableResult::TableFull => Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "could not add symbol, table full",
                        Some(name),
                    )),
                    SymbolTableResult::NotFound => Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "symbol has not been defined",
                        Some(name),
                    )),
                }
            }
        }
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
