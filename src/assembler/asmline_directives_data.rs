// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

impl<'a> AsmLine<'a> {
    pub(crate) fn route_data_directive_ast(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> Option<LineStatus> {
        match directive {
            "FILL" => Some(self.fill_directive_ast(operands)),
            "ORG" => Some(self.org_directive_ast(operands)),
            "ALIGN" => Some(self.align_directive_ast(operands)),
            "CONST" | "VAR" | "SET" => Some(self.const_var_set_directive_ast(directive, operands)),
            "CPU" => Some(self.cpu_directive_ast(operands)),
            "ENCODE" => Some(self.begin_encode_directive_ast(operands)),
            "ENDENCODE" => Some(self.end_encode_directive_ast(operands)),
            "ENC" => Some(self.set_text_encoding_directive_ast(".enc", operands)),
            "ENCODING" => Some(self.set_text_encoding_directive_ast(".encoding", operands)),
            "CDEF" => Some(self.cdef_directive_ast(operands)),
            "TDEF" => Some(self.tdef_directive_ast(operands)),
            "EDEF" => Some(self.edef_directive_ast(operands)),
            "EMIT" => Some(self.emit_directive_ast(operands)),
            "RES" => Some(self.res_directive_ast(operands)),
            "BYTE" | "DB" => Some(self.store_arg_list_ast(operands, 1, ".byte")),
            "WORD" | "DW" => Some(self.store_arg_list_ast(operands, 2, ".word")),
            "LONG" => Some(self.store_arg_list_ast(operands, 4, ".long")),
            "TEXT" => Some(self.text_directive_ast(operands)),
            "NULL" => Some(self.null_directive_ast(operands)),
            "PTEXT" => Some(self.ptext_directive_ast(operands)),
            "DS" => Some(self.ds_directive_ast(operands)),
            _ => None,
        }
    }

    pub(crate) fn org_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        let expr = match operands.first() {
            Some(expr) => expr,
            None => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Missing expression for ORG",
                    None,
                )
            }
        };
        let val = match self.eval_expr_for_data_directive(expr) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        if let Err(err) = self.validate_program_address(val, ".org", expr_span(expr)) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        if let Some(section_name) = self.layout.current_section.as_deref() {
            if let Some(section) = self.layout.sections.get(section_name) {
                let current_abs = section.start_pc + section.pc;
                if val < current_abs {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".org cannot move backwards inside a section",
                        None,
                    );
                }
            }
        }
        self.start_addr = val;
        self.aux_value = val;
        LineStatus::DirEqu
    }

    pub(crate) fn align_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        let expr = match operands.first() {
            Some(expr) => expr,
            None => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Missing expression for .align",
                    None,
                )
            }
        };
        let val = match self.eval_expr_for_data_directive(expr) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        let align = val;
        if align == 0 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Alignment must be greater than zero",
                None,
            );
        }
        let addr = self.start_addr;
        let pad = (align - (addr % align)) % align;
        if let Err(err) = self.validate_program_span(pad, ".align", expr_span(expr)) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        self.aux_value = pad;
        LineStatus::DirDs
    }

    pub(crate) fn const_var_set_directive_ast(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> LineStatus {
        if self.label.is_none() {
            return self.failure_at(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Must specify symbol before .const/.var/.set",
                None,
                Some(1),
            );
        }
        let expr = match operands.first() {
            Some(expr) => expr,
            None => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Missing expression for .const/.var/.set",
                    None,
                )
            }
        };
        let is_rw = directive == "SET" || directive == "VAR";
        let val = match self.eval_expr_for_data_directive(expr) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        let label = self.label.clone().unwrap_or_default();
        if self.pass == 1 && self.selective_import_conflict(&label) {
            return self.failure_at(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "Symbol conflicts with selective import",
                Some(&label),
                Some(1),
            );
        }
        let full_name = self.scoped_define_name(&label);
        let res = if self.pass == 1 {
            self.symbols.add(
                &full_name,
                val,
                is_rw,
                self.current_visibility(),
                self.symbol_scope.module_active.as_deref(),
            )
        } else {
            self.symbols.update(&full_name, val)
        };
        if res == crate::symbol_table::SymbolTableResult::Duplicate {
            return self.failure_at(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "symbol has already been defined",
                Some(&label),
                Some(1),
            );
        } else if res == crate::symbol_table::SymbolTableResult::TableFull {
            return self.failure_at(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "could not add symbol, table full",
                Some(&label),
                Some(1),
            );
        }
        self.aux_value = val;
        LineStatus::DirEqu
    }

    pub(crate) fn cpu_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        let cpu_name = match operands.first() {
            Some(Expr::Identifier(name, _)) => name.clone(),
            Some(Expr::Register(name, _)) => name.clone(),
            Some(Expr::Number(name, _)) => name.clone(),
            Some(Expr::String(bytes, _)) => String::from_utf8_lossy(bytes).to_string(),
            _ => {
                let known = self.registry.cpu_name_list();
                let hint = known.join(", ");
                let message = if hint.is_empty() {
                    ".cpu requires a CPU type".to_string()
                } else {
                    format!(".cpu requires a CPU type: {hint}")
                };
                return self.failure(LineStatus::Error, AsmErrorKind::Directive, &message, None);
            }
        };
        match self.registry.resolve_cpu_name(&cpu_name) {
            Some(cpu) => {
                self.cpu = cpu;
                self.reset_cpu_runtime_profile();
                self.register_checker = Self::build_register_checker(self.registry, self.cpu);
                LineStatus::Ok
            }
            None => {
                let known = self.registry.cpu_name_list();
                let message = if known.is_empty() {
                    "Unknown CPU type.".to_string()
                } else {
                    format!("Unknown CPU type. Use: {}", known.join(", "))
                };
                self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &message,
                    Some(&cpu_name),
                )
            }
        }
    }

    pub(crate) fn ds_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        let expr = match operands.first() {
            Some(expr) => expr,
            None => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Missing expression for DS",
                    None,
                )
            }
        };
        let val = match self.eval_expr_for_data_directive(expr) {
            Ok(value) => value,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                )
            }
        };
        if let Err(err) = self.validate_program_span(val, ".ds", expr_span(expr)) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        self.aux_value = val;
        LineStatus::DirDs
    }
}
