// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Expression evaluation and error helpers for `AsmLine`.
//!
//! Houses `eval_expr_ast`, the failure/diagnostic helpers, and
//! the `AssemblerContext` trait implementation.

use super::*;

impl<'a> AsmLine<'a> {
    pub(super) fn eval_expr_ast(&self, expr: &Expr) -> Result<u32, AstEvalError> {
        #[cfg(test)]
        if HOST_EXPR_EVAL_FAILPOINT.with(|flag| flag.get()) {
            return Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "host expression evaluator failpoint",
                    None,
                ),
                span: expr_span(expr),
            });
        }

        match expr {
            Expr::Error(message, span) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, message, None),
                span: *span,
            }),
            Expr::Number(text, span) => parse_number_text(text, *span),
            Expr::Identifier(name, span) | Expr::Register(name, span) => {
                match self.lookup_scoped_entry(name) {
                    Some(entry) => {
                        if !self.entry_is_visible(entry) {
                            return Err(AstEvalError {
                                error: self.visibility_error(name),
                                span: *span,
                            });
                        }
                        Ok(entry.val)
                    }
                    None => {
                        if self.pass > 1 {
                            Err(AstEvalError {
                                error: AsmError::new(
                                    AsmErrorKind::Expression,
                                    "Label not found",
                                    Some(name),
                                ),
                                span: *span,
                            })
                        } else {
                            Ok(0)
                        }
                    }
                }
            }
            Expr::Indirect(inner, _span) => {
                // For 6502-style indirect like ($20), evaluate the inner address expression
                self.eval_expr_ast(inner)
            }
            Expr::IndirectLong(inner, _span) => {
                // For 65816-style bracketed indirect like [$20], evaluate inner expression.
                self.eval_expr_ast(inner)
            }
            Expr::Immediate(inner, _span) => {
                // Immediate expressions like #$FF - evaluate the inner expression
                self.eval_expr_ast(inner)
            }
            Expr::Tuple(_, span) => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "Tuple cannot be evaluated as expression",
                    None,
                ),
                span: *span,
            }),
            Expr::Dollar(_span) => Ok(self.start_addr),
            Expr::String(bytes, span) => {
                let encoded_bytes = self.encode_text_bytes(
                    bytes,
                    *span,
                    "String expression",
                    AsmErrorKind::Expression,
                )?;
                if encoded_bytes.len() == 1 {
                    Ok(encoded_bytes[0] as u32)
                } else if encoded_bytes.len() == 2 {
                    Ok(((encoded_bytes[0] as u32) << 8) | (encoded_bytes[1] as u32))
                } else {
                    Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Multi-character string not allowed in expression.",
                            None,
                        ),
                        span: *span,
                    })
                }
            }
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                let cond_val = self.eval_expr_ast(cond)?;
                if cond_val != 0 {
                    self.eval_expr_ast(then_expr)
                } else {
                    self.eval_expr_ast(else_expr)
                }
            }
            Expr::Unary { op, expr, span: _ } => {
                let inner = self.eval_expr_ast(expr)?;
                Ok(eval_unary_op(*op, inner))
            }
            Expr::Binary {
                op,
                left,
                right,
                span,
            } => {
                let left_val = self.eval_expr_ast(left)?;
                let right_val = self.eval_expr_ast(right)?;
                eval_binary_op(*op, left_val, right_val, *span, self.line_end_span)
            }
        }
    }

    pub(super) fn failure_at_span(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
        span: Span,
    ) -> LineStatus {
        self.failure_at(status, kind, msg, param, Some(span.col_start))
    }

    pub(super) fn failure(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
    ) -> LineStatus {
        let column = self.line_end_span.map(|span| span.col_start);
        self.failure_at(status, kind, msg, param, column)
    }

    pub(super) fn set_failure_core(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
        column: Option<usize>,
    ) -> LineStatus {
        self.diagnostics.last_error = Some(AsmError::new(kind, msg, param));
        self.diagnostics.last_error_column = column;
        status
    }

    pub(super) fn failure_at(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
        column: Option<usize>,
    ) -> LineStatus {
        let status = self.set_failure_core(status, kind, msg, param, column);
        self.diagnostics.last_error_help = None;
        self.diagnostics.last_error_fixits.clear();
        status
    }
}

/// Implement AssemblerContext for AsmLine to provide expression evaluation
/// and symbol lookup to family and CPU handlers.
impl<'a> AssemblerContext for AsmLine<'a> {
    fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
        if matches!(expr, Expr::Identifier(_, _) | Expr::Register(_, _)) {
            return self
                .eval_expr_ast(expr)
                .map(|v| v as i64)
                .map_err(|e| e.error.message().to_string());
        }

        if matches!(expr, Expr::String(_, _)) {
            return self
                .eval_expr_ast(expr)
                .map(|v| v as i64)
                .map_err(|e| e.error.message().to_string());
        }

        if let Some(model) = self.opthread_execution_model.as_ref() {
            if let Ok(pipeline) = Self::resolve_pipeline_for_cpu(self.registry, self.cpu) {
                if crate::vm::rollout::package_runtime_default_enabled_for_family(
                    pipeline.family_id.as_str(),
                ) && self.portable_expr_runtime_enabled_for_family(pipeline.family_id.as_str())
                {
                    let program = compile_core_expr_to_portable_program(expr)
                        .map_err(|err| err.to_string())?;
                    match model.evaluate_portable_expression_program_with_contract_for_assembler(
                        self.cpu.as_str(),
                        None,
                        &program,
                        self,
                    ) {
                        Ok(evaluation) => return Ok(evaluation.value),
                        Err(err) => {
                            let message = err.to_string();
                            let is_unknown_symbol = {
                                let trimmed = message.trim_start();
                                trimmed == "ope004" || trimmed.starts_with("ope004:")
                            };
                            if !is_unknown_symbol {
                                return Err(message);
                            }
                        }
                    }
                }
            }
        }

        self.eval_expr_ast(expr)
            .map(|v| v as i64)
            .map_err(|e| e.error.message().to_string())
    }

    fn symbols(&self) -> &SymbolTable {
        self.symbols
    }

    fn has_symbol(&self, name: &str) -> bool {
        self.lookup_scoped_entry(name).is_some()
    }

    fn symbol_is_finalized(&self, name: &str) -> Option<bool> {
        self.lookup_scoped_entry(name).map(|entry| entry.updated)
    }

    fn current_address(&self) -> u32 {
        self.start_addr
    }

    fn pass(&self) -> u8 {
        self.pass
    }

    fn cpu_state_flag(&self, key: &str) -> Option<u32> {
        self.cpu_mode.state_flags.get(key).copied()
    }
}
