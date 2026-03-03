// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Expression evaluation and error helpers for `AsmLine`.
//!
//! Houses `eval_expr_ast`, the failure/diagnostic helpers, and
//! the `AssemblerContext` trait implementation.

use super::*;
use crate::core::{AsmValue, AsmValueError, StructDef, StructInstance};
use std::collections::HashMap;

impl<'a> AsmLine<'a> {
    pub(super) fn eval_value_ast(&self, expr: &Expr) -> Result<AsmValue, AstEvalError> {
        match expr {
            Expr::Identifier(name, span) | Expr::Register(name, span) => {
                if let Some(full_name) = self.resolve_scoped_value_name(name) {
                    if let Some(value) = self.lookup_value_symbol(&full_name) {
                        return Ok(value.clone());
                    }
                }
                match self.resolve_scoped_name(name) {
                    Ok(Some(full_name)) => {
                        if let Some(def) = self.struct_table.get(&full_name) {
                            return Ok(AsmValue::Struct(def.clone()));
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        return Err(AstEvalError {
                            error: err,
                            span: *span,
                        });
                    }
                }
                self.eval_expr_ast(expr)
                    .map(|value| AsmValue::Scalar(i64::from(value)))
            }
            Expr::List(items, _span) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    let value = self.eval_expr_ast(item)?;
                    values.push(i64::from(value));
                }
                Ok(AsmValue::List(values))
            }
            Expr::Range {
                start,
                end,
                step,
                inclusive,
                span,
            } => {
                let start = i64::from(self.eval_expr_ast(start)?);
                let end = i64::from(self.eval_expr_ast(end)?);
                let step = match step {
                    Some(step_expr) => Some(i64::from(self.eval_expr_ast(step_expr)?)),
                    None => None,
                };
                AsmValue::try_range(start, end, *inclusive, step).map_err(|err| {
                    let message = match err {
                        AsmValueError::ZeroStep => "range step must be non-zero".to_string(),
                        AsmValueError::DirectionMismatch { .. } => {
                            "range step direction conflicts with start..end".to_string()
                        }
                        AsmValueError::EndOverflow => {
                            "range end overflows supported integer range".to_string()
                        }
                    };
                    AstEvalError {
                        error: AsmError::new(AsmErrorKind::Expression, &message, None),
                        span: *span,
                    }
                })
            }
            Expr::Index { base, index, span } => {
                let value = self.eval_value_ast(base)?;
                let index_value = i64::from(self.eval_expr_ast(index)?);
                if index_value < 0 {
                    return Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Index cannot be negative",
                            None,
                        ),
                        span: *span,
                    });
                }
                let index_usize = usize::try_from(index_value).map_err(|_| AstEvalError {
                    error: AsmError::new(AsmErrorKind::Expression, "Index out of range", None),
                    span: *span,
                })?;
                match value.get(index_usize) {
                    Some(element) => Ok(AsmValue::Scalar(element)),
                    None => Err(AstEvalError {
                        error: AsmError::new(AsmErrorKind::Expression, "Index out of bounds", None),
                        span: *span,
                    }),
                }
            }
            Expr::StructLiteral {
                type_name,
                fields,
                span,
            } => {
                let def = self.resolve_struct_def_for_literal(type_name, *span)?;
                let mut values: HashMap<String, i64> = HashMap::new();

                for (field_name, field_expr) in fields {
                    let resolved_field = match def
                        .fields
                        .iter()
                        .find(|candidate| candidate.name.eq_ignore_ascii_case(field_name))
                    {
                        Some(field) => field.name.clone(),
                        None => {
                            return Err(AstEvalError {
                                error: AsmError::new(
                                    AsmErrorKind::Expression,
                                    &format!(
                                        "unknown field '{}' in struct literal for '{}'",
                                        field_name, def.name
                                    ),
                                    None,
                                ),
                                span: *span,
                            })
                        }
                    };
                    let field_key = resolved_field.to_ascii_uppercase();
                    if values.contains_key(&field_key) {
                        return Err(AstEvalError {
                            error: AsmError::new(
                                AsmErrorKind::Expression,
                                &format!(
                                    "duplicate field '{}' in struct literal for '{}'",
                                    resolved_field, def.name
                                ),
                                None,
                            ),
                            span: *span,
                        });
                    }
                    let field_value = i64::from(self.eval_expr_ast(field_expr)?);
                    values.insert(field_key, field_value);
                }

                for required in &def.fields {
                    let required_key = required.name.to_ascii_uppercase();
                    if !values.contains_key(&required_key) {
                        return Err(AstEvalError {
                            error: AsmError::new(
                                AsmErrorKind::Expression,
                                &format!(
                                    "missing required field '{}' in struct literal for '{}'",
                                    required.name, def.name
                                ),
                                None,
                            ),
                            span: *span,
                        });
                    }
                }

                Ok(AsmValue::StructInstance(StructInstance {
                    type_name: def.name,
                    fields: values,
                }))
            }
            Expr::Member { base, field, span } => {
                if let Expr::Identifier(name, name_span) | Expr::Register(name, name_span) = &**base
                {
                    if let Some(full_name) = self.resolve_scoped_value_name(name) {
                        if let Some(value) = self.lookup_value_symbol(&full_name) {
                            if let Some(field_value) = value.field_value(field) {
                                return Ok(AsmValue::Scalar(field_value));
                            }
                            if let AsmValue::StructInstance(instance) = value {
                                return Err(AstEvalError {
                                    error: AsmError::new(
                                        AsmErrorKind::Expression,
                                        &format!(
                                            "struct '{}' has no field '{}'",
                                            instance.type_name, field
                                        ),
                                        None,
                                    ),
                                    span: *span,
                                });
                            }
                        }
                    }

                    let scoped_name = match self.resolve_scoped_name(name) {
                        Ok(Some(full)) => full,
                        Ok(None) => name.clone(),
                        Err(err) => {
                            return Err(AstEvalError {
                                error: err,
                                span: *name_span,
                            });
                        }
                    };
                    let struct_def = if let Some(def) = self.struct_table.get(&scoped_name) {
                        Some(def.clone())
                    } else if let Some(AsmValue::Struct(def)) =
                        self.lookup_value_symbol(&scoped_name)
                    {
                        Some(def.clone())
                    } else {
                        None
                    };
                    if let Some(def) = struct_def {
                        if let Some(offset) = def
                            .fields
                            .iter()
                            .find(|candidate| candidate.name.eq_ignore_ascii_case(field.as_str()))
                            .map(|candidate| candidate.offset)
                        {
                            return Ok(AsmValue::Scalar(i64::from(offset)));
                        }
                        return Err(AstEvalError {
                            error: AsmError::new(
                                AsmErrorKind::Expression,
                                &format!("struct '{}' has no field '{}'", def.name, field),
                                None,
                            ),
                            span: *span,
                        });
                    }
                    return Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            &format!("no struct type associated with '{name}' for field access"),
                            None,
                        ),
                        span: *span,
                    });
                }

                let base_value = self.eval_value_ast(base)?;
                match base_value {
                    AsmValue::Struct(def) => {
                        if let Some(offset) = def
                            .fields
                            .iter()
                            .find(|candidate| candidate.name.eq_ignore_ascii_case(field.as_str()))
                            .map(|candidate| candidate.offset)
                        {
                            Ok(AsmValue::Scalar(i64::from(offset)))
                        } else {
                            Err(AstEvalError {
                                error: AsmError::new(
                                    AsmErrorKind::Expression,
                                    &format!("struct '{}' has no field '{}'", def.name, field),
                                    None,
                                ),
                                span: *span,
                            })
                        }
                    }
                    AsmValue::StructInstance(instance) => {
                        if let Some(value) = instance.fields.get(&field.to_ascii_uppercase()) {
                            Ok(AsmValue::Scalar(*value))
                        } else {
                            Err(AstEvalError {
                                error: AsmError::new(
                                    AsmErrorKind::Expression,
                                    &format!(
                                        "struct '{}' has no field '{}'",
                                        instance.type_name, field
                                    ),
                                    None,
                                ),
                                span: *span,
                            })
                        }
                    }
                    _ => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Member expression requires struct base value",
                            None,
                        ),
                        span: *span,
                    }),
                }
            }
            Expr::Call { name, args, span } => {
                if !name.eq_ignore_ascii_case(".len") {
                    return Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Unknown compile-time function call",
                            Some(name),
                        ),
                        span: *span,
                    });
                }
                if args.len() != 1 {
                    return Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            ".len() expects exactly one argument",
                            None,
                        ),
                        span: *span,
                    });
                }
                let value = self.eval_value_ast(&args[0])?;
                match value.len() {
                    Some(length) => Ok(AsmValue::Scalar(i64::try_from(length).unwrap_or(i64::MAX))),
                    None => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            ".len() expects a range or list argument",
                            None,
                        ),
                        span: *span,
                    }),
                }
            }
            Expr::Error(message, span) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, message, None),
                span: *span,
            }),
            Expr::Placeholder(span) => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "Placeholder cannot be evaluated as scalar expression",
                    None,
                ),
                span: *span,
            }),
            Expr::Indirect(inner, _) | Expr::IndirectLong(inner, _) | Expr::Immediate(inner, _) => {
                self.eval_value_ast(inner)
            }
            Expr::Tuple(_, span) => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "Tuple cannot be evaluated as expression",
                    None,
                ),
                span: *span,
            }),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                let cond_val = self.eval_expr_ast(cond)?;
                if cond_val != 0 {
                    self.eval_value_ast(then_expr)
                } else {
                    self.eval_value_ast(else_expr)
                }
            }
            Expr::Binary { .. }
            | Expr::Number(_, _)
            | Expr::Unary { .. }
            | Expr::Dollar(_)
            | Expr::String(_, _) => self
                .eval_expr_ast(expr)
                .map(|value| AsmValue::Scalar(i64::from(value))),
        }
    }

    fn resolve_struct_def_for_literal(
        &self,
        type_name: &str,
        span: Span,
    ) -> Result<StructDef, AstEvalError> {
        if let Some(full_name) = self.resolve_scoped_value_name(type_name) {
            if let Some(AsmValue::Struct(def)) = self.lookup_value_symbol(&full_name) {
                return Ok(def.clone());
            }
        }

        let scoped_name = match self.resolve_scoped_name(type_name) {
            Ok(Some(full)) => full,
            Ok(None) => type_name.to_string(),
            Err(err) => return Err(AstEvalError { error: err, span }),
        };
        if let Some(def) = self.struct_table.get(&scoped_name) {
            return Ok(def.clone());
        }
        if let Some(AsmValue::Struct(def)) = self.lookup_value_symbol(&scoped_name) {
            return Ok(def.clone());
        }
        Err(AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Expression,
                &format!("unknown struct type '{type_name}' for struct literal"),
                None,
            ),
            span,
        })
    }

    fn resolve_member_base_value(
        &self,
        name: &str,
        span: Span,
    ) -> Result<Option<AsmValue>, AstEvalError> {
        if let Some(full_name) = self.resolve_scoped_value_name(name) {
            if let Some(value) = self.lookup_value_symbol(&full_name) {
                return Ok(Some(value.clone()));
            }
        }

        let scoped_name = match self.resolve_scoped_name(name) {
            Ok(Some(full)) => full,
            Ok(None) => return Ok(None),
            Err(err) => return Err(AstEvalError { error: err, span }),
        };
        if let Some(def) = self.struct_table.get(&scoped_name) {
            return Ok(Some(AsmValue::Struct(def.clone())));
        }
        if let Some(AsmValue::Struct(def)) = self.lookup_value_symbol(&scoped_name) {
            return Ok(Some(AsmValue::Struct(def.clone())));
        }
        Ok(None)
    }

    fn eval_dotted_identifier_scalar(
        &self,
        name: &str,
        span: Span,
    ) -> Option<Result<u32, AstEvalError>> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 || parts.iter().any(|segment| segment.is_empty()) {
            return None;
        }

        for split_index in (1..parts.len()).rev() {
            let base = parts[..split_index].join(".");
            let fields = &parts[split_index..];
            let base_value = match self.resolve_member_base_value(&base, span) {
                Ok(Some(value)) => value,
                Ok(None) => continue,
                Err(err) => return Some(Err(err)),
            };

            let mut current = base_value;
            for field in fields {
                current = match current {
                    AsmValue::Struct(def) => {
                        if let Some(offset) = def
                            .fields
                            .iter()
                            .find(|candidate| candidate.name.eq_ignore_ascii_case(field))
                            .map(|candidate| candidate.offset)
                        {
                            AsmValue::Scalar(i64::from(offset))
                        } else {
                            return Some(Err(AstEvalError {
                                error: AsmError::new(
                                    AsmErrorKind::Expression,
                                    &format!("struct '{}' has no field '{}'", def.name, field),
                                    None,
                                ),
                                span,
                            }));
                        }
                    }
                    AsmValue::StructInstance(instance) => {
                        if let Some(value) = instance.fields.get(&field.to_ascii_uppercase()) {
                            AsmValue::Scalar(*value)
                        } else {
                            return Some(Err(AstEvalError {
                                error: AsmError::new(
                                    AsmErrorKind::Expression,
                                    &format!(
                                        "struct '{}' has no field '{}'",
                                        instance.type_name, field
                                    ),
                                    None,
                                ),
                                span,
                            }));
                        }
                    }
                    _ => {
                        return Some(Err(AstEvalError {
                            error: AsmError::new(
                                AsmErrorKind::Expression,
                                "Member expression requires struct base value",
                                None,
                            ),
                            span,
                        }))
                    }
                };
            }

            return match current {
                AsmValue::Scalar(value) => Some(Ok(value as u32)),
                _ => Some(Err(AstEvalError {
                    error: AsmError::new(
                        AsmErrorKind::Expression,
                        "Member expression requires struct base value",
                        None,
                    ),
                    span,
                })),
            };
        }

        None
    }

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
                if let Some(value) = self.lookup_loop_var(name) {
                    return Ok(value);
                }
                if let Some(full_name) = self.resolve_scoped_value_name(name) {
                    let message = match self.lookup_value_symbol(&full_name) {
                        Some(AsmValue::List(_)) => "List cannot be evaluated as scalar expression",
                        Some(AsmValue::Range { .. }) => {
                            "Range cannot be evaluated as scalar expression"
                        }
                        Some(AsmValue::Struct(_)) => {
                            "Struct cannot be evaluated as scalar expression"
                        }
                        Some(AsmValue::StructInstance(_)) => {
                            "Struct instance cannot be evaluated as scalar expression"
                        }
                        _ => "List cannot be evaluated as scalar expression",
                    };
                    return Err(AstEvalError {
                        error: AsmError::new(AsmErrorKind::Expression, message, None),
                        span: *span,
                    });
                }
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
                        if let Some(result) = self.eval_dotted_identifier_scalar(name, *span) {
                            return result;
                        }
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
            Expr::List(_, span) => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "List cannot be evaluated as scalar expression",
                    None,
                ),
                span: *span,
            }),
            Expr::Index { .. }
            | Expr::Member { .. }
            | Expr::StructLiteral { .. }
            | Expr::Call { .. } => {
                let value = self.eval_value_ast(expr)?;
                match value {
                    AsmValue::Scalar(value) => Ok(value as u32),
                    AsmValue::List(_) => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "List cannot be evaluated as scalar expression",
                            None,
                        ),
                        span: expr_span(expr),
                    }),
                    AsmValue::Range { .. } => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Range cannot be evaluated as scalar expression",
                            None,
                        ),
                        span: expr_span(expr),
                    }),
                    AsmValue::Struct(_) => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Struct cannot be evaluated as scalar expression",
                            None,
                        ),
                        span: expr_span(expr),
                    }),
                    AsmValue::StructInstance(_) => Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Expression,
                            "Struct instance cannot be evaluated as scalar expression",
                            None,
                        ),
                        span: expr_span(expr),
                    }),
                }
            }
            Expr::Placeholder(span) => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "Placeholder cannot be evaluated as scalar expression",
                    None,
                ),
                span: *span,
            }),
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
            Expr::Range { span, .. } => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Expression,
                    "Range cannot be evaluated as scalar expression",
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
        if Self::expr_requires_host_eval(expr) {
            return self
                .eval_expr_ast(expr)
                .map(|v| v as i64)
                .map_err(|e| e.error.message().to_string());
        }

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

impl<'a> AsmLine<'a> {
    fn expr_requires_host_eval(expr: &Expr) -> bool {
        match expr {
            Expr::List(_, _)
            | Expr::Index { .. }
            | Expr::Member { .. }
            | Expr::StructLiteral { .. }
            | Expr::Call { .. } => true,
            Expr::Range { .. } => true,
            Expr::Indirect(inner, _)
            | Expr::IndirectLong(inner, _)
            | Expr::Immediate(inner, _)
            | Expr::Unary { expr: inner, .. } => Self::expr_requires_host_eval(inner),
            Expr::Tuple(items, _) => items.iter().any(Self::expr_requires_host_eval),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
                ..
            } => {
                Self::expr_requires_host_eval(cond)
                    || Self::expr_requires_host_eval(then_expr)
                    || Self::expr_requires_host_eval(else_expr)
            }
            Expr::Binary { left, right, .. } => {
                Self::expr_requires_host_eval(left) || Self::expr_requires_host_eval(right)
            }
            Expr::Error(_, _)
            | Expr::Number(_, _)
            | Expr::Identifier(_, _)
            | Expr::Register(_, _)
            | Expr::Placeholder(_)
            | Expr::Dollar(_)
            | Expr::String(_, _) => false,
        }
    }
}
