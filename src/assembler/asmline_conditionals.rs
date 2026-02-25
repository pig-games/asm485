// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

impl<'a> AsmLine<'a> {
    pub(crate) fn process_conditional_ast(
        &mut self,
        kind: ConditionalKind,
        exprs: &[Expr],
        span: Span,
    ) -> LineStatus {
        let skipping = self.cond_stack.skipping();
        let end_span = self.line_end_span.unwrap_or(span);
        let expr_err_span = exprs.first().map(expr_span).unwrap_or(end_span);

        match kind {
            ConditionalKind::If => {
                let val = match exprs.first() {
                    Some(expr) => match self.eval_expr_ast(expr) {
                        Ok(v) => v,
                        Err(err) => {
                            return self.failure_at_span(
                                LineStatus::Error,
                                err.error.kind(),
                                err.error.message(),
                                None,
                                err.span,
                            );
                        }
                    },
                    None => 0,
                };
                if skipping {
                    if let Some(ctx) = self.cond_stack.last_mut() {
                        ctx.skip_level = ctx.skip_level.saturating_add(1);
                    }
                    return LineStatus::Skip;
                }
                let prev = self.cond_stack.last();
                let mut ctx = ConditionalContext::new(prev, ConditionalBlockKind::If);
                if val != 0 {
                    ctx.matched = true;
                } else {
                    ctx.skipping = true;
                }
                self.cond_stack.push(ctx);
            }
            ConditionalKind::Switch => {
                let val = match exprs.first() {
                    Some(expr) => match self.eval_expr_ast(expr) {
                        Ok(v) => v,
                        Err(err) => {
                            return self.failure_at_span(
                                LineStatus::Error,
                                err.error.kind(),
                                err.error.message(),
                                None,
                                err.span,
                            );
                        }
                    },
                    None => 0,
                };
                if skipping {
                    if let Some(ctx) = self.cond_stack.last_mut() {
                        ctx.skip_level = ctx.skip_level.saturating_add(1);
                    }
                    return LineStatus::Skip;
                }
                let prev = self.cond_stack.last();
                let mut ctx = ConditionalContext::new(prev, ConditionalBlockKind::Switch);
                ctx.switch_value = Some(val);
                ctx.skipping = true;
                self.cond_stack.push(ctx);
            }
            ConditionalKind::Else | ConditionalKind::ElseIf => {
                if self.cond_stack.is_empty() {
                    let err_span = if kind == ConditionalKind::ElseIf {
                        expr_err_span
                    } else {
                        end_span
                    };
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".else or .elseif found without matching .if",
                        None,
                        err_span,
                    );
                }
                let skip_level = match self.cond_stack.last() {
                    Some(ctx) => ctx.skip_level,
                    None => {
                        let err_span = if kind == ConditionalKind::ElseIf {
                            expr_err_span
                        } else {
                            end_span
                        };
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            ".else or .elseif found without matching .if",
                            None,
                            err_span,
                        );
                    }
                };
                if skip_level > 0 {
                    return LineStatus::Skip;
                }
                if self.cond_stack.last().map(|ctx| ctx.kind) != Some(ConditionalBlockKind::If) {
                    let err_span = if kind == ConditionalKind::ElseIf {
                        expr_err_span
                    } else {
                        end_span
                    };
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".else or .elseif found without matching .if",
                        None,
                        err_span,
                    );
                }
                let val = if kind == ConditionalKind::Else {
                    1
                } else {
                    match exprs.first() {
                        Some(expr) => match self.eval_expr_ast(expr) {
                            Ok(v) => v,
                            Err(err) => {
                                return self.failure_at_span(
                                    LineStatus::Error,
                                    err.error.kind(),
                                    err.error.message(),
                                    None,
                                    err.span,
                                );
                            }
                        },
                        None => 0,
                    }
                };
                let Some(ctx) = self.cond_stack.last_mut() else {
                    let err_span = if kind == ConditionalKind::ElseIf {
                        expr_err_span
                    } else {
                        end_span
                    };
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".else or .elseif found without matching .if",
                        None,
                        err_span,
                    );
                };
                if ctx.sub_type == TokenValue::Else {
                    let err_span = if kind == ConditionalKind::ElseIf {
                        expr_err_span
                    } else {
                        end_span
                    };
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".else or .elseif cannot follow .else",
                        None,
                        err_span,
                    );
                }
                let sub_type = if kind == ConditionalKind::Else {
                    TokenValue::Else
                } else {
                    TokenValue::ElseIf
                };
                if !ctx.skipping {
                    ctx.skipping = true;
                    ctx.sub_type = sub_type;
                } else if !ctx.matched && val != 0 {
                    ctx.matched = true;
                    ctx.skipping = false;
                    ctx.sub_type = sub_type;
                }
            }
            ConditionalKind::Case => {
                if self.cond_stack.is_empty() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".case found without matching .match",
                        None,
                        expr_err_span,
                    );
                }
                let skip_level = match self.cond_stack.last() {
                    Some(ctx) => ctx.skip_level,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            ".case found without matching .match",
                            None,
                            expr_err_span,
                        );
                    }
                };
                if skip_level > 0 {
                    return LineStatus::Skip;
                }
                let (switch_val, sub_type, kind) = match self.cond_stack.last() {
                    Some(ctx) => {
                        let sv = match ctx.switch_value {
                            Some(v) => v,
                            None => {
                                return self.failure_at_span(
                                    LineStatus::Error,
                                    AsmErrorKind::Conditional,
                                    ".case found without matching .match",
                                    None,
                                    expr_err_span,
                                );
                            }
                        };
                        (sv, ctx.sub_type, ctx.kind)
                    }
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            ".case found without matching .match",
                            None,
                            expr_err_span,
                        );
                    }
                };
                if kind != ConditionalBlockKind::Switch {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".case found without matching .match",
                        None,
                        expr_err_span,
                    );
                }
                if sub_type == TokenValue::Default {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".case cannot follow .default",
                        None,
                        expr_err_span,
                    );
                }
                let mut case_match = false;
                for expr in exprs.iter() {
                    match self.eval_expr_ast(expr) {
                        Ok(val) => {
                            if val == switch_val {
                                case_match = true;
                                break;
                            }
                        }
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
                let sub_type = TokenValue::Case;
                let Some(ctx) = self.cond_stack.last_mut() else {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".case found without matching .match",
                        None,
                        expr_err_span,
                    );
                };
                if !ctx.skipping {
                    ctx.skipping = true;
                    ctx.sub_type = sub_type;
                } else if !ctx.matched && case_match {
                    ctx.matched = true;
                    ctx.skipping = false;
                    ctx.sub_type = sub_type;
                } else {
                    ctx.sub_type = sub_type;
                }
            }
            ConditionalKind::Default => {
                if self.cond_stack.is_empty() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".default found without matching .match",
                        None,
                        end_span,
                    );
                }
                let skip_level = match self.cond_stack.last() {
                    Some(ctx) => ctx.skip_level,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Conditional,
                            ".default found without matching .match",
                            None,
                            end_span,
                        );
                    }
                };
                if skip_level > 0 {
                    return LineStatus::Skip;
                }
                if self.cond_stack.last().map(|ctx| ctx.kind) != Some(ConditionalBlockKind::Switch)
                {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".default found without matching .match",
                        None,
                        end_span,
                    );
                }
                let Some(ctx) = self.cond_stack.last_mut() else {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".default found without matching .match",
                        None,
                        end_span,
                    );
                };
                if ctx.sub_type == TokenValue::Default {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".default cannot follow .default",
                        None,
                        end_span,
                    );
                }
                ctx.sub_type = TokenValue::Default;
                if ctx.matched {
                    ctx.skipping = true;
                } else {
                    ctx.matched = true;
                    ctx.skipping = false;
                }
            }
            ConditionalKind::EndIf => {
                if self.cond_stack.is_empty() {
                    let err_span = end_span;
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endif found without matching .if",
                        None,
                        err_span,
                    );
                }
                let Some(ctx) = self.cond_stack.last_mut() else {
                    let err_span = end_span;
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endif found without matching .if",
                        None,
                        err_span,
                    );
                };
                if ctx.skip_level > 0 {
                    ctx.skip_level = ctx.skip_level.saturating_sub(1);
                    return LineStatus::Skip;
                }
                if ctx.kind != ConditionalBlockKind::If {
                    let err_span = end_span;
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endif found without matching .if",
                        None,
                        err_span,
                    );
                }
                self.cond_stack.pop();
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
            }
            ConditionalKind::EndSwitch => {
                if self.cond_stack.is_empty() {
                    let err_span = end_span;
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endmatch found without matching .match",
                        None,
                        err_span,
                    );
                }
                let Some(ctx) = self.cond_stack.last_mut() else {
                    let err_span = end_span;
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endmatch found without matching .match",
                        None,
                        err_span,
                    );
                };
                if ctx.skip_level > 0 {
                    ctx.skip_level = ctx.skip_level.saturating_sub(1);
                    return LineStatus::Skip;
                }
                if ctx.kind != ConditionalBlockKind::Switch {
                    let err_span = end_span;
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".endmatch found without matching .match",
                        None,
                        err_span,
                    );
                }
                self.cond_stack.pop();
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
            }
        }

        LineStatus::Ok
    }
}
