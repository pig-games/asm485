// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Text encoding directives for `AsmLine`.
//!
//! Handles `.encode`/`.endencode`, `.cdef`, `.tdef`, `.edef`,
//! `.text`, `.null`, `.ptext`, and text-encoding helper methods.

use super::*;

impl<'a> AsmLine<'a> {
    pub(super) fn has_open_encoding_scope(&self) -> bool {
        !self.encoding_scope_stack.is_empty()
    }

    pub(super) fn current_encoding_definition_name(&self) -> Option<&str> {
        self.encoding_scope_stack
            .last()
            .map(|scope| scope.definition_name.as_str())
    }

    pub(super) fn begin_encode_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.is_empty() || operands.len() > 2 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .encode <name> [, <base>]",
                None,
            );
        }
        let (name, name_span) = match self.encoding_name_operand(&operands[0], ".encode") {
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
        };
        let normalized = if operands.len() == 2 {
            let (base, base_span) = match self.encoding_name_operand(&operands[1], ".encode") {
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
            };
            match self
                .text_encoding_registry
                .ensure_encoding_from_base(&name, &base)
            {
                Ok(value) => value,
                Err(err) => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!(".encode: {err}"),
                        None,
                        base_span,
                    );
                }
            }
        } else {
            match self.text_encoding_registry.ensure_encoding(&name) {
                Ok(value) => value,
                Err(err) => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!(".encode: {err}"),
                        None,
                        name_span,
                    );
                }
            }
        };
        self.encoding_scope_stack.push(EncodingScopeState {
            definition_name: normalized.clone(),
            previous_active_encoding: self.active_text_encoding.clone(),
        });
        self.active_text_encoding = normalized;
        LineStatus::Ok
    }

    pub(super) fn end_encode_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unexpected operands for .endencode",
                None,
            );
        }
        let Some(scope) = self.encoding_scope_stack.pop() else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".endencode found without matching .encode",
                None,
            );
        };
        self.active_text_encoding = scope.previous_active_encoding;
        LineStatus::Ok
    }

    pub(super) fn cdef_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() != 3 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .cdef <start>, <end>, <value>",
                None,
            );
        }
        let Some(encoding) = self.current_encoding_definition_name().map(str::to_string) else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".cdef is only valid inside .encode ... .endencode",
                None,
            );
        };
        let (start, start_span) = match self.source_byte_operand(&operands[0], ".cdef") {
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
        };
        let (end, end_span) = match self.source_byte_operand(&operands[1], ".cdef") {
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
        };
        let coded = match self.eval_expr_ast(&operands[2]) {
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
        };
        let err_span = Span {
            line: start_span.line,
            col_start: start_span.col_start.min(end_span.col_start),
            col_end: start_span.col_end.max(end_span.col_end),
        };
        match self
            .text_encoding_registry
            .define_cdef_range(&encoding, start, end, coded)
        {
            Ok(()) => LineStatus::Ok,
            Err(err) => self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!(".cdef: {err}"),
                None,
                err_span,
            ),
        }
    }

    pub(super) fn tdef_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() < 2 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .tdef <chars>, <value...>",
                None,
            );
        }
        let Some(encoding) = self.current_encoding_definition_name().map(str::to_string) else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".tdef is only valid inside .encode ... .endencode",
                None,
            );
        };
        let (chars, chars_span) = match self.string_literal_operand(&operands[0], ".tdef", "chars")
        {
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
        };
        if operands.len() == 2 {
            let start_value = match self.eval_expr_ast(&operands[1]) {
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
            };
            return match self.text_encoding_registry.define_tdef_increment(
                &encoding,
                &chars,
                start_value,
            ) {
                Ok(()) => LineStatus::Ok,
                Err(err) => self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!(".tdef: {err}"),
                    None,
                    chars_span,
                ),
            };
        }

        let mut values = Vec::with_capacity(operands.len().saturating_sub(1));
        for expr in &operands[1..] {
            let (value, _) = match self.byte_operand(expr, ".tdef") {
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
            };
            values.push(value);
        }

        match self
            .text_encoding_registry
            .define_tdef_values(&encoding, &chars, &values)
        {
            Ok(()) => LineStatus::Ok,
            Err(err) => self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!(".tdef: {err}"),
                None,
                chars_span,
            ),
        }
    }

    pub(super) fn edef_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if operands.len() < 2 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .edef <pattern>, <replacement...>",
                None,
            );
        }
        let Some(encoding) = self.current_encoding_definition_name().map(str::to_string) else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".edef is only valid inside .encode ... .endencode",
                None,
            );
        };
        let (pattern, span) =
            match self.string_literal_operand(&operands[0], ".edef", "escape pattern") {
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
            };
        let mut replacement = Vec::new();
        for expr in &operands[1..] {
            if let Expr::String(bytes, _) = expr {
                replacement.extend_from_slice(bytes);
                continue;
            }
            let (value, _) = match self.byte_operand(expr, ".edef") {
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
            };
            replacement.push(value);
        }

        match self
            .text_encoding_registry
            .define_edef(&encoding, &pattern, &replacement)
        {
            Ok(()) => LineStatus::Ok,
            Err(err) => self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!(".edef: {err}"),
                None,
                span,
            ),
        }
    }

    pub(super) fn set_text_encoding_directive_ast(
        &mut self,
        directive_name: &str,
        operands: &[Expr],
    ) -> LineStatus {
        if operands.len() != 1 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("Expected {directive_name} <name>"),
                None,
            );
        }
        let operand = &operands[0];
        let name = match Self::expr_text_value_core(operand) {
            Some(value) => value,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Invalid encoding name for {directive_name}"),
                    None,
                    expr_span(operand),
                )
            }
        };
        let encoding = match self.text_encoding_registry.resolve_name(&name) {
            Some(encoding) => encoding,
            None => {
                let known = self.text_encoding_registry.known_names().join(", ");
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Unknown encoding '{name}'. Use: {known}"),
                    None,
                    expr_span(operand),
                );
            }
        };
        self.active_text_encoding = encoding;
        LineStatus::Ok
    }

    pub(super) fn encoding_name_operand(
        &self,
        expr: &Expr,
        directive_name: &str,
    ) -> Result<(String, Span), AstEvalError> {
        let span = expr_span(expr);
        let name = Self::expr_text_value_core(expr).ok_or_else(|| AstEvalError {
            error: AsmError::new(
                AsmErrorKind::Directive,
                &format!("Invalid encoding name for {directive_name}"),
                None,
            ),
            span,
        })?;
        Ok((name, span))
    }

    pub(super) fn byte_operand(
        &self,
        expr: &Expr,
        directive_name: &str,
    ) -> Result<(u8, Span), AstEvalError> {
        let span = expr_span(expr);
        let value = self.eval_expr_ast(expr)?;
        if value > u8::MAX as u32 {
            return Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Directive,
                    &format!("{directive_name} value ${value:X} does not fit in a byte"),
                    None,
                ),
                span,
            });
        }
        Ok((value as u8, span))
    }

    pub(super) fn source_byte_operand(
        &self,
        expr: &Expr,
        directive_name: &str,
    ) -> Result<(u8, Span), AstEvalError> {
        match expr {
            Expr::String(bytes, span) => {
                if bytes.len() != 1 {
                    return Err(AstEvalError {
                        error: AsmError::new(
                            AsmErrorKind::Directive,
                            &format!("{directive_name} character operand must be one byte"),
                            None,
                        ),
                        span: *span,
                    });
                }
                Ok((bytes[0], *span))
            }
            _ => self.byte_operand(expr, directive_name),
        }
    }

    pub(super) fn string_literal_operand(
        &self,
        expr: &Expr,
        directive_name: &str,
        context: &str,
    ) -> Result<(Vec<u8>, Span), AstEvalError> {
        match expr {
            Expr::String(bytes, span) => Ok((bytes.clone(), *span)),
            _ => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Directive,
                    &format!("{directive_name} expects string literal for {context}"),
                    None,
                ),
                span: expr_span(expr),
            }),
        }
    }

    pub(super) fn expr_text_value_core(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(value, _) | Expr::Register(value, _) | Expr::Number(value, _) => {
                Some(value.clone())
            }
            Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
            _ => None,
        }
    }

    pub(super) fn encode_text_bytes(
        &self,
        input: &[u8],
        span: Span,
        context: &str,
        error_kind: AsmErrorKind,
    ) -> Result<Vec<u8>, AstEvalError> {
        self.text_encoding_registry
            .encode_bytes(&self.active_text_encoding, input)
            .map_err(|err| AstEvalError {
                error: AsmError::new(error_kind, &format!("{context}: {err}"), None),
                span,
            })
    }

    pub(super) fn parse_text_operand(
        &self,
        expr: &Expr,
        directive_name: &str,
    ) -> Result<(Vec<u8>, Span), AstEvalError> {
        match expr {
            Expr::String(raw, span) => {
                let encoded =
                    self.encode_text_bytes(raw, *span, directive_name, AsmErrorKind::Directive)?;
                Ok((encoded, *span))
            }
            _ => Err(AstEvalError {
                error: AsmError::new(
                    AsmErrorKind::Directive,
                    &format!("{directive_name} expects string operand"),
                    None,
                ),
                span: expr_span(expr),
            }),
        }
    }

    pub(super) fn text_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !self.section_kind_allows_data() {
            let msg = format!(
                ".text is not allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing string in .text list",
                None,
            );
        }

        let mut projected_total = 0u32;
        let mut encoded_chunks: Vec<Vec<u8>> = Vec::with_capacity(operands.len());
        for expr in operands {
            let (encoded, span) = match self.parse_text_operand(expr, ".text") {
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
            };
            let chunk_len = match u32::try_from(encoded.len()) {
                Ok(value) => value,
                Err(_) => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "String literal too large to emit",
                        None,
                        span,
                    );
                }
            };
            projected_total = match projected_total.checked_add(chunk_len) {
                Some(total) => total,
                None => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".text total size overflow exceeds supported range",
                        None,
                        span,
                    );
                }
            };
            if let Err(err) = self.validate_program_span(projected_total, ".text", span) {
                return self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                );
            }
            encoded_chunks.push(encoded);
        }
        for chunk in encoded_chunks {
            self.bytes.extend_from_slice(&chunk);
        }
        LineStatus::Ok
    }

    pub(super) fn null_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !self.section_kind_allows_data() {
            let msg = format!(
                ".null is not allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }
        if operands.len() != 1 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .null <string>",
                None,
            );
        }

        let (encoded, span) = match self.parse_text_operand(&operands[0], ".null") {
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
        };
        if encoded.contains(&0) {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".null source contains zero byte after encoding",
                None,
                span,
            );
        }
        let text_len = match u32::try_from(encoded.len()) {
            Ok(value) => value,
            Err(_) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "String literal too large to emit",
                    None,
                    span,
                );
            }
        };
        let total = match text_len.checked_add(1) {
            Some(value) => value,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    ".null total size overflow exceeds supported range",
                    None,
                    span,
                );
            }
        };
        if let Err(err) = self.validate_program_span(total, ".null", span) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        self.bytes.extend_from_slice(&encoded);
        self.bytes.push(0);
        LineStatus::Ok
    }

    pub(super) fn ptext_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if !self.section_kind_allows_data() {
            let msg = format!(
                ".ptext is not allowed in kind=bss section (current kind={})",
                self.current_section_kind_label()
            );
            return self.failure(LineStatus::Error, AsmErrorKind::Directive, &msg, None);
        }
        if operands.len() != 1 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .ptext <string>",
                None,
            );
        }

        let (encoded, span) = match self.parse_text_operand(&operands[0], ".ptext") {
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
        };
        if encoded.len() > u8::MAX as usize {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".ptext encoded string length exceeds 255 bytes",
                None,
                span,
            );
        }
        let text_len = encoded.len() as u32;
        let total = match text_len.checked_add(1) {
            Some(value) => value,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    ".ptext total size overflow exceeds supported range",
                    None,
                    span,
                );
            }
        };
        if let Err(err) = self.validate_program_span(total, ".ptext", span) {
            return self.failure_at_span(
                LineStatus::Error,
                err.error.kind(),
                err.error.message(),
                None,
                err.span,
            );
        }
        self.bytes.push(encoded.len() as u8);
        self.bytes.extend_from_slice(&encoded);
        LineStatus::Ok
    }
}
