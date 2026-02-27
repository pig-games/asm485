// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

impl<'a> AsmLine<'a> {
    pub(crate) fn route_metadata_directive_ast(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> Option<LineStatus> {
        match directive {
            "META" => {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .meta",
                        None,
                    ));
                }
                if self.output_state.in_meta_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Nested .meta is not allowed",
                        None,
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".meta") {
                    return Some(status);
                }
                self.output_state.in_meta_block = true;
                Some(LineStatus::Ok)
            }
            "ENDMETA" => {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endmeta",
                        None,
                    ));
                }
                if !self.output_state.in_meta_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endmeta found without matching .meta",
                        None,
                    ));
                }
                if self.output_state.in_output_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Cannot close .meta with open .output block",
                        None,
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".endmeta") {
                    return Some(status);
                }
                self.output_state.in_meta_block = false;
                Some(LineStatus::Ok)
            }
            "OUTPUT" => {
                if self.output_state.in_meta_block {
                    if !operands.is_empty() {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Unexpected operands for .output",
                            None,
                        ));
                    }
                    if self.output_state.in_output_block {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Nested .output is not allowed",
                            None,
                        ));
                    }
                    if let Some(status) = self.validate_metadata_scope(".output") {
                        return Some(status);
                    }
                    self.output_state.in_output_block = true;
                    self.output_state.output_cpu_block = None;
                    return Some(LineStatus::Ok);
                }
                Some(self.linker_output_directive_ast(operands))
            }
            "ENDOUTPUT" => {
                if !self.output_state.in_meta_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endoutput is only allowed inside a .meta block",
                        None,
                    ));
                }
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endoutput",
                        None,
                    ));
                }
                if !self.output_state.in_output_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endoutput found without matching .output",
                        None,
                    ));
                }
                if self.output_state.output_cpu_block.is_some() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Cannot close .output with open CPU output block",
                        None,
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".endoutput") {
                    return Some(status);
                }
                self.output_state.in_output_block = false;
                Some(LineStatus::Ok)
            }
            "NAME" => {
                if !self.output_state.in_meta_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".name is only allowed inside a .meta block",
                        None,
                    ));
                }
                if self.output_state.in_output_block {
                    if let Some(status) = self.validate_metadata_scope(".output.name") {
                        return Some(status);
                    }
                    let target = self.output_state.output_cpu_block.clone();
                    return Some(self.set_output_entry(
                        target.as_deref(),
                        "NAME",
                        operands,
                        ".name",
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".name") {
                    return Some(status);
                }
                let value = match self.metadata_value(operands, ".name") {
                    Some(value) => value,
                    None => return Some(LineStatus::Error),
                };
                self.output_state.root_metadata.name = Some(value);
                Some(LineStatus::Ok)
            }
            "VERSION" => {
                if !self.output_state.in_meta_block || self.output_state.in_output_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".version is only allowed inside a .meta block",
                        None,
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".version") {
                    return Some(status);
                }
                let value = match self.metadata_value(operands, ".version") {
                    Some(value) => value,
                    None => return Some(LineStatus::Error),
                };
                self.output_state.root_metadata.version = Some(value);
                Some(LineStatus::Ok)
            }
            "LIST" | "HEX" | "BIN" => {
                if !self.output_state.in_output_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!(".{directive} is only allowed inside a .output block"),
                        None,
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".output") {
                    return Some(status);
                }
                let target = self.output_state.output_cpu_block.clone();
                Some(self.set_output_entry(
                    target.as_deref(),
                    directive,
                    operands,
                    &format!(".{directive}"),
                ))
            }
            "FILL" => {
                if self.output_state.in_output_block {
                    if let Some(status) = self.validate_metadata_scope(".output") {
                        return Some(status);
                    }
                    let target = self.output_state.output_cpu_block.clone();
                    return Some(self.set_output_entry(
                        target.as_deref(),
                        directive,
                        operands,
                        &format!(".{directive}"),
                    ));
                }
                None
            }
            _ if self.output_state.in_output_block => {
                if let Some(status) = self.handle_output_cpu_block(directive, operands) {
                    return Some(status);
                }
                Some(LineStatus::NothingDone)
            }
            "MAPFILE" => Some(self.mapfile_directive_ast(operands)),
            "EXPORTSECTIONS" => Some(self.exportsections_directive_ast(operands)),
            _ if self.output_state.in_meta_block && directive.starts_with("OUTPUT.") => {
                if self.output_state.in_output_block {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Inline .output directives are not allowed inside a .output block",
                        None,
                    ));
                }
                if let Some(status) = self.validate_metadata_scope(".output") {
                    return Some(status);
                }
                let parts: Vec<&str> = directive.split('.').collect();
                let output_parts = &parts[1..];
                let (target, key) = match self.parse_output_inline_parts(output_parts) {
                    Ok((target, key)) => (target, key),
                    Err(message) => {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            message,
                            None,
                        ))
                    }
                };
                let directive_name = if let Some(target) = target.as_deref() {
                    format!(".output.{target}.{key}")
                } else {
                    format!(".output.{key}")
                };
                Some(self.set_output_entry(target.as_deref(), key, operands, &directive_name))
            }
            _ if directive.starts_with("OUTPUT.") => Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".output directives are only allowed inside a .meta block",
                None,
            )),
            _ if directive.starts_with("META.") => {
                if let Some(status) = self.validate_metadata_scope(".meta") {
                    return Some(status);
                }
                let parts: Vec<&str> = directive.split('.').collect();
                if parts.len() < 2 {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid .meta directive",
                        None,
                    ));
                }
                let key = parts[1];
                if key.eq_ignore_ascii_case("OUTPUT") {
                    if parts.len() < 3 {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Missing output key for .meta.output",
                            None,
                        ));
                    }
                    let output_parts = &parts[2..];
                    let (target, output_key) = match self.parse_output_inline_parts(output_parts) {
                        Ok((target, key)) => (target, key),
                        Err(message) => {
                            return Some(self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                message,
                                None,
                            ))
                        }
                    };
                    let directive_name = if let Some(target) = target.as_deref() {
                        format!(".meta.output.{target}.{output_key}")
                    } else {
                        format!(".meta.output.{output_key}")
                    };
                    return Some(self.set_output_entry(
                        target.as_deref(),
                        output_key,
                        operands,
                        &directive_name,
                    ));
                }

                if parts.len() > 2 {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unknown .meta directive",
                        None,
                    ));
                }

                match key.to_ascii_uppercase().as_str() {
                    "NAME" => {
                        let value = match self.metadata_value(operands, ".meta.name") {
                            Some(value) => value,
                            None => return Some(LineStatus::Error),
                        };
                        self.output_state.root_metadata.name = Some(value);
                    }
                    "VERSION" => {
                        let value = match self.metadata_value(operands, ".meta.version") {
                            Some(value) => value,
                            None => return Some(LineStatus::Error),
                        };
                        self.output_state.root_metadata.version = Some(value);
                    }
                    _ => {
                        return Some(self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Unknown .meta directive",
                            None,
                        ));
                    }
                }

                Some(LineStatus::Ok)
            }
            _ => None,
        }
    }

    pub(crate) fn validate_metadata_scope(&mut self, directive: &str) -> Option<LineStatus> {
        if !self.in_module() {
            return Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("{directive} must appear inside a module"),
                None,
            ));
        }
        if self.symbol_scope.scope_stack.depth() != self.symbol_scope.module_scope_depth {
            return Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("{directive} must appear at module scope"),
                None,
            ));
        }
        if let (Some(root_id), Some(module_id)) = (
            self.output_state.root_metadata.root_module_id.as_deref(),
            self.symbol_scope.module_active.as_deref(),
        ) {
            if !module_id.eq_ignore_ascii_case(root_id) {
                return Some(self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("{directive} is only allowed in the root module"),
                    None,
                ));
            }
        }
        None
    }

    pub(crate) fn expr_text_value(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(value, _) | Expr::Register(value, _) | Expr::Number(value, _) => {
                Some(value.clone())
            }
            Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
            _ => None,
        }
    }

    pub(crate) fn parse_option_kv<'b>(
        &mut self,
        directive: &str,
        option: &'b Expr,
    ) -> Result<(String, &'b Expr, Span), LineStatus> {
        let Expr::Binary {
            op: asm_parser::BinaryOp::Eq,
            left,
            right,
            span,
        } = option
        else {
            return Err(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("Expected key=value option in {directive}"),
                None,
                expr_span(option),
            ));
        };

        let key = match left.as_ref() {
            Expr::Identifier(name, _) | Expr::Register(name, _) => name.clone(),
            _ => {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Invalid option key in {directive}"),
                    None,
                    *span,
                ))
            }
        };

        Ok((key, right, *span))
    }

    pub(crate) fn is_key_value_option_expr(&self, expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::Binary {
                op: asm_parser::BinaryOp::Eq,
                left,
                ..
            } if matches!(left.as_ref(), Expr::Identifier(_, _) | Expr::Register(_, _))
        )
    }

    pub(crate) fn parse_bool_value(
        &mut self,
        directive: &str,
        key: &str,
        value_expr: &Expr,
        span: Span,
    ) -> Result<bool, LineStatus> {
        let value = match self.expr_text_value(value_expr) {
            Some(value) => value,
            None => {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Invalid {key} value in {directive}"),
                    None,
                    span,
                ))
            }
        };
        if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes") || value == "1" {
            Ok(true)
        } else if value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("no")
            || value == "0"
        {
            Ok(false)
        } else {
            Err(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("{key} must be true/false"),
                None,
                span,
            ))
        }
    }

    pub(crate) fn parse_u32_expr_value(
        &mut self,
        _directive: &str,
        _key: &str,
        value_expr: &Expr,
        _span: Span,
    ) -> Result<u32, LineStatus> {
        let value = match self.eval_expr_for_data_directive(value_expr) {
            Ok(value) => value,
            Err(err) => {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                ))
            }
        };
        Ok(value)
    }

    pub(crate) fn parse_image_span_text(
        &mut self,
        value_expr: &Expr,
        span: Span,
    ) -> Result<(u32, u32), LineStatus> {
        let value = match self.expr_text_value(value_expr) {
            Some(value) => value,
            None => {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Invalid image span value",
                    None,
                    span,
                ))
            }
        };
        let Some((start_text, end_text)) = value.split_once("..") else {
            return Err(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "image must use start..end (quote it for now)",
                None,
                span,
            ));
        };

        let start = match parse_number_text(start_text.trim(), span) {
            Ok(value) => value,
            Err(err) => {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                ))
            }
        };
        let end = match parse_number_text(end_text.trim(), span) {
            Ok(value) => value,
            Err(err) => {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    err.error.kind(),
                    err.error.message(),
                    None,
                    err.span,
                ))
            }
        };
        if start > end {
            return Err(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Invalid image span range",
                None,
                span,
            ));
        }
        Ok((start, end))
    }

    pub(crate) fn append_section_names_from_text(
        &mut self,
        directive: &str,
        sections: &mut Vec<String>,
        raw_value: &str,
        span: Span,
    ) -> Result<(), LineStatus> {
        for part in raw_value.split(',') {
            let section = part.trim();
            if section.is_empty() {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Invalid empty section name in {directive}"),
                    None,
                    span,
                ));
            }
            if sections
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(section))
            {
                return Err(self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Duplicate section name in {directive} sections list"),
                    Some(section),
                    span,
                ));
            }
            sections.push(section.to_string());
        }
        Ok(())
    }

    pub(crate) fn mapfile_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if let Some(status) = self.validate_metadata_scope(".mapfile") {
            return status;
        }
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .mapfile \"path\" [, symbols=all|public|none]",
                None,
            );
        }

        let path = match self.expr_text_value(&operands[0]) {
            Some(value) => value,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Invalid mapfile path",
                    None,
                    expr_span(&operands[0]),
                )
            }
        };

        let mut symbols = MapSymbolsMode::None;
        let mut saw_symbols = false;
        for option in &operands[1..] {
            let (key, value_expr, option_span) = match self.parse_option_kv(".mapfile", option) {
                Ok(parts) => parts,
                Err(status) => return status,
            };

            if !key.eq_ignore_ascii_case("symbols") {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Unknown .mapfile option key",
                    Some(&key),
                    option_span,
                );
            }
            if saw_symbols {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Duplicate symbols option in .mapfile",
                    None,
                    option_span,
                );
            }

            let value = match self.expr_text_value(value_expr) {
                Some(value) => value,
                None => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid symbols value in .mapfile",
                        None,
                        option_span,
                    )
                }
            };
            symbols = if value.eq_ignore_ascii_case("all") {
                MapSymbolsMode::All
            } else if value.eq_ignore_ascii_case("public") {
                MapSymbolsMode::Public
            } else if value.eq_ignore_ascii_case("none") {
                MapSymbolsMode::None
            } else {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Mapfile symbols must be all, public, or none",
                    None,
                    option_span,
                );
            };
            saw_symbols = true;
        }

        self.output_state
            .root_metadata
            .mapfiles
            .push(MapFileDirective { path, symbols });
        LineStatus::Ok
    }

    pub(crate) fn exportsections_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if let Some(status) = self.validate_metadata_scope(".exportsections") {
            return status;
        }
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .exportsections dir=... format=bin [, include=bss|no_bss]",
                None,
            );
        }

        let mut dir: Option<String> = None;
        let mut format: Option<ExportSectionsFormat> = None;
        let mut include = ExportSectionsInclude::NoBss;
        let mut saw_include = false;

        for option in operands {
            let (key, value_expr, option_span) =
                match self.parse_option_kv(".exportsections", option) {
                    Ok(parts) => parts,
                    Err(status) => return status,
                };

            if key.eq_ignore_ascii_case("dir") {
                if dir.is_some() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate dir option in .exportsections",
                        None,
                        option_span,
                    );
                }
                let value = match self.expr_text_value(value_expr) {
                    Some(value) => value,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Invalid dir value in .exportsections",
                            None,
                            option_span,
                        )
                    }
                };
                dir = Some(value);
                continue;
            }

            if key.eq_ignore_ascii_case("format") {
                if format.is_some() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate format option in .exportsections",
                        None,
                        option_span,
                    );
                }
                let value = match self.expr_text_value(value_expr) {
                    Some(value) => value,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Invalid format value in .exportsections",
                            None,
                            option_span,
                        )
                    }
                };
                if !value.eq_ignore_ascii_case("bin") {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "exportsections format must be bin",
                        None,
                        option_span,
                    );
                }
                format = Some(ExportSectionsFormat::Bin);
                continue;
            }

            if key.eq_ignore_ascii_case("include") {
                if saw_include {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate include option in .exportsections",
                        None,
                        option_span,
                    );
                }
                let value = match self.expr_text_value(value_expr) {
                    Some(value) => value,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Invalid include value in .exportsections",
                            None,
                            option_span,
                        )
                    }
                };
                include = if value.eq_ignore_ascii_case("bss") {
                    ExportSectionsInclude::Bss
                } else if value.eq_ignore_ascii_case("no_bss") {
                    ExportSectionsInclude::NoBss
                } else {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "include must be bss or no_bss",
                        None,
                        option_span,
                    );
                };
                saw_include = true;
                continue;
            }

            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unknown .exportsections option key",
                Some(&key),
                option_span,
            );
        }

        let Some(dir) = dir else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing dir option in .exportsections",
                None,
            );
        };
        let Some(format) = format else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing format option in .exportsections",
                None,
            );
        };

        self.output_state
            .root_metadata
            .export_sections
            .push(ExportSectionsDirective {
                dir,
                format,
                include,
            });
        LineStatus::Ok
    }

    pub(crate) fn linker_output_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
        if let Some(status) = self.validate_metadata_scope(".output") {
            return status;
        }
        if operands.len() < 2 {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Expected .output \"file\", format=..., sections=...",
                None,
            );
        }

        let path = match self.expr_text_value(&operands[0]) {
            Some(value) => value,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Invalid output path",
                    None,
                    expr_span(&operands[0]),
                )
            }
        };

        let mut format: Option<LinkerOutputFormat> = None;
        let mut sections: Vec<String> = Vec::new();
        let mut contiguous = true;
        let mut saw_contiguous = false;
        let mut image_start: Option<u32> = None;
        let mut image_end: Option<u32> = None;
        let mut fill: Option<u8> = None;
        let mut loadaddr: Option<u32> = None;

        let mut idx = 1usize;
        while idx < operands.len() {
            let option = &operands[idx];
            let (key, value_expr, option_span) = match self.parse_option_kv(".output", option) {
                Ok(parts) => parts,
                Err(status) => return status,
            };

            if key.eq_ignore_ascii_case("format") {
                if format.is_some() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate format option in .output",
                        None,
                        option_span,
                    );
                }
                let value = match self.expr_text_value(value_expr) {
                    Some(value) => value,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Invalid format value in .output",
                            None,
                            option_span,
                        )
                    }
                };
                format = if value.eq_ignore_ascii_case("bin") {
                    Some(LinkerOutputFormat::Bin)
                } else if value.eq_ignore_ascii_case("prg") {
                    Some(LinkerOutputFormat::Prg)
                } else {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Output format must be bin or prg",
                        None,
                        option_span,
                    );
                };
                idx += 1;
                continue;
            }

            if key.eq_ignore_ascii_case("sections") {
                if !sections.is_empty() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate sections option in .output",
                        None,
                        option_span,
                    );
                }
                let value = match self.expr_text_value(value_expr) {
                    Some(value) => value,
                    None => {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Invalid sections value in .output",
                            None,
                            option_span,
                        )
                    }
                };
                if let Err(status) = self.append_section_names_from_text(
                    ".output",
                    &mut sections,
                    &value,
                    option_span,
                ) {
                    return status;
                }
                idx += 1;
                while idx < operands.len() {
                    if self.is_key_value_option_expr(&operands[idx]) {
                        break;
                    }
                    let value = match self.expr_text_value(&operands[idx]) {
                        Some(value) => value,
                        None => {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "Invalid section name in .output sections list",
                                None,
                                expr_span(&operands[idx]),
                            )
                        }
                    };
                    if let Err(status) = self.append_section_names_from_text(
                        ".output",
                        &mut sections,
                        &value,
                        expr_span(&operands[idx]),
                    ) {
                        return status;
                    }
                    idx += 1;
                }
                continue;
            }

            if key.eq_ignore_ascii_case("contiguous") {
                if saw_contiguous {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate contiguous option in .output",
                        None,
                        option_span,
                    );
                }
                contiguous =
                    match self.parse_bool_value(".output", "contiguous", value_expr, option_span) {
                        Ok(value) => value,
                        Err(status) => return status,
                    };
                saw_contiguous = true;
                idx += 1;
                continue;
            }

            if key.eq_ignore_ascii_case("image") {
                if image_start.is_some() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate image option in .output",
                        None,
                        option_span,
                    );
                }
                let (start, end) = match self.parse_image_span_text(value_expr, option_span) {
                    Ok(range) => range,
                    Err(status) => return status,
                };
                image_start = Some(start);
                image_end = Some(end);
                idx += 1;
                continue;
            }

            if key.eq_ignore_ascii_case("fill") {
                if fill.is_some() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate fill option in .output",
                        None,
                        option_span,
                    );
                }
                let value = match self.eval_expr_for_data_directive(value_expr) {
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
                if value > u8::MAX as u32 {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "fill must be in range 0..255 in .output",
                        None,
                        option_span,
                    );
                }
                fill = Some(value as u8);
                idx += 1;
                continue;
            }

            if key.eq_ignore_ascii_case("loadaddr") {
                if loadaddr.is_some() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Duplicate loadaddr option in .output",
                        None,
                        option_span,
                    );
                }
                loadaddr =
                    match self.parse_u32_expr_value(".output", "loadaddr", value_expr, option_span)
                    {
                        Ok(value) => Some(value),
                        Err(status) => return status,
                    };
                idx += 1;
                continue;
            }

            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unknown .output option key",
                Some(&key),
                option_span,
            );
        }

        let Some(format) = format else {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing format option in .output",
                None,
            );
        };
        if sections.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing sections option in .output",
                None,
            );
        }
        if image_start.is_some() && fill.is_none() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "image output requires fill in .output",
                None,
            );
        }
        if image_start.is_none() && fill.is_some() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "fill is only allowed with image output in .output",
                None,
            );
        }

        self.output_state
            .root_metadata
            .linker_outputs
            .push(LinkerOutputDirective {
                path,
                format,
                sections,
                contiguous,
                image_start,
                image_end,
                fill,
                loadaddr,
            });
        LineStatus::Ok
    }

    pub(crate) fn metadata_value(&mut self, operands: &[Expr], directive: &str) -> Option<String> {
        if operands.len() != 1 {
            self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("Missing value for {directive}"),
                None,
            );
            return None;
        }
        match operands.first()? {
            Expr::Identifier(name, _) | Expr::Register(name, _) | Expr::Number(name, _) => {
                Some(name.clone())
            }
            Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
            _ => {
                self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Invalid value for {directive}"),
                    None,
                );
                None
            }
        }
    }

    pub(crate) fn metadata_optional_value(
        &mut self,
        operands: &[Expr],
        directive: &str,
    ) -> Option<String> {
        if operands.is_empty() {
            return Some(String::new());
        }
        if operands.len() != 1 {
            self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("Invalid value for {directive}"),
                None,
            );
            return None;
        }
        self.metadata_value(operands, directive)
    }

    pub(crate) fn metadata_bin_spec(
        &mut self,
        operands: &[Expr],
        directive: &str,
    ) -> Option<BinOutputSpec> {
        let value = self.metadata_optional_value(operands, directive)?;
        match crate::assembler::cli::parse_bin_output_arg(&value) {
            Ok(spec) => Some(spec),
            Err(message) => {
                self.failure(LineStatus::Error, AsmErrorKind::Directive, message, None);
                None
            }
        }
    }

    pub(crate) fn metadata_fill_byte(&mut self, operands: &[Expr], directive: &str) -> Option<u8> {
        let value = self.metadata_value(operands, directive)?;
        if !crate::assembler::cli::is_valid_hex_2(&value) {
            self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("Invalid {directive} byte; must be 2 hex digits"),
                None,
            );
            return None;
        }
        match u8::from_str_radix(&value, 16) {
            Ok(byte) => Some(byte),
            Err(_) => {
                self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Invalid {directive} byte; must be 2 hex digits"),
                    None,
                );
                None
            }
        }
    }

    pub(crate) fn resolve_cpu_key(&self, name: &str) -> Option<String> {
        self.registry
            .resolve_cpu_name(name)
            .map(|cpu| cpu.as_str().to_ascii_lowercase())
    }

    pub(crate) fn parse_output_inline_parts<'b>(
        &self,
        parts: &'b [&'b str],
    ) -> Result<(Option<String>, &'b str), &'static str> {
        match parts.len() {
            0 => Err("Missing output key"),
            1 => {
                if self.resolve_cpu_key(parts[0]).is_some() {
                    Err("Missing output key for CPU-specific output")
                } else {
                    Ok((None, parts[0]))
                }
            }
            2 => {
                if let Some(cpu) = self.resolve_cpu_key(parts[0]) {
                    Ok((Some(cpu), parts[1]))
                } else {
                    Err("Unknown .output directive")
                }
            }
            _ => Err("Unknown .output directive"),
        }
    }

    pub(crate) fn set_output_entry(
        &mut self,
        target: Option<&str>,
        key: &str,
        operands: &[Expr],
        directive: &str,
    ) -> LineStatus {
        let key = key.to_ascii_uppercase();
        match key.as_str() {
            "NAME" => {
                let value = match self.metadata_value(operands, directive) {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                let config = self.output_state.root_metadata.output_config_mut(target);
                config.name = Some(value);
                LineStatus::Ok
            }
            "LIST" => {
                let value = match self.metadata_optional_value(operands, directive) {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                let config = self.output_state.root_metadata.output_config_mut(target);
                config.list_name = Some(value);
                LineStatus::Ok
            }
            "HEX" => {
                let value = match self.metadata_optional_value(operands, directive) {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                let config = self.output_state.root_metadata.output_config_mut(target);
                config.hex_name = Some(value);
                LineStatus::Ok
            }
            "BIN" => {
                let spec = match self.metadata_bin_spec(operands, directive) {
                    Some(spec) => spec,
                    None => return LineStatus::Error,
                };
                let config = self.output_state.root_metadata.output_config_mut(target);
                config.bin_specs.push(spec);
                LineStatus::Ok
            }
            "FILL" => {
                let fill = match self.metadata_fill_byte(operands, directive) {
                    Some(fill) => fill,
                    None => return LineStatus::Error,
                };
                let config = self.output_state.root_metadata.output_config_mut(target);
                config.fill_byte = Some(fill);
                LineStatus::Ok
            }
            _ => self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unknown .output directive",
                None,
            ),
        }
    }

    pub(crate) fn handle_output_cpu_block(
        &mut self,
        directive: &str,
        operands: &[Expr],
    ) -> Option<LineStatus> {
        let upper = directive.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("END") {
            if let Some(cpu_key) = self.resolve_cpu_key(rest) {
                if !operands.is_empty() {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!("Unexpected operands for .end{}", rest.to_ascii_lowercase()),
                        None,
                    ));
                }
                if self.output_state.output_cpu_block.as_deref() != Some(cpu_key.as_str()) {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!(".end{} found without matching .{}", rest, rest),
                        None,
                    ));
                }
                self.output_state.output_cpu_block = None;
                return Some(LineStatus::Ok);
            }
        }
        if let Some(cpu_key) = self.resolve_cpu_key(&upper) {
            if !operands.is_empty() {
                return Some(self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &format!("Unexpected operands for .{}", upper.to_ascii_lowercase()),
                    None,
                ));
            }
            if self.output_state.output_cpu_block.is_some() {
                return Some(self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Nested CPU output block is not allowed",
                    None,
                ));
            }
            self.output_state.output_cpu_block = Some(cpu_key);
            return Some(LineStatus::Ok);
        }
        None
    }
}
