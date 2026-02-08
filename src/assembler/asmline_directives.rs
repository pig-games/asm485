// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

impl<'a> AsmLine<'a> {
    pub(crate) fn process_directive_ast(
        &mut self,
        mnemonic: &str,
        operands: &[Expr],
    ) -> LineStatus {
        let upper = mnemonic.to_ascii_uppercase();
        let had_dot = upper.starts_with('.');
        let directive = upper.strip_prefix('.').unwrap_or(&upper);
        if !had_dot {
            return LineStatus::NothingDone;
        }
        match directive {
            "META" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .meta",
                        None,
                    );
                }
                if self.in_meta_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Nested .meta is not allowed",
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".meta") {
                    return status;
                }
                self.in_meta_block = true;
                LineStatus::Ok
            }
            "ENDMETA" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endmeta",
                        None,
                    );
                }
                if !self.in_meta_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endmeta found without matching .meta",
                        None,
                    );
                }
                if self.in_output_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Cannot close .meta with open .output block",
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".endmeta") {
                    return status;
                }
                self.in_meta_block = false;
                LineStatus::Ok
            }
            "OUTPUT" => {
                if self.in_meta_block {
                    if !operands.is_empty() {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Unexpected operands for .output",
                            None,
                        );
                    }
                    if self.in_output_block {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Nested .output is not allowed",
                            None,
                        );
                    }
                    if let Some(status) = self.validate_metadata_scope(".output") {
                        return status;
                    }
                    self.in_output_block = true;
                    self.output_cpu_block = None;
                    return LineStatus::Ok;
                }
                self.linker_output_directive_ast(operands)
            }
            "ENDOUTPUT" => {
                if !self.in_meta_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endoutput is only allowed inside a .meta block",
                        None,
                    );
                }
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endoutput",
                        None,
                    );
                }
                if !self.in_output_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endoutput found without matching .output",
                        None,
                    );
                }
                if self.output_cpu_block.is_some() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Cannot close .output with open CPU output block",
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".endoutput") {
                    return status;
                }
                self.in_output_block = false;
                LineStatus::Ok
            }
            "DSECTION" => self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".dsection has been removed; use .place/.pack with .output",
                None,
            ),
            "REGION" => {
                if operands.len() < 3 {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Expected .region <name>, <start>, <end> [, align=<n>]",
                        None,
                    );
                }
                let Some(name) = operands.first().and_then(expr_to_ident) else {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid region name for .region",
                        None,
                    );
                };

                let start = match self.eval_expr_ast(&operands[1]) {
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
                let end = match self.eval_expr_ast(&operands[2]) {
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
                if start > end {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid .region range",
                        Some(&name),
                    );
                }

                let mut align: u32 = 1;
                for expr in &operands[3..] {
                    let Expr::Binary {
                        op: asm_parser::BinaryOp::Eq,
                        left,
                        right,
                        span,
                    } = expr
                    else {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Expected region option in key=value form",
                            None,
                            expr_span(expr),
                        );
                    };
                    let key = match left.as_ref() {
                        Expr::Identifier(name, _) | Expr::Register(name, _) => name,
                        _ => {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "Invalid region option key",
                                None,
                                *span,
                            )
                        }
                    };
                    if !key.eq_ignore_ascii_case("align") {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Unknown region option key",
                            Some(key),
                            *span,
                        );
                    }
                    let value = match self.eval_expr_ast(right) {
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
                    if value == 0 {
                        return self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Region align must be greater than zero",
                            None,
                            *span,
                        );
                    }
                    align = value;
                }

                if let Some(existing) = self.regions.get(&name) {
                    if existing.start != start || existing.end != end || existing.align != align {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Region conflicts with existing definition",
                            Some(&name),
                        );
                    }
                } else {
                    if let Some((other_name, overlap_start, overlap_end)) =
                        self.regions.iter().find_map(|(existing_name, existing)| {
                            if start <= existing.end && existing.start <= end {
                                Some((
                                    existing_name,
                                    start.max(existing.start),
                                    end.min(existing.end),
                                ))
                            } else {
                                None
                            }
                        })
                    {
                        let msg = format!(
                            "Region range overlaps existing region '{other_name}' at ${}..${}",
                            super::format_addr(overlap_start),
                            super::format_addr(overlap_end)
                        );
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            &msg,
                            Some(&name),
                        );
                    }
                    self.regions.insert(
                        name.clone(),
                        RegionState {
                            name,
                            start,
                            end,
                            cursor: start,
                            align,
                            placed: Vec::new(),
                        },
                    );
                }
                LineStatus::Ok
            }
            "SECTION" => {
                if operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Missing section name for .section",
                        None,
                    );
                }
                let Some(name) = operands.first().and_then(expr_to_ident) else {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid section name for .section",
                        None,
                    );
                };
                let options = match self.parse_section_options(&operands[1..]) {
                    Ok(options) => options,
                    Err(status) => return status,
                };
                if let Some(section) = self.sections.get_mut(&name) {
                    if section.align == 0 {
                        // Normalize legacy defaulted sections.
                        section.align = 1;
                    }
                }
                if let Some(section) = self.sections.get(&name) {
                    if section.emitted {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Section has already been placed",
                            Some(&name),
                        );
                    }
                    if let Some(align) = options.align {
                        if section.align != align {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "Section align conflicts with existing definition",
                                Some(&name),
                            );
                        }
                    }
                    if let Some(kind) = options.kind {
                        if section.kind != kind {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "Section kind conflicts with existing definition",
                                Some(&name),
                            );
                        }
                    }
                    if let Some(region) = options.region.as_deref() {
                        if section.default_region.as_deref() != Some(region) {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                "Section region conflicts with existing definition",
                                Some(&name),
                            );
                        }
                    }
                } else {
                    let mut section = SectionState {
                        align: 1,
                        ..SectionState::default()
                    };
                    if let Some(align) = options.align {
                        section.align = align;
                    }
                    if let Some(kind) = options.kind {
                        section.kind = kind;
                    }
                    section.default_region = options.region;
                    self.sections.insert(name.clone(), section);
                }
                self.section_stack.push(self.current_section.take());
                self.current_section = Some(name);
                LineStatus::Ok
            }
            "ENDSECTION" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endsection",
                        None,
                    );
                }
                if !self.in_section() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endsection found without matching .section",
                        None,
                    );
                }
                self.current_section = self.section_stack.pop().unwrap_or(None);
                LineStatus::Ok
            }
            "MAPFILE" => self.mapfile_directive_ast(operands),
            "EXPORTSECTIONS" => self.exportsections_directive_ast(operands),
            "NAME" => {
                if !self.in_meta_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".name is only allowed inside a .meta block",
                        None,
                    );
                }
                if self.in_output_block {
                    if let Some(status) = self.validate_metadata_scope(".output.name") {
                        return status;
                    }
                    let target = self.output_cpu_block.clone();
                    return self.set_output_entry(target.as_deref(), "NAME", operands, ".name");
                }
                if let Some(status) = self.validate_metadata_scope(".name") {
                    return status;
                }
                let value = match self.metadata_value(operands, ".name") {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                self.root_metadata.name = Some(value);
                LineStatus::Ok
            }
            "VERSION" => {
                if !self.in_meta_block || self.in_output_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".version is only allowed inside a .meta block",
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".version") {
                    return status;
                }
                let value = match self.metadata_value(operands, ".version") {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                self.root_metadata.version = Some(value);
                LineStatus::Ok
            }
            "LIST" | "HEX" | "BIN" => {
                if !self.in_output_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!(".{directive} is only allowed inside a .output block"),
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".output") {
                    return status;
                }
                let target = self.output_cpu_block.clone();
                self.set_output_entry(
                    target.as_deref(),
                    directive,
                    operands,
                    &format!(".{directive}"),
                )
            }
            "FILL" => {
                if self.in_output_block {
                    if let Some(status) = self.validate_metadata_scope(".output") {
                        return status;
                    }
                    let target = self.output_cpu_block.clone();
                    return self.set_output_entry(
                        target.as_deref(),
                        directive,
                        operands,
                        &format!(".{directive}"),
                    );
                }
                self.fill_directive_ast(operands)
            }
            _ if self.in_output_block => {
                if let Some(status) = self.handle_output_cpu_block(directive, operands) {
                    return status;
                }
                LineStatus::NothingDone
            }
            "MODULE" => {
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
                if self.scope_stack.depth() > 0 {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".module must appear at top level",
                        None,
                    );
                }
                if self.top_level_content_seen {
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
                self.saw_explicit_module = true;
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
                if let Err(message) = self.scope_stack.push_named(&module_id) {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        message,
                        Some(&module_id),
                    );
                }
                self.push_visibility();
                self.module_active = Some(module_id);
                self.module_scope_depth = self.scope_stack.depth();
                LineStatus::Ok
            }
            "ENDMODULE" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endmodule",
                        None,
                    );
                }
                if self.in_meta_block {
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
                if !self.in_module() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endmodule found without matching .module",
                        None,
                    );
                }
                if self.scope_stack.depth() != self.module_scope_depth {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Cannot close module with open scopes",
                        None,
                    );
                }
                if !self.scope_stack.pop() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endmodule found without matching .module",
                        None,
                    );
                }
                self.pop_visibility();
                self.module_active = None;
                self.module_scope_depth = 0;
                LineStatus::Ok
            }
            "BLOCK" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .block",
                        None,
                    );
                }
                if let Some(label) = self.label.clone() {
                    if let Err(message) = self.scope_stack.push_named(&label) {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            message,
                            Some(&label),
                        );
                    }
                } else {
                    self.scope_stack.push_anonymous();
                }
                self.push_visibility();
                LineStatus::Ok
            }
            "ENDBLOCK" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .endblock",
                        None,
                    );
                }
                if !self.scope_stack.pop() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        ".endblock found without matching .block",
                        None,
                    );
                }
                self.pop_visibility();
                LineStatus::Ok
            }
            "PUB" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .pub",
                        None,
                    );
                }
                self.set_visibility(SymbolVisibility::Public);
                LineStatus::Ok
            }
            "PRIV" => {
                if !operands.is_empty() {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unexpected operands for .priv",
                        None,
                    );
                }
                self.set_visibility(SymbolVisibility::Private);
                LineStatus::Ok
            }
            "ORG" => {
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
                let val = match self.eval_expr_ast(expr) {
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
                if let Some(section_name) = self.current_section.as_deref() {
                    if let Some(section) = self.sections.get(section_name) {
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
            "ALIGN" => {
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
                let val = match self.eval_expr_ast(expr) {
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
                self.aux_value = pad;
                LineStatus::DirDs
            }
            "CONST" | "VAR" | "SET" => {
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
                let val = match self.eval_expr_ast(expr) {
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
                        self.module_active.as_deref(),
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
            "CPU" => {
                // .cpu directive to switch target CPU
                let cpu_name = match operands.first() {
                    Some(Expr::Identifier(name, _)) => name.clone(),
                    Some(Expr::Register(name, _)) => name.clone(), // In case Z80 is parsed as register
                    Some(Expr::Number(name, _)) => name.clone(),   // For bare "8085" without quotes
                    Some(Expr::String(bytes, _)) => String::from_utf8_lossy(bytes).to_string(),
                    _ => {
                        let known = self.registry.cpu_name_list();
                        let hint = known.join(", ");
                        let message = if hint.is_empty() {
                            ".cpu requires a CPU type".to_string()
                        } else {
                            format!(".cpu requires a CPU type: {hint}")
                        };
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            &message,
                            None,
                        );
                    }
                };
                match self.registry.resolve_cpu_name(&cpu_name) {
                    Some(cpu) => {
                        self.cpu = cpu;
                        self.reset_cpu_runtime_profile();
                        self.register_checker =
                            Self::build_register_checker(self.registry, self.cpu);
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
            "EMIT" => self.emit_directive_ast(operands),
            "RES" => self.res_directive_ast(operands),
            "BYTE" | "DB" => self.store_arg_list_ast(operands, 1),
            "WORD" | "DW" => self.store_arg_list_ast(operands, 2),
            "LONG" => self.store_arg_list_ast(operands, 4),
            "DS" => {
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
                let val = match self.eval_expr_ast(expr) {
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
                self.aux_value = val;
                LineStatus::DirDs
            }
            _ if self.in_meta_block && directive.starts_with("OUTPUT.") => {
                if self.in_output_block {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Inline .output directives are not allowed inside a .output block",
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".output") {
                    return status;
                }
                let parts: Vec<&str> = directive.split('.').collect();
                let output_parts = &parts[1..];
                let (target, key) = match self.parse_output_inline_parts(output_parts) {
                    Ok((target, key)) => (target, key),
                    Err(message) => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            message,
                            None,
                        )
                    }
                };
                let directive_name = if let Some(target) = target.as_deref() {
                    format!(".output.{target}.{key}")
                } else {
                    format!(".output.{key}")
                };
                self.set_output_entry(target.as_deref(), key, operands, &directive_name)
            }
            _ if directive.starts_with("OUTPUT.") => self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".output directives are only allowed inside a .meta block",
                None,
            ),
            _ if directive.starts_with("META") => {
                if directive == "META" {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Missing metadata key for .meta",
                        None,
                    );
                }
                if let Some(status) = self.validate_metadata_scope(".meta") {
                    return status;
                }
                let parts: Vec<&str> = directive.split('.').collect();
                if parts.len() < 2 {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid .meta directive",
                        None,
                    );
                }
                let key = parts[1];
                if key.eq_ignore_ascii_case("OUTPUT") {
                    if parts.len() < 3 {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Missing output key for .meta.output",
                            None,
                        );
                    }
                    let output_parts = &parts[2..];
                    let (target, output_key) = match self.parse_output_inline_parts(output_parts) {
                        Ok((target, key)) => (target, key),
                        Err(message) => {
                            return self.failure(
                                LineStatus::Error,
                                AsmErrorKind::Directive,
                                message,
                                None,
                            )
                        }
                    };
                    let directive_name = if let Some(target) = target.as_deref() {
                        format!(".meta.output.{target}.{output_key}")
                    } else {
                        format!(".meta.output.{output_key}")
                    };
                    return self.set_output_entry(
                        target.as_deref(),
                        output_key,
                        operands,
                        &directive_name,
                    );
                }

                if parts.len() > 2 {
                    return self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unknown .meta directive",
                        None,
                    );
                }

                match key.to_ascii_uppercase().as_str() {
                    "NAME" => {
                        let value = match self.metadata_value(operands, ".meta.name") {
                            Some(value) => value,
                            None => return LineStatus::Error,
                        };
                        self.root_metadata.name = Some(value);
                    }
                    "VERSION" => {
                        let value = match self.metadata_value(operands, ".meta.version") {
                            Some(value) => value,
                            None => return LineStatus::Error,
                        };
                        self.root_metadata.version = Some(value);
                    }
                    _ => {
                        return self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Unknown .meta directive",
                            None,
                        );
                    }
                }

                LineStatus::Ok
            }
            "END" => LineStatus::Ok,
            _ => LineStatus::NothingDone,
        }
    }

    fn validate_metadata_scope(&mut self, directive: &str) -> Option<LineStatus> {
        if !self.in_module() {
            return Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("{directive} must appear inside a module"),
                None,
            ));
        }
        if self.scope_stack.depth() != self.module_scope_depth {
            return Some(self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                &format!("{directive} must appear at module scope"),
                None,
            ));
        }
        if let (Some(root_id), Some(module_id)) = (
            self.root_metadata.root_module_id.as_deref(),
            self.module_active.as_deref(),
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

    fn expr_text_value(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(value, _) | Expr::Register(value, _) | Expr::Number(value, _) => {
                Some(value.clone())
            }
            Expr::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
            _ => None,
        }
    }

    fn parse_option_kv<'b>(
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

    fn is_key_value_option_expr(&self, expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::Binary {
                op: asm_parser::BinaryOp::Eq,
                left,
                ..
            } if matches!(left.as_ref(), Expr::Identifier(_, _) | Expr::Register(_, _))
        )
    }

    fn parse_bool_value(
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

    fn parse_u32_expr_value(
        &mut self,
        _directive: &str,
        _key: &str,
        value_expr: &Expr,
        _span: Span,
    ) -> Result<u32, LineStatus> {
        let value = match self.eval_expr_ast(value_expr) {
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

    fn parse_image_span_text(
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

    fn append_section_names_from_text(
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
            sections.push(section.to_string());
        }
        Ok(())
    }

    fn mapfile_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

        self.root_metadata
            .mapfiles
            .push(MapFileDirective { path, symbols });
        LineStatus::Ok
    }

    fn exportsections_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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

        self.root_metadata
            .export_sections
            .push(ExportSectionsDirective {
                dir,
                format,
                include,
            });
        LineStatus::Ok
    }

    fn linker_output_directive_ast(&mut self, operands: &[Expr]) -> LineStatus {
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
                let value = match self.eval_expr_ast(value_expr) {
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

        self.root_metadata
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

    fn metadata_value(&mut self, operands: &[Expr], directive: &str) -> Option<String> {
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

    fn metadata_optional_value(&mut self, operands: &[Expr], directive: &str) -> Option<String> {
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

    fn metadata_bin_spec(&mut self, operands: &[Expr], directive: &str) -> Option<BinOutputSpec> {
        let value = self.metadata_optional_value(operands, directive)?;
        match crate::assembler::cli::parse_bin_output_arg(&value) {
            Ok(spec) => Some(spec),
            Err(message) => {
                self.failure(LineStatus::Error, AsmErrorKind::Directive, message, None);
                None
            }
        }
    }

    fn metadata_fill_byte(&mut self, operands: &[Expr], directive: &str) -> Option<u8> {
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

    fn resolve_cpu_key(&self, name: &str) -> Option<String> {
        self.registry
            .resolve_cpu_name(name)
            .map(|cpu| cpu.as_str().to_ascii_lowercase())
    }

    fn parse_output_inline_parts<'b>(
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

    fn set_output_entry(
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
                let config = self.root_metadata.output_config_mut(target);
                config.name = Some(value);
                LineStatus::Ok
            }
            "LIST" => {
                let value = match self.metadata_optional_value(operands, directive) {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                let config = self.root_metadata.output_config_mut(target);
                config.list_name = Some(value);
                LineStatus::Ok
            }
            "HEX" => {
                let value = match self.metadata_optional_value(operands, directive) {
                    Some(value) => value,
                    None => return LineStatus::Error,
                };
                let config = self.root_metadata.output_config_mut(target);
                config.hex_name = Some(value);
                LineStatus::Ok
            }
            "BIN" => {
                let spec = match self.metadata_bin_spec(operands, directive) {
                    Some(spec) => spec,
                    None => return LineStatus::Error,
                };
                let config = self.root_metadata.output_config_mut(target);
                config.bin_specs.push(spec);
                LineStatus::Ok
            }
            "FILL" => {
                let fill = match self.metadata_fill_byte(operands, directive) {
                    Some(fill) => fill,
                    None => return LineStatus::Error,
                };
                let config = self.root_metadata.output_config_mut(target);
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

    fn handle_output_cpu_block(
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
                if self.output_cpu_block.as_deref() != Some(cpu_key.as_str()) {
                    return Some(self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        &format!(".end{} found without matching .{}", rest, rest),
                        None,
                    ));
                }
                self.output_cpu_block = None;
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
            if self.output_cpu_block.is_some() {
                return Some(self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Nested CPU output block is not allowed",
                    None,
                ));
            }
            self.output_cpu_block = Some(cpu_key);
            return Some(LineStatus::Ok);
        }
        None
    }

    fn parse_section_kind_expr(&self, expr: &Expr) -> Option<SectionKind> {
        let text = match expr {
            Expr::Identifier(text, _) | Expr::Register(text, _) | Expr::Number(text, _) => {
                text.as_str()
            }
            Expr::String(bytes, _) => std::str::from_utf8(bytes).ok()?,
            _ => return None,
        };
        if text.eq_ignore_ascii_case("code") {
            Some(SectionKind::Code)
        } else if text.eq_ignore_ascii_case("data") {
            Some(SectionKind::Data)
        } else if text.eq_ignore_ascii_case("bss") {
            Some(SectionKind::Bss)
        } else {
            None
        }
    }

    fn parse_section_options(&mut self, operands: &[Expr]) -> Result<SectionOptions, LineStatus> {
        let mut options = SectionOptions::default();
        for option in operands {
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
                    "Expected section option in key=value form",
                    None,
                    expr_span(option),
                ));
            };
            let key = match left.as_ref() {
                Expr::Identifier(name, _) | Expr::Register(name, _) => name,
                _ => {
                    return Err(self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Invalid section option key",
                        None,
                        *span,
                    ))
                }
            };

            if key.eq_ignore_ascii_case("align") {
                let align = match self.eval_expr_ast(right) {
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
                if align == 0 {
                    return Err(self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Section align must be greater than zero",
                        None,
                        *span,
                    ));
                }
                options.align = Some(align);
                continue;
            }

            if key.eq_ignore_ascii_case("kind") {
                let kind = match self.parse_section_kind_expr(right) {
                    Some(kind) => kind,
                    None => {
                        return Err(self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Section kind must be code, data, or bss",
                            None,
                            *span,
                        ))
                    }
                };
                options.kind = Some(kind);
                continue;
            }

            if key.eq_ignore_ascii_case("region") {
                let region = match right.as_ref() {
                    Expr::Identifier(name, _) | Expr::Register(name, _) => name.clone(),
                    Expr::String(bytes, _) => String::from_utf8_lossy(bytes).to_string(),
                    _ => {
                        return Err(self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Directive,
                            "Section region must be an identifier or string",
                            None,
                            *span,
                        ))
                    }
                };
                options.region = Some(region);
                continue;
            }

            return Err(self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Unknown section option key",
                Some(key),
                *span,
            ));
        }
        Ok(options)
    }

    fn align_up(value: u32, align: u32) -> Option<u32> {
        if align <= 1 {
            return Some(value);
        }
        let rem = value % align;
        if rem == 0 {
            Some(value)
        } else {
            value.checked_add(align - rem)
        }
    }

    fn place_section_in_region(
        &mut self,
        section_name: &str,
        region_name: &str,
        directive_align: Option<u32>,
        span: Span,
    ) -> LineStatus {
        if self.in_section() {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                ".place/.pack is not allowed inside an active .section block",
                None,
                span,
            );
        }

        let (section_align, section_size, section_placed, section_default_region) =
            match self.sections.get(section_name) {
                Some(section) => (
                    section.align.max(1),
                    section.size_bytes(),
                    section.layout_placed,
                    section.default_region.clone(),
                ),
                None => {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Unknown section in placement directive",
                        Some(section_name),
                        span,
                    )
                }
            };
        if section_placed {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Section has already been placed",
                Some(section_name),
                span,
            );
        }
        if let Some(bound_region) = section_default_region {
            if !bound_region.eq_ignore_ascii_case(region_name) {
                let msg = format!(
                    "Section is bound to region '{bound_region}' but was placed in region '{region_name}'"
                );
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    &msg,
                    Some(section_name),
                    span,
                );
            }
        }

        let (region_align, region_cursor, region_end) = match self.regions.get(region_name) {
            Some(region) => (region.align.max(1), region.cursor, region.end),
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Unknown region in placement directive",
                    Some(region_name),
                    span,
                )
            }
        };

        let align = directive_align
            .unwrap_or(1)
            .max(region_align)
            .max(section_align);
        let base = match Self::align_up(region_cursor, align) {
            Some(base) => base,
            None => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Section alignment overflows address range",
                    Some(section_name),
                    span,
                )
            }
        };
        let size = section_size;
        let last_addr = if size == 0 {
            base
        } else {
            base.saturating_add(size.saturating_sub(1))
        };
        if size > 0 && last_addr > region_end {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Section placement overflows region",
                Some(section_name),
                span,
            );
        }
        let new_cursor = base.saturating_add(size);
        if new_cursor > region_end.saturating_add(1) {
            return self.failure_at_span(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Section placement overflows region",
                Some(section_name),
                span,
            );
        }

        if let Some(region) = self.regions.get_mut(region_name) {
            region.cursor = new_cursor;
            region.placed.push(PlacedSectionInfo {
                name: section_name.to_string(),
                base,
                size: section_size,
            });
        }
        if let Some(section) = self.sections.get_mut(section_name) {
            section.start_pc = base;
            section.base_addr = Some(base);
            section.layout_placed = true;
        }
        LineStatus::Ok
    }

    pub(crate) fn process_place_ast(
        &mut self,
        section: &str,
        region: &str,
        align_expr: Option<&Expr>,
        span: Span,
    ) -> LineStatus {
        let directive_align = if let Some(expr) = align_expr {
            let value = match self.eval_expr_ast(expr) {
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
            if value == 0 {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Directive,
                    "Placement align must be greater than zero",
                    None,
                    span,
                );
            }
            Some(value)
        } else {
            None
        };
        if self.pass == 1 {
            self.placement_directives.push(PlacementDirective::Place {
                section: section.to_string(),
                region: region.to_string(),
                align: directive_align,
                span,
            });
            return LineStatus::Ok;
        }
        self.place_section_in_region(section, region, directive_align, span)
    }

    pub(crate) fn process_pack_ast(
        &mut self,
        region: &str,
        sections: &[String],
        span: Span,
    ) -> LineStatus {
        if self.pass == 1 {
            self.placement_directives.push(PlacementDirective::Pack {
                region: region.to_string(),
                sections: sections.to_vec(),
                span,
            });
            return LineStatus::Ok;
        }
        for section in sections {
            let status = self.place_section_in_region(section, region, None, span);
            if status == LineStatus::Error || status == LineStatus::Pass1Error {
                return status;
            }
        }
        LineStatus::Ok
    }

    pub(crate) fn apply_placement_directive(
        &mut self,
        directive: &PlacementDirective,
    ) -> LineStatus {
        match directive {
            PlacementDirective::Place {
                section,
                region,
                align,
                span,
            } => self.place_section_in_region(section, region, *align, *span),
            PlacementDirective::Pack {
                region,
                sections,
                span,
            } => {
                for section in sections {
                    let status = self.place_section_in_region(section, region, None, *span);
                    if status == LineStatus::Error || status == LineStatus::Pass1Error {
                        return status;
                    }
                }
                LineStatus::Ok
            }
        }
    }
}
