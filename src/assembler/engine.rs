// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use super::*;

pub(crate) struct Assembler {
    pub(crate) symbols: SymbolTable,
    pub(crate) image: ImageStore,
    pub(crate) sections: HashMap<String, SectionState>,
    pub(crate) regions: HashMap<String, RegionState>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) cpu: CpuType,
    pub(crate) registry: ModuleRegistry,
    pub(crate) root_metadata: RootMetadata,
    pub(crate) module_macro_names: HashMap<String, HashMap<String, SymbolVisibility>>,
    pub(crate) loop_iteration_trace_pass1: Vec<(u32, u32)>,
}

impl Assembler {
    pub(crate) fn new() -> Self {
        let registry = crate::build_default_registry();

        Self {
            symbols: SymbolTable::new(),
            image: ImageStore::new(),
            sections: HashMap::new(),
            regions: HashMap::new(),
            diagnostics: Vec::new(),
            cpu: default_cpu(),
            registry,
            root_metadata: RootMetadata::default(),
            module_macro_names: HashMap::new(),
            loop_iteration_trace_pass1: Vec::new(),
        }
    }

    pub(crate) fn cpu(&self) -> CpuType {
        self.cpu
    }

    pub(crate) fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    pub(crate) fn image(&self) -> &ImageStore {
        &self.image
    }

    pub(crate) fn sections(&self) -> &HashMap<String, SectionState> {
        &self.sections
    }

    pub(crate) fn regions(&self) -> &HashMap<String, RegionState> {
        &self.regions
    }

    pub(crate) fn clear_diagnostics(&mut self) {
        self.diagnostics.clear();
    }

    pub(crate) fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub(crate) fn pass1(&mut self, lines: &[String]) -> PassCounts {
        self.sections.clear();
        self.regions.clear();
        self.loop_iteration_trace_pass1.clear();
        let mut addr: u32 = 0;
        let line_num: u32 = u32::try_from(lines.len())
            .unwrap_or(u32::MAX.saturating_sub(1))
            .saturating_add(1);
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;

        {
            let root_metadata = std::mem::take(&mut self.root_metadata);
            let mut asm_line = AsmLine::with_cpu(&mut self.symbols, self.cpu, &self.registry);
            asm_line.output_state.root_metadata = root_metadata;
            asm_line.clear_conditionals();
            asm_line.clear_scopes();

            Self::execute_pass1_lines(
                lines,
                0,
                lines.len(),
                &mut asm_line,
                &mut addr,
                &mut counts,
                diagnostics,
                &mut self.loop_iteration_trace_pass1,
                false,
            );

            if !asm_line.cond_is_empty() {
                let err = AsmError::new(
                    AsmErrorKind::Conditional,
                    "Found .if without .endif in pass 1",
                    None,
                );
                diagnostics.push(
                    Diagnostic::new(line_num, Severity::Error, err)
                        .with_help("add a matching .endif to close the open conditional block")
                        .with_fixit(crate::core::assembler::error::Fixit {
                            file: None,
                            line: line_num,
                            col_start: Some(1),
                            col_end: Some(1),
                            replacement: ".endif".to_string(),
                            applicability: "machine-applicable".to_string(),
                        }),
                );
                asm_line.clear_conditionals();
                counts.errors += 1;
            }

            if asm_line.in_module() {
                let err = AsmError::new(
                    AsmErrorKind::Directive,
                    "Found .module without .endmodule",
                    None,
                );
                diagnostics.push(
                    Diagnostic::new(line_num, Severity::Error, err)
                        .with_help("add a matching .endmodule to close the open module block")
                        .with_fixit(crate::core::assembler::error::Fixit {
                            file: None,
                            line: line_num,
                            col_start: Some(1),
                            col_end: Some(1),
                            replacement: ".endmodule".to_string(),
                            applicability: "machine-applicable".to_string(),
                        }),
                );
                counts.errors += 1;
            }

            if asm_line.in_section() {
                let err = AsmError::new(
                    AsmErrorKind::Directive,
                    "Found .section without .endsection",
                    None,
                );
                diagnostics.push(
                    Diagnostic::new(line_num, Severity::Error, err)
                        .with_help("add a matching .endsection to close the open section block")
                        .with_fixit(crate::core::assembler::error::Fixit {
                            file: None,
                            line: line_num,
                            col_start: Some(1),
                            col_end: Some(1),
                            replacement: ".endsection".to_string(),
                            applicability: "machine-applicable".to_string(),
                        }),
                );
                counts.errors += 1;
            }

            if let Some(open_line) = asm_line.open_struct_line() {
                let err = AsmError::new(
                    AsmErrorKind::Directive,
                    &format!("unterminated .struct (opened at line {open_line})"),
                    None,
                );
                diagnostics.push(
                    Diagnostic::new(line_num, Severity::Error, err)
                        .with_help("add a matching .endstruct to close the open struct definition")
                        .with_fixit(crate::core::assembler::error::Fixit {
                            file: None,
                            line: line_num,
                            col_start: Some(1),
                            col_end: Some(1),
                            replacement: ".endstruct".to_string(),
                            applicability: "machine-applicable".to_string(),
                        }),
                );
                asm_line.clear_struct_definition();
                counts.errors += 1;
            }

            let placement_directives = asm_line.take_placement_directives();
            if !asm_line.in_section() {
                for directive in &placement_directives {
                    let status = asm_line.apply_placement_directive(directive);
                    if status == LineStatus::Error || status == LineStatus::Pass1Error {
                        if let Some(err) = asm_line.error() {
                            diagnostics.push(Self::diagnostic_from_asmline(
                                &asm_line,
                                directive.line(),
                                Severity::Error,
                                err.clone(),
                            ));
                        }
                        counts.errors += 1;
                    }
                }
            }

            for err in asm_line.finalize_section_symbol_addresses() {
                diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                counts.errors += 1;
            }

            for (name, section) in &asm_line.layout.sections {
                if section.default_region.is_some() && !section.layout_placed {
                    let err = AsmError::new(
                        AsmErrorKind::Directive,
                        "Section with region=... must be explicitly placed",
                        Some(name),
                    );
                    diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                    counts.errors += 1;
                }
            }

            for output in &asm_line.output_state.root_metadata.linker_outputs {
                for section_name in &output.sections {
                    let is_placed = asm_line
                        .layout
                        .sections
                        .get(section_name)
                        .map(|section| section.layout_placed)
                        .unwrap_or(false);
                    if !is_placed {
                        let err = AsmError::new(
                            AsmErrorKind::Directive,
                            "Section referenced by .output must be explicitly placed",
                            Some(section_name),
                        );
                        diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                        counts.errors += 1;
                    }
                }
            }

            self.root_metadata = asm_line.take_root_metadata();
            self.sections = asm_line.take_sections();
            self.regions = asm_line.take_regions();
        }

        for issue in self.symbols.validate_imports(&self.module_macro_names) {
            let kind = match issue.kind {
                crate::core::symbol_table::ImportIssueKind::Directive => AsmErrorKind::Directive,
                crate::core::symbol_table::ImportIssueKind::Symbol => AsmErrorKind::Symbol,
            };
            let err = AsmError::new(kind, &issue.message, issue.param.as_deref());
            diagnostics
                .push(Diagnostic::new(issue.line, Severity::Error, err).with_column(issue.column));
            counts.errors += 1;
        }

        counts.lines = u32::try_from(lines.len()).unwrap_or(u32::MAX);
        counts
    }

    pub(crate) fn pass2<W: Write>(
        &mut self,
        lines: &[String],
        listing: &mut ListingWriter<W>,
    ) -> std::io::Result<PassCounts> {
        let pass1_loop_trace = self.loop_iteration_trace_pass1.clone();
        let mut asm_line = AsmLine::with_cpu(&mut self.symbols, self.cpu, &self.registry);
        asm_line.clear_conditionals();
        asm_line.clear_scopes();
        // Seed pass2 with pass1 placement/layout state so section-local encoding
        // (especially relative branches) uses rebased absolute addresses even if
        // .place/.pack directives appear later in source order.
        asm_line.layout.sections = self.sections.clone();
        asm_line.layout.regions = self.regions.clone();
        for section in asm_line.layout.sections.values_mut() {
            section.pc = 0;
            section.bytes.clear();
            section.emitted = false;
        }
        self.image = ImageStore::new();

        let mut addr: u32 = 0;
        let line_num: u32 = u32::try_from(lines.len())
            .unwrap_or(u32::MAX.saturating_sub(1))
            .saturating_add(1);
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;
        let image = &mut self.image;
        let mut pass2_loop_trace_cursor = 0usize;

        if let Some(err) = image.init_error() {
            let message = format!("failed to initialize image store: {err}");
            let diag = Diagnostic::new(
                line_num,
                Severity::Error,
                AsmError::new(AsmErrorKind::Io, &message, None),
            );
            diagnostics.push(diag.clone());
            listing.write_diagnostic_with_annotations(&diag, lines)?;
            counts.errors += 1;
            counts.lines = u32::try_from(lines.len()).unwrap_or(u32::MAX);
            return Ok(counts);
        }

        Self::execute_pass2_lines(
            lines,
            0,
            lines.len(),
            &mut asm_line,
            &mut addr,
            &mut counts,
            diagnostics,
            listing,
            image,
            &pass1_loop_trace,
            &mut pass2_loop_trace_cursor,
            false,
        )?;

        if !asm_line.cond_is_empty() {
            let err = AsmError::new(AsmErrorKind::Conditional, "Found .if without .endif", None);
            let diag = Diagnostic::new(line_num, Severity::Error, err.clone())
                .with_help("add a matching .endif to close the open conditional block")
                .with_fixit(crate::core::assembler::error::Fixit {
                    file: None,
                    line: line_num,
                    col_start: Some(1),
                    col_end: Some(1),
                    replacement: ".endif".to_string(),
                    applicability: "machine-applicable".to_string(),
                });
            diagnostics.push(diag.clone());
            listing.write_diagnostic_with_annotations(&diag, lines)?;
            asm_line.clear_conditionals();
            counts.errors += 1;
        }

        if asm_line.in_module() {
            let err = AsmError::new(
                AsmErrorKind::Directive,
                "Found .module without .endmodule",
                None,
            );
            let diag = Diagnostic::new(line_num, Severity::Error, err.clone())
                .with_help("add a matching .endmodule to close the open module block")
                .with_fixit(crate::core::assembler::error::Fixit {
                    file: None,
                    line: line_num,
                    col_start: Some(1),
                    col_end: Some(1),
                    replacement: ".endmodule".to_string(),
                    applicability: "machine-applicable".to_string(),
                });
            diagnostics.push(diag.clone());
            listing.write_diagnostic_with_annotations(&diag, lines)?;
            counts.errors += 1;
        }

        if asm_line.in_section() {
            let err = AsmError::new(
                AsmErrorKind::Directive,
                "Found .section without .endsection",
                None,
            );
            let diag = Diagnostic::new(line_num, Severity::Error, err.clone())
                .with_help("add a matching .endsection to close the open section block")
                .with_fixit(crate::core::assembler::error::Fixit {
                    file: None,
                    line: line_num,
                    col_start: Some(1),
                    col_end: Some(1),
                    replacement: ".endsection".to_string(),
                    applicability: "machine-applicable".to_string(),
                });
            diagnostics.push(diag.clone());
            listing.write_diagnostic_with_annotations(&diag, lines)?;
            counts.errors += 1;
        }

        if let Some(open_line) = asm_line.open_struct_line() {
            let err = AsmError::new(
                AsmErrorKind::Directive,
                &format!("unterminated .struct (opened at line {open_line})"),
                None,
            );
            let diag = Diagnostic::new(line_num, Severity::Error, err.clone())
                .with_help("add a matching .endstruct to close the open struct definition")
                .with_fixit(crate::core::assembler::error::Fixit {
                    file: None,
                    line: line_num,
                    col_start: Some(1),
                    col_end: Some(1),
                    replacement: ".endstruct".to_string(),
                    applicability: "machine-applicable".to_string(),
                });
            diagnostics.push(diag.clone());
            listing.write_diagnostic_with_annotations(&diag, lines)?;
            asm_line.clear_struct_definition();
            counts.errors += 1;
        }

        let sections = asm_line.take_sections();
        let mut deferred_sections: Vec<_> = sections
            .iter()
            .filter_map(|(name, section)| {
                if section.is_bss() || section.bytes.is_empty() || section.emitted {
                    return None;
                }
                section
                    .base_addr
                    .map(|base_addr| (base_addr, name, section))
            })
            .collect();
        deferred_sections.sort_by_key(|(base_addr, name, _)| (*base_addr, *name));
        for (base_addr, _, section) in deferred_sections {
            image.store_slice(base_addr, &section.bytes);
        }

        if Self::cpu_warns_for_wide_output(asm_line.cpu) {
            if let Ok(Some((_min_addr, max_addr))) = image.output_range() {
                if max_addr > 0xFFFF {
                    let message = format!(
                        "assembled output exceeds 64 KB for CPU {} (max emitted address ${max_addr:08X})",
                        asm_line.cpu.as_str()
                    );
                    let diag = Diagnostic::new(
                        line_num.saturating_sub(1),
                        Severity::Warning,
                        AsmError::new(AsmErrorKind::Assembler, &message, None),
                    );
                    diagnostics.push(diag.clone());
                    listing.write_diagnostic_with_annotations(&diag, lines)?;
                    counts.warnings += 1;
                }
            }
        }

        self.sections = sections;
        counts.lines = u32::try_from(lines.len()).unwrap_or(u32::MAX);
        Ok(counts)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_pass1_lines(
        lines: &[String],
        start_idx: usize,
        end_idx_exclusive: usize,
        asm_line: &mut AsmLine<'_>,
        addr: &mut u32,
        counts: &mut PassCounts,
        diagnostics: &mut Vec<Diagnostic>,
        pass1_loop_trace: &mut Vec<(u32, u32)>,
        in_unscoped_for: bool,
    ) {
        let mut idx = start_idx;
        while idx < end_idx_exclusive {
            let line_num = u32::try_from(idx)
                .unwrap_or(u32::MAX.saturating_sub(1))
                .saturating_add(1);
            let src = &lines[idx];

            let parsed_ast =
                super::repetition::parse_line_ast_for_repetition(asm_line, src, line_num).ok();
            if let Some(ast) = parsed_ast {
                if in_unscoped_for {
                    if let Some(label) = super::repetition::line_label(&ast) {
                        let message = format!(
                            "label '{}' not allowed inside .for (use .bfor for scoped repetition)",
                            label.name
                        );
                        diagnostics.push(
                            Diagnostic::new(
                                line_num,
                                Severity::Error,
                                AsmError::new(AsmErrorKind::Directive, &message, None),
                            )
                            .with_column(Some(label.span.col_start)),
                        );
                        counts.errors += 1;
                        idx = idx.saturating_add(1);
                        continue;
                    }
                }

                if let Some((label, mnemonic, operands)) = super::repetition::statement_parts(&ast)
                {
                    if super::repetition::is_endfor_directive_name(&mnemonic) {
                        let (message, column) = if let Some(label) = label {
                            (
                                "label not allowed on .endfor / .endwhile".to_string(),
                                Some(label.span.col_start),
                            )
                        } else {
                            (".endfor without matching .for".to_string(), None)
                        };
                        diagnostics.push(
                            Diagnostic::new(
                                line_num,
                                Severity::Error,
                                AsmError::new(AsmErrorKind::Directive, &message, None),
                            )
                            .with_column(column),
                        );
                        counts.errors += 1;
                        idx = idx.saturating_add(1);
                        continue;
                    }

                    if super::repetition::is_for_directive_name(&mnemonic) {
                        let Some(end_idx) = super::repetition::find_matching_endfor(
                            lines,
                            asm_line,
                            idx.saturating_add(1),
                            end_idx_exclusive,
                        ) else {
                            let message = format!("unterminated .for (opened at line {line_num})");
                            diagnostics.push(Diagnostic::new(
                                line_num,
                                Severity::Error,
                                AsmError::new(AsmErrorKind::Directive, &message, None),
                            ));
                            counts.errors += 1;
                            return;
                        };

                        let plan = match super::repetition::evaluate_for_plan(
                            asm_line,
                            &operands,
                            super::repetition::DEFAULT_MAX_LOOP_ITERATIONS,
                        ) {
                            Ok(plan) => plan,
                            Err(err) => {
                                diagnostics.push(
                                    Diagnostic::new(line_num, Severity::Error, err.error)
                                        .with_column(Some(err.span.col_start)),
                                );
                                counts.errors += 1;
                                idx = end_idx.saturating_add(1);
                                continue;
                            }
                        };

                        pass1_loop_trace.push((
                            line_num,
                            u32::try_from(plan.values.len()).unwrap_or(u32::MAX),
                        ));
                        for value in &plan.values {
                            if let Some(var_name) = plan.var_name.as_deref() {
                                asm_line.push_loop_var(var_name, *value);
                            }
                            Self::execute_pass1_lines(
                                lines,
                                idx.saturating_add(1),
                                end_idx,
                                asm_line,
                                addr,
                                counts,
                                diagnostics,
                                pass1_loop_trace,
                                true,
                            );
                            if plan.var_name.is_some() {
                                asm_line.pop_loop_var();
                            }
                        }

                        idx = end_idx.saturating_add(1);
                        continue;
                    }
                }
            }

            Self::execute_regular_line_pass1(asm_line, src, line_num, addr, counts, diagnostics);
            idx = idx.saturating_add(1);
        }
    }

    fn execute_regular_line_pass1(
        asm_line: &mut AsmLine<'_>,
        src: &str,
        line_num: u32,
        addr: &mut u32,
        counts: &mut PassCounts,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        let line_addr = match asm_line.current_addr(*addr) {
            Ok(line_addr) => line_addr,
            Err(()) => {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(Self::diagnostic_from_asmline(
                        asm_line,
                        line_num,
                        Severity::Error,
                        err.clone(),
                    ));
                }
                counts.errors += 1;
                *addr
            }
        };

        let status = asm_line.process(src, line_num, line_addr, 1);
        let status_failed = status == LineStatus::Pass1Error || status == LineStatus::Error;
        let update_failed = !status_failed && asm_line.update_addresses(addr, status).is_err();
        if status_failed || update_failed {
            if let Some(err) = asm_line.error() {
                diagnostics.push(Self::diagnostic_from_asmline(
                    asm_line,
                    line_num,
                    Severity::Error,
                    err.clone(),
                ));
            }
            counts.errors += 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_pass2_lines<W: Write>(
        lines: &[String],
        start_idx: usize,
        end_idx_exclusive: usize,
        asm_line: &mut AsmLine<'_>,
        addr: &mut u32,
        counts: &mut PassCounts,
        diagnostics: &mut Vec<Diagnostic>,
        listing: &mut ListingWriter<W>,
        image: &mut ImageStore,
        pass1_loop_trace: &[(u32, u32)],
        pass2_loop_trace_cursor: &mut usize,
        in_unscoped_for: bool,
    ) -> std::io::Result<()> {
        let mut idx = start_idx;
        while idx < end_idx_exclusive {
            let line_num = u32::try_from(idx)
                .unwrap_or(u32::MAX.saturating_sub(1))
                .saturating_add(1);
            let src = &lines[idx];

            let parsed_ast =
                super::repetition::parse_line_ast_for_repetition(asm_line, src, line_num).ok();
            if let Some(ast) = parsed_ast {
                if in_unscoped_for {
                    if let Some(label) = super::repetition::line_label(&ast) {
                        let message = format!(
                            "label '{}' not allowed inside .for (use .bfor for scoped repetition)",
                            label.name
                        );
                        let diagnostic = Diagnostic::new(
                            line_num,
                            Severity::Error,
                            AsmError::new(AsmErrorKind::Directive, &message, None),
                        )
                        .with_column(Some(label.span.col_start));
                        diagnostics.push(diagnostic.clone());
                        listing.write_diagnostic_with_annotations(&diagnostic, lines)?;
                        counts.errors += 1;
                        idx = idx.saturating_add(1);
                        continue;
                    }
                }

                if let Some((label, mnemonic, operands)) = super::repetition::statement_parts(&ast)
                {
                    if super::repetition::is_endfor_directive_name(&mnemonic) {
                        let (message, column) = if let Some(label) = label {
                            (
                                "label not allowed on .endfor / .endwhile".to_string(),
                                Some(label.span.col_start),
                            )
                        } else {
                            (".endfor without matching .for".to_string(), None)
                        };
                        let diagnostic = Diagnostic::new(
                            line_num,
                            Severity::Error,
                            AsmError::new(AsmErrorKind::Directive, &message, None),
                        )
                        .with_column(column);
                        diagnostics.push(diagnostic.clone());
                        listing.write_diagnostic_with_annotations(&diagnostic, lines)?;
                        counts.errors += 1;
                        idx = idx.saturating_add(1);
                        continue;
                    }

                    if super::repetition::is_for_directive_name(&mnemonic) {
                        let Some(end_idx) = super::repetition::find_matching_endfor(
                            lines,
                            asm_line,
                            idx.saturating_add(1),
                            end_idx_exclusive,
                        ) else {
                            let message = format!("unterminated .for (opened at line {line_num})");
                            let diagnostic = Diagnostic::new(
                                line_num,
                                Severity::Error,
                                AsmError::new(AsmErrorKind::Directive, &message, None),
                            );
                            diagnostics.push(diagnostic.clone());
                            listing.write_diagnostic_with_annotations(&diagnostic, lines)?;
                            counts.errors += 1;
                            return Ok(());
                        };

                        let plan = match super::repetition::evaluate_for_plan(
                            asm_line,
                            &operands,
                            super::repetition::DEFAULT_MAX_LOOP_ITERATIONS,
                        ) {
                            Ok(plan) => plan,
                            Err(err) => {
                                let diagnostic =
                                    Diagnostic::new(line_num, Severity::Error, err.error)
                                        .with_column(Some(err.span.col_start));
                                diagnostics.push(diagnostic.clone());
                                listing.write_diagnostic_with_annotations(&diagnostic, lines)?;
                                counts.errors += 1;
                                idx = end_idx.saturating_add(1);
                                continue;
                            }
                        };

                        let pass2_count = u32::try_from(plan.values.len()).unwrap_or(u32::MAX);
                        let (pass1_line, pass1_count) = pass1_loop_trace
                            .get(*pass2_loop_trace_cursor)
                            .copied()
                            .unwrap_or((line_num, 0));
                        *pass2_loop_trace_cursor = pass2_loop_trace_cursor.saturating_add(1);
                        if pass1_line != line_num || pass1_count != pass2_count {
                            let message = format!(
                                "loop iteration count changed between passes (pass1: {pass1_count}, pass2: {pass2_count})"
                            );
                            let diagnostic = Diagnostic::new(
                                line_num,
                                Severity::Error,
                                AsmError::new(AsmErrorKind::Directive, &message, None),
                            );
                            diagnostics.push(diagnostic.clone());
                            listing.write_diagnostic_with_annotations(&diagnostic, lines)?;
                            counts.errors += 1;
                        }

                        for value in &plan.values {
                            if let Some(var_name) = plan.var_name.as_deref() {
                                asm_line.push_loop_var(var_name, *value);
                            }
                            Self::execute_pass2_lines(
                                lines,
                                idx.saturating_add(1),
                                end_idx,
                                asm_line,
                                addr,
                                counts,
                                diagnostics,
                                listing,
                                image,
                                pass1_loop_trace,
                                pass2_loop_trace_cursor,
                                true,
                            )?;
                            if plan.var_name.is_some() {
                                asm_line.pop_loop_var();
                            }
                        }

                        idx = end_idx.saturating_add(1);
                        continue;
                    }
                }
            }

            Self::execute_regular_line_pass2(
                asm_line,
                src,
                line_num,
                addr,
                counts,
                diagnostics,
                listing,
                image,
                lines,
            )?;
            idx = idx.saturating_add(1);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_regular_line_pass2<W: Write>(
        asm_line: &mut AsmLine<'_>,
        src: &str,
        line_num: u32,
        addr: &mut u32,
        counts: &mut PassCounts,
        diagnostics: &mut Vec<Diagnostic>,
        listing: &mut ListingWriter<W>,
        image: &mut ImageStore,
        all_lines: &[String],
    ) -> std::io::Result<()> {
        let line_addr = match asm_line.current_addr(*addr) {
            Ok(line_addr) => line_addr,
            Err(()) => {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(Self::diagnostic_from_asmline(
                        asm_line,
                        line_num,
                        Severity::Error,
                        err.clone(),
                    ));
                    listing.write_diagnostic(
                        "ERROR",
                        err.message(),
                        line_num,
                        asm_line.error_column(),
                        all_lines,
                        asm_line.parser_error_ref(),
                    )?;
                }
                counts.errors += 1;
                *addr
            }
        };
        let status = asm_line.process(src, line_num, line_addr, 2);
        let line_addr = asm_line.start_addr();
        let bytes = asm_line.bytes();
        if !bytes.is_empty() && !asm_line.in_section() {
            image.store_slice(line_addr, bytes);
        }

        listing.write_line(ListingLine {
            addr: line_addr,
            bytes,
            status,
            aux: asm_line.aux_value(),
            line_num,
            source: src,
            section: asm_line.current_section_name(),
            cond: asm_line.cond_last(),
        })?;

        match status {
            LineStatus::Error | LineStatus::Pass1Error => {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(Self::diagnostic_from_asmline(
                        asm_line,
                        line_num,
                        Severity::Error,
                        err.clone(),
                    ));
                    listing.write_diagnostic(
                        "ERROR",
                        err.message(),
                        line_num,
                        asm_line.error_column(),
                        all_lines,
                        asm_line.parser_error_ref(),
                    )?;
                }
                counts.errors += 1;
            }
            LineStatus::Warning => {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(Self::diagnostic_from_asmline(
                        asm_line,
                        line_num,
                        Severity::Warning,
                        err.clone(),
                    ));
                    listing.write_diagnostic(
                        "WARNING",
                        err.message(),
                        line_num,
                        asm_line.error_column(),
                        all_lines,
                        asm_line.parser_error_ref(),
                    )?;
                }
                counts.warnings += 1;
            }
            _ => {}
        }

        if asm_line.update_addresses(addr, status).is_err() {
            if let Some(err) = asm_line.error() {
                diagnostics.push(Self::diagnostic_from_asmline(
                    asm_line,
                    line_num,
                    Severity::Error,
                    err.clone(),
                ));
                listing.write_diagnostic(
                    "ERROR",
                    err.message(),
                    line_num,
                    asm_line.error_column(),
                    all_lines,
                    None,
                )?;
            }
            counts.errors += 1;
        }
        Ok(())
    }

    fn cpu_warns_for_wide_output(cpu: CpuType) -> bool {
        // `8080` is retained as a defensive alias for direct helper calls/tests,
        // even though registry-backed Intel-family resolution currently canonicalizes
        // to concrete CPU ids (`8085`/`z80`).
        matches!(
            cpu.as_str(),
            "m6502" | "65c02" | "8080" | "8085" | "z80" | "m6809" | "hd6309"
        )
    }

    fn diagnostic_from_asmline(
        asm_line: &AsmLine<'_>,
        line_num: u32,
        severity: Severity,
        err: AsmError,
    ) -> Diagnostic {
        let mut diagnostic = Diagnostic::new(line_num, severity, err)
            .with_column(asm_line.error_column())
            .with_parser_error(asm_line.parser_error());

        if let Some(help) = asm_line.error_help() {
            diagnostic = diagnostic.with_help(help.to_string());
        }
        for fixit in asm_line.error_fixits() {
            diagnostic = diagnostic.with_fixit(fixit.clone());
        }
        diagnostic
    }
}

#[cfg(test)]
mod tests {
    use super::Assembler;
    use crate::assembler::ListingWriter;
    use crate::core::assembler::error::Severity;
    use crate::core::cpu::CpuType;

    fn run_wide_output_case(cpu: CpuType) -> (usize, Vec<String>, Vec<(u32, u8)>) {
        let mut assembler = Assembler::new();
        assembler.cpu = cpu;
        assembler.clear_diagnostics();

        let lines = vec![".org $10000".to_string(), ".byte $aa".to_string()];
        let pass1 = assembler.pass1(&lines);
        assert_eq!(
            pass1.errors,
            0,
            "pass1 should succeed for {:?}; diagnostics: {:?}",
            cpu,
            assembler
                .diagnostics
                .iter()
                .map(|diag| diag.error.message().to_string())
                .collect::<Vec<_>>()
        );

        let mut listing_out = Vec::new();
        let mut listing = ListingWriter::new(&mut listing_out, false);
        let pass2 = assembler
            .pass2(&lines, &mut listing)
            .expect("pass2 should run");
        assert_eq!(pass2.errors, 0, "pass2 should succeed for {:?}", cpu);

        let warning_messages: Vec<String> = assembler
            .diagnostics
            .iter()
            .filter(|diag| diag.severity() == Severity::Warning)
            .map(|diag| diag.error.message().to_string())
            .collect();
        let entries = assembler
            .image
            .entries()
            .expect("image entries should be readable");

        (pass2.warnings as usize, warning_messages, entries)
    }

    fn run_legacy_cross_boundary_case(cpu: CpuType) -> Vec<String> {
        let mut assembler = Assembler::new();
        assembler.cpu = cpu;
        assembler.clear_diagnostics();

        let lines = vec![".org $ffff".to_string(), ".byte $aa, $bb".to_string()];
        let _ = assembler.pass1(&lines);
        assembler
            .diagnostics
            .iter()
            .map(|diag| diag.error.message().to_string())
            .collect()
    }

    #[test]
    fn wide_output_warning_policy_matches_target_cpu() {
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("m6502")));
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("65c02")));
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("8080")));
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("8085")));
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("z80")));
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("m6809")));
        assert!(Assembler::cpu_warns_for_wide_output(CpuType::new("hd6309")));
        assert!(!Assembler::cpu_warns_for_wide_output(CpuType::new("65816")));
        assert!(!Assembler::cpu_warns_for_wide_output(CpuType::new(
            "45gs02"
        )));
    }

    #[test]
    fn wide_output_integration_suppresses_warning_for_65816() {
        let cpu = CpuType::new("65816");
        let (warnings, warning_messages, entries) = run_wide_output_case(cpu);
        assert!(
            entries
                .iter()
                .any(|(addr, val)| *addr == 0x010000 && *val == 0xaa),
            "wide-output byte should be emitted for {:?}",
            cpu
        );
        assert_eq!(warnings, 0, "unexpected wide-output warning for {:?}", cpu);
        assert!(
            !warning_messages
                .iter()
                .any(|message| message.contains("assembled output exceeds 64 KB")),
            "unexpected wide-output warning diagnostic for {:?}: {warning_messages:?}",
            cpu
        );
    }

    #[test]
    fn legacy_cross_boundary_output_is_rejected_before_warning_policy() {
        for cpu in [
            CpuType::new("m6502"),
            CpuType::new("65c02"),
            CpuType::new("8085"),
            CpuType::new("m6809"),
            CpuType::new("hd6309"),
        ] {
            let diagnostics = run_legacy_cross_boundary_case(cpu);
            assert!(
                diagnostics.iter().any(|message| {
                    message.contains("span")
                        && message.contains("exceeds max $FFFF")
                        && message.contains(cpu.as_str())
                }),
                "expected legacy span guard diagnostic for {:?}: {diagnostics:?}",
                cpu
            );
        }
    }

    #[test]
    fn pass2_reports_image_store_init_failure_as_diagnostic() {
        crate::core::imagestore::run_with_forced_open_failure_for_tests(|| {
            let mut assembler = Assembler::new();
            let lines = vec![".byte $01".to_string()];
            let pass1 = assembler.pass1(&lines);
            assert_eq!(pass1.errors, 0, "pass1 should succeed");

            let mut listing_out = Vec::new();
            let mut listing = ListingWriter::new(&mut listing_out, false);
            let pass2 = assembler
                .pass2(&lines, &mut listing)
                .expect("pass2 should return counts");
            assert_eq!(pass2.errors, 1);
            assert!(assembler.diagnostics.iter().any(|diag| {
                diag.severity() == Severity::Error
                    && diag
                        .error
                        .message()
                        .contains("failed to initialize image store")
            }));
        });
    }
}
