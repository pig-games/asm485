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
}

impl Assembler {
    pub(crate) fn new() -> Self {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(Intel8080FamilyModule));
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(I8085CpuModule));
        registry.register_cpu(Box::new(Z80CpuModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry.register_cpu(Box::new(M65816CpuModule));

        Self {
            symbols: SymbolTable::new(),
            image: ImageStore::new(65536),
            sections: HashMap::new(),
            regions: HashMap::new(),
            diagnostics: Vec::new(),
            cpu: default_cpu(),
            registry,
            root_metadata: RootMetadata::default(),
            module_macro_names: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_opthread_runtime_enabled(&mut self, _enabled: bool) {}

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
        let mut addr: u32 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;

        {
            let root_metadata = std::mem::take(&mut self.root_metadata);
            let mut asm_line = AsmLine::with_cpu(&mut self.symbols, self.cpu, &self.registry);
            asm_line.root_metadata = root_metadata;
            asm_line.clear_conditionals();
            asm_line.clear_scopes();

            for src in lines {
                let line_addr = match asm_line.current_addr(addr) {
                    Ok(line_addr) => line_addr,
                    Err(()) => {
                        if let Some(err) = asm_line.error() {
                            diagnostics.push(
                                Diagnostic::new(line_num, Severity::Error, err.clone())
                                    .with_column(asm_line.error_column()),
                            );
                        }
                        counts.errors += 1;
                        addr
                    }
                };
                let status = asm_line.process(src, line_num, line_addr, 1);
                if status == LineStatus::Pass1Error || status == LineStatus::Error {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Error, err.clone())
                                .with_column(asm_line.error_column())
                                .with_parser_error(asm_line.parser_error()),
                        );
                    }
                    counts.errors += 1;
                } else if asm_line.update_addresses(&mut addr, status).is_err() {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Error, err.clone())
                                .with_column(asm_line.error_column()),
                        );
                    }
                    counts.errors += 1;
                }
                line_num += 1;
            }

            if !asm_line.cond_is_empty() {
                let err = AsmError::new(
                    AsmErrorKind::Conditional,
                    "Found .if without .endif in pass 1",
                    None,
                );
                diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                asm_line.clear_conditionals();
                counts.errors += 1;
            }

            if asm_line.in_module() {
                let err = AsmError::new(
                    AsmErrorKind::Directive,
                    "Found .module without .endmodule",
                    None,
                );
                diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                counts.errors += 1;
            }

            if asm_line.in_section() {
                let err = AsmError::new(
                    AsmErrorKind::Directive,
                    "Found .section without .endsection",
                    None,
                );
                diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                counts.errors += 1;
            }

            let placement_directives = asm_line.take_placement_directives();
            if !asm_line.in_section() {
                for directive in &placement_directives {
                    let status = asm_line.apply_placement_directive(directive);
                    if status == LineStatus::Error || status == LineStatus::Pass1Error {
                        if let Some(err) = asm_line.error() {
                            diagnostics.push(
                                Diagnostic::new(directive.line(), Severity::Error, err.clone())
                                    .with_column(asm_line.error_column()),
                            );
                        }
                        counts.errors += 1;
                    }
                }
            }

            for err in asm_line.finalize_section_symbol_addresses() {
                diagnostics.push(Diagnostic::new(line_num, Severity::Error, err));
                counts.errors += 1;
            }

            for (name, section) in &asm_line.sections {
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

            for output in &asm_line.root_metadata.linker_outputs {
                for section_name in &output.sections {
                    let is_placed = asm_line
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

        counts.lines = line_num - 1;
        counts
    }

    pub(crate) fn pass2<W: Write>(
        &mut self,
        lines: &[String],
        listing: &mut ListingWriter<W>,
    ) -> std::io::Result<PassCounts> {
        let mut asm_line = AsmLine::with_cpu(&mut self.symbols, self.cpu, &self.registry);
        asm_line.clear_conditionals();
        asm_line.clear_scopes();
        self.image = ImageStore::new(65536);

        let mut addr: u32 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;
        let image = &mut self.image;

        for src in lines {
            let line_addr = match asm_line.current_addr(addr) {
                Ok(line_addr) => line_addr,
                Err(()) => {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Error, err.clone())
                                .with_column(asm_line.error_column()),
                        );
                        listing.write_diagnostic(
                            "ERROR",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                            asm_line.parser_error_ref(),
                        )?;
                    }
                    counts.errors += 1;
                    addr
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
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Error, err.clone())
                                .with_column(asm_line.error_column())
                                .with_parser_error(asm_line.parser_error()),
                        );
                        listing.write_diagnostic(
                            "ERROR",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                            asm_line.parser_error_ref(),
                        )?;
                    }
                    counts.errors += 1;
                }
                LineStatus::Warning => {
                    if let Some(err) = asm_line.error() {
                        diagnostics.push(
                            Diagnostic::new(line_num, Severity::Warning, err.clone())
                                .with_column(asm_line.error_column())
                                .with_parser_error(asm_line.parser_error()),
                        );
                        listing.write_diagnostic(
                            "WARNING",
                            err.message(),
                            line_num,
                            asm_line.error_column(),
                            lines,
                            asm_line.parser_error_ref(),
                        )?;
                    }
                    counts.warnings += 1;
                }
                _ => {}
            }

            if asm_line.update_addresses(&mut addr, status).is_err() {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(
                        Diagnostic::new(line_num, Severity::Error, err.clone())
                            .with_column(asm_line.error_column()),
                    );
                    listing.write_diagnostic(
                        "ERROR",
                        err.message(),
                        line_num,
                        asm_line.error_column(),
                        lines,
                        None,
                    )?;
                }
                counts.errors += 1;
            }
            line_num += 1;
        }

        if !asm_line.cond_is_empty() {
            let err = AsmError::new(AsmErrorKind::Conditional, "Found .if without .endif", None);
            diagnostics.push(Diagnostic::new(line_num, Severity::Error, err.clone()));
            listing.write_diagnostic("ERROR", err.message(), line_num, None, lines, None)?;
            asm_line.clear_conditionals();
            counts.errors += 1;
        }

        if asm_line.in_module() {
            let err = AsmError::new(
                AsmErrorKind::Directive,
                "Found .module without .endmodule",
                None,
            );
            diagnostics.push(Diagnostic::new(line_num, Severity::Error, err.clone()));
            listing.write_diagnostic("ERROR", err.message(), line_num, None, lines, None)?;
            counts.errors += 1;
        }

        if asm_line.in_section() {
            let err = AsmError::new(
                AsmErrorKind::Directive,
                "Found .section without .endsection",
                None,
            );
            diagnostics.push(Diagnostic::new(line_num, Severity::Error, err.clone()));
            listing.write_diagnostic("ERROR", err.message(), line_num, None, lines, None)?;
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
        self.sections = sections;
        counts.lines = line_num - 1;
        Ok(counts)
    }
}
