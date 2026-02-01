// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Multi-CPU Assembler - main entry point.
//!
//! This module ties together the CPU-agnostic core with CPU-specific
//! instruction encoding (8085, Z80).

pub mod cli;

use std::fs::{self, File};
use std::io::{self, Write};

use clap::Parser;

use crate::core::cpu::CpuType;
use crate::core::family::{AssemblerContext, EncodeResult};
use crate::core::registry::{ModuleRegistry, RegistryError};
use crate::core::imagestore::ImageStore;
use crate::core::macro_processor::MacroProcessor;
use crate::core::parser::{AssignOp, Expr, Label, LineAst, ParseError};
use crate::core::parser as asm_parser;
use crate::core::preprocess::Preprocessor;
use crate::core::symbol_table::SymbolTable;
use crate::core::tokenizer::{ConditionalKind, Span, register_checker_none};
use std::sync::Arc;
use crate::core::token_value::TokenValue;
use crate::core::assembler::conditional::{ConditionalBlockKind, ConditionalContext, ConditionalStack};
use crate::core::assembler::error::{
    AsmError, AsmErrorKind, AsmRunError, AsmRunReport, Diagnostic, LineStatus, PassCounts, Severity,
};
use crate::core::assembler::expression::{
    apply_assignment_op, eval_binary_op, eval_unary_op, expr_span, parse_number_text, AstEvalError,
};
use crate::core::assembler::listing::{ListingLine, ListingWriter};
use crate::core::assembler::scope::ScopeStack;

use crate::families::intel8080::module::Intel8080FamilyModule;
use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use crate::i8085::module::I8085CpuModule;
use crate::m65c02::module::M65C02CpuModule;
use crate::z80::module::Z80CpuModule;

use cli::{
    input_base_from_path, resolve_bin_path, resolve_output_path, validate_cli, BinOutputSpec, Cli,
};

// Re-export public types
pub use cli::VERSION;
pub use crate::core::assembler::error::{AsmRunError as RunError, AsmRunReport as RunReport};

fn default_cpu() -> CpuType {
    crate::i8085::module::CPU_ID
}

/// Run the assembler with command-line arguments.
pub fn run() -> Result<Vec<AsmRunReport>, AsmRunError> {
    let cli = Cli::parse();
    let config = validate_cli(&cli)?;

    let mut reports = Vec::new();
    for asm_path in &cli.infiles {
        let (asm_name, input_base) = input_base_from_path(asm_path)?;
        let out_base = if let Some(dir) = &config.out_dir {
            dir.join(&input_base).to_string_lossy().to_string()
        } else {
            cli.outfile.as_deref().unwrap_or(&input_base).to_string()
        };
        let report = run_one(
            &cli,
            &asm_name,
            &out_base,
            &config.bin_specs,
            config.go_addr.as_deref(),
            config.fill_byte,
            config.pp_macro_depth,
        )?;
        reports.push(report);
    }

    Ok(reports)
}

fn run_one(
    cli: &Cli,
    asm_name: &str,
    out_base: &str,
    bin_specs: &[BinOutputSpec],
    go_addr: Option<&str>,
    fill_byte: u8,
    pp_macro_depth: usize,
) -> Result<AsmRunReport, AsmRunError> {
    let list_path = resolve_output_path(out_base, cli.list_name.clone(), "lst");
    let hex_path = resolve_output_path(out_base, cli.hex_name.clone(), "hex");

    let mut pp = Preprocessor::with_max_depth(pp_macro_depth);
    for def in &cli.defines {
        if let Some((name, value)) = def.split_once('=') {
            pp.define(name, value);
        } else {
            pp.define(def, "1");
        }
    }
    if let Err(err) = pp.process_file(asm_name) {
        let err_msg = AsmError::new(AsmErrorKind::Preprocess, err.message(), None);
        let mut diagnostics = Vec::new();
        let mut source_lines = Vec::new();
        if let (Some(line), Some(file)) = (err.line(), err.file()) {
            if let Ok(contents) = fs::read_to_string(file) {
                source_lines = contents.lines().map(|s| s.to_string()).collect();
            }
            let source_override = if source_lines.is_empty() {
                err.source().map(|s| s.to_string())
            } else {
                None
            };
            diagnostics.push(
                Diagnostic::new(line, Severity::Error, err_msg.clone())
                    .with_column(err.column())
                    .with_file(Some(file.to_string()))
                    .with_source(source_override),
            );
        }
        return Err(AsmRunError::new(err_msg, diagnostics, source_lines));
    }
    let src_lines: Vec<String> = pp.lines().to_vec();
    let mut mp = MacroProcessor::new();
    let expanded_lines = match mp.expand(&src_lines) {
        Ok(lines) => lines,
        Err(err) => {
            let err_msg = AsmError::new(AsmErrorKind::Preprocess, err.message(), None);
            let mut diagnostics = Vec::new();
            if let Some(line) = err.line() {
                diagnostics.push(
                    Diagnostic::new(line, Severity::Error, err_msg.clone())
                        .with_column(err.column()),
                );
            }
            return Err(AsmRunError::new(err_msg, diagnostics, src_lines.clone()));
        }
    };

    let mut assembler = Assembler::new();
    assembler.clear_diagnostics();
    let pass1 = assembler.pass1(&expanded_lines);
    if pass1.errors > 0 {
        return Err(AsmRunError::new(
            AsmError::new(
                AsmErrorKind::Assembler,
                "Errors detected in source. No hex file created.",
                None,
            ),
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        ));
    }

    let mut list_output: Box<dyn Write> = if let Some(path) = &list_path {
        Box::new(File::create(path).map_err(|_| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, "Error opening file for write", Some(path)),
                Vec::new(),
                Vec::new(),
            )
        })?)
    } else {
        Box::new(io::sink())
    };
    let mut listing = ListingWriter::new(&mut *list_output, cli.debug_conditionals);
    let cpu_name = assembler
        .registry
        .cpu_display_name(assembler.cpu())
        .unwrap_or_else(|| assembler.cpu().as_str());
    let header_title = format!("opForge {cpu_name} Assembler v{VERSION}");
    if let Err(err) = listing.header(&header_title) {
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        ));
    }
    let pass2 = match assembler.pass2(&expanded_lines, &mut listing) {
        Ok(counts) => counts,
        Err(err) => {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                expanded_lines.clone(),
            ))
        }
    };
    if let Err(err) = listing.footer(&pass2, assembler.symbols(), assembler.image().num_entries()) {
        return Err(AsmRunError::new(
            AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
            assembler.take_diagnostics(),
            expanded_lines.clone(),
        ));
    }

    if let Some(hex_path) = &hex_path {
        let mut hex_file = File::create(hex_path).map_err(|_| {
            AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, "Error opening file for write", Some(hex_path)),
                assembler.take_diagnostics(),
                expanded_lines.clone(),
            )
        })?;
        if let Err(err) = assembler.image().write_hex_file(&mut hex_file, go_addr) {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                expanded_lines.clone(),
            ));
        }
    }

    let mut bin_outputs = Vec::new();
    let bin_count = bin_specs.len();
    for spec in bin_specs {
        let bin_name = resolve_bin_path(out_base, spec.name.as_deref(), &spec.range, bin_count);
        bin_outputs.push((bin_name, spec.range.clone()));
    }

    for (bin_name, range) in bin_outputs {
        let mut bin_file = match File::create(&bin_name) {
            Ok(file) => file,
            Err(_) => {
                return Err(AsmRunError::new(
                    AsmError::new(
                        AsmErrorKind::Io,
                        "Error opening file for write",
                        Some(&bin_name),
                    ),
                    assembler.take_diagnostics(),
                    expanded_lines.clone(),
                ))
            }
        };
        if let Err(err) =
            assembler
                .image()
                .write_bin_file(&mut bin_file, range.start, range.end, fill_byte)
        {
            return Err(AsmRunError::new(
                AsmError::new(AsmErrorKind::Io, &err.to_string(), None),
                assembler.take_diagnostics(),
                expanded_lines.clone(),
            ));
        }
    }

    Ok(AsmRunReport::new(
        assembler.take_diagnostics(),
        expanded_lines,
    ))
}

/// Core assembler state.
struct Assembler {
    symbols: SymbolTable,
    image: ImageStore,
    diagnostics: Vec<Diagnostic>,
    cpu: CpuType,
    registry: ModuleRegistry,
}

impl Assembler {
    fn new() -> Self {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(Intel8080FamilyModule));
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(I8085CpuModule));
        registry.register_cpu(Box::new(Z80CpuModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));

        Self {
            symbols: SymbolTable::new(),
            image: ImageStore::new(65536),
            diagnostics: Vec::new(),
            cpu: default_cpu(),
            registry,
        }
    }

    fn cpu(&self) -> CpuType {
        self.cpu
    }

    fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    fn image(&self) -> &ImageStore {
        &self.image
    }

    fn clear_diagnostics(&mut self) {
        self.diagnostics.clear();
    }

    fn take_diagnostics(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    fn pass1(&mut self, lines: &[String]) -> PassCounts {
        let mut asm_line = AsmLine::with_cpu(&mut self.symbols, self.cpu, &self.registry);
        asm_line.clear_conditionals();
        asm_line.clear_scopes();
        let mut addr: u16 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;

        for src in lines {
            let status = asm_line.process(src, line_num, addr, 1);
            if status == LineStatus::Pass1Error {
                if let Some(err) = asm_line.error() {
                    diagnostics.push(
                        Diagnostic::new(line_num, Severity::Error, err.clone())
                            .with_column(asm_line.error_column())
                            .with_parser_error(asm_line.parser_error()),
                    );
                }
                counts.errors += 1;
            } else if status == LineStatus::DirDs {
                addr = asm_line.start_addr().wrapping_add(asm_line.aux_value());
            } else {
                addr = asm_line
                    .start_addr()
                    .wrapping_add(asm_line.num_bytes() as u16);
            }
            line_num += 1;
        }

        if !asm_line.cond_is_empty() {
            let err = AsmError::new(
                AsmErrorKind::Conditional,
                "Found .if without .endif in pass 1",
                None,
            );
            diagnostics.push(Diagnostic::new(line_num, Severity::Warning, err));
            asm_line.clear_conditionals();
            counts.warnings += 1;
        }

        counts.lines = line_num - 1;
        counts
    }

    fn pass2<W: Write>(
        &mut self,
        lines: &[String],
        listing: &mut ListingWriter<W>,
    ) -> std::io::Result<PassCounts> {
        let mut asm_line = AsmLine::with_cpu(&mut self.symbols, self.cpu, &self.registry);
        asm_line.clear_conditionals();
        asm_line.clear_scopes();
        self.image = ImageStore::new(65536);

        let mut addr: u16 = 0;
        let mut line_num: u32 = 1;
        let mut counts = PassCounts::new();
        let diagnostics = &mut self.diagnostics;
        let image = &mut self.image;

        for src in lines {
            let status = asm_line.process(src, line_num, addr, 2);
            addr = asm_line.start_addr();
            let bytes = asm_line.bytes();
            if !bytes.is_empty() {
                image.store_slice(addr, bytes);
            }

            listing.write_line(ListingLine {
                addr,
                bytes,
                status,
                aux: asm_line.aux_value(),
                line_num,
                source: src,
                cond: asm_line.cond_last(),
            })?;

            match status {
                LineStatus::Error => {
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

            if status == LineStatus::DirDs {
                addr = addr.wrapping_add(asm_line.aux_value());
            } else {
                addr = addr.wrapping_add(asm_line.num_bytes() as u16);
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

        counts.lines = line_num - 1;
        Ok(counts)
    }
}

/// Per-line assembler state.
struct AsmLine<'a> {
    symbols: &'a mut SymbolTable,
    registry: &'a ModuleRegistry,
    cond_stack: ConditionalStack,
    scope_stack: ScopeStack,
    last_error: Option<AsmError>,
    last_error_column: Option<usize>,
    last_parser_error: Option<ParseError>,
    line_end_span: Option<Span>,
    line_end_token: Option<String>,
    bytes: Vec<u8>,
    start_addr: u16,
    aux_value: u16,
    pass: u8,
    label: Option<String>,
    mnemonic: Option<String>,
    cpu: CpuType,
    statement_depth: usize,
}

impl<'a> AsmLine<'a> {
    #[cfg(test)]
    fn new(symbols: &'a mut SymbolTable, registry: &'a ModuleRegistry) -> Self {
        Self::with_cpu(symbols, default_cpu(), registry)
    }

    fn with_cpu(symbols: &'a mut SymbolTable, cpu: CpuType, registry: &'a ModuleRegistry) -> Self {
        Self {
            symbols,
            registry,
            cond_stack: ConditionalStack::new(),
            scope_stack: ScopeStack::new(),
            last_error: None,
            last_error_column: None,
            last_parser_error: None,
            line_end_span: None,
            line_end_token: None,
            bytes: Vec::with_capacity(256),
            start_addr: 0,
            aux_value: 0,
            pass: 1,
            label: None,
            mnemonic: None,
            cpu,
            statement_depth: 0,
        }
    }

    fn error(&self) -> Option<&AsmError> {
        self.last_error.as_ref()
    }

    fn error_column(&self) -> Option<usize> {
        self.last_error_column
    }

    fn parser_error(&self) -> Option<ParseError> {
        self.last_parser_error.clone()
    }

    fn parser_error_ref(&self) -> Option<&ParseError> {
        self.last_parser_error.as_ref()
    }

    #[cfg(test)]
    fn error_message(&self) -> &str {
        self.last_error
            .as_ref()
            .map(|err| err.message())
            .unwrap_or("")
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn num_bytes(&self) -> usize {
        self.bytes.len()
    }

    fn start_addr(&self) -> u16 {
        self.start_addr
    }

    fn aux_value(&self) -> u16 {
        self.aux_value
    }

    fn clear_conditionals(&mut self) {
        self.cond_stack.clear();
    }

    fn clear_scopes(&mut self) {
        self.scope_stack.clear();
    }

    fn cond_last(&self) -> Option<&ConditionalContext> {
        self.cond_stack.last()
    }

    #[cfg(test)]
    fn cond_skipping(&self) -> bool {
        self.cond_stack.skipping()
    }

    fn cond_is_empty(&self) -> bool {
        self.cond_stack.is_empty()
    }

    #[cfg(test)]
    fn symbols(&self) -> &SymbolTable {
        &*self.symbols
    }

    fn scoped_define_name(&self, name: &str) -> String {
        if name.contains('.') {
            name.to_string()
        } else {
            self.scope_stack.qualify(name)
        }
    }

    fn resolve_scoped_name(&self, name: &str) -> Option<String> {
        if name.contains('.') {
            return self
                .symbols
                .entry(name)
                .map(|_| name.to_string());
        }
        let mut depth = self.scope_stack.depth();
        while depth > 0 {
            let prefix = self.scope_stack.prefix(depth);
            let candidate = format!("{prefix}.{name}");
            if self.symbols.entry(&candidate).is_some() {
                return Some(candidate);
            }
            depth = depth.saturating_sub(1);
        }
        if self.symbols.entry(name).is_some() {
            Some(name.to_string())
        } else {
            None
        }
    }

    fn lookup_scoped_value(&self, name: &str) -> Option<u32> {
        if name.contains('.') {
            return self.symbols.entry(name).map(|entry| entry.val);
        }
        let mut depth = self.scope_stack.depth();
        while depth > 0 {
            let prefix = self.scope_stack.prefix(depth);
            let candidate = format!("{prefix}.{name}");
            if let Some(entry) = self.symbols.entry(&candidate) {
                return Some(entry.val);
            }
            depth = depth.saturating_sub(1);
        }
        self.symbols.entry(name).map(|entry| entry.val)
    }

    fn process(
        &mut self,
        line: &str,
        line_num: u32,
        addr: u16,
        pass: u8,
    ) -> LineStatus {
        self.last_error = None;
        self.last_error_column = None;
        self.last_parser_error = None;
        self.line_end_span = None;
        self.line_end_token = None;
        self.start_addr = addr;
        self.pass = pass;
        self.bytes.clear();
        self.aux_value = 0;

        self.label = None;
        self.mnemonic = None;

        // Get register checker from the family handler
        let is_register_fn = match self.registry.resolve_pipeline(self.cpu, None) {
            Ok(pipeline) => {
                let family = pipeline.family;
                Arc::new(move |ident: &str| {
                    family.is_register(ident) || family.is_condition(ident)
                })
            }
            Err(_) => register_checker_none(),
        };

        match asm_parser::Parser::from_line_with_registers(line, line_num, is_register_fn) {
            Ok(mut parser) => {
                self.line_end_span = Some(parser.end_span());
                self.line_end_token = parser.end_token_text().map(|s| s.to_string());
                match parser.parse_line() {
                    Ok(ast) => self.process_ast(ast),
                    Err(err) => {
                        self.last_error =
                            Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                        self.last_error_column = Some(err.span.col_start);
                        self.last_parser_error = Some(err);
                        LineStatus::Error
                    }
                }
            }
            Err(err) => {
                self.last_error = Some(AsmError::new(AsmErrorKind::Parser, &err.message, None));
                self.last_error_column = Some(err.span.col_start);
                self.last_parser_error = Some(err);
                LineStatus::Error
            }
        }
    }

    fn process_ast(&mut self, ast: LineAst) -> LineStatus {
        if self.statement_depth > 0 {
            return match ast {
                LineAst::StatementEnd { .. } => {
                    self.statement_depth = self.statement_depth.saturating_sub(1);
                    LineStatus::Skip
                }
                LineAst::StatementDef { span, .. } => {
                    self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Parser,
                        "Nested .statement definitions are not supported",
                        None,
                        span,
                    )
                }
                _ => LineStatus::Skip,
            };
        }
        match ast {
            LineAst::Empty => LineStatus::NothingDone,
            LineAst::Conditional { kind, exprs, span } => {
                self.process_conditional_ast(kind, &exprs, span)
            }
            LineAst::StatementDef { .. } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                self.statement_depth = self.statement_depth.saturating_add(1);
                LineStatus::Skip
            }
            LineAst::StatementEnd { span } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Parser,
                    "Found .endstatement without matching .statement",
                    None,
                    span,
                )
            }
            LineAst::Assignment { label, op, expr, span } => {
                if self.cond_stack.skipping() {
                    return LineStatus::Skip;
                }
                self.process_assignment_ast(&label, op, &expr, span)
            }
            LineAst::Statement {
                label,
                mnemonic,
                operands,
            } => {
                self.label = label.as_ref().map(|l| l.name.clone());
                self.mnemonic = mnemonic.clone();

                if self.cond_stack.skipping() {
                    if let Some(name) = mnemonic.as_deref() {
                        if is_scope_directive(name) {
                            return self.process_directive_ast(name, &operands);
                        }
                    }
                    return LineStatus::Skip;
                }

                let mnemonic = match mnemonic {
                    Some(m) => m,
                    None => {
                        if let Some(label) = &label {
                            let full_name = self.scoped_define_name(&label.name);
                            let res = if self.pass == 1 {
                                self.symbols.add(&full_name, self.start_addr as u32, false)
                            } else {
                                self.symbols.update(&full_name, self.start_addr as u32)
                            };
                            if res == crate::symbol_table::SymbolTableResult::Duplicate {
                                return self.failure_at_span(
                                    LineStatus::Error,
                                    AsmErrorKind::Symbol,
                                    "Symbol defined more than once",
                                    Some(&label.name),
                                    label.span,
                                );
                            }
                        }
                        return LineStatus::NothingDone;
                    }
                };

                if let Some(label) = &label {
                    if !is_symbol_assignment_directive(&mnemonic) {
                        let full_name = self.scoped_define_name(&label.name);
                        let res = if self.pass == 1 {
                            self.symbols.add(&full_name, self.start_addr as u32, false)
                        } else {
                            self.symbols.update(&full_name, self.start_addr as u32)
                        };
                        if res == crate::symbol_table::SymbolTableResult::Duplicate {
                            return self.failure_at_span(
                                LineStatus::Error,
                                AsmErrorKind::Symbol,
                                "Symbol defined more than once",
                                Some(&label.name),
                                label.span,
                            );
                        }
                    }
                }

                let mut status = self.process_directive_ast(&mnemonic, &operands);
                if status == LineStatus::NothingDone {
                    status = self.process_instruction_ast(&mnemonic, &operands);
                }
                status
            }
        }
    }

    fn process_conditional_ast(
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
                let ctx = self.cond_stack.last_mut().unwrap();
                if ctx.sub_type == TokenValue::Else as i32 {
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
                    TokenValue::Else as i32
                } else {
                    TokenValue::ElseIf as i32
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
                if sub_type == TokenValue::Default as i32 {
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
                let sub_type = TokenValue::Case as i32;
                let ctx = self.cond_stack.last_mut().unwrap();
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
                let ctx = self.cond_stack.last_mut().unwrap();
                if ctx.sub_type == TokenValue::Default as i32 {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Conditional,
                        ".default cannot follow .default",
                        None,
                        end_span,
                    );
                }
                ctx.sub_type = TokenValue::Default as i32;
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
                let ctx = self.cond_stack.last_mut().unwrap();
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
                let ctx = self.cond_stack.last_mut().unwrap();
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

    fn process_directive_ast(&mut self, mnemonic: &str, operands: &[Expr]) -> LineStatus {
        let upper = mnemonic.to_ascii_uppercase();
        let had_dot = upper.starts_with('.');
        let directive = upper.strip_prefix('.').unwrap_or(&upper);
        if !had_dot {
            return LineStatus::NothingDone;
        }
        match directive {
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
                self.start_addr = val as u16;
                self.aux_value = val as u16;
                LineStatus::DirEqu
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
                let full_name = self.scoped_define_name(&label);
                let res = if self.pass == 1 {
                    self.symbols.add(&full_name, val, is_rw)
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
                self.aux_value = val as u16;
                LineStatus::DirEqu
            }
            "CPU" => {
                // .cpu directive to switch target CPU
                let cpu_name = match operands.first() {
                    Some(Expr::Identifier(name, _)) => name.clone(),
                    Some(Expr::Register(name, _)) => name.clone(), // In case Z80 is parsed as register
                    Some(Expr::Number(name, _)) => name.clone(), // For bare "8085" without quotes
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
                        )
                    }
                };
                match self.registry.resolve_cpu_name(&cpu_name) {
                    Some(cpu) => {
                        self.cpu = cpu;
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
            "BYTE" | "DB" => self.store_arg_list_ast(operands, 1),
            "WORD" | "DW" => self.store_arg_list_ast(operands, 2),
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
                self.aux_value = val as u16;
                LineStatus::DirDs
            }
            "END" => LineStatus::Ok,
            _ => LineStatus::NothingDone,
        }
    }

    fn process_assignment_ast(
        &mut self,
        label: &Label,
        op: AssignOp,
        expr: &Expr,
        span: Span,
    ) -> LineStatus {
        self.label = Some(label.name.clone());

        match op {
            AssignOp::Const | AssignOp::Var | AssignOp::VarIfUndef => {
                let full_name = self.scoped_define_name(&label.name);
                if op == AssignOp::VarIfUndef {
                    if let Some(entry) = self.symbols.entry(&full_name) {
                        self.aux_value = entry.val as u16;
                        return LineStatus::DirEqu;
                    }
                }
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
                let is_rw = op != AssignOp::Const;
                let res = if self.pass == 1 {
                    self.symbols.add(&full_name, val, is_rw)
                } else {
                    self.symbols.update(&full_name, val)
                };
                if res == crate::symbol_table::SymbolTableResult::Duplicate {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "symbol has already been defined",
                        Some(&label.name),
                        Some(1),
                    );
                } else if res == crate::symbol_table::SymbolTableResult::TableFull {
                    return self.failure_at(
                        LineStatus::Error,
                        AsmErrorKind::Symbol,
                        "could not add symbol, table full",
                        Some(&label.name),
                        Some(1),
                    );
                }
                self.aux_value = val as u16;
                return LineStatus::DirEqu;
            }
            _ => {}
        }

        let target = match self.resolve_scoped_name(&label.name) {
            Some(name) => name,
            None => {
                return self.failure_at(
                    LineStatus::Error,
                    AsmErrorKind::Symbol,
                    "symbol has not been defined",
                    Some(&label.name),
                    Some(1),
                )
            }
        };
        let (left_val, is_rw) = match self.symbols.entry(&target) {
            Some(entry) => (entry.val, entry.rw),
            None => {
                return self.failure_at(
                    LineStatus::Error,
                    AsmErrorKind::Symbol,
                    "symbol has not been defined",
                    Some(&label.name),
                    Some(1),
                )
            }
        };

        if !is_rw {
            return self.failure_at(
                LineStatus::Error,
                AsmErrorKind::Symbol,
                "symbol is read-only",
                Some(&label.name),
                Some(1),
            );
        }

        let rhs = match self.eval_expr_ast(expr) {
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
        let new_val = match apply_assignment_op(op, left_val, rhs, span) {
            Ok(val) => val,
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

        if let Some(entry) = self.symbols.entry_mut(&target) {
            entry.val = new_val;
            entry.updated = true;
        }
        self.aux_value = new_val as u16;
        LineStatus::DirEqu
    }

    fn process_instruction_ast(&mut self, mnemonic: &str, operands: &[Expr]) -> LineStatus {
        let pipeline = match self.registry.resolve_pipeline(self.cpu, None) {
            Ok(pipeline) => pipeline,
            Err(err) => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &registry_error_message(err),
                    None,
                )
            }
        };

        let family_operands = match pipeline.family.parse_operands(mnemonic, operands) {
            Ok(ops) => ops,
            Err(err) => {
                return self.failure_at_span(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &err.message,
                    None,
                    err.span,
                )
            }
        };

        let (mapped_mnemonic, mapped_operands) = pipeline
            .dialect
            .map_mnemonic(mnemonic, family_operands.as_ref())
            .unwrap_or_else(|| (mnemonic.to_string(), family_operands.clone()));

        match pipeline.family.encode_family_operands(
            &mapped_mnemonic,
            mnemonic,
            mapped_operands.as_ref(),
            self,
        ) {
            crate::core::family::FamilyEncodeResult::Ok(bytes) => {
                self.bytes.extend_from_slice(&bytes);
                return LineStatus::Ok;
            }
            crate::core::family::FamilyEncodeResult::Error {
                bytes,
                message,
                span,
                param,
            } => {
                self.bytes.extend_from_slice(&bytes);
                if let Some(span) = span {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &message,
                        param.as_deref(),
                        span,
                    );
                }
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &message,
                    param.as_deref(),
                );
            }
            crate::core::family::FamilyEncodeResult::NotFound => {}
        }

        let resolved_operands = match pipeline.cpu.resolve_operands(
            mnemonic,
            mapped_operands.as_ref(),
            self,
        ) {
            Ok(ops) => ops,
            Err(err) => {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &err,
                    None,
                )
            }
        };

        if let Some(validator) = pipeline.validator.as_ref() {
            if let Err(err) = validator.validate_instruction(
                &mapped_mnemonic,
                resolved_operands.as_ref(),
                self,
            ) {
                return self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &err,
                    None,
                );
            }
        }

        match pipeline.family.encode_instruction(
            &mapped_mnemonic,
            resolved_operands.as_ref(),
            self,
        ) {
            EncodeResult::Ok(bytes) => {
                self.bytes.extend_from_slice(&bytes);
                LineStatus::Ok
            }
            EncodeResult::Error(msg, span_opt) => {
                if let Some(span) = span_opt {
                    self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &msg,
                        None,
                        span,
                    )
                } else {
                    self.failure(
                        LineStatus::Error,
                        AsmErrorKind::Instruction,
                        &msg,
                        None,
                    )
                }
            }
            EncodeResult::NotFound => match pipeline.cpu.encode_instruction(
                &mapped_mnemonic,
                resolved_operands.as_ref(),
                self,
            ) {
                EncodeResult::Ok(bytes) => {
                    self.bytes.extend_from_slice(&bytes);
                    LineStatus::Ok
                }
                EncodeResult::Error(msg, span_opt) => {
                    if let Some(span) = span_opt {
                        self.failure_at_span(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &msg,
                            None,
                            span,
                        )
                    } else {
                        self.failure(
                            LineStatus::Error,
                            AsmErrorKind::Instruction,
                            &msg,
                            None,
                        )
                    }
                }
                EncodeResult::NotFound => self.failure(
                    LineStatus::Error,
                    AsmErrorKind::Instruction,
                    &format!(
                        "No instruction found for {}",
                        mnemonic.to_ascii_uppercase()
                    ),
                    None,
                ),
            },
        }
    }

    fn store_arg_list_ast(&mut self, operands: &[Expr], size: usize) -> LineStatus {
        if operands.is_empty() {
            return self.failure(
                LineStatus::Error,
                AsmErrorKind::Directive,
                "Missing expression in data list",
                None,
            );
        }

        for expr in operands {
            if let Expr::String(bytes, span) = expr {
                if bytes.len() > 1 {
                    self.bytes.extend_from_slice(bytes);
                    continue;
                }
                if bytes.is_empty() {
                    return self.failure_at_span(
                        LineStatus::Error,
                        AsmErrorKind::Directive,
                        "Empty string not allowed in expression list",
                        None,
                        *span,
                    );
                }
            }
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
            if size == 1 {
                self.bytes.push((val & 0xff) as u8);
            } else {
                self.bytes.push((val & 0xff) as u8);
                self.bytes.push((val >> 8) as u8);
            }
        }

        LineStatus::Ok
    }

    fn eval_expr_ast(&self, expr: &Expr) -> Result<u32, AstEvalError> {
        match expr {
            Expr::Error(message, span) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, message, None),
                span: *span,
            }),
            Expr::Number(text, span) => parse_number_text(text, *span),
            Expr::Identifier(name, span) | Expr::Register(name, span) => {
                match self.lookup_scoped_value(name) {
                    Some(value) => Ok(value),
                    None => {
                        if self.pass > 1 {
                            Err(AstEvalError {
                                error: AsmError::new(AsmErrorKind::Expression, "Label not found", Some(name)),
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
            Expr::Immediate(inner, _span) => {
                // Immediate expressions like #$FF - evaluate the inner expression
                self.eval_expr_ast(inner)
            }
            Expr::Tuple(_, span) => Err(AstEvalError {
                error: AsmError::new(AsmErrorKind::Expression, "Tuple cannot be evaluated as expression", None),
                span: *span,
            }),
            Expr::Dollar(_span) => Ok(self.start_addr as u32),
            Expr::String(bytes, span) => {
                if bytes.len() == 1 {
                    Ok(bytes[0] as u32)
                } else if bytes.len() == 2 {
                    Ok(((bytes[0] as u32) << 8) | (bytes[1] as u32))
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
                let then_val = self.eval_expr_ast(then_expr)?;
                let else_val = self.eval_expr_ast(else_expr)?;
                if cond_val != 0 {
                    Ok(then_val)
                } else {
                    Ok(else_val)
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

    fn failure_at_span(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
        span: Span,
    ) -> LineStatus {
        self.failure_at(status, kind, msg, param, Some(span.col_start))
    }

    fn failure(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
    ) -> LineStatus {
        let column = self.line_end_span.map(|span| span.col_start);
        self.failure_at(status, kind, msg, param, column)
    }

    fn failure_at(
        &mut self,
        status: LineStatus,
        kind: AsmErrorKind,
        msg: &str,
        param: Option<&str>,
        column: Option<usize>,
    ) -> LineStatus {
        self.last_error = Some(AsmError::new(kind, msg, param));
        self.last_error_column = column;
        status
    }
}

/// Implement AssemblerContext for AsmLine to provide expression evaluation
/// and symbol lookup to family and CPU handlers.
impl<'a> AssemblerContext for AsmLine<'a> {
    fn eval_expr(&self, expr: &Expr) -> Result<i64, String> {
        self.eval_expr_ast(expr)
            .map(|v| v as i64)
            .map_err(|e| e.error.message().to_string())
    }

    fn symbols(&self) -> &SymbolTable {
        self.symbols
    }

    fn current_address(&self) -> u16 {
        self.start_addr
    }

    fn pass(&self) -> u8 {
        self.pass
    }
}

fn registry_error_message(err: RegistryError) -> String {
    match err {
        RegistryError::MissingFamily(family) => {
            format!("Missing family module for {family:?}")
        }
        RegistryError::MissingCpu(cpu) => format!("Missing CPU module for {cpu:?}"),
        RegistryError::MissingDialect { family, dialect } => {
            format!("Missing dialect '{dialect}' for {family:?}")
        }
    }
}

fn is_symbol_assignment_directive(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        ".CONST" | ".VAR" | ".SET"
    )
}

fn is_scope_directive(mnemonic: &str) -> bool {
    matches!(
        mnemonic.to_ascii_uppercase().as_str(),
        ".BLOCK" | ".ENDBLOCK"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AsmErrorKind, AsmLine, Assembler, LineStatus, ListingWriter,
    };
    use crate::core::registry::ModuleRegistry;
    use crate::families::intel8080::module::Intel8080FamilyModule;
    use crate::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
    use crate::i8085::module::{CPU_ID as i8085_cpu_id, I8085CpuModule};
    use crate::m65c02::module::M65C02CpuModule;
    use crate::z80::module::{CPU_ID as z80_cpu_id, Z80CpuModule};
    use crate::core::macro_processor::MacroProcessor;
    use crate::core::preprocess::Preprocessor;
    use crate::core::symbol_table::SymbolTable;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn default_registry() -> ModuleRegistry {
        let mut registry = ModuleRegistry::new();
        registry.register_family(Box::new(Intel8080FamilyModule));
        registry.register_family(Box::new(MOS6502FamilyModule));
        registry.register_cpu(Box::new(I8085CpuModule));
        registry.register_cpu(Box::new(Z80CpuModule));
        registry.register_cpu(Box::new(M6502CpuModule));
        registry.register_cpu(Box::new(M65C02CpuModule));
        registry
    }

    fn make_asm_line<'a>(
        symbols: &'a mut SymbolTable,
        registry: &'a ModuleRegistry,
    ) -> AsmLine<'a> {
        AsmLine::new(symbols, registry)
    }

    fn process_line(
        asm: &mut AsmLine<'_>,
        line: &str,
        addr: u16,
        pass: u8,
    ) -> LineStatus {
        asm.process(line, 1, addr, pass)
    }

    fn assemble_bytes(cpu: crate::core::cpu::CpuType, line: &str) -> Vec<u8> {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = AsmLine::with_cpu(&mut symbols, cpu, &registry);
        asm.clear_conditionals();
        asm.clear_scopes();
        let status = asm.process(line, 1, 0, 2);
        assert_eq!(status, LineStatus::Ok);
        asm.bytes().to_vec()
    }

    fn assemble_example(asm_path: &Path, out_dir: &Path) -> Result<(), String> {
        let asm_name = asm_path.to_string_lossy().to_string();
        let base = asm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "Invalid example filename".to_string())?;

        let list_path = out_dir.join(format!("{base}.lst"));
        let hex_path = out_dir.join(format!("{base}.hex"));

        let mut list_file =
            File::create(&list_path).map_err(|err| format!("Create list file: {err}"))?;
        let mut hex_file =
            File::create(&hex_path).map_err(|err| format!("Create hex file: {err}"))?;

        let mut pp = Preprocessor::new();
        pp.process_file(&asm_name)
            .map_err(|err| format!("Preprocess failed: {}", err.message()))?;
        let src_lines: Vec<String> = pp.lines().to_vec();
        let mut mp = MacroProcessor::new();
        let expanded_lines = mp
            .expand(&src_lines)
            .map_err(|err| format!("Macro expand failed: {}", err.message()))?;

        let mut assembler = Assembler::new();
        assembler.clear_diagnostics();
        let _ = assembler.pass1(&expanded_lines);

        let mut listing = ListingWriter::new(&mut list_file, false);
        listing
            .header("opForge 8085 Assembler v1.0")
            .map_err(|err| format!("Write listing header: {err}"))?;
        let pass2 = assembler
            .pass2(&expanded_lines, &mut listing)
            .map_err(|err| format!("Pass2 failed: {err}"))?;
        listing
            .footer(&pass2, assembler.symbols(), assembler.image().num_entries())
            .map_err(|err| format!("Write listing footer: {err}"))?;

        assembler
            .image()
            .write_hex_file(&mut hex_file, None)
            .map_err(|err| format!("Write hex file: {err}"))?;

        Ok(())
    }

    fn diff_text(expected: &str, actual: &str, max_lines: usize) -> String {
        let expected_lines: Vec<&str> = expected.split('\n').collect();
        let actual_lines: Vec<&str> = actual.split('\n').collect();
        let max = expected_lines.len().max(actual_lines.len());
        let mut out = String::new();
        let mut shown = 0usize;

        for idx in 0..max {
            let exp = expected_lines.get(idx).copied().unwrap_or("");
            let act = actual_lines.get(idx).copied().unwrap_or("");
            if exp != act {
                shown += 1;
                out.push_str(&format!("{:>5} | -{}\n", idx + 1, exp));
                out.push_str(&format!("{:>5} | +{}\n", idx + 1, act));
                if shown >= max_lines {
                    out.push_str("...\n");
                    break;
                }
            }
        }

        if shown == 0 {
            out.push_str("(no differences)\n");
        }

        out
    }

    #[test]
    fn examples_match_reference_outputs() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let examples_dir = repo_root.join("examples");
        let reference_dir = examples_dir.join("reference");
        let update_reference = std::env::var("opForge_UPDATE_REFERENCE").is_ok();

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let out_dir = repo_root.join("target").join(format!(
            "example-outputs-{}-{}",
            process::id(),
            nanos
        ));
        fs::create_dir_all(&out_dir).expect("Create example output directory");
        if update_reference {
            fs::create_dir_all(&reference_dir).expect("Create reference directory");
        }

        let mut asm_files: Vec<PathBuf> = fs::read_dir(&examples_dir)
            .expect("Read examples directory")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("asm"))
            .collect();
        asm_files.sort();
        assert!(
            !asm_files.is_empty(),
            "No .asm examples found in {}",
            examples_dir.display()
        );

        for asm_path in asm_files {
            let base = asm_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("<unknown>");

            assemble_example(&asm_path, &out_dir)
                .unwrap_or_else(|err| panic!("Failed to assemble {base}: {err}"));

            let out_hex = fs::read(out_dir.join(format!("{base}.hex")))
                .unwrap_or_else(|err| panic!("Missing output hex for {base}: {err}"));
            let out_lst = fs::read(out_dir.join(format!("{base}.lst")))
                .unwrap_or_else(|err| panic!("Missing output list for {base}: {err}"));
            let ref_hex_path = reference_dir.join(format!("{base}.hex"));
            let ref_lst_path = reference_dir.join(format!("{base}.lst"));
            if update_reference {
                fs::write(&ref_hex_path, &out_hex).unwrap_or_else(|err| {
                    panic!("Failed to write reference hex {}: {err}", ref_hex_path.display())
                });
                fs::write(&ref_lst_path, &out_lst).unwrap_or_else(|err| {
                    panic!("Failed to write reference list {}: {err}", ref_lst_path.display())
                });
            } else {
                let ref_hex = fs::read(&ref_hex_path).unwrap_or_else(|err| {
                    panic!("Missing reference hex {}: {err}", ref_hex_path.display())
                });
                assert_eq!(out_hex, ref_hex, "Hex mismatch for {base}");

                let ref_lst = fs::read(&ref_lst_path).unwrap_or_else(|err| {
                    panic!("Missing reference list {}: {err}", ref_lst_path.display())
                });
                let out_lst_text = String::from_utf8_lossy(&out_lst);
                let ref_lst_text = String::from_utf8_lossy(&ref_lst);
                if out_lst_text != ref_lst_text {
                    let diff = diff_text(&ref_lst_text, &out_lst_text, 20);
                    panic!("List mismatch for {base}\n{diff}");
                }
            }
        }
    }

    #[test]
    fn zilog_dialect_encodes_like_intel() {
        let intel = assemble_bytes(i8085_cpu_id, "    MVI A,55h");
        let zilog = assemble_bytes(z80_cpu_id, "    LD A,55h");
        assert_eq!(intel, zilog);

        let intel = assemble_bytes(i8085_cpu_id, "    MOV A,B");
        let zilog = assemble_bytes(z80_cpu_id, "    LD A,B");
        assert_eq!(intel, zilog);

        let intel = assemble_bytes(i8085_cpu_id, "    JMP 1000h");
        let zilog = assemble_bytes(z80_cpu_id, "    JP 1000h");
        assert_eq!(intel, zilog);

        let intel = assemble_bytes(i8085_cpu_id, "    JZ 1000h");
        let zilog = assemble_bytes(z80_cpu_id, "    JP Z,1000h");
        assert_eq!(intel, zilog);

        let intel = assemble_bytes(i8085_cpu_id, "    ADI 10h");
        let zilog = assemble_bytes(z80_cpu_id, "    ADD A,10h");
        assert_eq!(intel, zilog);
    }

    #[test]
    fn org_sets_address() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .org 1000h", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.start_addr(), 0x1000);
        assert_eq!(asm.aux_value(), 0x1000);

        let status = process_line(&mut asm, "* = 1200h", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.start_addr(), 0x1200);
    }

    #[test]
    fn ds_reserves_space_and_defines_label() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "BUFFER: .ds 4", 0x0200, 1);
        assert_eq!(status, LineStatus::DirDs);
        assert_eq!(asm.aux_value(), 4);
        assert_eq!(asm.symbols().lookup("BUFFER"), Some(0x0200));
    }

    #[test]
    fn db_and_dw_emit_bytes() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .byte 1, 2, 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 2, 3]);

        let status = process_line(&mut asm, "    .word 7", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[7, 0]);
    }

    #[test]
    fn equ_defines_symbol_for_pass2() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "VAL .const 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), Some(3));

        let status = process_line(&mut asm, "    .word VAL+1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[4, 0]);
    }

    #[test]
    fn scoped_symbols_resolve_in_current_scope() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "SCOPE .block", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "VAL .const 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "    .word VAL", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[3, 0]);
        let status = process_line(&mut asm, ".endblock", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.symbols().lookup("SCOPE.VAL"), Some(3));
        assert_eq!(asm.symbols().lookup("VAL"), None);
    }

    #[test]
    fn segment_symbols_visible_outside_definition() {
        let lines = vec![
            "MYSEG .segment".to_string(),
            "VAL .const 3".to_string(),
            ".endsegment".to_string(),
            ".MYSEG".to_string(),
            ".word VAL".to_string(),
        ];
        let mut mp = MacroProcessor::new();
        let expanded_lines = mp.expand(&lines).expect("expand");

        let mut assembler = Assembler::new();
        assembler.clear_diagnostics();
        let pass1 = assembler.pass1(&expanded_lines);
        assert_eq!(pass1.errors, 0);
        assert_eq!(assembler.symbols().lookup("VAL"), Some(3));
    }

    #[test]
    fn statement_definitions_skip_body_lines() {
        let lines = vec![
            ".statement foo byte:a".to_string(),
            "BADTOKEN".to_string(),
            ".endstatement".to_string(),
            ".byte 1".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.clear_diagnostics();
        let pass1 = assembler.pass1(&lines);
        assert_eq!(pass1.errors, 0);

        let mut output = Vec::new();
        let mut listing = ListingWriter::new(&mut output, false);
        let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
        assert_eq!(pass2.errors, 0);
    }

    #[test]
    fn statement_definition_rejects_unquoted_commas() {
        let lines = vec![
            ".statement move.b char:dst, char:src".to_string(),
            ".endstatement".to_string(),
        ];
        let mut assembler = Assembler::new();
        assembler.clear_diagnostics();
        let _ = assembler.pass1(&lines);

        let mut output = Vec::new();
        let mut listing = ListingWriter::new(&mut output, false);
        let pass2 = assembler.pass2(&lines, &mut listing).expect("pass2");
        assert!(pass2.errors > 0);
    }

    #[test]
    fn qualified_symbol_resolves_outside_scope() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "SCOPE .block", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "VAL .const 7", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, ".endblock", 0, 1);
        assert_eq!(status, LineStatus::Ok);

        let status = process_line(&mut asm, "    .word SCOPE.VAL", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[7, 0]);
    }

    #[test]
    fn scoped_symbol_shadowing_prefers_inner_scope() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "VAL .const 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "SCOPE .block", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "VAL .const 2", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "    .word VAL", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[2, 0]);
        let status = process_line(&mut asm, ".endblock", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "    .word VAL", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 0]);
    }

    #[test]
    fn nested_scopes_are_addressable_by_qualified_name() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "OUTER .block", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "INNER .block", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "VAL .const 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, ".endblock", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, ".endblock", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        let status = process_line(&mut asm, "    .word OUTER.INNER.VAL", 0, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[5, 0]);
    }

    #[test]
    fn var_allows_redefinition_and_set_alias() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "VAL .var 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), Some(1));

        let status = process_line(&mut asm, "VAL .var 2", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), Some(2));

        let status = process_line(&mut asm, "VAL .set 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("VAL"), Some(3));
    }

    #[test]
    fn assignment_ops_update_symbols() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);

        let status = process_line(&mut asm, "WIDTH = 40", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("WIDTH"), Some(40));

        let status = process_line(&mut asm, "var2 := 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), Some(1));

        let status = process_line(&mut asm, "var2 += 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), Some(2));

        let status = process_line(&mut asm, "var2 *= 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), Some(6));

        let status = process_line(&mut asm, "var2 <?= 4", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), Some(4));

        let status = process_line(&mut asm, "var2 >?= 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var2"), Some(5));

        let status = process_line(&mut asm, "var3 :?= 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var3"), Some(5));

        let status = process_line(&mut asm, "var3 :?= 7", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("var3"), Some(5));

        let status = process_line(&mut asm, "rep := $ab", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "rep x= 3", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("rep"), Some(0x00ababab));

        let status = process_line(&mut asm, "cat := $12", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "cat ..= $3456", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("cat"), Some(0x00123456));

        let status = process_line(&mut asm, "mem := 1", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        let status = process_line(&mut asm, "mem .= 5", 0, 1);
        assert_eq!(status, LineStatus::DirEqu);
        assert_eq!(asm.symbols().lookup("mem"), Some(5));
    }

    #[test]
    fn label_without_colon_defines_symbol() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "LABEL NOP", 0x1000, 1);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.symbols().lookup("LABEL"), Some(0x1000));
    }

    #[test]
    fn set_without_dot_is_not_directive() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    SET 1", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
    }

    #[test]
    fn undotted_directives_are_not_recognized() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    ORG 1000h", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
    }

    #[test]
    fn instruction_encoding_mvi() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    MVI A, 12h", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x3e, 0x12]);
    }

    #[test]
    fn conditionals_do_not_skip_mnemonic_lines() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .if 0", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_skipping());

        let status = process_line(&mut asm, "    .byte 5", 0, 2);
        assert_eq!(status, LineStatus::Skip);
        assert!(asm.bytes().is_empty());
    }

    #[test]
    fn undefined_label_in_pass2_errors() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word MISSING", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.symbols().lookup("MISSING"), None);
    }

    #[test]
    fn expression_precedence_and_ops() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word 1+2*3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[7, 0]);

        let status = process_line(&mut asm, "    .word (1+2)*3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[9, 0]);

        let status = process_line(&mut asm, "    .word 1 << 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x10, 0x00]);

        let status = process_line(&mut asm, "    .word 1 | 2", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[3, 0]);

        let status = process_line(&mut asm, "    .word 2 ** 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[8, 0]);

        let status = process_line(&mut asm, "    .word 0 ? 1 : 2", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[2, 0]);
    }

    #[test]
    fn logical_ops_use_truthiness() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word 2 && 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x00]);

        let status = process_line(&mut asm, "    .word 0 && 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x00, 0x00]);

        let status = process_line(&mut asm, "    .word 0 || 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x00]);

        let status = process_line(&mut asm, "    .word 2 ^^ 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x00, 0x00]);

        let status = process_line(&mut asm, "    .word 0 ^^ 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x00]);

        let status = process_line(&mut asm, "    .word !0", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x00]);
    }

    #[test]
    fn expression_literals_and_prefixes() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(
            &mut asm,
            "    .word $1f, %1010, 1_0_0_0, 17o, 17q",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(
            asm.bytes(),
            &[0x1f, 0x00, 0x0a, 0x00, 0xe8, 0x03, 0x0f, 0x00, 0x0f, 0x00]
        );
    }

    #[test]
    fn expression_comparisons_and_logicals() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(
            &mut asm,
            "    .byte 3==3, 3!=4, 3<>4, 3<=3, 2<3, 3>=2, 3>2, 4=4",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 1, 1, 1, 1, 1, 1, 1]);

        let status = process_line(
            &mut asm,
            "    .byte 2&&3, 0||5, 2^^3, !0, !1",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 1, 0, 1, 0]);
    }

    #[test]
    fn expression_bitwise_ops() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(
            &mut asm,
            "    .byte 0f0h & 00fh, 0f0h | 00fh, 0f0h ^ 00fh",
            0,
            2,
        );
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x00, 0xff, 0xff]);
    }

    #[test]
    fn expression_power_and_ternary_precedence() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word 2 ** 3 ** 2", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x00, 0x02]);

        let status = process_line(&mut asm, "    .byte 0 || 1 ? 2 : 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[2]);
    }

    #[test]
    fn expression_ternary_associativity() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .byte 0 ? 1 : 0 ? 2 : 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[3]);

        let status = process_line(&mut asm, "    .byte 0 ? 1 : 0 || 1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1]);
    }

    #[test]
    fn expression_shift_precedence() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word 1 + 2 << 3", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[24, 0]);

        let status = process_line(&mut asm, "    .word 1 << 2 + 1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[8, 0]);
    }

    #[test]
    fn expression_high_low_with_groups() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .byte >($1234+1), <($1234+1)", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x12, 0x35]);
    }

    #[test]
    fn expression_not_equal_aliases() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .byte 3 <> 4, 3 != 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1, 1]);
    }

    #[test]
    fn expression_nested_ternary_with_parens() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .byte 1 ? (0 ? 2 : 3) : 4", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[3]);

        let status = process_line(&mut asm, "    .byte 0 ? 1 : (0 ? 2 : 5)", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[5]);
    }

    #[test]
    fn expression_underscores_in_hex_suffix() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word 1_2_3_4h, 0_f_f_fh", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x34, 0x12, 0xff, 0x0f]);
    }

    #[test]
    fn conditional_nesting_state_changes() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .if 0", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_skipping());

        let status = process_line(&mut asm, "    .else", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(!asm.cond_skipping());

        let status = process_line(&mut asm, "    .endif", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_is_empty());
    }

    #[test]
    fn conditionals_skip_unmatched_blocks() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);

        let status = process_line(&mut asm, "    .if 1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(!asm.cond_skipping());

        let status = process_line(&mut asm, "    .byte 1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[1]);

        let status = process_line(&mut asm, "    .else", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_skipping());

        let status = process_line(&mut asm, "    .byte 2", 0, 2);
        assert_eq!(status, LineStatus::Skip);
        assert!(asm.bytes().is_empty());

        let status = process_line(&mut asm, "    .endif", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert!(asm.cond_is_empty());
    }

    #[test]
    fn conditionals_only_emit_true_branch_bytes() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let mut addr: u16 = 0;
        let mut out = Vec::new();

        let lines = [
            "    .if 1",
            "    .byte 1",
            "    .else",
            "    .byte 2",
            "    .endif",
            "    .if 0",
            "    .byte 3",
            "    .else",
            "    .byte 4",
            "    .endif",
        ];

        for line in lines {
            let status = asm.process(line, 1, addr, 2);
            match status {
                LineStatus::Ok => {
                    out.extend_from_slice(asm.bytes());
                    addr = addr.wrapping_add(asm.num_bytes() as u16);
                }
                LineStatus::DirDs => {
                    addr = addr.wrapping_add(asm.aux_value());
                }
                LineStatus::DirEqu => {
                    addr = asm.start_addr();
                }
                _ => {}
            }
        }

        assert_eq!(out, vec![1, 4]);
    }

    #[test]
    fn match_only_emits_matching_case() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let mut addr: u16 = 0;
        let mut out = Vec::new();

        let lines = [
            "    .match 2",
            "    .case 1",
            "    .byte 1",
            "    .case 2, 3",
            "    .byte 2",
            "    .default",
            "    .byte 9",
            "    .endmatch",
        ];

        for line in lines {
            let status = asm.process(line, 1, addr, 2);
            match status {
                LineStatus::Ok => {
                    out.extend_from_slice(asm.bytes());
                    addr = addr.wrapping_add(asm.num_bytes() as u16);
                }
                LineStatus::DirDs => {
                    addr = addr.wrapping_add(asm.aux_value());
                }
                LineStatus::DirEqu => {
                    addr = asm.start_addr();
                }
                _ => {}
            }
        }

        assert_eq!(out, vec![2]);
    }

    #[test]
    fn expression_high_low_and_unary() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word > 1234H", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x12, 0x00]);

        let status = process_line(&mut asm, "    .word < 1234H", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x34, 0x00]);

        let status = process_line(&mut asm, "    .word -1", 0, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0xff, 0xff]);
    }

    #[test]
    fn expression_current_address_dollar() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word $ + 1", 0x1000, 2);
        assert_eq!(status, LineStatus::Ok);
        assert_eq!(asm.bytes(), &[0x01, 0x10]);
    }

    #[test]
    fn conditional_errors_for_mismatched_blocks() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .else", 0, 2);
        assert_eq!(status, LineStatus::Error);

        let status = process_line(&mut asm, "    .endif", 0, 2);
        assert_eq!(status, LineStatus::Error);
    }

    #[test]
    fn column_one_errors_for_identifier() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "1mov a,b", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert!(asm.error_message().contains("column 1"));
    }

    #[test]
    fn error_kind_for_parser_failure() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "123", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Parser);
    }

    #[test]
    fn error_kind_for_directive_failure() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .const 5", 0, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Directive);
    }

    #[test]
    fn error_kind_for_instruction_failure() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    RST A", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Instruction);
    }

    #[test]
    fn error_kind_for_expression_failure() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "    .word 1/0", 0, 2);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Expression);
    }

    #[test]
    fn error_kind_for_symbol_failure() {
        let mut symbols = SymbolTable::new();
        let registry = default_registry();
        let mut asm = make_asm_line(&mut symbols, &registry);
        let status = process_line(&mut asm, "LABEL: NOP", 0, 1);
        assert_eq!(status, LineStatus::Ok);

        let status = process_line(&mut asm, "LABEL: NOP", 1, 1);
        assert_eq!(status, LineStatus::Error);
        assert_eq!(asm.error().unwrap().kind(), AsmErrorKind::Symbol);
    }
}
